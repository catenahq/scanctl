// Command scanctl runs a config-driven bundle of FOSS security scanners over a
// repo, merges their SARIF, prints a summary, and gates the build. v1 is
// serverless: one binary, no dashboard. tools.lock is embedded so the pinned
// scanner versions travel with the binary.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/catenahq/scanctl"
	"github.com/catenahq/scanctl/internal/config"
	"github.com/catenahq/scanctl/internal/gate"
	"github.com/catenahq/scanctl/internal/report"
	"github.com/catenahq/scanctl/internal/runner"
	"github.com/catenahq/scanctl/internal/upload"
)

// version is set via -ldflags at release; "dev" for local builds.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		os.Exit(runCmd(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Println("scanctl", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `scanctl - bundled FOSS security scanners

usage:
  scanctl run [flags] [path]   detect, scan, merge SARIF, gate (path default ".")
  scanctl version

run flags:
  -config string   path to scanctl.yml (default "scanctl.yml"; missing = defaults)
  -lock string     path to tools.lock (default: embedded copy)
  -profile string  override the config profile ("sellable" or "full")
  -out string      merged SARIF output path (default "scanctl.sarif")
  -summary string  markdown summary output path (default: stdout only)
  -sbom string     write a CycloneDX SBOM to this path (syft)
  -no-gate         scan and report but always exit 0

upload (optional, via scanctl.yml + env): findings -> DefectDojo
(DEFECTDOJO_TOKEN), SBOM -> Dependency-Track (DEPENDENCYTRACK_APIKEY).
`)
}

func runCmd(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", "scanctl.yml", "")
	lockPath := fs.String("lock", "", "")
	profile := fs.String("profile", "", "")
	outPath := fs.String("out", "scanctl.sarif", "")
	summaryPath := fs.String("summary", "", "")
	sbomOut := fs.String("sbom", "", "")
	noGate := fs.Bool("no-gate", false, "")
	_ = fs.Parse(args)

	root := "."
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 2
	}
	if *profile != "" {
		if *profile != config.ProfileSellable && *profile != config.ProfileFull {
			fmt.Fprintf(os.Stderr, "config: invalid -profile %q (want %q or %q)\n", *profile, config.ProfileSellable, config.ProfileFull)
			return 2
		}
		cfg.Profile = *profile
	}

	lock, err := loadLock(*lockPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "lock:", err)
		return 2
	}

	out, err := runner.Run(context.Background(), root, cfg, lock)
	if err != nil {
		fmt.Fprintln(os.Stderr, "run:", err)
		return 2
	}

	for _, w := range out.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}

	if err := report.WriteSARIF(out.Report, *outPath); err != nil {
		fmt.Fprintln(os.Stderr, "write sarif:", err)
		return 2
	}

	ctx := context.Background()
	uploadResults(ctx, cfg, *outPath)
	sbomStep(ctx, cfg, lock, root, *sbomOut)

	summary := report.Summary(out.Report)
	fmt.Print(summary)
	fmt.Printf("\nran: %v\n", out.Ran)
	if *summaryPath != "" {
		// #nosec G306 -- the summary is non-sensitive report output; 0644 is intentional
		if err := os.WriteFile(*summaryPath, []byte(summary), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write summary:", err)
		}
	}

	verdict := gate.Evaluate(out.Report, cfg)
	fmt.Printf("gate: %d gating finding(s) of %d total (floor=%s)\n",
		verdict.Gating, verdict.Total, cfg.Gate.Floor)

	if *noGate {
		return 0
	}
	if verdict.Failed() {
		return 1
	}
	return 0
}

// uploadResults pushes the merged SARIF to DefectDojo when configured. A
// missing/unconfigured target is silently skipped; an upload failure is a
// warning, never fatal -- the scan + gate already happened.
func uploadResults(ctx context.Context, cfg config.Config, sarifPath string) {
	dd := cfg.Upload.DefectDojo
	if client, ok := upload.DefectDojoFromEnv(dd.URL, dd.ProductName, dd.EngagementName); ok {
		if err := client.ImportSARIF(ctx, sarifPath); err != nil {
			fmt.Fprintln(os.Stderr, "warning: defectdojo upload:", err)
		} else {
			fmt.Println("uploaded findings to DefectDojo")
		}
	} else if dd.URL != "" {
		fmt.Fprintln(os.Stderr, "warning: DefectDojo URL set but DEFECTDOJO_TOKEN missing -- skipping upload")
	}
}

// sbomStep generates a CycloneDX SBOM and uploads it to Dependency-Track when
// configured. It runs if --sbom is set OR a DT target is configured. As with
// findings upload, failures are warnings -- never fatal.
func sbomStep(ctx context.Context, cfg config.Config, lock runner.Lock, root, sbomOut string) {
	dt := cfg.Upload.DependencyTrack
	client, dtActive := upload.DependencyTrackFromEnv(dt.URL, dt.ProjectName, dt.ProjectVersion)
	if sbomOut == "" && !dtActive {
		if dt.URL != "" {
			fmt.Fprintln(os.Stderr, "warning: Dependency-Track URL set but DEPENDENCYTRACK_APIKEY missing -- skipping SBOM upload")
		}
		return
	}

	path := sbomOut
	if path == "" {
		path = "scanctl.sbom.cdx.json"
		defer os.Remove(path)
	}
	if err := runner.GenerateSBOM(ctx, root, lock, path); err != nil {
		fmt.Fprintln(os.Stderr, "warning: sbom:", err)
		return
	}
	if sbomOut != "" {
		fmt.Println("wrote SBOM to", sbomOut)
	}
	if dtActive {
		if err := client.UploadBOM(ctx, path); err != nil {
			fmt.Fprintln(os.Stderr, "warning: dependency-track upload:", err)
		} else {
			fmt.Println("uploaded SBOM to Dependency-Track")
		}
	}
}

func loadLock(path string) (runner.Lock, error) {
	if path != "" {
		return runner.LoadLock(path)
	}
	return runner.ParseLock(scanctl.ToolsLock)
}
