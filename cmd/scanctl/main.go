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
	"sort"
	"strings"

	"github.com/catenahq/scanctl"
	"github.com/catenahq/scanctl/internal/baseline"
	"github.com/catenahq/scanctl/internal/config"
	"github.com/catenahq/scanctl/internal/dismiss"
	"github.com/catenahq/scanctl/internal/gate"
	"github.com/catenahq/scanctl/internal/report"
	"github.com/catenahq/scanctl/internal/runner"
	"github.com/catenahq/scanctl/internal/sarif"
	"github.com/catenahq/scanctl/internal/upload"
)

// multiFlag collects a repeatable string flag, e.g. -import a.sarif -import b.sarif.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

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
  -baseline string optional SARIF of findings accepted for good; they are
                   suppressed on every run, and an entry the scan no longer
                   produces fails it (missing file = no-op)
  -dismiss-baseline
                   also close the matching GitHub code-scanning alert for every
                   finding the -baseline accepted (GitHub does not act on SARIF
                   "external" suppressions itself). Requires GITHUB_REPOSITORY +
                   GH_TOKEN/GITHUB_TOKEN (set by Actions); a no-op elsewhere.
                   Ignored unless -baseline is also set.
  -baseline-ref string
                   git ref (e.g. origin/main); the images pinned at the
                   merge-base of HEAD and it are scanned too, and only the
                   image CVEs the change introduces gate. Findings in the
                   repo's own tree gate either way. Empty inside GitHub
                   Actions: read from the event (pull request: its target
                   branch; push: the commit before it). With no ref, image
                   findings are reported, not gated
  -own-image string
                   an image this repo builds (e.g. the tag the workflow's
                   docker build produced); scanned like images, but its
                   CVEs gate on every run, like the tree's; repeatable
  -import string   fold an external SARIF file (e.g. CodeQL) into the merge;
                   repeatable
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
	baselinePath := fs.String("baseline", "", "")
	dismissBaseline := fs.Bool("dismiss-baseline", false, "")
	baselineRef := fs.String("baseline-ref", "", "")
	var imports, ownImages multiFlag
	fs.Var(&imports, "import", "")
	fs.Var(&ownImages, "own-image", "")
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
	cfg.OwnImages = ownImages

	lock, err := loadLock(*lockPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "lock:", err)
		return 2
	}

	// Resolved BEFORE the scan below, not just before the baseline: knowing
	// what the change touches is what lets the image pins be narrowed to it,
	// and both sides of the diff have to be narrowed the same way or the
	// baseline stops lining up with the report it is suppressing against.
	baseRef := resolveBaseRef(context.Background(), root, *baselineRef)
	baseSha := ""
	pinsScoped := false
	if baseRef != "" {
		fmt.Printf("baseline-ref: comparing with %s\n", baseRef)
		sha, err := mergeBase(context.Background(), root, baseRef)
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: baseline-ref:", err)
		} else {
			baseSha = sha
			if len(cfg.ImagePins) > 0 {
				cfg = scopeImagePins(context.Background(), cfg, root, sha)
				pinsScoped = true
				fmt.Printf("image_pins: %d pin file(s) changed since %.12s; "+
					"the rest resolve identically on both sides and are not rescanned\n",
					len(cfg.ImagePins), sha)
			}
		}
	}

	out, err := runner.Run(context.Background(), root, cfg, lock)
	if err != nil {
		fmt.Fprintln(os.Stderr, "run:", err)
		return 2
	}

	for _, w := range out.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}

	// Fold in externally-produced SARIF (e.g. a CodeQL job's output) before
	// the report, gate, and uploads so everything sees one merged view.
	for _, p := range imports {
		ext, err := sarif.Load(p)
		if err != nil {
			fmt.Fprintln(os.Stderr, "import:", err)
			return 2
		}
		out.Report.Merge(ext)
		fmt.Printf("imported %d finding(s) from %s\n", ext.ResultCount(), p)
	}

	// Image CVEs are upstream's to fix: only the ones a change INTRODUCES gate.
	// With a base, the images it pinned are scanned and their findings
	// suppressed; a failed base scan degrades to the full gate (stricter,
	// never looser) with a warning. With no change to grade, no image finding
	// was introduced, so all of them are reported.
	if baseSha != "" {
		set, err := baselineRefSet(context.Background(), root, baseSha, *cfgPath, *profile, cfg, lock)
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: baseline-ref:", err)
		} else if n := baseline.ApplyRoot(out.Report, set, absPath(root)); n > 0 {
			fmt.Printf("baseline-ref: suppressed %d image finding(s) already present at %.12s\n", n, baseSha)
		}
	} else if baseRef == "" {
		if n := reportImageFindings(out.Report); n > 0 {
			fmt.Printf("no change to grade: %d image finding(s) reported, not gated\n", n)
		}
	}

	// Findings accepted for good in a committed baseline are marked suppressed
	// (kind: external) on every run. An entry matching nothing in this scan
	// fails the run: it would accept the finding again if it came back.
	var stale []baseline.Entry
	if *baselinePath != "" {
		baseRep, err := baseline.LoadReport(*baselinePath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "baseline:", err)
			return 2
		}
		if baseRep != nil {
			if n := baseline.Apply(out.Report, baseline.FromReport(baseRep)); n > 0 {
				fmt.Printf("baseline: suppressed %d known finding(s) from %s\n", n, *baselinePath)
			}
			stale = baseline.Stale(baseRep, out.Report)
		}

		// The SARIF suppression above never closes the GitHub alert itself
		// (GitHub does not act on third-party "external" suppressions) --
		// close it directly through the API instead. Skipped on a
		// pull_request event: a feature-branch run is not the source of
		// truth for what the org has accepted, so it must never dismiss a
		// repo-wide alert.
		if *dismissBaseline && os.Getenv("GITHUB_EVENT_NAME") != "pull_request" {
			if gh, ok := dismiss.FromEnv(); ok {
				n, err := gh.Dismiss(context.Background(), out.Report)
				if err != nil {
					fmt.Fprintln(os.Stderr, "warning: dismiss-baseline:", err)
				} else if n > 0 {
					fmt.Printf("dismiss-baseline: closed %d matching GitHub alert(s)\n", n)
				}
			}
		}
	}

	// A run that scanned only the pins its change touched writes no third-party
	// image findings: uploaded, they would close the alerts of every image it
	// skipped.
	if err := report.WriteSARIF(out.Report, *outPath, pinsScoped); err != nil {
		fmt.Fprintln(os.Stderr, "write sarif:", err)
		return 2
	}

	ctx := context.Background()
	uploadResults(ctx, cfg, *outPath)
	sbomStep(ctx, cfg, lock, root, *sbomOut)

	summary := report.Summary(out.Report, cfg) + staleSection(*baselinePath, stale) + failedSection(out.Failed)
	fmt.Print(summary)
	fmt.Printf("\nran: %v\n", out.Ran)
	if *summaryPath != "" {
		// #nosec G306 -- the summary is non-sensitive report output; 0644 is intentional
		if err := os.WriteFile(*summaryPath, []byte(summary), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write summary:", err)
		}
	}

	verdict := gate.Evaluate(out.Report, cfg)
	fmt.Printf("gate: %d gating finding(s) of %d total (floor=%s); %d blocking scan(s) did not run\n",
		verdict.Gating, verdict.Total, cfg.Gate.Floor, len(out.Failed))

	if *noGate {
		return 0
	}
	if verdict.Failed() || len(stale) > 0 || len(out.Failed) > 0 {
		return 1
	}
	return 0
}

// failedSection lists the blocking scans that produced no report; "" when
// every one ran.
func failedSection(failed map[string]string) string {
	if len(failed) == 0 {
		return ""
	}
	keys := make([]string, 0, len(failed))
	for k := range failed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "\n### Scanners that did not run (%d)\n\n", len(failed))
	b.WriteString("Their findings would gate, and nothing looked for them, so the run fails. The warnings above say why.\n\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "- %s: %s\n", k, failed[k])
	}
	return b.String()
}

// staleSection lists the committed baseline entries that match nothing in this
// scan; "" when there are none.
func staleSection(path string, stale []baseline.Entry) string {
	if len(stale) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n### Stale baseline entries (%d)\n\n", len(stale))
	fmt.Fprintf(&b, "%s accepts findings this scan does not produce. Remove them.\n\n", path)
	for _, e := range stale {
		where := ""
		if len(e.Result.Locations) > 0 {
			where = " (" + e.Result.Locations[0].PhysicalLocation.ArtifactLocation.URI + ")"
		}
		fmt.Fprintf(&b, "- [%s] %s%s\n", e.Tool, e.Result.RuleID, where)
	}
	return b.String()
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
