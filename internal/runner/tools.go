package runner

import (
	"context"
	"debug/buildinfo"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/catenahq/scanctl/internal/config"
	"github.com/catenahq/scanctl/internal/detect"
	"github.com/catenahq/scanctl/internal/sarif"
)

// invocation describes how to run a tool: the argv, the working directory
// (empty = current), variables added to scanctl's environment, and whether the
// SARIF lands on stdout (captured to the out file) rather than being written by
// the tool itself.
type invocation struct {
	args        []string
	workdir     string
	env         []string
	stdoutToOut bool
}

// toolDef is a single scanner: when it applies, how to fetch it, how to run it.
type toolDef struct {
	name string
	// scanType is the DefectDojo parser id, recorded for the P2 upload phase.
	scanType string
	// fullOnly marks a tool that is resale-restricted (e.g. Semgrep registry
	// rules, deps.dev): it runs only under the "full" profile. The default core
	// is resale-clean and runs in both profiles.
	fullOnly bool
	applies  func(detect.Result) bool
	ensure   func(ctx context.Context, e LockEntry, root string) (binPath string, err error)
	// invoke builds the argv. det is passed so a tool can shape its invocation
	// from what was detected (e.g. semgrep selects rule packs per ecosystem);
	// tools that do not need it ignore the arg.
	invoke func(binPath, root, outPath string, det detect.Result) invocation
	// convert is the adapter seam for tools that do NOT emit SARIF: it turns the
	// tool's native output bytes into a SARIF report. nil means the tool already
	// writes SARIF (the v1 core). This is how JSON-only scanners (GuardDog,
	// Scorecard, libyear, ...) plug in without touching the runner.
	convert func(raw []byte) (*sarif.Report, error)
}

// profileAllows reports whether td may run under the given profile.
func profileAllows(td toolDef, profile string) bool {
	return !td.fullOnly || profile == config.ProfileFull
}

// registry is the v1 core: all resale-clean, all SARIF-native.
var registry = []toolDef{
	{
		name:     "trivy",
		scanType: "Trivy Scan",
		applies:  func(r detect.Result) bool { return true }, // fs scan always useful
		ensure:   releaseEnsure("trivy"),
		invoke: func(bin, root, out string, _ detect.Result) invocation {
			// License scanning is intentionally omitted here: permissive-license
			// notices are noise, and license *policy* is owned by Dependency-Track
			// (P3), which reasons over the full SBOM rather than per-file matches.
			args := trivyArgs("fs", "--quiet", "--format", "sarif", "--output", out,
				"--scanners", "vuln,misconfig,secret", "--ignore-unfixed")
			// The same ignore file the image scan honours. trivy reads neither
			// on its own, so without this a repo's suppressions apply to its
			// images and not to its tree -- one file, two answers, and no way
			// to tell from the output which half took effect.
			if ign := trivyIgnoreFile(root); ign != "" {
				args = append(args, "--ignorefile", ign)
			}
			return invocation{args: append(args, root)}
		},
	},
	{
		name:     "osv-scanner",
		scanType: "OSV Scan",
		applies:  func(r detect.Result) bool { return r.HasLockfile },
		ensure:   releaseEnsure("osv-scanner"),
		invoke: func(bin, root, out string, _ detect.Result) invocation {
			return invocation{args: []string{
				"scan", "source", "--recursive", "--format", "sarif", "--output", out, root,
			}}
		},
	},
	{
		name:     "gitleaks",
		scanType: "Gitleaks Scan",
		applies:  func(r detect.Result) bool { return true },
		ensure:   releaseEnsure("gitleaks"),
		invoke: func(bin, root, out string, _ detect.Result) invocation {
			args := []string{"detect", "--source", root, "--report-format", "sarif",
				"--report-path", out, "--redact"}
			if cfg := gitleaksConfigPath(root); cfg != "" {
				args = append(args, "--config", cfg)
			}
			// Scan the history of the commit being scanned when root is a
			// repo; otherwise scan files. Other branches are scanned when they
			// are pushed.
			if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
				args = append(args, "--log-opts=HEAD")
			} else {
				args = append(args, "--no-git")
			}
			return invocation{args: args}
		},
	},
	{
		name:     "gosec",
		scanType: "Gosec Scanner",
		applies:  func(r detect.Result) bool { return r.Has(detect.Go) },
		ensure:   releaseEnsure("gosec"),
		invoke: func(bin, root, out string, _ detect.Result) invocation {
			// G101 (hardcoded credentials) reads names such as settings keys
			// and env-var names as secrets. gitleaks owns secrets, over the
			// whole history.
			return invocation{
				args:    []string{"-fmt", "sarif", "-out", out, "-quiet", "-no-fail", "-exclude=G101", "./..."},
				workdir: root,
			}
		},
	},
	{
		name:     "govulncheck",
		scanType: "Govulncheck Scanner",
		applies:  func(r detect.Result) bool { return r.Has(detect.Go) },
		ensure: func(ctx context.Context, e LockEntry, root string) (string, error) {
			return goInstall(ctx, "golang.org/x/vuln", "cmd/govulncheck", e.Version, root)
		},
		invoke: func(bin, root, out string, _ detect.Result) invocation {
			inv := invocation{
				args:        []string{"-C", root, "-format", "sarif", "./..."},
				stdoutToOut: true,
			}
			// govulncheck grades the standard library of `go env GOVERSION` and
			// loads packages with that go. Both run under the toolchain that
			// built it, the one the module selects (goInstall): under a
			// runner's GOTOOLCHAIN=local, go is whichever comes first on PATH.
			if bi, err := buildinfo.ReadFile(bin); err == nil {
				inv.env = []string{"GOTOOLCHAIN=" + bi.GoVersion}
			}
			return inv
		},
	},
	{
		// semgrep SAST. fullOnly: the registry rule packs (p/...) are resale-
		// restricted, so it runs only under the "full" profile. Packs are
		// auto-selected from the detected ecosystems (mirrors the per-repo
		// --config choices the standalone semgrep workflows used). --error is
		// omitted: scanctl's severity gate decides blocking, not semgrep's exit
		// code (runTool treats non-zero + SARIF as findings, not failure).
		name:     "semgrep",
		scanType: "Semgrep JSON Report",
		fullOnly: true,
		applies:  func(r detect.Result) bool { return r.Has(detect.Go) || r.Has(detect.Node) || r.Has(detect.Python) },
		ensure: func(ctx context.Context, e LockEntry, _ string) (string, error) {
			return pyInstall(ctx, "semgrep", e.Version, "semgrep")
		},
		invoke: func(bin, root, out string, det detect.Result) invocation {
			args := []string{"scan", "--metrics=off", "--sarif-output", out, "--quiet"}
			for _, cfg := range semgrepConfigs(det) {
				args = append(args, "--config", cfg)
			}
			args = append(args, root)
			return invocation{args: args}
		},
	},
	{
		// zizmor: GitHub Actions workflow audit (Rust binary, SARIF-native).
		// Resale-clean (MIT/Apache). Some audits call the GitHub API; we honor
		// GH_TOKEN when present and run --offline otherwise so a tokenless run
		// still produces the static-analysis findings.
		name:     "zizmor",
		scanType: "SARIF",
		applies:  func(r detect.Result) bool { return r.HasWorkflows },
		ensure:   releaseEnsure("zizmor"),
		invoke: func(bin, root, out string, _ detect.Result) invocation {
			args := []string{"--format", "sarif", "--persona", "regular"}
			// Bundled policy: first-party catenahq/* may ref-pin (intentional
			// @main reusable workflow), third-party must hash-pin. --config is
			// safe here because scanctl audits a single input source (root).
			if cfgPath, err := zizmorConfigPath(); err == nil {
				args = append(args, "--config", cfgPath)
			}
			if os.Getenv("GH_TOKEN") == "" {
				args = append(args, "--offline")
			}
			args = append(args, root)
			return invocation{args: args, stdoutToOut: true}
		},
	},
}

// semgrepConfigs maps detected ecosystems to semgrep registry rule packs. The
// OWASP Top Ten pack always runs; language packs are added per detected
// ecosystem. Order is stable for testability; the root pack is implicit (none).
func semgrepConfigs(det detect.Result) []string {
	cfgs := []string{"p/owasp-top-ten"}
	if det.Has(detect.Go) {
		cfgs = append(cfgs, "p/golang")
	}
	if det.Has(detect.Python) {
		cfgs = append(cfgs, "p/python")
	}
	if det.Has(detect.Node) {
		cfgs = append(cfgs, "p/javascript", "p/typescript")
	}
	if det.Has(detect.Docker) {
		cfgs = append(cfgs, "p/dockerfile")
	}
	if det.Has(detect.Terraform) {
		cfgs = append(cfgs, "p/terraform")
	}
	return cfgs
}

// trivyArgs builds a trivy argv from its subcommand and the rest of its flags,
// with the two flags that stop trivy reporting its install id, command and flags
// to its maker (version check and telemetry) placed right after the subcommand.
func trivyArgs(subcommand string, rest ...string) []string {
	return append([]string{subcommand, "--skip-version-check", "--disable-telemetry"}, rest...)
}

// downloadTrivyDB fetches trivy's vulnerability database into its cache without
// scanning, so the time it takes is its own step. The scans that follow find it
// there, and fetch it themselves when this fails.
func downloadTrivyDB(ctx context.Context, bin string) error {
	// #nosec G204 -- bin is the pinned trivy; the args are fixed flags
	cmd := exec.CommandContext(ctx, bin, trivyArgs("image", "--download-db-only", "--quiet")...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w\n%s", err, out)
	}
	return nil
}

// releaseTool describes a scanner distributed as a GitHub release file: the
// file's name for a version (linux amd64), and the binary inside it when the
// file is a .tar.gz ("" when the file is the binary).
type releaseTool struct {
	asset func(version string) string
	bin   string
}

// releaseTools holds the scanners fetched from a GitHub release, keyed by the
// name tools.lock pins them under. Both the fetch and `scanctl refresh-digests`
// read it.
var releaseTools = map[string]releaseTool{
	"trivy": {
		asset: func(v string) string { return fmt.Sprintf("trivy_%s_Linux-64bit.tar.gz", v) },
		bin:   "trivy",
	},
	"osv-scanner": {
		asset: func(string) string { return "osv-scanner_linux_amd64" },
	},
	"gitleaks": {
		asset: func(v string) string { return fmt.Sprintf("gitleaks_%s_linux_x64.tar.gz", v) },
		bin:   "gitleaks",
	},
	"gosec": {
		asset: func(v string) string { return fmt.Sprintf("gosec_%s_linux_amd64.tar.gz", v) },
		bin:   "gosec",
	},
	"syft": {
		asset: func(v string) string { return fmt.Sprintf("syft_%s_linux_amd64.tar.gz", v) },
		bin:   "syft",
	},
	"zizmor": {
		asset: func(string) string { return "zizmor-x86_64-unknown-linux-gnu.tar.gz" },
		bin:   "zizmor",
	},
}

// hostOS and hostArch are the platform release files are fetched for.
var hostOS, hostArch = runtime.GOOS, runtime.GOARCH

// releaseEnsure returns an ensure func for a releaseTools scanner: the release
// file checked against the sha256 tools.lock pins for it (see releaseFile), then
// made executable (a plain binary) or with its binary extracted from it afresh
// (a .tar.gz). The check and extraction run once per tool version per process.
func releaseEnsure(tool string) func(context.Context, LockEntry, string) (string, error) {
	return func(ctx context.Context, e LockEntry, _ string) (string, error) {
		rt, ok := releaseTools[tool]
		if !ok {
			return "", fmt.Errorf("%s: not a release tool", tool)
		}
		if hostOS != "linux" || hostArch != "amd64" {
			return "", fmt.Errorf("%s: release scanners are pinned for linux amd64, not %s/%s", tool, hostOS, hostArch)
		}
		return checkedOnce(tool, e, func() (string, error) {
			file, err := releaseFile(ctx, tool, e, rt.asset(e.Version))
			if err != nil {
				return "", err
			}
			if rt.bin == "" {
				if err := os.Chmod(file, 0o755); err != nil { // #nosec G302 -- a scanner binary must be executable
					return "", err
				}
				return file, nil
			}
			dest := filepath.Join(filepath.Dir(file), tool)
			if err := extractTarGz(file, rt.bin, dest); err != nil {
				return "", err
			}
			return dest, nil
		})
	}
}
