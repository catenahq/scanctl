package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/catenahq/scanctl/internal/config"
	"github.com/catenahq/scanctl/internal/detect"
	"github.com/catenahq/scanctl/internal/sarif"
)

// invocation describes how to run a tool: the argv, the working directory
// (empty = current), and whether the SARIF lands on stdout (captured to the
// out file) rather than being written by the tool itself.
type invocation struct {
	args        []string
	workdir     string
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
	ensure   func(ctx context.Context, version string) (binPath string, err error)
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
		ensure: ghTarGz("trivy", func(v string) string {
			return fmt.Sprintf("https://github.com/aquasecurity/trivy/releases/download/v%s/trivy_%s_Linux-%s.tar.gz",
				v, v, trivyArch())
		}, "trivy"),
		invoke: func(bin, root, out string, _ detect.Result) invocation {
			// License scanning is intentionally omitted here: permissive-license
			// notices are noise, and license *policy* is owned by Dependency-Track
			// (P3), which reasons over the full SBOM rather than per-file matches.
			return invocation{args: []string{
				"fs", "--quiet", "--format", "sarif", "--output", out,
				"--scanners", "vuln,misconfig,secret", "--ignore-unfixed", root,
			}}
		},
	},
	{
		name:     "osv-scanner",
		scanType: "OSV Scan",
		applies:  func(r detect.Result) bool { return r.HasLockfile },
		ensure: ghBinary("osv-scanner", func(v string) string {
			return fmt.Sprintf("https://github.com/google/osv-scanner/releases/download/v%s/osv-scanner_linux_%s",
				v, runtime.GOARCH)
		}),
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
		ensure: ghTarGz("gitleaks", func(v string) string {
			return fmt.Sprintf("https://github.com/gitleaks/gitleaks/releases/download/v%s/gitleaks_%s_linux_%s.tar.gz",
				v, v, gitleaksArch())
		}, "gitleaks"),
		invoke: func(bin, root, out string, _ detect.Result) invocation {
			args := []string{"detect", "--source", root, "--report-format", "sarif",
				"--report-path", out, "--redact"}
			// Scan full git history when root is a repo; otherwise scan files.
			if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
				args = append(args, "--log-opts=--all")
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
		ensure: ghTarGz("gosec", func(v string) string {
			return fmt.Sprintf("https://github.com/securego/gosec/releases/download/v%s/gosec_%s_linux_%s.tar.gz",
				v, v, runtime.GOARCH)
		}, "gosec"),
		invoke: func(bin, root, out string, _ detect.Result) invocation {
			return invocation{
				args:    []string{"-fmt", "sarif", "-out", out, "-quiet", "-no-fail", "./..."},
				workdir: root,
			}
		},
	},
	{
		name:     "govulncheck",
		scanType: "Govulncheck Scanner",
		applies:  func(r detect.Result) bool { return r.Has(detect.Go) },
		ensure: func(ctx context.Context, version string) (string, error) {
			return goInstall(ctx, "golang.org/x/vuln", "cmd/govulncheck", version)
		},
		invoke: func(bin, root, out string, _ detect.Result) invocation {
			return invocation{
				args:        []string{"-C", root, "-format", "sarif", "./..."},
				stdoutToOut: true,
			}
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
		ensure: func(ctx context.Context, version string) (string, error) {
			return pyInstall(ctx, "semgrep", version, "semgrep")
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
		ensure: ghTarGz("zizmor", func(v string) string {
			return fmt.Sprintf("https://github.com/zizmorcore/zizmor/releases/download/v%s/zizmor-%s-unknown-linux-gnu.tar.gz",
				v, zizmorArch())
		}, "zizmor"),
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

// trivyArch maps GOARCH to trivy's asset token.
func trivyArch() string {
	if runtime.GOARCH == "arm64" {
		return "ARM64"
	}
	return "64bit"
}

// gitleaksArch maps GOARCH to gitleaks' asset token (amd64 -> x64).
func gitleaksArch() string {
	if runtime.GOARCH == "arm64" {
		return "arm64"
	}
	return "x64"
}

// zizmorArch maps GOARCH to zizmor's release-asset target triple token.
func zizmorArch() string {
	if runtime.GOARCH == "arm64" {
		return "aarch64"
	}
	return "x86_64"
}

// ghBinary returns an ensure func for a plain (non-archive) release binary,
// cached per version under the cache root.
func ghBinary(tool string, urlFn func(version string) string) func(context.Context, string) (string, error) {
	return func(ctx context.Context, version string) (string, error) {
		dest := filepath.Join(cacheRoot(), tool+"-"+version, tool)
		if fi, err := os.Stat(dest); err == nil && !fi.IsDir() {
			return dest, nil
		}
		if err := downloadBinary(ctx, urlFn(version), dest); err != nil {
			return "", err
		}
		return dest, nil
	}
}

// ghTarGz returns an ensure func for a .tar.gz release asset, extracting
// binInArchive, cached per version.
func ghTarGz(tool string, urlFn func(version string) string, binInArchive string) func(context.Context, string) (string, error) {
	return func(ctx context.Context, version string) (string, error) {
		dest := filepath.Join(cacheRoot(), tool+"-"+version, tool)
		if fi, err := os.Stat(dest); err == nil && !fi.IsDir() {
			return dest, nil
		}
		if err := downloadTarGzBinary(ctx, urlFn(version), binInArchive, dest); err != nil {
			return "", err
		}
		return dest, nil
	}
}
