package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/catenahq/scanctl/internal/detect"
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
	applies  func(detect.Result) bool
	ensure   func(ctx context.Context, version string) (binPath string, err error)
	invoke   func(binPath, root, outPath string) invocation
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
		invoke: func(bin, root, out string) invocation {
			// License scanning is intentionally omitted here: permissive-license
			// notices are noise, and license *policy* is owned by Dependency-Track
			// (P3), which reasons over the full SBOM rather than per-file matches.
			return invocation{args: []string{
				"fs", "--quiet", "--format", "sarif", "--output", out,
				"--scanners", "vuln,misconfig,secret", root,
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
		invoke: func(bin, root, out string) invocation {
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
		invoke: func(bin, root, out string) invocation {
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
		invoke: func(bin, root, out string) invocation {
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
		invoke: func(bin, root, out string) invocation {
			return invocation{
				args:        []string{"-C", root, "-format", "sarif", "./..."},
				stdoutToOut: true,
			}
		},
	},
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
