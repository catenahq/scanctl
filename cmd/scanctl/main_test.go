package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A config where trivy is the only scanner, and a lock that does not pin it:
// the one blocking scan cannot run.
func unrunnableScan(t *testing.T) (root string, args []string) {
	t.Helper()
	t.Setenv("GITHUB_ACTIONS", "")
	root = t.TempDir()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "scanctl.yml")
	var b strings.Builder
	b.WriteString("tools:\n  trivy:\n    enabled: true\n    mode: block\n")
	for _, tool := range []string{"osv-scanner", "govulncheck", "gosec", "gitleaks", "semgrep", "zizmor", "guarddog", "trivy-license"} {
		b.WriteString("  " + tool + ":\n    enabled: false\n")
	}
	lock := filepath.Join(dir, "tools.lock")
	for path, body := range map[string]string{
		cfg:  b.String(),
		lock: "tools:\n  syft:\n    version: 1.0.0\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, []string{"-config", cfg, "-lock", lock,
		"-out", filepath.Join(dir, "out.sarif"), "-summary", filepath.Join(dir, "summary.md")}
}

func TestAScanThatDoesNotRunFailsTheGate(t *testing.T) {
	root, args := unrunnableScan(t)
	if code := runCmd(append(args, root)); code != 1 {
		t.Errorf("exit = %d, want 1: zero findings from a scanner that never ran is not a pass", code)
	}
	summary, err := os.ReadFile(args[len(args)-1]) // #nosec G304 -- path is under our temp dir
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(summary), "### Scanners that did not run (1)") ||
		!strings.Contains(string(summary), "- trivy: unpinned in tools.lock") {
		t.Errorf("summary does not name the scanner:\n%s", summary)
	}
}

// -own-image reaches the image step: with trivy unpinned, the image scan is a
// second blocking scan that did not run.
func TestOwnImageIsScanned(t *testing.T) {
	root, args := unrunnableScan(t)
	if code := runCmd(append(append(args, "-own-image", "catena-admin:ci"), root)); code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	summary, err := os.ReadFile(args[len(args)-1]) // #nosec G304 -- path is under our temp dir
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(summary), "- trivy-image: unpinned in tools.lock") {
		t.Errorf("summary does not list the own-image scan:\n%s", summary)
	}
}

func TestNoGateStillExitsZero(t *testing.T) {
	root, args := unrunnableScan(t)
	if code := runCmd(append(append(args, "-no-gate"), root)); code != 0 {
		t.Errorf("exit = %d, want 0 under -no-gate", code)
	}
}
