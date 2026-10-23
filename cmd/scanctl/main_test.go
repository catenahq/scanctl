package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/catenahq/scanctl/internal/sarif"
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

// A lock that pins no release tool needs no digest: it is not rewritten and
// makes no download.
func TestRefreshDigestsLeavesALockWithNoReleaseToolAsItIs(t *testing.T) {
	committed := []byte("tools:\n  govulncheck:\n    module: golang.org/x/vuln\n    version: 1.9.0\n")
	path := filepath.Join(t.TempDir(), "tools.lock")
	if err := os.WriteFile(path, committed, 0o600); err != nil {
		t.Fatal(err)
	}
	if code := refreshDigestsCmd([]string{"-lock", path}); code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
	got, err := os.ReadFile(path) // #nosec G304 -- path is under the test's temp dir
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(committed) {
		t.Errorf("tools.lock changed:\n%s", got)
	}
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

const trivyImageMessage = "Package: libssl3\nInstalled Version: 3.5.7-r0\nVulnerability CVE-2026-1\nSeverity: HIGH\nFixed Version: %s\nLink: x"

// imageScan is a run with no scanner to run (every tool disabled, trivy still
// in block mode) and a SARIF to import holding one third-party image
// vulnerability scored 8.0, with the given fixed version ("" for none).
func imageScan(t *testing.T, fixed string) (root string, args []string) {
	t.Helper()
	t.Setenv("GITHUB_ACTIONS", "")
	root = t.TempDir()
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("tools:\n  trivy:\n    enabled: false\n    mode: block\n")
	for _, tool := range []string{"osv-scanner", "govulncheck", "gosec", "gitleaks", "semgrep", "zizmor", "guarddog", "trivy-license"} {
		b.WriteString("  " + tool + ":\n    enabled: false\n")
	}
	cfg := filepath.Join(dir, "scanctl.yml")
	lock := filepath.Join(dir, "tools.lock")
	in := filepath.Join(dir, "in.sarif")
	if err := os.WriteFile(in, []byte(imageSARIF(fixed)), 0o600); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{
		cfg:  b.String(),
		lock: "tools:\n  syft:\n    version: 1.0.0\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, []string{"-config", cfg, "-lock", lock, "-import", in,
		"-out", filepath.Join(dir, "out.sarif"), "-summary", filepath.Join(dir, "summary.md")}
}

func imageSARIF(fixed string) string {
	msg, _ := json.Marshal(fmt.Sprintf(trivyImageMessage, fixed))
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"trivy"}},"results":[` +
		`{"ruleId":"CVE-2026-1/postgres","level":"error","message":{"text":` + string(msg) + `},` +
		`"properties":{"security-severity":"8.0","image":"postgres:18"}}]}]}`
}

// fileOf reads the file a flag in args names.
func fileOf(t *testing.T, args []string, flag string) string {
	t.Helper()
	for i, a := range args {
		if a == flag {
			b, err := os.ReadFile(args[i+1]) // #nosec G304 -- path is under our temp dir
			if err != nil {
				t.Fatal(err)
			}
			return string(b)
		}
	}
	t.Fatalf("no %s in %v", flag, args)
	return ""
}

func TestARunThatGradesNoChangeFailsOnAnImageVulnerabilityWithAFix(t *testing.T) {
	root, args := imageScan(t, "3.5.8-r0")
	if code := runCmd(append(args, root)); code != 1 {
		t.Errorf("exit = %d, want 1: a fixable image vulnerability gates when no change is graded", code)
	}
}

func TestARunThatGradesNoChangePassesAnImageFindingWithNoFixedVersion(t *testing.T) {
	root, args := imageScan(t, "")
	if code := runCmd(append(args, root)); code != 0 {
		t.Errorf("exit = %d, want 0: nothing upstream has fixed it", code)
	}
}

// baselineFor writes a baseline accepting the imageScan finding, with the
// given extra result properties, and returns the args to pass it.
func baselineFor(t *testing.T, extra string) []string {
	t.Helper()
	msg, _ := json.Marshal(fmt.Sprintf(trivyImageMessage, "3.5.8-r0"))
	body := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"trivy"}},"results":[` +
		`{"ruleId":"CVE-2026-1/postgres","level":"error","message":{"text":` + string(msg) + `},` +
		`"properties":{"image":"postgres:18"` + extra + `}}]}]}`
	p := filepath.Join(t.TempDir(), "baseline.sarif")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{"-baseline", p}
}

func TestAnImageFindingAcceptedUntilAFutureDateIsSuppressed(t *testing.T) {
	root, args := imageScan(t, "3.5.8-r0")
	args = append(args, baselineFor(t, `,"acceptedUntil":"2999-01-01"`)...)
	if code := runCmd(append(args, root)); code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if out := fileOf(t, args, "-out"); !strings.Contains(out, sarif.AcceptedInBaseline) {
		t.Errorf("SARIF does not mark the finding accepted in the baseline:\n%s", out)
	}
}

func TestAnImageFindingAcceptedUntilYesterdayGatesAgain(t *testing.T) {
	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
	root, args := imageScan(t, "3.5.8-r0")
	args = append(args, baselineFor(t, `,"acceptedUntil":"`+yesterday+`"`)...)
	if code := runCmd(append(args, root)); code != 1 {
		t.Errorf("exit = %d, want 1: an expired entry accepts nothing", code)
	}
	if s := fileOf(t, args, "-summary"); !strings.Contains(s, "### Expired baseline entries (1)") {
		t.Errorf("summary does not list the expired entry:\n%s", s)
	}
}

func TestAnUndatedImageEntryAcceptsNothing(t *testing.T) {
	root, args := imageScan(t, "3.5.8-r0")
	args = append(args, baselineFor(t, "")...)
	if code := runCmd(append(args, root)); code != 1 {
		t.Errorf("exit = %d, want 1: an image entry needs a date", code)
	}
}

// unmatchedImageEntrySummary runs scanctl with trivy unable to scan the pinned or
// listed image and a baseline whose one dated image entry matches nothing, and
// returns the summary.
func unmatchedImageEntrySummary(t *testing.T, root string, pins bool, extra ...string) string {
	t.Helper()
	t.Setenv("GITHUB_ACTIONS", "")
	dir := t.TempDir()
	cfg := filepath.Join(dir, "scanctl.yml")
	body := "images: [postgres:18]\n"
	if pins {
		body += "image_pins:\n  - file: catalog.go\n    pattern: 'c\\.\\w+Image = \"([^\"]+)\"'\n"
	}
	body += "tools:\n  trivy:\n    enabled: true\n    mode: block\n"
	for _, tool := range []string{"osv-scanner", "govulncheck", "gosec", "gitleaks", "semgrep", "zizmor", "guarddog", "trivy-license"} {
		body += "  " + tool + ":\n    enabled: false\n"
	}
	lock := filepath.Join(dir, "tools.lock")
	for path, content := range map[string]string{cfg: body, lock: "tools:\n  syft:\n    version: 1.0.0\n"} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"-config", cfg, "-lock", lock, "-out", filepath.Join(dir, "out.sarif"),
		"-summary", filepath.Join(dir, "summary.md")}
	args = append(args, baselineFor(t, `,"acceptedUntil":"2999-01-01"`)...)
	args = append(args, extra...)
	runCmd(append(args, root))
	return fileOf(t, args, "-summary")
}

func TestAnUnmatchedImageEntryIsNotStaleWhenAnImageScanFailed(t *testing.T) {
	if s := unmatchedImageEntrySummary(t, t.TempDir(), false); strings.Contains(s, "Stale baseline entries") {
		t.Errorf("a run whose image scan failed judged an image entry stale:\n%s", s)
	}
}

func TestAnUnmatchedImageEntryIsNotStaleWhenOnlyTheChangedPinsWereScanned(t *testing.T) {
	root, sha := gitRepo(t)
	if s := unmatchedImageEntrySummary(t, root, true, "-baseline-ref", sha); strings.Contains(s, "Stale baseline entries") {
		t.Errorf("a pin-scoped run judged an image entry stale:\n%s", s)
	}
}

func TestAnUnmatchedImageEntryIsStaleWhenEveryImageWasScanned(t *testing.T) {
	root, args := imageScan(t, "3.5.8-r0")
	args = append(args, "-baseline", filepath.Join(t.TempDir(), "b.sarif"))
	msg, _ := json.Marshal(fmt.Sprintf(trivyImageMessage, "3.5.8-r0"))
	body := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"trivy"}},"results":[` +
		`{"ruleId":"CVE-9/redis","message":{"text":` + string(msg) + `},` +
		`"properties":{"image":"redis:7","acceptedUntil":"2999-01-01"}}]}]}`
	if err := os.WriteFile(args[len(args)-1], []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runCmd(append(args, root)); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if s := fileOf(t, args, "-summary"); !strings.Contains(s, "Stale baseline entries (1)") {
		t.Errorf("a run that scanned every image did not report the unmatched entry:\n%s", s)
	}
}

func TestNoGateStillExitsZero(t *testing.T) {
	root, args := unrunnableScan(t)
	if code := runCmd(append(append(args, "-no-gate"), root)); code != 0 {
		t.Errorf("exit = %d, want 0 under -no-gate", code)
	}
}
