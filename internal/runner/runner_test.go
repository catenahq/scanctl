package runner

import (
	"testing"

	"github.com/catenahq/scanctl/internal/detect"
)

func TestParseRealSARIFFixture(t *testing.T) {
	rep := parseIfPresent("testdata/gosec.sarif")
	if rep == nil {
		t.Fatal("fixture failed to parse")
	}
	if rep.ResultCount() != 1 {
		t.Fatalf("result count = %d, want 1", rep.ResultCount())
	}
	if rep.Runs[0].Results[0].RuleID != "G401" {
		t.Errorf("ruleId = %q, want G401", rep.Runs[0].Results[0].RuleID)
	}
}

func TestParseMissingFileIsNil(t *testing.T) {
	if parseIfPresent("testdata/does-not-exist.sarif") != nil {
		t.Error("missing file should parse as nil (zero findings)")
	}
}

func TestTagDriverNormalizesName(t *testing.T) {
	rep := parseIfPresent("testdata/gosec.sarif")
	tagDriver(rep, "gosec-canonical")
	if rep.Runs[0].Tool.Driver.Name != "gosec-canonical" {
		t.Errorf("driver name = %q, want gosec-canonical", rep.Runs[0].Tool.Driver.Name)
	}
}

func TestParseLock(t *testing.T) {
	lock, err := ParseLock([]byte("tools:\n  trivy:\n    repo: aquasecurity/trivy\n    version: 0.71.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := lock.Version("trivy")
	if err != nil || v != "0.71.0" {
		t.Errorf("version = %q (err %v), want 0.71.0", v, err)
	}
	if _, err := lock.Version("nope"); err == nil {
		t.Error("expected error for unpinned tool")
	}
	if _, err := ParseLock([]byte("tools: {}\n")); err == nil {
		t.Error("expected error for empty lock")
	}
}

func TestAppliesPredicates(t *testing.T) {
	goRepo := detect.Result{Ecosystems: map[detect.Ecosystem]bool{detect.Go: true}, HasLockfile: true}
	nonGo := detect.Result{Ecosystems: map[detect.Ecosystem]bool{detect.Python: true}}
	byName := map[string]toolDef{}
	for _, td := range registry {
		byName[td.name] = td
	}
	if !byName["gosec"].applies(goRepo) {
		t.Error("gosec should apply to a Go repo")
	}
	if byName["gosec"].applies(nonGo) {
		t.Error("gosec should not apply to a non-Go repo")
	}
	if !byName["osv-scanner"].applies(goRepo) {
		t.Error("osv-scanner should apply when a lockfile exists")
	}
	if byName["osv-scanner"].applies(nonGo) {
		t.Error("osv-scanner should not apply without a lockfile")
	}
	if !byName["trivy"].applies(nonGo) {
		t.Error("trivy fs should always apply")
	}
}
