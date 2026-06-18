package sarif

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeRendersEmptyResultsArray(t *testing.T) {
	// A run with nil Results must marshal as [] not null (SARIF schema requires
	// an array; GitHub code scanning + DefectDojo reject null).
	r := &Report{Runs: []Run{{Tool: Tool{Driver: Driver{Name: "x"}}}}}
	r.Normalize()
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"results":null`) {
		t.Errorf("normalized SARIF still has null results: %s", data)
	}
	if !strings.Contains(string(data), `"results":[]`) {
		t.Errorf("expected empty results array: %s", data)
	}
}

func TestSuppressionsRoundTrip(t *testing.T) {
	// A semgrep nosemgrep finding arrives with suppressions; the merged output
	// must keep them so GitHub creates the alert dismissed, not open.
	in := []byte(`{"$schema":"x","version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},` +
		`"results":[{"ruleId":"r","level":"warning","message":{"text":"m"},` +
		`"suppressions":[{"kind":"inSource"}]}]}]}`)
	var rep Report
	if err := json.Unmarshal(in, &rep); err != nil {
		t.Fatal(err)
	}
	res := rep.Runs[0].Results[0]
	if !res.Suppressed() {
		t.Fatal("Suppressed() = false, want true")
	}
	out, err := json.Marshal(&rep)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"suppressions":[{"kind":"inSource"}]`) {
		t.Errorf("suppressions dropped on re-marshal: %s", out)
	}
}

func TestPropertiesAndFingerprintsRoundTrip(t *testing.T) {
	in := []byte(`{"runs":[{"tool":{"driver":{"name":"trivy","rules":[` +
		`{"id":"R","properties":{"security-severity":"7.5"}}]}},` +
		`"results":[{"ruleId":"R","level":"error","message":{"text":"m"},` +
		`"partialFingerprints":{"primaryLocationLineHash":"abc"},"properties":{"k":"v"}}]}]}`)
	var rep Report
	if err := json.Unmarshal(in, &rep); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(&rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"security-severity":"7.5"`, `"primaryLocationLineHash":"abc"`, `"k":"v"`} {
		if !strings.Contains(string(out), want) {
			t.Errorf("dropped %q on re-marshal: %s", want, out)
		}
	}
	if s, ok := SecuritySeverity(rep.Runs[0].Tool.Driver.Rules[0].Properties); !ok || s != 7.5 {
		t.Errorf("SecuritySeverity = %v,%v want 7.5,true", s, ok)
	}
	if _, ok := SecuritySeverity(map[string]any{}); ok {
		t.Error("SecuritySeverity ok on empty props")
	}
}

func TestFingerprint(t *testing.T) {
	r := Result{RuleID: "R", Message: Message{Text: "m"}, Locations: []Location{{
		PhysicalLocation: PhysicalLocation{
			ArtifactLocation: ArtifactLocation{URI: "a.go"}, Region: &Region{StartLine: 3}}}}}
	if Fingerprint("trivy", r) != Fingerprint("trivy", r) {
		t.Error("fingerprint not stable")
	}
	if Fingerprint("trivy", r) == Fingerprint("gosec", r) {
		t.Error("tool not part of fingerprint")
	}
	r2 := Result{RuleID: "R", PartialFingerprints: map[string]string{"primaryLocationLineHash": "h"}}
	if got := Fingerprint("trivy", r2); got != "trivy:R:h" {
		t.Errorf("partialFingerprint path = %q, want trivy:R:h", got)
	}
}

func run(tool string, n int) Run {
	r := Run{Tool: Tool{Driver: Driver{Name: tool}}}
	for i := 0; i < n; i++ {
		r.Results = append(r.Results, Result{Level: LevelError, Message: Message{Text: "x"}})
	}
	return r
}

func TestMergePreservesRuns(t *testing.T) {
	dst := New()
	a := &Report{Runs: []Run{run("trivy", 2)}}
	b := &Report{Runs: []Run{run("gosec", 3)}}
	dst.Merge(a)
	dst.Merge(b)
	dst.Merge(nil) // nil is a no-op

	if len(dst.Runs) != 2 {
		t.Fatalf("runs = %d, want 2", len(dst.Runs))
	}
	if dst.ResultCount() != 5 {
		t.Errorf("result count = %d, want 5", dst.ResultCount())
	}
	if dst.Runs[0].Tool.Driver.Name != "trivy" || dst.Runs[1].Tool.Driver.Name != "gosec" {
		t.Error("per-tool run identity not preserved after merge")
	}
}
