package sarif

import "testing"

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
