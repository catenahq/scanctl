package gate

import (
	"testing"

	"github.com/catenahq/scanctl/internal/config"
	"github.com/catenahq/scanctl/internal/sarif"
)

func report(tool, level string, n int) sarif.Run {
	r := sarif.Run{Tool: sarif.Tool{Driver: sarif.Driver{Name: tool}}}
	for i := 0; i < n; i++ {
		r.Results = append(r.Results, sarif.Result{Level: level})
	}
	return r
}

func baseCfg() config.Config {
	c := config.Default()
	c.Gate.Floor = config.SevHigh
	return c
}

func TestReportModeNeverGates(t *testing.T) {
	cfg := baseCfg()
	// gitleaks defaults to report mode; even error-level findings must not gate.
	rep := &sarif.Report{Runs: []sarif.Run{report("gitleaks", sarif.LevelError, 4)}}
	v := Evaluate(rep, cfg)
	if v.Failed() {
		t.Errorf("report-mode tool should never gate; gating=%d", v.Gating)
	}
	if v.Total != 4 {
		t.Errorf("total = %d, want 4", v.Total)
	}
}

func TestBlockModeGatesAtOrAboveFloor(t *testing.T) {
	cfg := baseCfg() // floor = high; error maps to high
	rep := &sarif.Report{Runs: []sarif.Run{
		report("trivy", sarif.LevelError, 2),   // high >= high -> gates
		report("trivy", sarif.LevelWarning, 5), // medium < high -> does not gate
	}}
	v := Evaluate(rep, cfg)
	if v.Gating != 2 {
		t.Errorf("gating = %d, want 2", v.Gating)
	}
	if !v.Failed() {
		t.Error("expected failure")
	}
}

func TestFloorRaisedSuppressesGating(t *testing.T) {
	cfg := baseCfg()
	cfg.Gate.Floor = config.SevCritical // nothing maps to critical from level alone
	rep := &sarif.Report{Runs: []sarif.Run{report("trivy", sarif.LevelError, 3)}}
	v := Evaluate(rep, cfg)
	if v.Failed() {
		t.Errorf("error(high) should not gate under critical floor; gating=%d", v.Gating)
	}
}
