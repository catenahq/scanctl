// Package gate turns the merged report into a pass/fail decision. Only tools in
// "block" mode can fail the run; "report" tools surface findings without
// affecting the exit code (preserving catena-ce's blocking-vs-report split). A
// finding gates when its severity is at or above the configured floor.
package gate

import (
	"github.com/catenahq/scanctl/internal/config"
	"github.com/catenahq/scanctl/internal/sarif"
)

// Result is the gate verdict.
type Result struct {
	Gating int            // findings from blocking tools at/above the floor
	Total  int            // all findings
	ByTool map[string]int // gating findings per tool
}

// Failed reports whether the run should exit non-zero.
func (r Result) Failed() bool { return r.Gating > 0 }

// levelToSeverity maps a SARIF level to scanctl's severity scale. SARIF levels
// are coarse; tools encode finer severity in properties we do not yet read, so
// v1 uses this conservative mapping (error == high).
func levelToSeverity(level string) config.Severity {
	switch level {
	case sarif.LevelError:
		return config.SevHigh
	case sarif.LevelWarning:
		return config.SevMedium
	case sarif.LevelNote:
		return config.SevLow
	default:
		return config.SevNone
	}
}

// Evaluate computes the verdict for rep under cfg.
func Evaluate(rep *sarif.Report, cfg config.Config) Result {
	floor := cfg.Gate.Floor.Rank()
	res := Result{ByTool: map[string]int{}}
	for _, run := range rep.Runs {
		res.Total += len(run.Results)
		tc, ok := cfg.Tools[run.Tool.Driver.Name]
		blocking := ok && tc.Mode == config.ModeBlock
		if !blocking {
			continue
		}
		for _, r := range run.Results {
			if r.Suppressed() {
				continue // in-source suppressed (e.g. nosemgrep) never gates
			}
			if levelToSeverity(r.Level).Rank() >= floor {
				res.Gating++
				res.ByTool[run.Tool.Driver.Name]++
			}
		}
	}
	return res
}
