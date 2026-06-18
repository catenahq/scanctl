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

// levelToSeverity maps a SARIF level to scanctl's severity scale. Used as the
// fallback when a finding carries no "security-severity" score.
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

// cvssToSeverity maps a SARIF "security-severity" CVSS score (0-10) to scanctl's
// band, using the same thresholds GitHub code scanning applies.
func cvssToSeverity(score float64) config.Severity {
	switch {
	case score >= 9.0:
		return config.SevCritical
	case score >= 7.0:
		return config.SevHigh
	case score >= 4.0:
		return config.SevMedium
	case score > 0.0:
		return config.SevLow
	default:
		return config.SevNone
	}
}

// Severity resolves a result's severity, preferring the CVSS "security-
// severity" score (from the result's own properties, then its rule's) over the
// coarse SARIF level. This makes the gate floor mean what it says: a MEDIUM CVE
// a tool happens to emit at error-level no longer over-gates, and vice versa.
// Exported so the report renders the same severity the gate decides on.
func Severity(rules map[string]sarif.Rule, r sarif.Result) config.Severity {
	if score, ok := sarif.SecuritySeverity(r.Properties); ok {
		return cvssToSeverity(score)
	}
	if rule, ok := rules[r.RuleID]; ok {
		if score, ok := sarif.SecuritySeverity(rule.Properties); ok {
			return cvssToSeverity(score)
		}
	}
	return levelToSeverity(r.Level)
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
		rules := run.RulesByID()
		for _, r := range run.Results {
			if r.Suppressed() {
				continue // suppressed (nosemgrep / baseline) never gates
			}
			if Severity(rules, r).Rank() >= floor {
				res.Gating++
				res.ByTool[run.Tool.Driver.Name]++
			}
		}
	}
	return res
}
