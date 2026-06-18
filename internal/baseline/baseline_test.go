package baseline

import (
	"testing"

	"github.com/catenahq/scanctl/internal/sarif"
)

func mk(tool, rule, uri string, line int) sarif.Run {
	return sarif.Run{
		Tool: sarif.Tool{Driver: sarif.Driver{Name: tool}},
		Results: []sarif.Result{{
			RuleID:  rule,
			Message: sarif.Message{Text: "m"},
			Locations: []sarif.Location{{PhysicalLocation: sarif.PhysicalLocation{
				ArtifactLocation: sarif.ArtifactLocation{URI: uri},
				Region:           &sarif.Region{StartLine: line},
			}}},
		}},
	}
}

func TestApplySuppressesKnownNotNew(t *testing.T) {
	base := fingerprints(&sarif.Report{Runs: []sarif.Run{mk("gosec", "G304", "a.go", 5)}})
	cur := &sarif.Report{Runs: []sarif.Run{
		mk("gosec", "G304", "a.go", 5), // in baseline -> suppressed
		mk("gosec", "G401", "b.go", 9), // new -> stays
	}}
	if n := Apply(cur, base); n != 1 {
		t.Fatalf("suppressed = %d, want 1", n)
	}
	if !cur.Runs[0].Results[0].Suppressed() {
		t.Error("known finding not suppressed")
	}
	if cur.Runs[1].Results[0].Suppressed() {
		t.Error("new finding wrongly suppressed")
	}
}

func TestEmptyBaselineIsNoop(t *testing.T) {
	cur := &sarif.Report{Runs: []sarif.Run{mk("gosec", "G304", "a.go", 5)}}
	if n := Apply(cur, Set{}); n != 0 {
		t.Errorf("empty baseline suppressed %d, want 0", n)
	}
}

func TestLoadMissingFileIsEmptySet(t *testing.T) {
	s, err := Load("/nonexistent/baseline.sarif")
	if err != nil {
		t.Fatalf("missing baseline should not error: %v", err)
	}
	if len(s) != 0 {
		t.Errorf("missing baseline set len = %d, want 0", len(s))
	}
}
