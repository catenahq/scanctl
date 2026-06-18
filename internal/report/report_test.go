package report

import (
	"strings"
	"testing"

	"github.com/catenahq/scanctl/internal/config"
	"github.com/catenahq/scanctl/internal/sarif"
)

func TestSummaryEmpty(t *testing.T) {
	s := Summary(sarif.New(), config.Default())
	if !strings.Contains(s, "0 finding") {
		t.Errorf("empty summary missing zero-count line: %q", s)
	}
}

func TestSummaryCountsAndLists(t *testing.T) {
	rep := &sarif.Report{Runs: []sarif.Run{{
		Tool: sarif.Tool{Driver: sarif.Driver{Name: "trivy"}},
		Results: []sarif.Result{
			{RuleID: "CVE-1", Level: sarif.LevelError, Message: sarif.Message{Text: "bad"},
				Locations: []sarif.Location{{PhysicalLocation: sarif.PhysicalLocation{
					ArtifactLocation: sarif.ArtifactLocation{URI: "go.mod"},
					Region:           &sarif.Region{StartLine: 7},
				}}}},
			{RuleID: "CVE-2", Level: sarif.LevelWarning, Message: sarif.Message{Text: "meh"}},
		},
	}}}
	s := Summary(rep, config.Default())
	if !strings.Contains(s, "2 finding") {
		t.Errorf("missing total: %q", s)
	}
	if !strings.Contains(s, "trivy") || !strings.Contains(s, "CVE-1") {
		t.Errorf("missing per-tool row or top finding: %q", s)
	}
	if !strings.Contains(s, "go.mod:7") {
		t.Errorf("missing location: %q", s)
	}
	// trivy blocks by default and CVE-1 is error (HIGH) >= high floor, so it
	// must land in the gating list with its severity label.
	if !strings.Contains(s, "Gating findings") || !strings.Contains(s, "HIGH CVE-1") {
		t.Errorf("CVE-1 should be a gating finding: %q", s)
	}
}
