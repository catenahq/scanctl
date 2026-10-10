package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/catenahq/scanctl/internal/config"
	"github.com/catenahq/scanctl/internal/sarif"
)

// A scan covering 30 images writes a report code scanning uploads: no two runs
// share the key codeql-action upload-sarif reads as a run's category (its
// createRunKey: the driver's name, fullName, version, semanticVersion and guid,
// and automationDetails.id), and the file holds at most 20 runs.
func TestWriteSARIFUploadsWhateverTheNumberOfImages(t *testing.T) {
	rep := sarif.New()
	add := func(tool string, props map[string]any) {
		rep.Merge(&sarif.Report{Runs: []sarif.Run{{
			Tool:    sarif.Tool{Driver: sarif.Driver{Name: tool, Rules: []sarif.Rule{{ID: "R"}}}},
			Results: []sarif.Result{{RuleID: "R", Message: sarif.Message{Text: "m"}, Properties: props}},
		}}})
	}
	add("trivy", nil)
	for i := 0; i < 30; i++ {
		add("trivy", map[string]any{sarif.ImageProperty: fmt.Sprintf("repo/app%d:1", i)})
	}
	add("trivy", map[string]any{sarif.OwnImageProperty: "app:ci"})
	add("trivy-license", nil)
	add("guarddog", nil)
	add("guarddog", nil)
	add("gosec", nil)

	path := filepath.Join(t.TempDir(), "scanctl.sarif")
	if err := WriteSARIF(rep, path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is under our temp dir
	if err != nil {
		t.Fatal(err)
	}
	var written struct {
		Runs []struct {
			Tool struct {
				Driver map[string]any `json:"driver"`
			} `json:"tool"`
			AutomationDetails struct {
				ID any `json:"id"`
			} `json:"automationDetails"`
			Results []any `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &written); err != nil {
		t.Fatal(err)
	}
	if len(written.Runs) > 20 {
		t.Errorf("%d runs, code scanning rejects a file of more than 20", len(written.Runs))
	}
	keys := map[string]bool{}
	results := 0
	for _, run := range written.Runs {
		d := run.Tool.Driver
		key := fmt.Sprint(d["name"], d["fullName"], d["version"], d["semanticVersion"], d["guid"], run.AutomationDetails.ID)
		if keys[key] {
			t.Errorf("two runs share the category %q: upload-sarif refuses the file", key)
		}
		keys[key] = true
		results += len(run.Results)
	}
	if results != rep.ResultCount() {
		t.Errorf("written results = %d, want %d", results, rep.ResultCount())
	}
	if len(rep.Runs) != 36 {
		t.Errorf("WriteSARIF left %d runs in the report, want its 36 scans", len(rep.Runs))
	}
}

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
