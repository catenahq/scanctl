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
		run := sarif.Run{
			Tool:    sarif.Tool{Driver: sarif.Driver{Name: tool, Rules: []sarif.Rule{{ID: "R"}}}},
			Results: []sarif.Result{{RuleID: "R", Message: sarif.Message{Text: "m"}, Properties: props}},
		}
		if _, ok := props[sarif.ImageProperty]; ok {
			run.AutomationDetails = &sarif.AutomationDetails{ID: sarif.ImageCategory}
		}
		rep.Merge(&sarif.Report{Runs: []sarif.Run{run}})
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
	if err := WriteSARIF(rep, path, false); err != nil {
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

// imageScan is one third-party image scan as the runner merges it: a trivy run
// in sarif.ImageCategory, each finding naming the image.
func imageScan(ref string, findings int) sarif.Run {
	run := sarif.Run{
		Tool:              sarif.Tool{Driver: sarif.Driver{Name: "trivy"}},
		Results:           []sarif.Result{},
		AutomationDetails: &sarif.AutomationDetails{ID: sarif.ImageCategory},
	}
	for i := 0; i < findings; i++ {
		run.Results = append(run.Results, sarif.Result{RuleID: fmt.Sprintf("CVE-%d", i),
			Message: sarif.Message{Text: "m"}, Properties: map[string]any{sarif.ImageProperty: ref}})
	}
	return run
}

// scan is a run's merged report: trivy's fs scan, the repo's own image and
// gosec, one finding each, then the third-party image scans.
func scan(images ...sarif.Run) *sarif.Report {
	finding := func(props map[string]any) []sarif.Result {
		return []sarif.Result{{RuleID: "R", Message: sarif.Message{Text: "m"}, Properties: props}}
	}
	rep := sarif.New()
	rep.Merge(&sarif.Report{Runs: append([]sarif.Run{
		{Tool: sarif.Tool{Driver: sarif.Driver{Name: "trivy"}}, Results: finding(nil)},
		{Tool: sarif.Tool{Driver: sarif.Driver{Name: "trivy"}}, Results: finding(map[string]any{sarif.OwnImageProperty: "app:ci"})},
		{Tool: sarif.Tool{Driver: sarif.Driver{Name: "gosec"}}, Results: finding(nil)},
	}, images...)})
	return rep
}

// writeAndLoad writes rep as WriteSARIF does and reads back the file code
// scanning uploads, split into the trivy run in the default category and the
// one in sarif.ImageCategory (nil when absent).
func writeAndLoad(t *testing.T, rep *sarif.Report, partialImages bool) (fs, images *sarif.Run) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scanctl.sarif")
	if err := WriteSARIF(rep, path, partialImages); err != nil {
		t.Fatal(err)
	}
	written, err := sarif.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for i, run := range written.Runs {
		if run.Tool.Driver.Name != "trivy" {
			continue
		}
		switch {
		case run.AutomationDetails == nil:
			fs = &written.Runs[i]
		case run.AutomationDetails.ID == sarif.ImageCategory:
			images = &written.Runs[i]
		default:
			t.Errorf("trivy run in category %q", run.AutomationDetails.ID)
		}
	}
	if fs == nil || len(fs.Results) != 2 {
		t.Fatalf("written trivy run in the default category = %+v, want the fs and own-image findings", fs)
	}
	for _, r := range fs.Results {
		if _, ok := r.Properties[sarif.ImageProperty]; ok {
			t.Errorf("a third-party image finding is in the default category: %+v", r)
		}
	}
	return fs, images
}

// A push that touches no pin file scans no image. Its upload carries trivy's
// default category alone, so the image alerts, in their own category, stay as
// the last full scan left them.
func TestWriteSARIFOfAPushThatScannedNoImage(t *testing.T) {
	if _, images := writeAndLoad(t, scan(), true); images != nil {
		t.Errorf("written image run = %+v, want none", images)
	}
}

// A push that touches one pin file scans that pin's image alone. Its image
// findings stay out of the SARIF: an upload holding them would close the alerts
// of every image it did not scan. The summary and the gate still read them.
func TestWriteSARIFOfAPushThatScannedOneImage(t *testing.T) {
	rep := scan(imageScan("redis:8.10.1", 1))
	if _, images := writeAndLoad(t, rep, true); images != nil {
		t.Errorf("written image run = %+v, want none", images)
	}
	if rep.ResultCount() != 4 {
		t.Errorf("report findings = %d, want 4: the image finding stays in the report", rep.ResultCount())
	}
}

// A run that scanned every image writes them all in the image category, a
// clean image's empty run included, so the upload closes every image alert the
// scan does not report.
func TestWriteSARIFOfAFullScanFilesEveryImageInTheImageCategory(t *testing.T) {
	_, images := writeAndLoad(t, scan(imageScan("redis:8.10.1", 2), imageScan("postgres:18.6", 1)), false)
	if images == nil || len(images.Results) != 3 {
		t.Errorf("written image run = %+v, want the 3 image findings", images)
	}
	_, images = writeAndLoad(t, scan(imageScan("redis:8.10.1", 0)), false)
	if images == nil || len(images.Results) != 0 {
		t.Errorf("written image run of a clean image = %+v, want an empty run", images)
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
