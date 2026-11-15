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

// A scan covering 30 images writes the upload set code scanning takes: one run
// per image, each in its own category, grouped into files of at most
// MaxRunsPerFile runs, and no two runs share the key codeql-action
// upload-sarif reads as a category (the driver's name, fullName, version,
// semanticVersion and guid, and automationDetails.id).
func TestWriteUploadSetCarriesEveryImageUnderItsOwnCategory(t *testing.T) {
	rep := sarif.New()
	add := func(tool, category string, props map[string]any) {
		run := sarif.Run{
			Tool:    sarif.Tool{Driver: sarif.Driver{Name: tool, Rules: []sarif.Rule{{ID: "R"}}}},
			Results: []sarif.Result{{RuleID: "R", Message: sarif.Message{Text: "m"}, Properties: props}},
		}
		if category != "" {
			run.AutomationDetails = &sarif.AutomationDetails{ID: category}
		}
		rep.Merge(&sarif.Report{Runs: []sarif.Run{run}})
	}
	add("trivy", "", nil)
	for i := 0; i < 30; i++ {
		ref := fmt.Sprintf("repo/app%d:1", i)
		add("trivy", sarif.ImageCategory(ref), map[string]any{sarif.ImageProperty: ref})
	}
	add("trivy", "", map[string]any{sarif.OwnImageProperty: "app:ci"})
	add("trivy-license", "", nil)
	add("guarddog", "", nil)
	add("guarddog", "", nil)
	add("gosec", "", nil)

	dir := t.TempDir()
	n, err := WriteUploadSet(rep, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 34 runs (30 images, trivy's fs and own image joined, the two guarddog
	// runs joined, license and gosec), at most MaxRunsPerFile per file.
	if want := 2; n != want {
		t.Errorf("files = %d, want %d", n, want)
	}
	keys := map[string]bool{}
	results := 0
	runs := 0
	for _, path := range uploadFiles(t, dir) {
		written := load(t, path)
		if len(written.Runs) > MaxRunsPerFile {
			t.Errorf("%s: %d runs, code scanning rejects a file of more than %d", path, len(written.Runs), MaxRunsPerFile)
		}
		for _, run := range written.Runs {
			id := ""
			if run.AutomationDetails != nil {
				id = run.AutomationDetails.ID
			}
			key := run.Tool.Driver.Name + "\x00" + id
			if keys[key] {
				t.Errorf("two runs share the category %q: upload-sarif refuses the upload", key)
			}
			keys[key] = true
			runs++
			results += len(run.Results)
		}
	}
	if want := 34; runs != want {
		t.Errorf("written runs = %d, want %d", runs, want)
	}
	if results != rep.ResultCount() {
		t.Errorf("written results = %d, want %d", results, rep.ResultCount())
	}
	if len(rep.Runs) != 36 {
		t.Errorf("WriteUploadSet left %d runs in the report, want its 36 scans", len(rep.Runs))
	}
}

// A SARIF file an earlier upload set left in the directory is removed, so a
// category this run no longer carries stops uploading.
func TestWriteUploadSetClearsTheEarlierFiles(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "999.sarif")
	if err := os.WriteFile(stale, []byte(`{"version":"2.1.0","runs":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteUploadSet(scan(imageScan("redis:8.10.1", 1)), dir, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale file %s survived the upload set", stale)
	}
}

// imageScan is one third-party image scan as the runner merges it: a trivy run
// in the image's own category, each finding naming the image.
func imageScan(ref string, findings int) sarif.Run {
	run := sarif.Run{
		Tool:              sarif.Tool{Driver: sarif.Driver{Name: "trivy"}},
		Results:           []sarif.Result{},
		AutomationDetails: &sarif.AutomationDetails{ID: sarif.ImageCategory(ref)},
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

// imageCategory is the category of one third-party image.
func imageCategory(ref string) sarif.Category {
	return sarif.Category{Tool: "trivy", ID: sarif.ImageCategory(ref)}
}

// load reads a written SARIF file.
func load(t *testing.T, path string) *sarif.Report {
	t.Helper()
	rep, err := sarif.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// uploadFiles lists the SARIF files WriteUploadSet wrote in dir.
func uploadFiles(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no upload files in %s", dir)
	}
	return files
}

// uploaded writes rep as WriteSARIF does and reads back the file code scanning
// uploads.
func uploaded(t *testing.T, rep *sarif.Report, leaveOut map[sarif.Category]bool) *sarif.Report {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scanctl.sarif")
	if err := WriteSARIF(rep, path, leaveOut); err != nil {
		t.Fatal(err)
	}
	return load(t, path)
}

// writeAndLoad writes rep as WriteSARIF does and reads back the file code
// scanning uploads, split into the trivy run in the default category and the
// image runs indexed by their category.
func writeAndLoad(t *testing.T, rep *sarif.Report, leaveOut map[sarif.Category]bool) (fs *sarif.Run, images map[string]*sarif.Run) {
	t.Helper()
	written := uploaded(t, rep, leaveOut)
	images = map[string]*sarif.Run{}
	for i, run := range written.Runs {
		if run.Tool.Driver.Name != "trivy" {
			continue
		}
		switch {
		case run.AutomationDetails == nil:
			fs = &written.Runs[i]
		case sarif.IsImageCategory(run.AutomationDetails.ID):
			images[run.AutomationDetails.ID] = &written.Runs[i]
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
// default category alone, so the image alerts, in their own categories, stay
// as the last scan left them.
func TestWriteSARIFOfAPushThatScannedNoImage(t *testing.T) {
	if _, images := writeAndLoad(t, scan(), nil); len(images) != 0 {
		t.Errorf("written image runs = %+v, want none", images)
	}
}

// A push that touches one pin file scans that pin's image alone. Its upload
// carries that image's category and no other, so only its own alerts update.
// The summary and the gate still read every finding.
func TestWriteSARIFOfAPushThatScannedOneImage(t *testing.T) {
	rep := scan(imageScan("redis:8.10.1", 1))
	_, images := writeAndLoad(t, rep, nil)
	if len(images) != 1 || images[sarif.ImageCategory("redis:8.10.1")] == nil {
		t.Errorf("written image runs = %+v, want the redis category alone", images)
	}
	if rep.ResultCount() != 4 {
		t.Errorf("report findings = %d, want 4: the image finding stays in the report", rep.ResultCount())
	}
}

// A run that scanned every image writes each image's run in its own category,
// a clean image's empty run included, so the upload closes exactly the alerts
// of the images it scanned and reports nothing.
func TestWriteSARIFOfAFullScanFilesEachImageInItsOwnCategory(t *testing.T) {
	_, images := writeAndLoad(t, scan(imageScan("redis:8.10.1", 2), imageScan("postgres:18.6", 1)), nil)
	if len(images) != 2 {
		t.Fatalf("written image runs = %+v, want one per image", images)
	}
	if got := images[sarif.ImageCategory("redis:8.10.1")]; got == nil || len(got.Results) != 2 {
		t.Errorf("redis run = %+v, want its 2 findings", got)
	}
	if got := images[sarif.ImageCategory("postgres:18.6")]; got == nil || len(got.Results) != 1 {
		t.Errorf("postgres run = %+v, want its 1 finding", got)
	}
	_, images = writeAndLoad(t, scan(imageScan("redis:8.10.1", 0)), nil)
	clean := images[sarif.ImageCategory("redis:8.10.1")]
	if clean == nil || len(clean.Results) != 0 {
		t.Errorf("written image run of a clean image = %+v, want an empty run", clean)
	}
}

// A failed scan of one image leaves that image's category out: its alerts stay
// as the last scan left them. The other images' categories are written, so
// their alerts still update.
func TestWriteSARIFLeavesOutOnlyTheFailedImagesCategory(t *testing.T) {
	rep := scan(imageScan("redis:8.10.1", 1), imageScan("postgres:18.6", 1))
	failed := imageCategory("postgres:18.6")
	_, images := writeAndLoad(t, rep, map[sarif.Category]bool{failed: true})
	if len(images) != 1 || images[sarif.ImageCategory("redis:8.10.1")] == nil {
		t.Errorf("written image runs = %+v, want the redis category alone", images)
	}
	if rep.ResultCount() != 5 {
		t.Errorf("report findings = %d, want 5: every finding stays in the report", rep.ResultCount())
	}
}

// A failed scan of the repo's own image leaves trivy's default category out:
// written, the fs scan's run would close that image's alerts. The other tools
// and the image categories are written as usual.
func TestWriteSARIFLeavesOutTheDefaultCategoryOfAFailedOwnImage(t *testing.T) {
	rep := scan(imageScan("redis:8.10.1", 1))
	var got []sarif.Category
	for _, run := range uploaded(t, rep, map[sarif.Category]bool{{Tool: "trivy"}: true}).Runs {
		got = append(got, run.Category())
	}
	if want := []sarif.Category{{Tool: "gosec"}, imageCategory("redis:8.10.1")}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("written runs = %v, want %v", got, want)
	}
	if rep.ResultCount() != 4 {
		t.Errorf("report findings = %d, want 4: the fs and own-image findings stay in the report", rep.ResultCount())
	}
}

// writtenNames writes rep and returns the raw tool name of each written run,
// before sarif.Load maps an image run back to trivy.
func writtenNames(t *testing.T, rep *sarif.Report, leaveOut map[sarif.Category]bool) []string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scanctl.sarif")
	if err := WriteSARIF(rep, path, leaveOut); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is under our temp dir
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, run := range raw.Runs {
		names = append(names, run.Tool.Driver.Name)
	}
	return names
}

// The third-party image run is uploaded as tool trivy-image, the fs run as
// trivy, and the report keeps the in-memory driver name.
func TestWriteSARIFNamesTheImageRunTrivyImage(t *testing.T) {
	rep := scan(imageScan("redis:8.10.1", 1))
	got := writtenNames(t, rep, nil)
	if want := []string{"trivy", "gosec", "trivy-image"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("written tools = %v, want %v", got, want)
	}
	for _, run := range rep.Runs {
		if run.Tool.Driver.Name == sarif.ImageTool {
			t.Errorf("WriteSARIF renamed a run of the report: %+v", run.Tool)
		}
	}
	if got := writtenNames(t, rep, map[sarif.Category]bool{imageCategory("redis:8.10.1"): true}); fmt.Sprint(got) != fmt.Sprint([]string{"trivy", "gosec"}) {
		t.Errorf("written tools with the image category left out = %v, want trivy and gosec", got)
	}
}

// A run over the cap keeps its most severe results (ties by position), in
// their original order, and the rules they reference; the report keeps every
// result.
func TestWriteSARIFCutsARunToItsMostSevereResults(t *testing.T) {
	run := sarif.Run{Tool: sarif.Tool{Driver: sarif.Driver{Name: "gosec", Rules: []sarif.Rule{{ID: "LOW"}, {ID: "HIGH"}}}}}
	for i := 0; i < maxUploadResults; i++ {
		run.Results = append(run.Results, sarif.Result{RuleID: "LOW", Level: sarif.LevelNote, Message: sarif.Message{Text: fmt.Sprint("low", i)}})
	}
	for i := 0; i < 3; i++ {
		run.Results = append(run.Results, sarif.Result{RuleID: "HIGH", Level: sarif.LevelError, Message: sarif.Message{Text: fmt.Sprint("high", i)}})
	}
	rep := &sarif.Report{Schema: "s", Version: "2.1.0", Runs: []sarif.Run{run}}

	out := uploaded(t, rep, nil)
	if len(out.Runs) != 1 || len(out.Runs[0].Results) != maxUploadResults {
		t.Fatalf("written results = %d, want %d", out.ResultCount(), maxUploadResults)
	}
	got := out.Runs[0].Results
	n := len(got)
	for i, want := range []string{"high0", "high1", "high2"} {
		if got[n-3+i].Message.Text != want {
			t.Errorf("result %d = %q, want %q: every high result is kept", n-3+i, got[n-3+i].Message.Text, want)
		}
	}
	if got[0].Message.Text != "low0" || got[n-4].Message.Text != "low4996" {
		t.Errorf("the 4997 first low results are kept in order: %q ... %q", got[0].Message.Text, got[n-4].Message.Text)
	}
	if rules := out.Runs[0].Tool.Driver.Rules; len(rules) != 2 {
		t.Errorf("rules = %v, want both: each is still referenced", rules)
	}
	if rep.ResultCount() != maxUploadResults+3 || len(rep.Runs[0].Tool.Driver.Rules) != 2 {
		t.Errorf("WriteSARIF cut the report: %d results", rep.ResultCount())
	}
}

func TestWriteSARIFDropsTheRulesOfCutResults(t *testing.T) {
	run := sarif.Run{Tool: sarif.Tool{Driver: sarif.Driver{Name: "gosec", Rules: []sarif.Rule{{ID: "LOW"}, {ID: "HIGH"}}}}}
	for i := 0; i < maxUploadResults; i++ {
		run.Results = append(run.Results, sarif.Result{RuleID: "HIGH", Level: sarif.LevelError, Message: sarif.Message{Text: "h"}})
	}
	run.Results = append(run.Results, sarif.Result{RuleID: "LOW", Level: sarif.LevelNote, Message: sarif.Message{Text: "l"}})
	out := uploaded(t, &sarif.Report{Runs: []sarif.Run{run}}, nil)
	if got := out.Runs[0].Tool.Driver.Rules; len(got) != 1 || got[0].ID != "HIGH" {
		t.Errorf("rules = %v, want HIGH alone", got)
	}
	if n := len(out.Runs[0].Results); n != maxUploadResults {
		t.Errorf("written results = %d, want %d", n, maxUploadResults)
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
