package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/catenahq/scanctl/internal/config"
	"github.com/catenahq/scanctl/internal/detect"
	"github.com/catenahq/scanctl/internal/gate"
	"github.com/catenahq/scanctl/internal/report"
	"github.com/catenahq/scanctl/internal/sarif"
)

// catalogGo is the shape the pins actually take in catena-admin's tier-1
// catalog: several images in one file, each on its own assignment line, with a
// comment nearby that mentions an image in prose.
const catalogGo = `
// PGDATA moved when the pin went to postgres:18, see the migration note.
func withDefaults(c *Catalog) {
	c.TraefikImage = "traefik:v3.7.13"
	c.PostgresImage = "postgres:18.6-alpine"
	c.PortainerImage = "portainer/portainer-ce:2.35.0"
}
`

func writeFile(t *testing.T, root, name, body string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestResolveImageRefsReadsEveryPinInTheFile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "payload/engines/tier1/catalog.go", catalogGo)

	cfg := config.Config{ImagePins: []config.ImagePin{{
		File:    "payload/engines/tier1/catalog.go",
		Pattern: `c\.\w+Image = "([^"]+)"`,
	}}}
	refs, err := resolveImageRefs(cfg, root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"portainer/portainer-ce:2.35.0", "postgres:18.6-alpine", "traefik:v3.7.13"}
	if strings.Join(refs, ",") != strings.Join(want, ",") {
		t.Errorf("refs = %v, want %v", refs, want)
	}
}

// The prose mention of postgres:18 in the comment must not become a ref: it is
// not a pin, and scanning it would report on a tag no host runs.
func TestResolveImageRefsIgnoresProseMatchingTheImageShape(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "catalog.go", catalogGo)

	cfg := config.Config{ImagePins: []config.ImagePin{{
		File:    "catalog.go",
		Pattern: `c\.PostgresImage = "([^"]+)"`,
	}}}
	refs, err := resolveImageRefs(cfg, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0] != "postgres:18.6-alpine" {
		t.Errorf("refs = %v, want just the pinned postgres ref", refs)
	}
}

func TestResolveImageRefsMergesLiteralsAndPinsWithoutDuplicates(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "catalog.go", catalogGo)

	cfg := config.Config{
		Images: []string{"traefik:v3.7.13", "ghcr.io/x/app:1.2.3"},
		ImagePins: []config.ImagePin{{
			File:    "catalog.go",
			Pattern: `c\.TraefikImage = "([^"]+)"`,
		}},
	}
	refs, err := resolveImageRefs(cfg, root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ghcr.io/x/app:1.2.3", "traefik:v3.7.13"}
	if strings.Join(refs, ",") != strings.Join(want, ",") {
		t.Errorf("refs = %v, want %v (traefik once, not twice)", refs, want)
	}
}

// The catena-ce failure this exists to prevent: the pinned file moved, the
// pattern matched nothing, and the gate reported success having scanned no
// image at all.
func TestResolveImageRefsFailsWhenAPinMatchesNothing(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "defaults/main.yml", "gatus_image_tag: \"v5.36.0\"\n")

	cfg := config.Config{ImagePins: []config.ImagePin{{
		File:    "defaults/main.yml",
		Pattern: `clamav_image: "(clamav/clamav:[^"]+)"`,
	}}}
	_, err := resolveImageRefs(cfg, root)
	if err == nil {
		t.Fatal("a pin matching nothing must fail the run, not scan nothing quietly")
	}
	if !strings.Contains(err.Error(), "matched no image ref") {
		t.Errorf("error = %v, want it to name the unmatched pin", err)
	}
}

func TestResolveImageRefsFailsWhenThePinFileIsGone(t *testing.T) {
	cfg := config.Config{ImagePins: []config.ImagePin{{
		File:    "ansible/roles/keycloak/defaults/main.yml",
		Pattern: `keycloak_image_tag: "([^"]+)"`,
	}}}
	_, err := resolveImageRefs(cfg, t.TempDir())
	if err == nil {
		t.Fatal("a pin naming a file that does not exist must fail the run")
	}
}

func TestResolveImageRefsRejectsAPatternWithoutOneGroup(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "catalog.go", catalogGo)

	for _, pattern := range []string{
		`c\.TraefikImage = "[^"]+"`, // no group at all
		`c\.(\w+)Image = "([^"]+)"`, // two groups
	} {
		cfg := config.Config{ImagePins: []config.ImagePin{{File: "catalog.go", Pattern: pattern}}}
		if _, err := resolveImageRefs(cfg, root); err == nil {
			t.Errorf("pattern %q was accepted; it cannot yield a <repo>:<tag>", pattern)
		}
	}
}

// A glob pin reads every file it matches, and one of them yielding no ref is
// fine while another does.
func TestResolveImagePinReadsEveryFileAGlobMatches(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "blueprints/a/docker-compose.yml", "services:\n  a:\n    image: nginx:1.31-alpine\n")
	writeFile(t, root, "blueprints/b/docker-compose.yml", "services:\n  b:\n    image: \"redis:8.10.1\"\n  c:\n    image: postgres:18.6\n")
	writeFile(t, root, "blueprints/c/docker-compose.yml", "services: {}\n")

	refs, err := ResolveImagePin(config.ImagePin{
		File:    "blueprints/*/docker-compose.yml",
		Pattern: `(?m)^\s*image:\s*["']?([^"'\s#]+)`,
	}, root)
	if err != nil {
		t.Fatal(err)
	}
	want := "nginx:1.31-alpine,redis:8.10.1,postgres:18.6"
	if strings.Join(refs, ",") != want {
		t.Errorf("refs = %v, want %s", refs, want)
	}
}

func TestResolveImagePinFailsWhenAGlobMatchesNoFile(t *testing.T) {
	_, err := ResolveImagePin(config.ImagePin{
		File:    "blueprints/*/docker-compose.yml",
		Pattern: `image: (\S+)`,
	}, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Errorf("err = %v, want a glob matching no file to fail the run", err)
	}
}

// An Ansible role default splits the repo off the tag, so the pattern matches
// the tag line and `repo` supplies the other half.
func TestResolveImageRefsComposesRepoWithACapturedTag(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "defaults/main.yml",
		"keycloak_image_tag: \"26.6.4\"\nkeycloak_image: >-\n  {{ ('quay.io/phasetwo/phasetwo-keycloak:' ~ keycloak_image_tag) }}\n")

	cfg := config.Config{ImagePins: []config.ImagePin{{
		File:    "defaults/main.yml",
		Pattern: `keycloak_image_tag: "([^"]+)"`,
		Repo:    "quay.io/phasetwo/phasetwo-keycloak",
	}}}
	refs, err := resolveImageRefs(cfg, root)
	if err != nil {
		t.Fatal(err)
	}
	want := "quay.io/phasetwo/phasetwo-keycloak:26.6.4"
	if len(refs) != 1 || refs[0] != want {
		t.Errorf("refs = %v, want [%s]", refs, want)
	}
}

// trivy does not read a repo's ignore file on its own for an image scan, so
// the suppressions an operator has already reviewed and time-boxed only apply
// when the scan is told where they live.
func TestTrivyIgnoreFileIsFoundInTheScannedRoot(t *testing.T) {
	for _, name := range []string{".trivyignore.yaml", ".trivyignore.yml", ".trivyignore"} {
		root := t.TempDir()
		writeFile(t, root, name, "vulnerabilities:\n")
		got := trivyIgnoreFile(root)
		if got != filepath.Join(root, name) {
			t.Errorf("trivyIgnoreFile = %q, want the %s in the root", got, name)
		}
	}
}

func TestTrivyIgnoreFilePrefersTheYamlForm(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".trivyignore", "CVE-1\n")
	writeFile(t, root, ".trivyignore.yaml", "vulnerabilities:\n")
	if got := trivyIgnoreFile(root); got != filepath.Join(root, ".trivyignore.yaml") {
		t.Errorf("trivyIgnoreFile = %q, want the .yaml form (it carries the expired_at entries)", got)
	}
}

func TestTrivyIgnoreFileIsEmptyWhenTheRepoHasNone(t *testing.T) {
	if got := trivyIgnoreFile(t.TempDir()); got != "" {
		t.Errorf("trivyIgnoreFile = %q, want empty so no --ignorefile is passed", got)
	}
}

// One ignore file, one answer. Honouring it for images but not for the fs scan
// would mean a suppression the operator wrote once takes effect in half the
// run, with nothing in the output saying which half.
func TestTheFsScanPassesTheSameIgnoreFile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".trivyignore.yaml", "vulnerabilities:\n")

	var trivy toolDef
	for _, td := range registry {
		if td.name == "trivy" {
			trivy = td
		}
	}
	args := trivy.invoke("trivy", root, "out.sarif", detect.Result{}).args

	var got string
	for i, a := range args {
		if a == "--ignorefile" && i+1 < len(args) {
			got = args[i+1]
		}
	}
	if got != filepath.Join(root, ".trivyignore.yaml") {
		t.Errorf("--ignorefile = %q, want the repo's ignore file", got)
	}
	if args[len(args)-1] != root {
		t.Errorf("scan target moved off the end of the argv: %v", args)
	}
}

func TestTheFsScanPassesNoIgnoreFileWhenThereIsNone(t *testing.T) {
	var trivy toolDef
	for _, td := range registry {
		if td.name == "trivy" {
			trivy = td
		}
	}
	args := trivy.invoke("trivy", t.TempDir(), "out.sarif", detect.Result{}).args
	for _, a := range args {
		if a == "--ignorefile" {
			t.Errorf("passed --ignorefile with no file to point it at: %v", args)
		}
	}
}

// The base side of a --baseline-ref diff scans with no ignore file, so a
// suppression the change removes does not read as CVEs the change brought in.
func TestScanImagesAppliesNoIgnoreFile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".trivyignore.yaml", "vulnerabilities:\n")
	argv := filepath.Join(t.TempDir(), "argv")
	bin := filepath.Join(t.TempDir(), "trivy")
	writeFile(t, filepath.Dir(bin), "trivy", "#!/bin/sh\necho \"$@\" >> "+argv+"\n")
	if err := os.Chmod(bin, 0o700); err != nil { // #nosec G302 -- a test stand-in for the trivy binary
		t.Fatal(err)
	}
	saved := registry
	t.Cleanup(func() { registry = saved })
	registry = []toolDef{{
		name:   "trivy",
		ensure: func(context.Context, string, string) (string, error) { return bin, nil },
	}}
	cfg := config.Config{
		Images: []string{"nginx:1.31-alpine"},
		Tools:  map[string]config.ToolConfig{"trivy": {Enabled: true, Mode: config.ModeBlock}},
	}
	lock := Lock{Tools: map[string]LockEntry{"trivy": {Version: "1"}}}
	if _, err := ScanImages(context.Background(), root, cfg, lock); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(argv) // #nosec G304 -- path is under the test's temp dir
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "nginx:1.31-alpine") {
		t.Fatalf("trivy never scanned the image: %q", got)
	}
	if strings.Contains(string(got), "--ignorefile") {
		t.Errorf("the base-side scan passed an ignore file: %q", got)
	}
}

// Every result names its image, and every rule id, on the rules and the
// results alike, names the image's repository: two images reporting one CVE
// keep a rule each, and a bump keeps the id.
func TestTagImageNamesTheImageOnEveryResultAndRule(t *testing.T) {
	tag := func(ref string) sarif.Run {
		runs := []sarif.Run{{
			Tool: sarif.Tool{Driver: sarif.Driver{Rules: []sarif.Rule{{ID: "CVE-1"}, {ID: "CVE-2"}}}},
			Results: []sarif.Result{
				{RuleID: "CVE-1"},
				{RuleID: "CVE-2", Properties: map[string]any{"k": "v"}},
			},
		}}
		tagImage(runs, sarif.ImageProperty, ref)
		return runs[0]
	}
	run := tag("postgres:18.6-alpine")
	for i, r := range run.Results {
		if r.Properties[sarif.ImageProperty] != "postgres:18.6-alpine" {
			t.Errorf("%s: image = %v, want postgres:18.6-alpine", r.RuleID, r.Properties[sarif.ImageProperty])
		}
		if want := fmt.Sprintf("CVE-%d/postgres", i+1); r.RuleID != want || run.Tool.Driver.Rules[i].ID != want {
			t.Errorf("rule ids = %s on the result, %s on the rule, want %s", r.RuleID, run.Tool.Driver.Rules[i].ID, want)
		}
	}
	if run.Results[1].Properties["k"] != "v" {
		t.Error("tagging dropped a property the scanner set")
	}
	if bumped := tag("postgres:18.7-alpine"); bumped.Results[0].RuleID != run.Results[0].RuleID {
		t.Errorf("a bump moved the rule id from %s to %s", run.Results[0].RuleID, bumped.Results[0].RuleID)
	}
}

// fakeTrivy stands in for trivy for the length of the test: an image scan
// copies reports[ref] to its --output, and exits 1 with no report for a ref
// reports does not hold.
func fakeTrivy(t *testing.T, reports map[string]string) {
	t.Helper()
	dir := t.TempDir()
	name := strings.NewReplacer("/", "_", ":", "_")
	for ref, body := range reports {
		writeFile(t, dir, name.Replace(ref)+".sarif", body)
	}
	bin := filepath.Join(t.TempDir(), "trivy")
	writeFile(t, filepath.Dir(bin), "trivy", "#!/bin/sh\n"+
		"for a; do\n  [ \"$prev\" = --output ] && out=$a\n  prev=$a\ndone\n"+
		"src=\""+dir+"/$(printf %s \"$prev\" | tr /: __).sarif\"\n"+
		"[ -f \"$src\" ] || exit 1\ncp \"$src\" \"$out\"\n")
	if err := os.Chmod(bin, 0o700); err != nil { // #nosec G302 -- a test stand-in for the trivy binary
		t.Fatal(err)
	}
	saved := registry
	t.Cleanup(func() { registry = saved })
	registry = []toolDef{{
		name:   "trivy",
		ensure: func(context.Context, string, string) (string, error) { return bin, nil },
	}}
}

// trivyReport is trivy's SARIF for an image carrying cve, scored score.
func trivyReport(cve, score string) string {
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy","rules":[` +
		`{"id":"` + cve + `","properties":{"security-severity":"` + score + `"}}]}},` +
		`"results":[{"ruleId":"` + cve + `","level":"error",` +
		`"message":{"text":"Package: libssl3\nInstalled Version: 3.5.7-r0"}}]}]}`
}

// scanAndWrite runs the image step over cfg's images, after an fs scan with
// one finding, and writes the SARIF as scanctl run does. It returns the
// outcome and the file code scanning uploads.
func scanAndWrite(t *testing.T, cfg config.Config) (*Outcome, *sarif.Report) {
	t.Helper()
	cfg.Tools = map[string]config.ToolConfig{"trivy": {Enabled: true, Mode: config.ModeBlock}}
	out := newOutcome()
	out.Report.Merge(&sarif.Report{Runs: []sarif.Run{{
		Tool:    sarif.Tool{Driver: sarif.Driver{Name: "trivy"}},
		Results: []sarif.Result{{RuleID: "DS002", Message: sarif.Message{Text: "fs"}}},
	}}})
	lock := Lock{Tools: map[string]LockEntry{"trivy": {Version: "1"}}}
	if err := imageStep(context.Background(), cfg, lock, t.TempDir(), "", out); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "scanctl.sarif")
	if err := report.WriteSARIF(out.Report, path, out.Incomplete); err != nil {
		t.Fatal(err)
	}
	written, err := sarif.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return out, written
}

// Code scanning reads security-severity from the rule alone. Two images
// reporting one CVE at different scores write a rule each, so each alert shows
// the score its own image's scan reported, and the gate grades each the same.
func TestAnImageAlertShowsItsOwnImagesScore(t *testing.T) {
	fakeTrivy(t, map[string]string{
		"redis:8.10.1":  trivyReport("CVE-2026-1", "9.8"),
		"postgres:18.6": trivyReport("CVE-2026-1", "5.3"),
	})
	out, written := scanAndWrite(t, config.Config{Images: []string{"redis:8.10.1", "postgres:18.6"}})

	want := map[string]string{"redis:8.10.1": "9.8", "postgres:18.6": "5.3"}
	var images *sarif.Run
	for i, run := range written.Runs {
		if run.Category() == ThirdPartyImages {
			images = &written.Runs[i]
		}
	}
	if images == nil || len(images.Results) != 2 || len(images.Tool.Driver.Rules) != 2 {
		t.Fatalf("written image run = %+v, want 2 findings under 2 rules", images)
	}
	rules := images.RulesByID()
	for _, r := range images.Results {
		ref, _ := r.Properties[sarif.ImageProperty].(string)
		if got := rules[r.RuleID].Properties["security-severity"]; got != want[ref] {
			t.Errorf("%s: alert %s scores %v, want %s as its scan reported", ref, r.RuleID, got, want[ref])
		}
	}

	grade := map[string]config.Severity{"redis:8.10.1": config.SevCritical, "postgres:18.6": config.SevMedium}
	for _, run := range out.Report.Runs {
		for _, r := range run.Results {
			ref, ok := r.Properties[sarif.ImageProperty].(string)
			if got := gate.Severity("trivy", run.RulesByID(), r); ok && got != grade[ref] {
				t.Errorf("%s: gate grades %s, want %s", ref, got, grade[ref])
			}
		}
	}
}

// An image whose scan fails after its retry leaves its category out of the
// SARIF: uploaded, the category's run would close that image's alerts. The
// other category is written, and the report keeps every finding for the
// summary and the gate.
func TestAFailedImageScanLeavesItsCategoryOut(t *testing.T) {
	fakeTrivy(t, map[string]string{
		"redis:8.10.1": trivyReport("CVE-2026-1", "9.8"),
		"app:ci":       trivyReport("CVE-2026-2", "7.5"),
	})
	for name, tc := range map[string]struct {
		cfg    config.Config
		failed string
		want   sarif.Category
	}{
		"third-party": {config.Config{Images: []string{"redis:8.10.1", "gone:1"}, OwnImages: []string{"app:ci"}},
			"gone:1", ownImages},
		"own": {config.Config{Images: []string{"redis:8.10.1"}, OwnImages: []string{"app:ci", "gone:ci"}},
			"gone:ci", ThirdPartyImages},
	} {
		t.Run(name, func(t *testing.T) {
			out, written := scanAndWrite(t, tc.cfg)
			if len(written.Runs) != 1 || written.Runs[0].Category() != tc.want {
				t.Errorf("written runs = %+v, want the %v run alone", written.Runs, tc.want)
			}
			if out.Failed[tc.failed] == "" {
				t.Errorf("Failed = %v, want %s listed", out.Failed, tc.failed)
			}
			if out.Report.ResultCount() != 3 {
				t.Errorf("report findings = %d, want 3: fs, redis and app", out.Report.ResultCount())
			}
		})
	}
}

// A third-party image's run goes in the image category even when the image is
// clean; an own image's stays in the default one, with the fs scan.
func TestTagImageFilesAThirdPartyImageInTheImageCategory(t *testing.T) {
	third := []sarif.Run{{}}
	tagImage(third, sarif.ImageProperty, "postgres:18.6-alpine")
	if d := third[0].AutomationDetails; d == nil || d.ID != sarif.ImageCategory {
		t.Errorf("third-party image run category = %+v, want %s", d, sarif.ImageCategory)
	}
	own := []sarif.Run{{Results: []sarif.Result{{RuleID: "CVE-1"}}}}
	tagImage(own, sarif.OwnImageProperty, "catena-admin:ci")
	if own[0].AutomationDetails != nil {
		t.Errorf("own image run category = %+v, want the default", own[0].AutomationDetails)
	}
}

// Pin files are read from the tree being scanned, which is what makes a
// --baseline-ref run resolve the merge-base's pins from its worktree instead
// of re-reading HEAD's.
func TestResolveImageRefsReadsPinsRelativeToTheScannedRoot(t *testing.T) {
	head := t.TempDir()
	base := t.TempDir()
	writeFile(t, head, "catalog.go", `c.TraefikImage = "traefik:v3.7.13"`)
	writeFile(t, base, "catalog.go", `c.TraefikImage = "traefik:v3.7.12"`)

	cfg := config.Config{ImagePins: []config.ImagePin{{
		File:    "catalog.go",
		Pattern: `c\.TraefikImage = "([^"]+)"`,
	}}}
	for root, want := range map[string]string{head: "traefik:v3.7.13", base: "traefik:v3.7.12"} {
		refs, err := resolveImageRefs(cfg, root)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) != 1 || refs[0] != want {
			t.Errorf("refs under %s = %v, want [%s]", root, refs, want)
		}
	}
}
