package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/catenahq/scanctl/internal/baseline"
	"github.com/catenahq/scanctl/internal/sarif"
)

// imageResult is a trivy image finding. fixed is its Fixed Version ("" for
// none), score its security-severity.
func imageResult(rule, image, fixed, score string) sarif.Result {
	return sarif.Result{
		RuleID: rule + "/" + sarif.ImageRepo(image),
		Level:  "error",
		Message: sarif.Message{Text: fmt.Sprintf(
			"Package: %s\nInstalled Version: 1\nVulnerability %s\nSeverity: HIGH\nFixed Version: %s\nLink: x", rule+"-pkg", rule, fixed)},
		Properties: map[string]any{sarif.ImageProperty: image, "security-severity": score},
	}
}

func trivyRun(category string, results ...sarif.Result) sarif.Run {
	run := sarif.Run{Tool: sarif.Tool{Driver: sarif.Driver{Name: "trivy"}}, Results: results}
	if category != "" {
		run.AutomationDetails = &sarif.AutomationDetails{ID: category}
	}
	return run
}

func writeReport(t *testing.T, name string, runs ...sarif.Run) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	data, err := json.Marshal(&sarif.Report{Version: "2.1.0", Runs: runs})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// accept runs scanctl accept with the default config and returns the baseline
// it wrote.
func accept(t *testing.T, until, baselinePath, input string) *sarif.Report {
	t.Helper()
	if code := acceptCmd([]string{"-until", until, "-baseline", baselinePath, "-config", filepath.Join(t.TempDir(), "none.yml"), input}); code != 0 {
		t.Fatalf("accept exit = %d, want 0", code)
	}
	rep, err := sarif.Load(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func untilOf(r sarif.Result) any { return r.Properties[baseline.AcceptedUntil] }

func entries(rep *sarif.Report) map[string]sarif.Result {
	m := map[string]sarif.Result{}
	for _, run := range rep.Runs {
		for _, r := range run.Results {
			m[r.RuleID] = r
		}
	}
	return m
}

func TestAcceptWritesOnlyTheImageFindingsThatGate(t *testing.T) {
	own := imageResult("CVE-5", "app:ci", "2", "8.0")
	own.Properties = map[string]any{sarif.OwnImageProperty: "app:ci", "security-severity": "8.0"}
	tree := imageResult("CVE-4", "x:1", "2", "8.0")
	tree.Properties = map[string]any{"security-severity": "8.0"}
	suppressed := imageResult("CVE-1", "postgres:18", "2", "8.0")
	suppressed.Suppressions = []sarif.Suppression{{Kind: "external", Justification: sarif.NoFixedVersion}}
	in := writeReport(t, "in.sarif", trivyRun("",
		suppressed,
		imageResult("CVE-2", "postgres:18", "", "8.0"),
		imageResult("CVE-3", "postgres:18", "2", "5.0"),
		tree, own))

	got := entries(accept(t, "2999-01-01", filepath.Join(t.TempDir(), ".scanctl", "baseline.sarif"), in))
	if len(got) != 1 || untilOf(got["CVE-1/postgres"]) != "2999-01-01" {
		t.Errorf("entries = %v, want only CVE-1/postgres dated 2999-01-01", got)
	}
}

func TestAcceptKeepsALiveDateRenewsAnExpiredOneAndAddsANewOne(t *testing.T) {
	bl := filepath.Join(t.TempDir(), "baseline.sarif")
	accept(t, "2998-01-01", bl, writeReport(t, "a.sarif", trivyRun("",
		imageResult("CVE-1", "postgres:18", "2", "8.0"))))

	expiredEntry := imageResult("CVE-2", "redis:7", "2", "8.0")
	expiredEntry.Properties[baseline.AcceptedUntil] = "2000-01-01"
	existing, err := sarif.Load(bl)
	if err != nil {
		t.Fatal(err)
	}
	existing.Runs[0].Results = append(existing.Runs[0].Results, expiredEntry)
	data, _ := json.Marshal(existing)
	if err := os.WriteFile(bl, data, 0o600); err != nil {
		t.Fatal(err)
	}

	got := entries(accept(t, "2999-01-01", bl, writeReport(t, "b.sarif", trivyRun("",
		imageResult("CVE-1", "postgres:18", "2", "8.0"),
		imageResult("CVE-2", "redis:7", "2", "8.0"),
		imageResult("CVE-3", "mariadb:11", "2", "8.0")))))
	for rule, want := range map[string]string{
		"CVE-1/postgres": "2998-01-01",
		"CVE-2/redis":    "2999-01-01",
		"CVE-3/mariadb":  "2999-01-01",
	} {
		if untilOf(got[rule]) != want {
			t.Errorf("%s accepted until %v, want %s", rule, untilOf(got[rule]), want)
		}
	}
}

func TestAcceptDropsAnImageEntryTheInputNoLongerReportsWhenItHoldsAnImageRun(t *testing.T) {
	bl := filepath.Join(t.TempDir(), "baseline.sarif")
	accept(t, "2999-01-01", bl, writeReport(t, "a.sarif", trivyRun("",
		imageResult("CVE-1", "postgres:18", "2", "8.0"))))

	got := entries(accept(t, "2999-01-01", bl, writeReport(t, "b.sarif", trivyRun(sarif.ImageCategory))))
	if len(got) != 0 {
		t.Errorf("entries = %v, want CVE-1/postgres dropped", got)
	}
}

func TestAcceptKeepsAnImageEntryTheInputDoesNotReportWhenItHoldsNoImageRun(t *testing.T) {
	bl := filepath.Join(t.TempDir(), "baseline.sarif")
	accept(t, "2999-01-01", bl, writeReport(t, "a.sarif", trivyRun("",
		imageResult("CVE-1", "postgres:18", "2", "8.0"))))

	got := entries(accept(t, "2999-01-01", bl, writeReport(t, "b.sarif", trivyRun(""))))
	if _, ok := got["CVE-1/postgres"]; !ok {
		t.Errorf("entries = %v, want CVE-1/postgres kept: no run scanned every image", got)
	}
}

func TestAcceptKeepsAnEntryWhoseFindingIsReportedButDoesNotGate(t *testing.T) {
	bl := filepath.Join(t.TempDir(), "baseline.sarif")
	accept(t, "2998-01-01", bl, writeReport(t, "a.sarif", trivyRun("",
		imageResult("CVE-1", "postgres:18", "2", "8.0"),
		imageResult("CVE-2", "redis:7", "2", "8.0"))))

	got := entries(accept(t, "2999-01-01", bl, writeReport(t, "b.sarif", trivyRun(sarif.ImageCategory,
		imageResult("CVE-1", "postgres:18", "2", "5.0"),
		imageResult("CVE-2", "redis:7", "", "8.0")))))
	for _, rule := range []string{"CVE-1/postgres", "CVE-2/redis"} {
		if untilOf(got[rule]) != "2998-01-01" {
			t.Errorf("%s = %v, want kept with its date: the finding is still reported", rule, got[rule])
		}
	}
}

func TestAcceptLeavesATreeEntryAlone(t *testing.T) {
	bl := writeReport(t, "baseline.sarif", sarif.Run{
		Tool:    sarif.Tool{Driver: sarif.Driver{Name: "gosec"}},
		Results: []sarif.Result{{RuleID: "G304", Message: sarif.Message{Text: "m"}}},
	})
	got := entries(accept(t, "2999-01-01", bl, writeReport(t, "b.sarif", trivyRun(sarif.ImageCategory))))
	if _, ok := got["G304"]; !ok {
		t.Errorf("entries = %v, want the tree entry kept", got)
	}
}

func TestAcceptRefusesAnEndDateThatIsNotAfterToday(t *testing.T) {
	in := writeReport(t, "in.sarif", trivyRun(""))
	for _, until := range []string{"2000-01-01", "", "not-a-date"} {
		if code := acceptCmd([]string{"-until", until, "-baseline", filepath.Join(t.TempDir(), "b.sarif"), in}); code != 2 {
			t.Errorf("-until %q: exit = %d, want 2", until, code)
		}
	}
}

func TestARunPassesWithTheBaselineAcceptWroteFromItsOwnSARIF(t *testing.T) {
	root, args := imageScan(t, "3.5.8-r0")
	var cfg, in string
	for i, a := range args {
		switch a {
		case "-config":
			cfg = args[i+1]
		case "-import":
			in = args[i+1]
		}
	}
	bl := filepath.Join(t.TempDir(), "baseline.sarif")
	if code := acceptCmd([]string{"-until", "2999-01-01", "-config", cfg, "-baseline", bl, in}); code != 0 {
		t.Fatalf("accept exit = %d, want 0", code)
	}
	if code := runCmd(append(append(args, "-baseline", bl), root)); code != 0 {
		t.Errorf("exit = %d, want 0: the baseline accept wrote accepts the finding it came from", code)
	}
}
