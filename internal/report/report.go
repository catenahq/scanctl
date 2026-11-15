// Package report writes the merged SARIF to disk and renders a human-readable
// markdown summary. SARIF is the machine artifact (GitHub code-scanning + the
// DefectDojo upload consume it unchanged); the markdown is for the CI log and
// the operator.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/catenahq/scanctl/internal/config"
	"github.com/catenahq/scanctl/internal/gate"
	"github.com/catenahq/scanctl/internal/sarif"
)

// maxUploadResults is the most results of one run that code scanning keeps
// (the most severe); it rejects a file with a run of more than 25,000.
const maxUploadResults = 5000

// MaxRunsPerFile is the most runs code scanning accepts in one SARIF file; it
// rejects the file beyond that.
const MaxRunsPerFile = 20

// uploadReport returns the report code scanning takes from rep: one run per
// tool and category, named by Run.UploadTool, each cut to maxUploadResults
// results, without the categories in leaveOut (a category the run did not scan
// whole, whose upload would close the alerts of what it skipped). rep is
// normalized; its own runs and findings stay as they were.
func uploadReport(rep *sarif.Report, leaveOut map[sarif.Category]bool) *sarif.Report {
	rep.Normalize()
	written := rep.OneRunPerCategory()
	written.Runs = slices.DeleteFunc(written.Runs, func(run sarif.Run) bool {
		return leaveOut[run.Category()]
	})
	for i := range written.Runs {
		run := &written.Runs[i]
		trimToMostSevere(run, maxUploadResults)
		run.Tool.Driver.Name = run.UploadTool()
	}
	return written
}

// WriteSARIF marshals rep to path with indentation, one run per tool and
// category (the shape code scanning uploads, see
// sarif.Report.OneRunPerCategory), after normalizing it so the output is
// schema-valid (no null results arrays). leaveOut names the categories whose
// run is left out: a category the run did not scan whole, whose upload would
// close the alerts of what it skipped. An upload without a category leaves its
// alerts as they were. A written run holds at most maxUploadResults results,
// the most severe, and is named by Run.UploadTool. rep keeps every finding for
// the summary and the gate. One image now has a category of its own, so a
// report of more than MaxRunsPerFile runs needs WriteUploadSet instead: code
// scanning rejects a single file that big.
func WriteSARIF(rep *sarif.Report, path string, leaveOut map[sarif.Category]bool) error {
	written := uploadReport(rep, leaveOut)
	data, err := json.MarshalIndent(written, "", "  ")
	if err != nil {
		return err
	}
	// #nosec G306 -- a SARIF report is non-sensitive output meant to be read by
	// CI steps and humans; 0644 is intentional
	return os.WriteFile(path, data, 0o644)
}

// WriteUploadSet writes rep into dir as the SARIF files code scanning uploads:
// the same runs WriteSARIF writes, grouped into files of at most
// MaxRunsPerFile runs (code scanning rejects a file holding more) with one run
// per tool and category, each file a complete SARIF document. The directory is
// the sarif_file a github/codeql-action/upload-sarif call takes. A SARIF file
// an earlier call wrote in dir is removed first, so a category this run no
// longer carries stops uploading. It returns how many files it wrote.
func WriteUploadSet(rep *sarif.Report, dir string, leaveOut map[sarif.Category]bool) (int, error) {
	written := uploadReport(rep, leaveOut)
	// #nosec G301 -- the directory is non-sensitive output meant to be read by
	// CI steps
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	old, err := filepath.Glob(filepath.Join(dir, "*.sarif"))
	if err != nil {
		return 0, err
	}
	for _, p := range old {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return 0, err
		}
	}
	chunks := (len(written.Runs) + MaxRunsPerFile - 1) / MaxRunsPerFile
	if chunks == 0 {
		chunks = 1
	}
	for i := 0; i < chunks; i++ {
		start := i * MaxRunsPerFile
		end := start + MaxRunsPerFile
		if end > len(written.Runs) {
			end = len(written.Runs)
		}
		chunk := &sarif.Report{Schema: written.Schema, Version: written.Version, Runs: written.Runs[start:end]}
		data, err := json.MarshalIndent(chunk, "", "  ")
		if err != nil {
			return i, err
		}
		// #nosec G306 -- a SARIF report is non-sensitive output meant to be read
		// by CI steps and humans
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%03d.sarif", i+1)), data, 0o644); err != nil {
			return i, err
		}
	}
	return chunks, nil
}

// trimToMostSevere cuts run to its limit most severe results (ties go to the
// earlier one; the kept results keep their order) and to the rules those
// results reference. The run's slices are replaced, never edited in place.
func trimToMostSevere(run *sarif.Run, limit int) {
	if len(run.Results) <= limit {
		return
	}
	rules := run.RulesByID()
	rank := make([]int, len(run.Results))
	order := make([]int, len(run.Results))
	for i, res := range run.Results {
		rank[i] = gate.Severity(run.Tool.Driver.Name, rules, res).Rank()
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return rank[order[a]] > rank[order[b]] })
	order = order[:limit]
	sort.Ints(order)
	kept := make([]sarif.Result, 0, limit)
	used := map[string]bool{}
	for _, i := range order {
		kept = append(kept, run.Results[i])
		used[run.Results[i].RuleID] = true
	}
	var keptRules []sarif.Rule
	for _, rule := range run.Tool.Driver.Rules {
		if used[rule.ID] {
			keptRules = append(keptRules, rule)
		}
	}
	run.Results = kept
	run.Tool.Driver.Rules = keptRules
}

// finding is a flattened result row for the human-readable lists.
type finding struct {
	tool, sev, rule, msg, loc string
}

// Summary renders a markdown overview: total findings, a per-tool breakdown
// annotated with each tool's gate mode, then the findings split into the ones
// that GATE the build (a block-mode tool at/above the floor) and the ADVISORY
// ones that only surface. cfg supplies the per-tool block/report mode and the
// gate floor so a reader can see exactly why a finding does or does not fail
// the run -- e.g. a HIGH license finding from the report-mode trivy-license
// tool lands in "advisory", not "gating".
func Summary(rep *sarif.Report, cfg config.Config) string {
	var b strings.Builder
	total := rep.ResultCount()
	fmt.Fprintf(&b, "## scanctl: %d finding(s)\n\n", total)
	if total == 0 {
		b.WriteString("No findings.\n")
		return b.String()
	}

	floor := cfg.Gate.Floor.Rank()
	blocks := func(tool string) bool {
		tc, ok := cfg.Tools[tool]
		return ok && tc.Mode == config.ModeBlock
	}

	type row struct {
		tool             string
		mode             string
		errs, warns, oth int
	}
	rows := make([]row, 0, len(rep.Runs))
	for _, run := range rep.Runs {
		mode := "report"
		if blocks(run.Tool.Driver.Name) {
			mode = "block"
		}
		r := row{tool: run.Tool.Driver.Name, mode: mode}
		for _, res := range run.Results {
			switch res.Level {
			case sarif.LevelError:
				r.errs++
			case sarif.LevelWarning:
				r.warns++
			default:
				r.oth++
			}
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].tool < rows[j].tool })

	b.WriteString("| tool | mode | error | warning | other |\n|---|---|---|---|---|\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %s | %d | %d | %d |\n", r.tool, r.mode, r.errs, r.warns, r.oth)
	}

	var gating, advisory []finding
	for _, run := range rep.Runs {
		blocking := blocks(run.Tool.Driver.Name)
		rules := run.RulesByID()
		for _, res := range run.Results {
			sev := gate.Severity(run.Tool.Driver.Name, rules, res)
			f := finding{tool: run.Tool.Driver.Name, sev: strings.ToUpper(string(sev)), rule: res.RuleID, msg: msg(res), loc: loc(res)}
			if blocking && sev.Rank() >= floor && !res.Suppressed() {
				gating = append(gating, f)
			} else {
				advisory = append(advisory, f)
			}
		}
	}

	fmt.Fprintf(&b, "\ngate floor: %s -- %d finding(s) gate the build; %d advisory (report-mode or below floor).\n",
		cfg.Gate.Floor, len(gating), len(advisory))

	writeFindings(&b, "Gating findings", gating, 50)
	writeFindings(&b, "Advisory findings", advisory, 25)
	return b.String()
}

// writeFindings emits a titled list of findings, capped at limit with a
// "... N more" tail. Nothing is written for an empty list.
func writeFindings(b *strings.Builder, title string, fs []finding, limit int) {
	if len(fs) == 0 {
		return
	}
	fmt.Fprintf(b, "\n### %s (%d)\n\n", title, len(fs))
	for i, f := range fs {
		if i >= limit {
			fmt.Fprintf(b, "- ... (%d more)\n", len(fs)-limit)
			return
		}
		fmt.Fprintf(b, "- [%s] %s %s %s%s\n", f.tool, f.sev, f.rule, f.msg, f.loc)
	}
}

func msg(res sarif.Result) string {
	t := strings.TrimSpace(res.Message.Text)
	t = strings.ReplaceAll(t, "\n", " ")
	if len(t) > 240 {
		t = t[:237] + "..."
	}
	return t
}

func loc(res sarif.Result) string {
	if len(res.Locations) == 0 {
		return ""
	}
	pl := res.Locations[0].PhysicalLocation
	if pl.ArtifactLocation.URI == "" {
		return ""
	}
	if pl.Region != nil && pl.Region.StartLine > 0 {
		return fmt.Sprintf(" (%s:%d)", pl.ArtifactLocation.URI, pl.Region.StartLine)
	}
	return fmt.Sprintf(" (%s)", pl.ArtifactLocation.URI)
}
