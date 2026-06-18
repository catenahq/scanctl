// Package report writes the merged SARIF to disk and renders a human-readable
// markdown summary. SARIF is the machine artifact (GitHub code-scanning + the
// P2 DefectDojo upload consume it unchanged); the markdown is for the CI log
// and the operator.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/catenahq/scanctl/internal/config"
	"github.com/catenahq/scanctl/internal/sarif"
)

// WriteSARIF marshals rep to path with indentation, after normalizing it so the
// output is schema-valid (no null results arrays).
func WriteSARIF(rep *sarif.Report, path string) error {
	rep.Normalize()
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	// #nosec G306 -- a SARIF report is non-sensitive output meant to be read by
	// CI steps and humans; 0644 is intentional
	return os.WriteFile(path, data, 0o644)
}

// finding is a flattened result row for the human-readable lists.
type finding struct {
	tool, sev, rule, msg, loc string
}

// sevLabel maps a SARIF level to scanctl's severity label and comparable rank.
// Mirrors gate.levelToSeverity (error == high) but kept local so report does
// not depend on the gate package.
func sevLabel(level string) (string, int) {
	switch level {
	case sarif.LevelError:
		return "HIGH", 3
	case sarif.LevelWarning:
		return "MEDIUM", 2
	case sarif.LevelNote:
		return "LOW", 1
	default:
		return "-", 0
	}
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
		for _, res := range run.Results {
			sev, rank := sevLabel(res.Level)
			f := finding{tool: run.Tool.Driver.Name, sev: sev, rule: res.RuleID, msg: msg(res), loc: loc(res)}
			if blocking && rank >= floor {
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
