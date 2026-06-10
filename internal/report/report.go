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

// Summary renders a markdown overview: total findings, a per-tool/per-level
// breakdown, and a capped list of the most severe findings.
func Summary(rep *sarif.Report) string {
	var b strings.Builder
	total := rep.ResultCount()
	fmt.Fprintf(&b, "## scanctl: %d finding(s)\n\n", total)
	if total == 0 {
		b.WriteString("No findings.\n")
		return b.String()
	}

	type row struct {
		tool             string
		errs, warns, oth int
	}
	rows := make([]row, 0, len(rep.Runs))
	for _, run := range rep.Runs {
		r := row{tool: run.Tool.Driver.Name}
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

	b.WriteString("| tool | error | warning | other |\n|---|---|---|---|\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %d | %d | %d |\n", r.tool, r.errs, r.warns, r.oth)
	}

	b.WriteString("\n### Top findings\n\n")
	const cap = 25
	shown := 0
	for _, run := range rep.Runs {
		for _, res := range run.Results {
			if res.Level != sarif.LevelError {
				continue
			}
			fmt.Fprintf(&b, "- [%s] %s %s%s\n", run.Tool.Driver.Name, res.RuleID, msg(res), loc(res))
			if shown++; shown >= cap {
				fmt.Fprintf(&b, "- ... (%d more)\n", total-shown)
				return b.String()
			}
		}
	}
	return b.String()
}

func msg(res sarif.Result) string {
	t := strings.TrimSpace(res.Message.Text)
	if len(t) > 140 {
		t = t[:137] + "..."
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
