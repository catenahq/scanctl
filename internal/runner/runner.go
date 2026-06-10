// Package runner is the orchestrator: it detects the repo's ecosystems, fetches
// the matched scanners (lazy, pinned), runs each as a subprocess, and merges
// their SARIF into one report. Subprocess isolation is deliberate -- it keeps
// LGPL/copyleft tools at arm's length and leaves scanctl's own code unbound.
package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/catenahq/scanctl/internal/config"
	"github.com/catenahq/scanctl/internal/detect"
	"github.com/catenahq/scanctl/internal/sarif"
)

// Outcome is the result of a full run.
type Outcome struct {
	Report   *sarif.Report
	Ran      []string
	Skipped  map[string]string // tool -> reason
	Warnings []string
}

// Run detects, fetches, and executes the enabled+applicable tools, returning a
// merged report. A single tool failing is a warning, not a fatal error: a
// partial scan is more useful than none (robustness over strictness).
func Run(ctx context.Context, root string, cfg config.Config, lock Lock) (*Outcome, error) {
	det, err := detect.Detect(root, cfg.Ignore)
	if err != nil {
		return nil, fmt.Errorf("detect: %w", err)
	}
	out := &Outcome{Report: sarif.New(), Skipped: map[string]string{}}

	for _, td := range registry {
		tc, configured := cfg.Tools[td.name]
		if !configured || !tc.Enabled {
			out.Skipped[td.name] = "disabled"
			continue
		}
		if !td.applies(det) {
			out.Skipped[td.name] = "not applicable to this repo"
			continue
		}
		version, err := lock.Version(td.name)
		if err != nil {
			out.Warnings = append(out.Warnings, err.Error())
			out.Skipped[td.name] = "unpinned"
			continue
		}
		bin, err := td.ensure(ctx, version)
		if err != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf("%s: fetch failed: %v", td.name, err))
			out.Skipped[td.name] = "fetch failed"
			continue
		}
		rep, warn := runTool(ctx, td, bin, root)
		if warn != "" {
			out.Warnings = append(out.Warnings, warn)
		}
		if rep == nil {
			out.Skipped[td.name] = "no output"
			continue
		}
		tagDriver(rep, td.name)
		out.Report.Merge(rep)
		out.Ran = append(out.Ran, td.name)
	}
	return out, nil
}

// runTool executes one scanner and parses its SARIF. A non-zero exit is NOT an
// error by itself -- scanners signal "findings present" that way. The outcomes:
//   - parseable report          -> findings (or zero) from the tool
//   - no report, clean exit      -> tool ran and found nothing (some tools, e.g.
//     gosec, write no file when clean): an empty report, no warning
//   - no report, non-zero exit   -> a genuine failure: nil + a warning
func runTool(ctx context.Context, td toolDef, bin, root string) (*sarif.Report, string) {
	outFile, err := os.CreateTemp("", "scanctl-"+td.name+"-*.sarif")
	if err != nil {
		return nil, fmt.Sprintf("%s: temp file: %v", td.name, err)
	}
	outPath := outFile.Name()
	_ = outFile.Close()
	defer os.Remove(outPath)

	inv := td.invoke(bin, root, outPath)
	// #nosec G204 -- bin and args come from the internal tool registry + pinned
	// tools.lock, never from the scanned repo or user input
	cmd := exec.CommandContext(ctx, bin, inv.args...)
	cmd.Dir = inv.workdir

	var diag string
	var runErr error
	if inv.stdoutToOut {
		f, err := os.Create(outPath) // #nosec G304 -- outPath is our own CreateTemp file
		if err != nil {
			return nil, fmt.Sprintf("%s: %v", td.name, err)
		}
		cmd.Stdout = f
		diag, runErr = captureStderr(cmd)
		_ = f.Close()
	} else {
		var combined []byte
		combined, runErr = cmd.CombinedOutput()
		diag = string(combined)
	}

	if rep := parseIfPresent(outPath); rep != nil {
		return rep, ""
	}
	if runErr == nil {
		return emptyReport(td.name), "" // ran clean, no findings, no file written
	}
	return nil, fmt.Sprintf("%s: no SARIF produced: %v\n%s", td.name, runErr, diag)
}

// emptyReport is a zero-finding report carrying the tool's identity, so a clean
// tool still shows up as having run.
func emptyReport(name string) *sarif.Report {
	return &sarif.Report{Runs: []sarif.Run{{Tool: sarif.Tool{Driver: sarif.Driver{Name: name}}}}}
}

// captureStderr runs cmd (whose Stdout is already wired) capturing stderr.
func captureStderr(cmd *exec.Cmd) (string, error) {
	var buf stderrBuf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// parseIfPresent reads outPath and parses SARIF, returning nil when the file is
// absent, empty, or unparseable (treated as "no findings" by the caller).
func parseIfPresent(outPath string) *sarif.Report {
	data, err := os.ReadFile(outPath) // #nosec G304 -- outPath is our own CreateTemp file

	if err != nil || len(data) == 0 {
		return nil
	}
	var rep sarif.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil
	}
	return &rep
}

// tagDriver normalizes every run's tool name to the canonical id so the gate
// and any P2 upload can map findings back to their config entry.
func tagDriver(rep *sarif.Report, name string) {
	for i := range rep.Runs {
		rep.Runs[i].Tool.Driver.Name = name
	}
}

// stderrBuf is a tiny bounded-growth buffer for stderr capture.
type stderrBuf struct{ b []byte }

func (s *stderrBuf) Write(p []byte) (int, error) {
	s.b = append(s.b, p...)
	return len(p), nil
}
func (s *stderrBuf) String() string { return string(s.b) }
