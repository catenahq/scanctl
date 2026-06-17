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
		if !profileAllows(td, cfg.Profile) {
			out.Skipped[td.name] = "requires the full profile"
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
		rep, warn := runTool(ctx, td, bin, root, det, cfg.Ignore)
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

	// Steps whose shape the detect-driven registry does not fit (per-manifest,
	// per-image) run after the loop and merge into the same report. Like
	// runTool, a failure is a warning, never fatal (robustness over strictness).
	guarddogStep(ctx, cfg, lock, root, out)
	licenseStep(ctx, cfg, lock, root, out)
	imageStep(ctx, cfg, lock, out)

	return out, nil
}

// runTool executes one scanner and parses its SARIF. A non-zero exit is NOT an
// error by itself -- scanners signal "findings present" that way. The outcomes:
//   - parseable report          -> findings (or zero) from the tool
//   - no report, clean exit      -> tool ran and found nothing (some tools, e.g.
//     gosec, write no file when clean): an empty report, no warning
//   - no report, non-zero exit   -> a genuine failure: nil + a warning
func runTool(ctx context.Context, td toolDef, bin, root string, det detect.Result, ignore []string) (*sarif.Report, string) {
	outFile, err := os.CreateTemp("", "scanctl-"+td.name+"-*.sarif")
	if err != nil {
		return nil, fmt.Sprintf("%s: temp file: %v", td.name, err)
	}
	outPath := outFile.Name()
	_ = outFile.Close()
	defer os.Remove(outPath)

	inv := td.invoke(bin, root, outPath, det)
	inv.args = withSkips(td.name, inv.args, ignore)
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

	if rep := parseOutput(td, outPath); rep != nil {
		return rep, ""
	}
	if runErr == nil {
		return emptyReport(td.name), "" // ran clean, no findings, no file written
	}
	return nil, fmt.Sprintf("%s: no SARIF produced: %v\n%s", td.name, runErr, diag)
}

// withSkips threads the configured ignore globs into the tools that walk the
// whole tree and accept a directory-exclusion flag, so vendored / dependency
// trees (node_modules, .venv, vendored ansible collections, ...) stop
// producing findings against upstream files the repo does not own. Detection
// already honors `ignore`, but trivy's misconfig/secret pass, gosec, and
// semgrep traverse the filesystem independently and would otherwise flag a
// Dockerfile shipped inside node_modules or a test .go file inside a vendored
// collection. Tools without a dir-exclude flag (osv-scanner reads lockfiles,
// govulncheck reasons over Go packages, zizmor audits a single workflow dir,
// gitleaks is config-driven) are passed through unchanged.
//
// Each skip is inserted immediately before the final positional argument (the
// scan target / `./...`), which is the correct slot for all three tools.
func withSkips(name string, args, ignore []string) []string {
	if len(ignore) == 0 || len(args) == 0 {
		return args
	}
	var skip []string
	switch name {
	case "trivy":
		for _, d := range ignore {
			skip = append(skip, "--skip-dirs", "**/"+d)
		}
	case "gosec":
		for _, d := range ignore {
			skip = append(skip, "-exclude-dir", d)
		}
	case "semgrep":
		for _, d := range ignore {
			skip = append(skip, "--exclude", d)
		}
	default:
		return args
	}
	n := len(args)
	out := make([]string, 0, n+len(skip))
	out = append(out, args[:n-1]...)
	out = append(out, skip...)
	out = append(out, args[n-1])
	return out
}

// mergeSARIFRun executes cmd for a non-registry step, reads SARIF from outPath
// (or from stdout when stdoutToOut), tags it driver=driver, and merges it into
// out.Report. A failure is recorded as a warning, never fatal (same robustness
// contract as runTool). It returns whether a report merged, so the caller can
// record the step in out.Ran exactly once. driver controls gate mapping: image
// findings are tagged "trivy" so they inherit trivy's block/report mode.
func mergeSARIFRun(driver string, cmd *exec.Cmd, outPath string, stdoutToOut bool, out *Outcome) bool {
	var runErr error
	var diag string
	if stdoutToOut {
		f, err := os.Create(outPath) // #nosec G304 -- outPath is our own CreateTemp file
		if err != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf("%s: %v", driver, err))
			return false
		}
		cmd.Stdout = f
		diag, runErr = captureStderr(cmd)
		_ = f.Close()
	} else {
		var combined []byte
		combined, runErr = cmd.CombinedOutput()
		diag = string(combined)
	}
	rep := parseIfPresent(outPath)
	if rep == nil {
		if runErr != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf("%s: no SARIF produced: %v\n%s", driver, runErr, diag))
		}
		return false
	}
	tagDriver(rep, driver)
	out.Report.Merge(rep)
	return true
}

// trivyEnsure returns the pinned trivy binary, reusing the registry entry's
// fetch closure so the fs scan and image scan share one download.
func trivyEnsure(ctx context.Context, version string) (string, error) {
	for _, td := range registry {
		if td.name == "trivy" {
			return td.ensure(ctx, version)
		}
	}
	return "", fmt.Errorf("trivy not in registry")
}

// parseOutput turns a tool's output file into SARIF: directly for SARIF-native
// tools, or through the tool's convert adapter for JSON-only tools. Returns nil
// when the file is absent/empty/unparseable (treated as "no findings").
func parseOutput(td toolDef, outPath string) *sarif.Report {
	if td.convert == nil {
		return parseIfPresent(outPath)
	}
	data, err := os.ReadFile(outPath) // #nosec G304 -- outPath is our own CreateTemp file
	if err != nil || len(data) == 0 {
		return nil
	}
	rep, err := td.convert(data)
	if err != nil {
		return nil
	}
	return rep
}

// emptyReport is a zero-finding report carrying the tool's identity, so a clean
// tool still shows up as having run.
func emptyReport(name string) *sarif.Report {
	return &sarif.Report{Runs: []sarif.Run{{
		Tool:    sarif.Tool{Driver: sarif.Driver{Name: name}},
		Results: []sarif.Result{}, // must be [] not null to be valid SARIF
	}}}
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
