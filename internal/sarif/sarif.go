// Package sarif holds the minimal subset of the SARIF 2.1.0 schema that
// scanctl needs to parse per-tool reports and emit one merged report.
// Tools that emit SARIF natively (trivy, gosec, gitleaks, osv-scanner) are
// read straight into Report; the short tail that does not gets converted into
// these types by a small adapter in the runner.
package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	version = "2.1.0"
	schema  = "https://json.schemastore.org/sarif-2.1.0.json"
)

// Report is a full SARIF document.
type Report struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run is one tool's worth of results.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool names the producing scanner.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver carries the tool name (and, when known, the rules).
type Driver struct {
	Name           string `json:"name"`
	InformationURI string `json:"informationUri,omitempty"`
	Rules          []Rule `json:"rules,omitempty"`
}

// Rule is a finding category. Properties carries SARIF rule metadata, notably
// "security-severity" (a CVSS-style 0-10 score) which the gate prefers over the
// coarse result level. It MUST round-trip the merge so that score reaches the
// gate and downstream consumers (GitHub, DefectDojo).
type Rule struct {
	ID         string         `json:"id"`
	Name       string         `json:"name,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// RulesByID indexes this run's rule metadata by rule id (empty when the tool
// emits no rule catalog).
func (r Run) RulesByID() map[string]Rule {
	m := make(map[string]Rule, len(r.Tool.Driver.Rules))
	for _, rule := range r.Tool.Driver.Rules {
		m[rule.ID] = rule
	}
	return m
}

// SecuritySeverity reads the SARIF "security-severity" CVSS score (0-10) from a
// properties bag. GitHub and trivy/codeql/gosec encode it as a string; some
// tools use a number. ok is false when the field is absent or unparseable.
func SecuritySeverity(props map[string]any) (float64, bool) {
	v, ok := props["security-severity"]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(n), 64)
		if err != nil {
			return 0, false
		}
		return f, true
	case float64:
		return n, true
	default:
		return 0, false
	}
}

// Result is a single finding.
type Result struct {
	RuleID    string     `json:"ruleId,omitempty"`
	Level     string     `json:"level,omitempty"`
	Message   Message    `json:"message"`
	Locations []Location `json:"locations,omitempty"`
	// Suppressions carries a tool's in-source suppressions (e.g. a semgrep
	// `nosemgrep` comment). It MUST round-trip through the merge: GitHub code
	// scanning reads it to create the alert in the dismissed state, and the
	// gate ignores suppressed findings. Dropping it (the pre-fix behavior)
	// resurfaced every nosemgrep'd finding as an open alert.
	Suppressions []Suppression `json:"suppressions,omitempty"`
	// Properties may carry a per-result "security-severity" score (some tools
	// put it here instead of on the rule) and other metadata. Preserved.
	Properties map[string]any `json:"properties,omitempty"`
	// PartialFingerprints is the SARIF dedup key. Preserved so baseline diff
	// and downstream consumers can match a finding across runs.
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

// Suppression marks a result the producing tool suppressed. Kind is "inSource"
// (e.g. nosemgrep) or "external" (e.g. matched a scanctl baseline).
type Suppression struct {
	Kind string `json:"kind,omitempty"`
}

// Suppressed reports whether this result is suppressed (in source or by a
// baseline match). Suppressed findings are preserved in the output but never
// gate the build.
func (r Result) Suppressed() bool { return len(r.Suppressions) > 0 }

// Fingerprint returns a stable identifier for a finding, used by baseline diff.
// It prefers the SARIF partialFingerprints primary-location hash and otherwise
// synthesizes one from tool + rule + primary location + message. The same
// function is applied to baseline and current findings, so the two shapes never
// need to agree -- only be self-consistent.
func Fingerprint(tool string, r Result) string {
	if h := r.PartialFingerprints["primaryLocationLineHash"]; h != "" {
		return tool + ":" + r.RuleID + ":" + h
	}
	sum := sha256.Sum256([]byte(tool + "\x00" + r.RuleID + "\x00" + r.primaryLoc() + "\x00" + r.Message.Text))
	return hex.EncodeToString(sum[:])
}

// primaryLoc renders the first physical location as "uri:line" (or "" when the
// result has none), for fingerprint synthesis.
func (r Result) primaryLoc() string {
	if len(r.Locations) == 0 {
		return ""
	}
	pl := r.Locations[0].PhysicalLocation
	if pl.ArtifactLocation.URI == "" {
		return ""
	}
	if pl.Region != nil && pl.Region.StartLine > 0 {
		return fmt.Sprintf("%s:%d", pl.ArtifactLocation.URI, pl.Region.StartLine)
	}
	return pl.ArtifactLocation.URI
}

// Message is the human-readable finding text.
type Message struct {
	Text string `json:"text"`
}

// Location points at the offending file/line.
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation is the file + region of a finding.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

// ArtifactLocation is the file path of a finding.
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// Region is the line span of a finding.
type Region struct {
	StartLine int `json:"startLine,omitempty"`
}

// SARIF levels, highest-severity first. Order matters for gate comparisons.
const (
	LevelError   = "error"
	LevelWarning = "warning"
	LevelNote    = "note"
	LevelNone    = "none"
)

// New returns an empty, well-formed report.
func New() *Report {
	return &Report{Schema: schema, Version: version, Runs: []Run{}}
}

// Load reads a SARIF document from path. Used to fold externally-produced SARIF
// (e.g. CodeQL) into the merge and to read a baseline.
func Load(path string) (*Report, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-provided SARIF path
	if err != nil {
		return nil, err
	}
	var rep Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("sarif: parse %s: %w", path, err)
	}
	return &rep, nil
}

// Merge folds every run of src into dst, preserving per-tool runs so the
// producing scanner stays identifiable in the merged output.
func (dst *Report) Merge(src *Report) {
	if src == nil {
		return
	}
	dst.Runs = append(dst.Runs, src.Runs...)
}

// Normalize guarantees the document validates against the SARIF schema before
// marshaling: every run's Results must be an array, never null. A tool or
// converter that leaves Results nil would otherwise emit "results": null, which
// downstream consumers (GitHub code scanning, DefectDojo) reject.
func (r *Report) Normalize() {
	if r.Runs == nil {
		r.Runs = []Run{}
	}
	for i := range r.Runs {
		if r.Runs[i].Results == nil {
			r.Runs[i].Results = []Result{}
		}
	}
}

// ResultCount totals findings across all runs.
func (r *Report) ResultCount() int {
	n := 0
	for _, run := range r.Runs {
		n += len(run.Results)
	}
	return n
}
