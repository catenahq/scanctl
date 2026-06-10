// Package sarif holds the minimal subset of the SARIF 2.1.0 schema that
// scanctl needs to parse per-tool reports and emit one merged report.
// Tools that emit SARIF natively (trivy, gosec, gitleaks, osv-scanner) are
// read straight into Report; the short tail that does not gets converted into
// these types by a small adapter in the runner.
package sarif

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

// Rule is a finding category.
type Rule struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// Result is a single finding.
type Result struct {
	RuleID    string     `json:"ruleId,omitempty"`
	Level     string     `json:"level,omitempty"`
	Message   Message    `json:"message"`
	Locations []Location `json:"locations,omitempty"`
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

// Merge folds every run of src into dst, preserving per-tool runs so the
// producing scanner stays identifiable in the merged output.
func (dst *Report) Merge(src *Report) {
	if src == nil {
		return
	}
	dst.Runs = append(dst.Runs, src.Runs...)
}

// ResultCount totals findings across all runs.
func (r *Report) ResultCount() int {
	n := 0
	for _, run := range r.Runs {
		n += len(run.Results)
	}
	return n
}
