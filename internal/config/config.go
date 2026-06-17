// Package config loads scanctl.yml: which tools are enabled, whether each one
// blocks or only reports, the global gate severity floor, and ignore globs.
// When no file is present the built-in defaults apply, so `scanctl run .` works
// with zero configuration.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Mode controls whether a tool's findings affect the exit code.
type Mode string

const (
	// ModeBlock: findings at/above the gate floor fail the run.
	ModeBlock Mode = "block"
	// ModeReport: findings surface in the report but never fail the run.
	ModeReport Mode = "report"
)

// Severity is the gate floor, ordered low to high by Rank.
type Severity string

const (
	SevNone     Severity = "none"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// Rank maps a severity to a comparable integer (higher = more severe).
func (s Severity) Rank() int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	default:
		return 0
	}
}

// ToolConfig is the per-tool knob set.
type ToolConfig struct {
	Enabled bool `yaml:"enabled"`
	Mode    Mode `yaml:"mode"`
}

// Config is the whole scanctl.yml.
type Config struct {
	// Profile is "sellable" (default) or "full". It gates profile-restricted
	// tools (e.g. Semgrep registry rules / deps.dev are full-only). See Profile*.
	Profile string `yaml:"profile"`
	// Gate.Floor: a blocking tool fails the run on a finding at/above this.
	Gate GateConfig `yaml:"gate"`
	// Tools keyed by canonical tool name (osv-scanner, trivy, gitleaks, ...).
	Tools map[string]ToolConfig `yaml:"tools"`
	// Ignore globs, applied during detection and passed to tools that accept them.
	Ignore []string `yaml:"ignore"`
	// Images are container refs to scan with trivy image (in addition to the fs
	// scan). Empty = no image scan; only repos that ship images set this.
	Images []string `yaml:"images"`
	// Upload targets the aggregation plane (P2/P3); empty = serverless (v1).
	Upload UploadConfig `yaml:"upload"`
}

// Profile values.
const (
	ProfileSellable = "sellable"
	ProfileFull     = "full"
)

// GateConfig holds the global severity floor.
type GateConfig struct {
	Floor Severity `yaml:"floor"`
}

// UploadConfig points scanctl at the aggregation plane. A target is active only
// when its URL is set AND its credential env var is present; otherwise it is
// skipped with a warning (robustness: a misconfigured dashboard never fails the
// scan itself).
type UploadConfig struct {
	DefectDojo      DefectDojoConfig      `yaml:"defectdojo"`
	DependencyTrack DependencyTrackConfig `yaml:"dependency_track"`
}

// DefectDojoConfig: findings dashboard. Token from env DEFECTDOJO_TOKEN.
type DefectDojoConfig struct {
	URL            string `yaml:"url"`
	ProductName    string `yaml:"product_name"`
	EngagementName string `yaml:"engagement_name"`
}

// DependencyTrackConfig: SBOM portfolio. API key from env DEPENDENCYTRACK_APIKEY.
type DependencyTrackConfig struct {
	URL            string `yaml:"url"`
	ProjectName    string `yaml:"project_name"`
	ProjectVersion string `yaml:"project_version"`
}

// Default returns the zero-config baseline: sellable profile, high floor, the
// v1 core scanners enabled with the same block/report split catena-ce uses
// today (osv/trivy/govulncheck block; gitleaks/gosec report until baselined).
// zizmor blocks: a workflow-supply-chain finding is a security issue, not
// advisory. Its only baseline false-positive -- unpinned first-party @main
// reusable-workflow refs -- is exempted by the bundled zizmor policy
// (catenahq/* may ref-pin; third-party must hash-pin; see runner/zizmor.go).
// semgrep and guarddog stay report-mode like gosec/gitleaks until baselined.
// semgrep is fullOnly, so it only actually runs under the "full" profile
// (catena's internal scanctl.yml sets that).
func Default() Config {
	return Config{
		Profile: ProfileSellable,
		Gate:    GateConfig{Floor: SevHigh},
		Tools: map[string]ToolConfig{
			"osv-scanner":   {Enabled: true, Mode: ModeBlock},
			"trivy":         {Enabled: true, Mode: ModeBlock},
			"govulncheck":   {Enabled: true, Mode: ModeBlock},
			"gosec":         {Enabled: true, Mode: ModeReport},
			"gitleaks":      {Enabled: true, Mode: ModeReport},
			"semgrep":       {Enabled: true, Mode: ModeReport},
			"zizmor":        {Enabled: true, Mode: ModeBlock},
			"guarddog":      {Enabled: true, Mode: ModeReport},
			"trivy-license": {Enabled: true, Mode: ModeReport},
		},
		Ignore: []string{".git", "vendor", "node_modules", "testdata", ".venv"},
	}
}

// Load reads scanctl.yml at path, layering it over Default. A missing file is
// not an error: defaults are returned. Unknown tools in the file are kept (the
// runner ignores ones it has no definition for).
func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path) // #nosec G304 -- path is the operator-provided scanctl.yml

	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("read %s: %w", path, err)
	}
	var fromFile Config
	if err := yaml.Unmarshal(data, &fromFile); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}
	if fromFile.Profile != "" {
		cfg.Profile = fromFile.Profile
	}
	if fromFile.Gate.Floor != "" {
		cfg.Gate.Floor = fromFile.Gate.Floor
	}
	for name, tc := range fromFile.Tools {
		cfg.Tools[name] = tc
	}
	if fromFile.Ignore != nil {
		cfg.Ignore = fromFile.Ignore
	}
	if fromFile.Images != nil {
		cfg.Images = fromFile.Images
	}
	cfg.Upload = fromFile.Upload
	switch cfg.Profile {
	case ProfileSellable, ProfileFull:
	default:
		return cfg, fmt.Errorf("invalid profile %q (want %q or %q)", cfg.Profile, ProfileSellable, ProfileFull)
	}
	return cfg, nil
}
