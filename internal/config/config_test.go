package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultEnablesCoreTools(t *testing.T) {
	d := Default()
	for _, name := range []string{"osv-scanner", "trivy", "gitleaks", "gosec", "govulncheck"} {
		tc, ok := d.Tools[name]
		if !ok || !tc.Enabled {
			t.Errorf("default should enable %s", name)
		}
	}
	if d.Profile != "sellable" {
		t.Errorf("default profile = %q, want sellable", d.Profile)
	}
	if d.Gate.Floor != SevHigh {
		t.Errorf("default floor = %q, want high", d.Gate.Floor)
	}
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yml"))
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if cfg.Profile != "sellable" {
		t.Errorf("expected defaults, got profile %q", cfg.Profile)
	}
}

func TestLoadOverlaysFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scanctl.yml")
	yml := `
gate:
  floor: critical
tools:
  gitleaks:
    enabled: true
    mode: block
`
	if err := os.WriteFile(path, []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Gate.Floor != SevCritical {
		t.Errorf("floor = %q, want critical", cfg.Gate.Floor)
	}
	if cfg.Tools["gitleaks"].Mode != ModeBlock {
		t.Errorf("gitleaks mode = %q, want block", cfg.Tools["gitleaks"].Mode)
	}
	// Untouched defaults survive the overlay.
	if !cfg.Tools["trivy"].Enabled {
		t.Errorf("trivy should remain enabled after overlay")
	}
}

func TestSeverityRankOrder(t *testing.T) {
	if !(SevCritical.Rank() > SevHigh.Rank() &&
		SevHigh.Rank() > SevMedium.Rank() &&
		SevMedium.Rank() > SevLow.Rank() &&
		SevLow.Rank() > SevNone.Rank()) {
		t.Error("severity ranks are not strictly ordered")
	}
}
