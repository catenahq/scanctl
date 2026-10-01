package runner

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/catenahq/scanctl/internal/detect"
)

// The allowlist regex as the bundled config writes it.
func versionTagAllowlist(t *testing.T) *regexp.Regexp {
	t.Helper()
	s := string(gitleaksConfig)
	start := strings.Index(s, "regexes = ['''")
	if start < 0 {
		t.Fatal("bundled gitleaks config has no allowlist regex")
	}
	rest := s[start+len("regexes = ['''"):]
	return regexp.MustCompile(rest[:strings.Index(rest, "'''")])
}

// generic-api-key reads an image tag after "oauth2-proxy" as a secret. A tag
// is allowed; anything shaped like a credential still is not.
func TestGitleaksAllowsVersionTagsOnly(t *testing.T) {
	rx := versionTagAllowlist(t)
	for _, tag := range []string{"v7.15.4-alpine", "v7.14.3-alpine", "26.6.7", "4.18.0-alpine", "2026.9.1", "v3.7.13"} {
		if !rx.MatchString(tag) {
			t.Errorf("version tag %q is not allowed", tag)
		}
	}
	for _, secret := range []string{"3f9a7c1e0b2d4f6a8c0e", "Zm9vYmFyYmF6", "1a2b3c4d-5e6f", "v1"} {
		if rx.MatchString(secret) {
			t.Errorf("credential-shaped %q is allowed", secret)
		}
	}
	if !strings.Contains(string(gitleaksConfig), "useDefault = true") {
		t.Error("the bundled config must extend gitleaks' default rules")
	}
}

func TestGitleaksRunsWithTheBundledConfig(t *testing.T) {
	t.Setenv("SCANCTL_CACHE", t.TempDir())
	var gl toolDef
	for _, td := range registry {
		if td.name == "gitleaks" {
			gl = td
		}
	}
	args := gl.invoke("gitleaks", t.TempDir(), "out.sarif", detect.Result{}).args
	var cfg string
	for i, a := range args {
		if a == "--config" && i+1 < len(args) {
			cfg = args[i+1]
		}
	}
	got, err := os.ReadFile(cfg) // #nosec G304 -- path is under our temp cache
	if err != nil || string(got) != string(gitleaksConfig) {
		t.Errorf("--config %q does not hold the bundled config (err %v)", cfg, err)
	}
}

// A repo that carries its own .gitleaks.toml keeps it.
func TestGitleaksPrefersTheRepoConfig(t *testing.T) {
	root := t.TempDir()
	own := filepath.Join(root, ".gitleaks.toml")
	if err := os.WriteFile(own, []byte("[extend]\nuseDefault = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := gitleaksConfigPath(root); got != own {
		t.Errorf("config = %q, want the repo's %q", got, own)
	}
}
