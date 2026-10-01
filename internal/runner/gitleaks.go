package runner

import (
	_ "embed"
	"os"
	"path/filepath"
)

// gitleaksConfig is the bundled gitleaks config: gitleaks' default rules plus
// the allowlist every scanned repo needs; see gitleaks.toml.
//
//go:embed gitleaks.toml
var gitleaksConfig []byte

// gitleaksConfigPath returns the config gitleaks runs with: the repo's own
// .gitleaks.toml when it has one, else the bundled config written to a stable
// cache path. "" when neither is available; gitleaks then runs on its
// defaults.
func gitleaksConfigPath(root string) string {
	own := filepath.Join(root, ".gitleaks.toml")
	if st, err := os.Stat(own); err == nil && !st.IsDir() {
		return own
	}
	dir := filepath.Join(cacheRoot(), "gitleaks")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return ""
	}
	p := filepath.Join(dir, "gitleaks.toml")
	if err := os.WriteFile(p, gitleaksConfig, 0o600); err != nil {
		return ""
	}
	return p
}
