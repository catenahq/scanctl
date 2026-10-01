package runner

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

// gitleaksIgnoreConfig writes a config that extends base and allowlists every
// path under a directory named in ignore, and returns its path; "" when it
// cannot be written. Extending rather than appending keeps a repo's own config
// intact: gitleaks refuses a file that mixes the old [allowlist] table with
// [[allowlists]]. The file is named for its content, so two repos sharing a
// cache never overwrite each other's.
func gitleaksIgnoreConfig(base string, ignore []string) string {
	base, err := filepath.Abs(base)
	if err != nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[extend]\npath = %q\n\n[[allowlists]]\ndescription = \"scanctl ignore\"\npaths = [\n", base)
	for _, d := range ignore {
		fmt.Fprintf(&b, "  '''(^|/)%s(/|$)''',\n", regexp.QuoteMeta(d))
	}
	b.WriteString("]\n")
	sum := sha256.Sum256([]byte(b.String()))
	dir := filepath.Join(cacheRoot(), "gitleaks")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return ""
	}
	p := filepath.Join(dir, "ignore-"+hex.EncodeToString(sum[:8])+".toml")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		return ""
	}
	return p
}
