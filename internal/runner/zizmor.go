package runner

import (
	_ "embed"
	"os"
	"path/filepath"
)

// zizmorPolicy is the bundled zizmor config. It travels with the binary so the
// unpinned-uses policy is centralized in scanctl (no per-repo .github/zizmor.yml
// to keep in sync); see zizmor-policy.yml.
//
//go:embed zizmor-policy.yml
var zizmorPolicy []byte

// zizmorConfigPath writes the bundled policy to a stable cache path and returns
// it for zizmor's --config. Written idempotently on every run (the content is
// fixed), so a stale cache self-heals. Returns an error if the cache dir is not
// writable; the caller then runs zizmor without --config (degrades to zizmor's
// own defaults rather than failing the scan).
func zizmorConfigPath() (string, error) {
	dir := filepath.Join(cacheRoot(), "zizmor")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	p := filepath.Join(dir, "policy.yml")
	if err := os.WriteFile(p, zizmorPolicy, 0o600); err != nil {
		return "", err
	}
	return p, nil
}
