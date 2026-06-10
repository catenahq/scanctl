package runner

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Lock is the parsed tools.lock: canonical tool name -> pinned metadata.
type Lock struct {
	Tools map[string]LockEntry `yaml:"tools"`
}

// LockEntry is one tool's pin. Repo (GitHub releases) and Module (Go) are
// mutually exclusive; Version is always set.
type LockEntry struct {
	Repo    string `yaml:"repo"`
	Module  string `yaml:"module"`
	Version string `yaml:"version"`
}

// LoadLock reads tools.lock at path.
func LoadLock(path string) (Lock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Lock{}, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseLock(data)
}

// ParseLock parses tools.lock bytes (used with the binary's embedded copy).
func ParseLock(data []byte) (Lock, error) {
	var lock Lock
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return lock, fmt.Errorf("parse tools.lock: %w", err)
	}
	if len(lock.Tools) == 0 {
		return lock, fmt.Errorf("tools.lock: no tools pinned")
	}
	return lock, nil
}

// Version returns the pinned version for a tool, or an error if unpinned.
func (l Lock) Version(tool string) (string, error) {
	e, ok := l.Tools[tool]
	if !ok || e.Version == "" {
		return "", fmt.Errorf("tool %q not pinned in tools.lock", tool)
	}
	return e.Version, nil
}
