// Package detect is the v1 router: it walks the repo for manifest/lockfile
// markers and reports which ecosystems are present, so the runner only invokes
// the scanners that apply. This is deliberately a simple filename match; the
// go-enry content census (vendored/generated filtering, language proportions)
// is a later phase.
package detect

import (
	"io/fs"
	"path/filepath"
	"strings"
)

// Ecosystem is a detected language/format family.
type Ecosystem string

const (
	Go        Ecosystem = "go"
	Node      Ecosystem = "node"
	Python    Ecosystem = "python"
	Terraform Ecosystem = "terraform"
	Docker    Ecosystem = "docker"
)

// Result is the set of detected ecosystems plus whether any dependency
// lockfile/manifest exists at all (the trigger for SCA tools).
type Result struct {
	Ecosystems map[Ecosystem]bool
	HasLockfile bool
}

// Has reports whether ecosystem e was detected.
func (r Result) Has(e Ecosystem) bool { return r.Ecosystems[e] }

// manifestMarkers maps an exact filename to the ecosystem it implies.
var manifestMarkers = map[string]Ecosystem{
	"go.mod":           Go,
	"package.json":     Node,
	"requirements.txt": Python,
	"pyproject.toml":   Python,
	"setup.py":         Python,
	"Pipfile":          Python,
	"Dockerfile":       Docker,
}

// suffixMarkers maps a filename suffix to the ecosystem it implies.
var suffixMarkers = map[string]Ecosystem{
	".tf":         Terraform,
	".dockerfile": Docker,
}

// lockfiles indicate a resolved dependency tree worth SCA scanning.
var lockfiles = map[string]bool{
	"go.sum":            true,
	"package-lock.json": true,
	"yarn.lock":         true,
	"pnpm-lock.yaml":    true,
	"poetry.lock":       true,
	"Pipfile.lock":      true,
	"requirements.txt":  true,
	"Gemfile.lock":      true,
	"Cargo.lock":        true,
}

// Detect walks root, honoring ignore (path segments matched anywhere in the
// relative path), and returns the detected ecosystems.
func Detect(root string, ignore []string) (Result, error) {
	res := Result{Ecosystems: map[Ecosystem]bool{}}
	ignoreSet := make(map[string]bool, len(ignore))
	for _, ig := range ignore {
		ignoreSet[ig] = true
	}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		if d.IsDir() {
			if rel != "." && ignoreSet[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		if e, ok := manifestMarkers[name]; ok {
			res.Ecosystems[e] = true
		}
		lower := strings.ToLower(name)
		for suf, e := range suffixMarkers {
			if strings.HasSuffix(lower, suf) {
				res.Ecosystems[e] = true
			}
		}
		if lockfiles[name] {
			res.HasLockfile = true
		}
		return nil
	})
	if err != nil {
		return res, err
	}
	return res, nil
}

// DetectFS is the io/fs-backed variant used by tests; behaviour matches Detect.
func DetectFS(fsys fs.FS, ignore []string) (Result, error) {
	res := Result{Ecosystems: map[Ecosystem]bool{}}
	ignoreSet := make(map[string]bool, len(ignore))
	for _, ig := range ignore {
		ignoreSet[ig] = true
	}
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != "." && ignoreSet[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		if e, ok := manifestMarkers[name]; ok {
			res.Ecosystems[e] = true
		}
		lower := strings.ToLower(name)
		for suf, e := range suffixMarkers {
			if strings.HasSuffix(lower, suf) {
				res.Ecosystems[e] = true
			}
		}
		if lockfiles[name] {
			res.HasLockfile = true
		}
		return nil
	})
	return res, err
}
