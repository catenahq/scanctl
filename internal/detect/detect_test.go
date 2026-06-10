package detect

import (
	"testing"
	"testing/fstest"
)

func TestDetectEcosystems(t *testing.T) {
	fsys := fstest.MapFS{
		"go.mod":                {Data: []byte("module x")},
		"go.sum":                {Data: []byte("")},
		"web/package.json":      {Data: []byte("{}")},
		"api/requirements.txt":  {Data: []byte("")},
		"infra/main.tf":         {Data: []byte("")},
		"Dockerfile":            {Data: []byte("FROM scratch")},
		"vendor/dep/go.mod":     {Data: []byte("module y")}, // ignored dir
		"node_modules/x/pkg.go": {Data: []byte("package x")},
	}
	res, err := DetectFS(fsys, []string{"vendor", "node_modules"})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []Ecosystem{Go, Node, Python, Terraform, Docker} {
		if !res.Has(e) {
			t.Errorf("expected ecosystem %q detected", e)
		}
	}
	if !res.HasLockfile {
		t.Error("expected HasLockfile true (go.sum, requirements.txt)")
	}
}

func TestDetectEmptyRepo(t *testing.T) {
	res, err := DetectFS(fstest.MapFS{"README.md": {Data: []byte("hi")}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Ecosystems) != 0 {
		t.Errorf("expected no ecosystems, got %v", res.Ecosystems)
	}
	if res.HasLockfile {
		t.Error("expected HasLockfile false")
	}
}

func TestEnryFiltersVendoredWithoutIgnoreEntry(t *testing.T) {
	// third_party is a vendor pattern enry recognizes even though it is NOT in
	// the ignore list -- its go.mod must not trigger Go.
	fsys := fstest.MapFS{
		"third_party/lib/go.mod": {Data: []byte("module v")},
		"main.go":                {Data: []byte("package main")},
	}
	res, err := DetectFS(fsys, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Has(Go) {
		t.Error("vendored go.mod (enry-detected) should not trigger Go")
	}
	if res.Languages["Go"] == 0 {
		t.Error("expected non-vendored main.go counted in the language census")
	}
}

func TestIgnoreSkipsManifests(t *testing.T) {
	// A go.mod only under an ignored dir must not register Go.
	fsys := fstest.MapFS{"third_party/lib/go.mod": {Data: []byte("module z")}}
	res, err := DetectFS(fsys, []string{"third_party"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Has(Go) {
		t.Error("go.mod under ignored dir should not be detected")
	}
}
