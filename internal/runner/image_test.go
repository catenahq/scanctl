package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/catenahq/scanctl/internal/config"
)

// catalogGo is the shape the pins actually take in catena-admin's tier-1
// catalog: several images in one file, each on its own assignment line, with a
// comment nearby that mentions an image in prose.
const catalogGo = `
// PGDATA moved when the pin went to postgres:18, see the migration note.
func withDefaults(c *Catalog) {
	c.TraefikImage = "traefik:v3.7.13"
	c.PostgresImage = "postgres:18.6-alpine"
	c.PortainerImage = "portainer/portainer-ce:2.35.0"
}
`

func writeFile(t *testing.T, root, name, body string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestResolveImageRefsReadsEveryPinInTheFile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "payload/engines/tier1/catalog.go", catalogGo)

	cfg := config.Config{ImagePins: []config.ImagePin{{
		File:    "payload/engines/tier1/catalog.go",
		Pattern: `c\.\w+Image = "([^"]+)"`,
	}}}
	refs, err := resolveImageRefs(cfg, root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"portainer/portainer-ce:2.35.0", "postgres:18.6-alpine", "traefik:v3.7.13"}
	if strings.Join(refs, ",") != strings.Join(want, ",") {
		t.Errorf("refs = %v, want %v", refs, want)
	}
}

// The prose mention of postgres:18 in the comment must not become a ref: it is
// not a pin, and scanning it would report on a tag no host runs.
func TestResolveImageRefsIgnoresProseMatchingTheImageShape(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "catalog.go", catalogGo)

	cfg := config.Config{ImagePins: []config.ImagePin{{
		File:    "catalog.go",
		Pattern: `c\.PostgresImage = "([^"]+)"`,
	}}}
	refs, err := resolveImageRefs(cfg, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0] != "postgres:18.6-alpine" {
		t.Errorf("refs = %v, want just the pinned postgres ref", refs)
	}
}

func TestResolveImageRefsMergesLiteralsAndPinsWithoutDuplicates(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "catalog.go", catalogGo)

	cfg := config.Config{
		Images: []string{"traefik:v3.7.13", "ghcr.io/x/app:1.2.3"},
		ImagePins: []config.ImagePin{{
			File:    "catalog.go",
			Pattern: `c\.TraefikImage = "([^"]+)"`,
		}},
	}
	refs, err := resolveImageRefs(cfg, root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ghcr.io/x/app:1.2.3", "traefik:v3.7.13"}
	if strings.Join(refs, ",") != strings.Join(want, ",") {
		t.Errorf("refs = %v, want %v (traefik once, not twice)", refs, want)
	}
}

// The catena-ce failure this exists to prevent: the pinned file moved, the
// pattern matched nothing, and the gate reported success having scanned no
// image at all.
func TestResolveImageRefsFailsWhenAPinMatchesNothing(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "defaults/main.yml", "gatus_image_tag: \"v5.36.0\"\n")

	cfg := config.Config{ImagePins: []config.ImagePin{{
		File:    "defaults/main.yml",
		Pattern: `clamav_image: "(clamav/clamav:[^"]+)"`,
	}}}
	_, err := resolveImageRefs(cfg, root)
	if err == nil {
		t.Fatal("a pin matching nothing must fail the run, not scan nothing quietly")
	}
	if !strings.Contains(err.Error(), "matched no image ref") {
		t.Errorf("error = %v, want it to name the unmatched pin", err)
	}
}

func TestResolveImageRefsFailsWhenThePinFileIsGone(t *testing.T) {
	cfg := config.Config{ImagePins: []config.ImagePin{{
		File:    "ansible/roles/keycloak/defaults/main.yml",
		Pattern: `keycloak_image_tag: "([^"]+)"`,
	}}}
	_, err := resolveImageRefs(cfg, t.TempDir())
	if err == nil {
		t.Fatal("a pin naming a file that does not exist must fail the run")
	}
}

func TestResolveImageRefsRejectsAPatternWithoutOneGroup(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "catalog.go", catalogGo)

	for _, pattern := range []string{
		`c\.TraefikImage = "[^"]+"`, // no group at all
		`c\.(\w+)Image = "([^"]+)"`, // two groups
	} {
		cfg := config.Config{ImagePins: []config.ImagePin{{File: "catalog.go", Pattern: pattern}}}
		if _, err := resolveImageRefs(cfg, root); err == nil {
			t.Errorf("pattern %q was accepted; it cannot yield a <repo>:<tag>", pattern)
		}
	}
}

// An Ansible role default splits the repo off the tag, so the pattern matches
// the tag line and `repo` supplies the other half.
func TestResolveImageRefsComposesRepoWithACapturedTag(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "defaults/main.yml",
		"keycloak_image_tag: \"26.6.4\"\nkeycloak_image: >-\n  {{ ('quay.io/phasetwo/phasetwo-keycloak:' ~ keycloak_image_tag) }}\n")

	cfg := config.Config{ImagePins: []config.ImagePin{{
		File:    "defaults/main.yml",
		Pattern: `keycloak_image_tag: "([^"]+)"`,
		Repo:    "quay.io/phasetwo/phasetwo-keycloak",
	}}}
	refs, err := resolveImageRefs(cfg, root)
	if err != nil {
		t.Fatal(err)
	}
	want := "quay.io/phasetwo/phasetwo-keycloak:26.6.4"
	if len(refs) != 1 || refs[0] != want {
		t.Errorf("refs = %v, want [%s]", refs, want)
	}
}

// Pin files are read from the tree being scanned, which is what makes a
// --baseline-ref run resolve the merge-base's pins from its worktree instead
// of re-reading HEAD's.
func TestResolveImageRefsReadsPinsRelativeToTheScannedRoot(t *testing.T) {
	head := t.TempDir()
	base := t.TempDir()
	writeFile(t, head, "catalog.go", `c.TraefikImage = "traefik:v3.7.13"`)
	writeFile(t, base, "catalog.go", `c.TraefikImage = "traefik:v3.7.12"`)

	cfg := config.Config{ImagePins: []config.ImagePin{{
		File:    "catalog.go",
		Pattern: `c\.TraefikImage = "([^"]+)"`,
	}}}
	for root, want := range map[string]string{head: "traefik:v3.7.13", base: "traefik:v3.7.12"} {
		refs, err := resolveImageRefs(cfg, root)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) != 1 || refs[0] != want {
			t.Errorf("refs under %s = %v, want [%s]", root, refs, want)
		}
	}
}
