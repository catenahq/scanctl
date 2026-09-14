// The two halves of making image pins work as a PR gate: narrowing them to
// what the change touches, and letting the base branch not have them yet.
package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/catenahq/scanctl/internal/config"
)

const catalogGo = "c.TraefikImage = \"traefik:v3.7.13\"\n"
const roleYml = "keycloak_image_tag: \"26.6.4\"\n"

// gitRepo builds a repo with one commit, and returns its path plus that
// commit's sha to diff against.
func gitRepo(t *testing.T) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	root := t.TempDir()
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return string(out)
	}
	run("init", "-q")
	write(t, root, "catalog.go", catalogGo)
	write(t, root, "roles/keycloak.yml", roleYml)
	run("add", "-A")
	run("commit", "-qm", "base")
	sha := run("rev-parse", "HEAD")
	return root, sha[:40]
}

func write(t *testing.T, root, name, body string) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func pins() []config.ImagePin {
	return []config.ImagePin{
		{File: "catalog.go", Pattern: `c\.TraefikImage = "([^"]+)"`},
		{File: "roles/keycloak.yml", Pattern: `keycloak_image_tag: "([^"]+)"`,
			Repo: "quay.io/phasetwo/phasetwo-keycloak"},
	}
}

func TestScopeImagePinsKeepsOnlyTheFilesTheChangeTouches(t *testing.T) {
	root, sha := gitRepo(t)
	write(t, root, "roles/keycloak.yml", "keycloak_image_tag: \"26.6.6\"\n")

	got := scopeImagePins(context.Background(),
		config.Config{ImagePins: pins()}, root, sha)

	if len(got.ImagePins) != 1 || got.ImagePins[0].File != "roles/keycloak.yml" {
		t.Errorf("kept %v, want only the role default this change edited. "+
			"An untouched pin resolves to the same ref on both sides, so "+
			"scanning it twice can only prove a zero.", got.ImagePins)
	}
}

// The working tree is what the scan reads, so an uncommitted pin edit has to
// scope in or it would be scanned on one side and not the other.
func TestScopeImagePinsSeesAnUncommittedEdit(t *testing.T) {
	root, sha := gitRepo(t)
	write(t, root, "catalog.go", "c.TraefikImage = \"traefik:v3.7.14\"\n")

	got := scopeImagePins(context.Background(),
		config.Config{ImagePins: pins()}, root, sha)

	if len(got.ImagePins) != 1 || got.ImagePins[0].File != "catalog.go" {
		t.Errorf("kept %v, want the uncommitted catalog.go edit", got.ImagePins)
	}
}

func TestScopeImagePinsDropsThemAllWhenNoPinFileMoved(t *testing.T) {
	root, sha := gitRepo(t)
	write(t, root, "README.md", "docs only\n")

	got := scopeImagePins(context.Background(),
		config.Config{ImagePins: pins()}, root, sha)

	if len(got.ImagePins) != 0 {
		t.Errorf("kept %v, want none: a docs-only PR changes no image", got.ImagePins)
	}
}

// Cannot tell what moved -> scan everything. Never scan nothing.
func TestScopeImagePinsKeepsEveryPinWhenTheDiffFails(t *testing.T) {
	root, _ := gitRepo(t)
	got := scopeImagePins(context.Background(),
		config.Config{ImagePins: pins()}, root, "not-a-sha")
	if len(got.ImagePins) != 2 {
		t.Errorf("kept %v, want both: an unreadable diff must widen the scan, not narrow it", got.ImagePins)
	}
}

func TestPreresolveBasePinsTurnsThePinsIntoLiteralRefs(t *testing.T) {
	root, _ := gitRepo(t)
	got := preresolveBasePins(config.Config{ImagePins: pins()}, root)

	if got.ImagePins != nil {
		t.Error("pins should be consumed into Images so the runner cannot re-resolve them")
	}
	want := map[string]bool{
		"traefik:v3.7.13": true,
		"quay.io/phasetwo/phasetwo-keycloak:26.6.4": true,
	}
	if len(got.Images) != len(want) {
		t.Fatalf("Images = %v, want %v", got.Images, want)
	}
	for _, ref := range got.Images {
		if !want[ref] {
			t.Errorf("unexpected ref %q", ref)
		}
	}
}

// A pin the change ADDS has nothing to resolve at the merge base. That is a
// pin with no baseline, not a broken config: dropping it here is what makes
// every one of its findings gate.
func TestPreresolveBasePinsDropsAPinTheBaseBranchDoesNotHave(t *testing.T) {
	root, _ := gitRepo(t)
	withNew := append(pins(), config.ImagePin{
		File: "roles/added-by-this-pr.yml", Pattern: `tag: "([^"]+)"`})

	got := preresolveBasePins(config.Config{ImagePins: withNew}, root)

	if len(got.Images) != 2 {
		t.Errorf("Images = %v, want only the two pins the base branch has", got.Images)
	}
}

func TestPreresolveBasePinsKeepsLiteralImages(t *testing.T) {
	root, _ := gitRepo(t)
	got := preresolveBasePins(
		config.Config{Images: []string{"ghcr.io/x/app:1.0.0"}, ImagePins: pins()}, root)

	var found bool
	for _, ref := range got.Images {
		if ref == "ghcr.io/x/app:1.0.0" {
			found = true
		}
	}
	if !found {
		t.Errorf("Images = %v, want the literal entry kept alongside the resolved pins", got.Images)
	}
}
