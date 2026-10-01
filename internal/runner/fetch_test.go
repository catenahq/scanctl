package runner

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// goModule writes a minimal module at a temp root and returns the root and the
// toolchain it selects.
func goModule(t *testing.T) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not on PATH")
	}
	root := t.TempDir()
	writeFile(t, root, "go.mod", "module example.com/m\n\ngo 1.21\n")
	out, err := exec.Command("go", "-C", root, "env", "GOVERSION").Output()
	if err != nil {
		t.Fatal(err)
	}
	return root, strings.TrimSpace(string(out))
}

func TestModuleToolchainIsTheOneTheScannedModuleSelects(t *testing.T) {
	root, want := goModule(t)
	got, err := moduleToolchain(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("moduleToolchain = %q, want %q", got, want)
	}
}

// A govulncheck built by one toolchain is never reused for a module that
// selects another: the toolchain is part of the cache path.
func TestGoInstallIsCachedPerToolchain(t *testing.T) {
	root, toolchain := goModule(t)
	t.Setenv("SCANCTL_CACHE", t.TempDir())
	cached := filepath.Join(cacheRoot(), "govulncheck-1.8.0-"+toolchain, "govulncheck")
	writeFile(t, filepath.Dir(cached), "govulncheck", "")

	got, err := goInstall(context.Background(), "golang.org/x/vuln", "cmd/govulncheck", "1.8.0", root)
	if err != nil {
		t.Fatal(err)
	}
	if got != cached {
		t.Errorf("goInstall = %q, want the cached build for %s at %q", got, toolchain, cached)
	}
}

func TestGoVersionNamesOnlyReleasedToolchains(t *testing.T) {
	for _, v := range []string{"go1.27.1", "go1.21", "go1.28rc1"} {
		if !goVersionRx.MatchString(v) {
			t.Errorf("%q rejected", v)
		}
	}
	for _, v := range []string{"devel go1.28-abc", "go1.27.1 linux/amd64", "../x", ""} {
		if goVersionRx.MatchString(v) {
			t.Errorf("%q accepted", v)
		}
	}
}
