package runner

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/catenahq/scanctl/internal/detect"
)

// digestOf is a release file's digest as the GitHub API spells it.
func digestOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// tarGz is a gzipped tar holding one executable file.
func tarGz(t *testing.T, name, body string) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// fakeRelease serves the release v1.0.0 of o/r: the API document and the files.
type fakeRelease struct {
	auth      string // Authorization header of the last API call
	apiCalls  int
	downloads int
}

// serveRelease points the runner at a fake GitHub holding the files in served
// (name -> bytes at the download URL). digests is each file's digest field; an
// empty one is published as null. The cache is a fresh directory and no token
// is set.
func serveRelease(t *testing.T, served, digests map[string]string) *fakeRelease {
	t.Helper()
	fr := &fakeRelease{}
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/releases/tags/v1.0.0", func(w http.ResponseWriter, r *http.Request) {
		fr.apiCalls++
		fr.auth = r.Header.Get("Authorization")
		type fileDoc struct {
			Name   string  `json:"name"`
			URL    string  `json:"browser_download_url"`
			Digest *string `json:"digest"`
		}
		var doc struct {
			Assets []fileDoc `json:"assets"`
		}
		for name := range served {
			f := fileDoc{Name: name, URL: srv.URL + "/dl/" + name}
			if d := digests[name]; d != "" {
				f.Digest = &d
			}
			doc.Assets = append(doc.Assets, f)
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/dl/", func(w http.ResponseWriter, r *http.Request) {
		fr.downloads++
		_, _ = io.WriteString(w, served[strings.TrimPrefix(r.URL.Path, "/dl/")])
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	saved := githubAPI
	githubAPI = srv.URL
	t.Cleanup(func() { githubAPI = saved })
	t.Setenv("SCANCTL_CACHE", t.TempDir())
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	return fr
}

var releaseEntry = LockEntry{Repo: "o/r", Version: "1.0.0"}

func TestAReleaseFileThatMatchesItsDigestIsUsed(t *testing.T) {
	fr := serveRelease(t, map[string]string{"scan": "binary"}, map[string]string{"scan": digestOf("binary")})
	cached := filepath.Join(cacheRoot(), "scan-1.0.0", "scan")
	writeFile(t, filepath.Dir(cached), "scan", "binary")

	got, err := releaseFile(context.Background(), "scan", releaseEntry, "scan")
	if err != nil {
		t.Fatal(err)
	}
	if got != cached || fr.downloads != 0 {
		t.Errorf("releaseFile = %q with %d download(s), want the cached file and none", got, fr.downloads)
	}
}

func TestAChangedCachedFileIsDownloadedAgain(t *testing.T) {
	fr := serveRelease(t, map[string]string{"scan": "binary"}, map[string]string{"scan": digestOf("binary")})
	cached := filepath.Join(cacheRoot(), "scan-1.0.0", "scan")
	writeFile(t, filepath.Dir(cached), "scan", "swapped")

	got, err := releaseFile(context.Background(), "scan", releaseEntry, "scan")
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(got) // #nosec G304 -- path is under the test's temp dir
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "binary" || fr.downloads != 1 {
		t.Errorf("file = %q after %d download(s), want the published bytes after one", body, fr.downloads)
	}
}

func TestAFileThatNeverMatchesIsAnErrorAndIsDeleted(t *testing.T) {
	fr := serveRelease(t, map[string]string{"scan": "doctored"}, map[string]string{"scan": digestOf("binary")})

	_, err := releaseFile(context.Background(), "scan", releaseEntry, "scan")
	if err == nil {
		t.Fatal("a file that does not match its digest was accepted")
	}
	if fr.downloads != 2 {
		t.Errorf("downloads = %d, want 2", fr.downloads)
	}
	if _, err := os.Stat(filepath.Join(cacheRoot(), "scan-1.0.0", "scan")); err == nil {
		t.Error("the mismatching file was left in the cache")
	}
}

func TestAFileWithoutADigestIsAnError(t *testing.T) {
	fr := serveRelease(t, map[string]string{"scan": "binary"}, map[string]string{})

	if _, err := releaseFile(context.Background(), "scan", releaseEntry, "scan"); err == nil {
		t.Fatal("a file with no published digest was accepted")
	}
	if fr.downloads != 0 {
		t.Errorf("downloaded %d time(s) a file nothing could check", fr.downloads)
	}
}

func TestAFileTheReleaseDoesNotHoldIsAnError(t *testing.T) {
	serveRelease(t, map[string]string{"other": "x"}, map[string]string{"other": digestOf("x")})
	if _, err := releaseFile(context.Background(), "scan", releaseEntry, "scan"); err == nil {
		t.Fatal("a missing release file was accepted")
	}
}

func TestAPinWithoutARepoIsAnError(t *testing.T) {
	serveRelease(t, nil, nil)
	if _, err := releaseFile(context.Background(), "scan", LockEntry{Version: "1.0.0"}, "scan"); err == nil {
		t.Fatal("a tool pinned without a repo was fetched")
	}
}

func TestTheAPICallCarriesTheTokenWhenOneIsSet(t *testing.T) {
	files := map[string]string{"scan": "binary"}
	digests := map[string]string{"scan": digestOf("binary")}
	for _, c := range []struct{ gh, github, want string }{
		{"", "", ""},
		{"a", "", "Bearer a"},
		{"", "b", "Bearer b"},
		{"a", "b", "Bearer a"},
	} {
		fr := serveRelease(t, files, digests)
		t.Setenv("GH_TOKEN", c.gh)
		t.Setenv("GITHUB_TOKEN", c.github)
		if _, err := releaseFile(context.Background(), "scan", releaseEntry, "scan"); err != nil {
			t.Fatal(err)
		}
		if fr.auth != c.want {
			t.Errorf("GH_TOKEN=%q GITHUB_TOKEN=%q: Authorization = %q, want %q", c.gh, c.github, fr.auth, c.want)
		}
	}
}

// The binary inside a verified archive is extracted afresh on every call, so a
// swapped extracted binary never runs.
func TestAnArchiveBinaryIsExtractedAfreshAfterTheCheck(t *testing.T) {
	archive := tarGz(t, "scan", "real binary")
	serveRelease(t, map[string]string{"scan.tar.gz": archive}, map[string]string{"scan.tar.gz": digestOf(archive)})
	ensure := ghTarGz("scan", func(string) string { return "scan.tar.gz" }, "scan")

	bin, err := ensure(context.Background(), releaseEntry, "")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Dir(bin), "scan", "swapped binary")
	if bin, err = ensure(context.Background(), releaseEntry, ""); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(bin) // #nosec G304 -- path is under the test's temp dir
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "real binary" {
		t.Errorf("binary = %q, want the archive's", body)
	}
}

func TestAPlainBinaryIsCheckedAndExecutable(t *testing.T) {
	serveRelease(t, map[string]string{"scan_linux": "binary"}, map[string]string{"scan_linux": digestOf("binary")})
	ensure := ghBinary("scan", func(string) string { return "scan_linux" })

	bin, err := ensure(context.Background(), releaseEntry, "")
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(bin)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o100 == 0 {
		t.Errorf("mode = %v, want executable", fi.Mode())
	}
}

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

// govulncheck runs under the toolchain that built it, so the standard library
// it grades is that toolchain's, whatever go comes first on PATH.
func TestGovulncheckRunsUnderTheToolchainThatBuiltIt(t *testing.T) {
	var gv toolDef
	for _, td := range registry {
		if td.name == "govulncheck" {
			gv = td
		}
	}
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	env := gv.invoke(bin, t.TempDir(), "out.sarif", detect.Result{}).env
	if want := "GOTOOLCHAIN=" + runtime.Version(); !slices.Contains(env, want) {
		t.Errorf("govulncheck env = %v, want %q", env, want)
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
