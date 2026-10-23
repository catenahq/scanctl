package runner

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// digestOf is the hex sha256 of a release file's bytes, as tools.lock spells it.
func digestOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
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

// fakeDownloads serves the release files of v1.0.0 of o/r.
type fakeDownloads struct {
	auth      string // Authorization header of the last download
	downloads int
}

// serveDownloads points the runner at a fake GitHub holding the files in files
// (name -> bytes at the download URL) and the platform at linux amd64. The cache
// is a fresh directory and a token is set, which no download may carry.
func serveDownloads(t *testing.T, files map[string]string) *fakeDownloads {
	t.Helper()
	fd := &fakeDownloads{}
	const prefix = "/o/r/releases/download/v1.0.0/"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := files[strings.TrimPrefix(r.URL.Path, prefix)]
		if !strings.HasPrefix(r.URL.Path, prefix) || !ok {
			http.NotFound(w, r)
			return
		}
		fd.downloads++
		fd.auth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	savedURL, savedOS, savedArch := githubDownload, hostOS, hostArch
	githubDownload, hostOS, hostArch = srv.URL, "linux", "amd64"
	t.Cleanup(func() { githubDownload, hostOS, hostArch = savedURL, savedOS, savedArch })
	t.Setenv("SCANCTL_CACHE", t.TempDir())
	t.Setenv("GH_TOKEN", "tok")
	t.Setenv("GITHUB_TOKEN", "tok")
	return fd
}

// entryFor pins the files of v1.0.0 of o/r by the digests of their bytes.
func entryFor(files map[string]string) LockEntry {
	e := LockEntry{Repo: "o/r", Version: "1.0.0", SHA256: map[string]string{}}
	for name, body := range files {
		e.SHA256[digestKey("1.0.0", name)] = digestOf(body)
	}
	return e
}

// withReleaseTools replaces the release registry for the test.
func withReleaseTools(t *testing.T, tools map[string]releaseTool) {
	t.Helper()
	saved := releaseTools
	releaseTools = tools
	t.Cleanup(func() { releaseTools = saved })
}

func TestAReleaseFileThatMatchesItsPinIsUsed(t *testing.T) {
	files := map[string]string{"scan": "binary"}
	fd := serveDownloads(t, files)
	cached := filepath.Join(cacheRoot(), "scan-1.0.0", "scan")
	writeFile(t, filepath.Dir(cached), "scan", "binary")

	got, err := releaseFile(context.Background(), "scan", entryFor(files), "scan")
	if err != nil {
		t.Fatal(err)
	}
	if got != cached || fd.downloads != 0 {
		t.Errorf("releaseFile = %q with %d download(s), want the cached file and none", got, fd.downloads)
	}
}

func TestAChangedCachedFileIsDownloadedAgain(t *testing.T) {
	files := map[string]string{"scan": "binary"}
	fd := serveDownloads(t, files)
	cached := filepath.Join(cacheRoot(), "scan-1.0.0", "scan")
	writeFile(t, filepath.Dir(cached), "scan", "swapped")

	got, err := releaseFile(context.Background(), "scan", entryFor(files), "scan")
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(got) // #nosec G304 -- path is under the test's temp dir
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "binary" || fd.downloads != 1 {
		t.Errorf("file = %q after %d download(s), want the pinned bytes after one", body, fd.downloads)
	}
}

func TestAFileThatNeverMatchesIsAnErrorAndIsDeleted(t *testing.T) {
	fd := serveDownloads(t, map[string]string{"scan": "doctored"})
	entry := entryFor(map[string]string{"scan": "binary"})

	_, err := releaseFile(context.Background(), "scan", entry, "scan")
	if err == nil || !strings.Contains(err.Error(), "tools.lock pins "+digestOf("binary")) {
		t.Fatalf("a file that does not match its pin was accepted, or the error is vague: %v", err)
	}
	if fd.downloads != 2 {
		t.Errorf("downloads = %d, want 2", fd.downloads)
	}
	requireOnlyFiles(t, filepath.Join(cacheRoot(), "scan-1.0.0"))
}

// A failed check never touches the destination: the doctored download is
// removed from its temporary name, and the file already there is the one that
// failed its own check.
func TestAFailedDownloadLeavesNoPartialFileAtTheDestination(t *testing.T) {
	serveDownloads(t, map[string]string{"scan": "doctored"})
	dir := filepath.Join(cacheRoot(), "scan-1.0.0")
	writeFile(t, dir, "scan", "swapped")

	if _, err := releaseFile(context.Background(), "scan", entryFor(map[string]string{"scan": "binary"}), "scan"); err == nil {
		t.Fatal("a file that does not match its pin was accepted")
	}
	requireOnlyFiles(t, dir)
}

func TestAFileWithoutAPinnedDigestIsAnErrorAndNothingIsDownloaded(t *testing.T) {
	files := map[string]string{"scan": "binary"}
	fd := serveDownloads(t, files)
	missing := LockEntry{Repo: "o/r", Version: "1.0.0"}
	malformed := LockEntry{Repo: "o/r", Version: "1.0.0", SHA256: map[string]string{"v1.0.0/scan": "sha256:" + digestOf("binary")}}
	otherVersion := LockEntry{Repo: "o/r", Version: "1.0.0", SHA256: map[string]string{"v0.9.0/scan": digestOf("binary")}}

	for name, entry := range map[string]LockEntry{"no digests": missing, "malformed": malformed, "older version": otherVersion} {
		_, err := releaseFile(context.Background(), "scan", entry, "scan")
		if err == nil || !strings.Contains(err.Error(), "refresh-digests") {
			t.Errorf("%s: error = %v, want a refusal that names scanctl refresh-digests", name, err)
		}
	}
	if fd.downloads != 0 {
		t.Errorf("downloaded %d time(s) a file nothing could check", fd.downloads)
	}
}

func TestAFileTheReleaseDoesNotHoldIsAnErrorNamingTheURL(t *testing.T) {
	serveDownloads(t, map[string]string{"other": "x"})
	_, err := releaseFile(context.Background(), "scan", entryFor(map[string]string{"scan": "binary"}), "scan")
	if err == nil || !strings.Contains(err.Error(), "/o/r/releases/download/v1.0.0/scan: status 404") {
		t.Fatalf("error = %v, want the download URL and its status", err)
	}
}

func TestAPinWithoutARepoIsAnError(t *testing.T) {
	fd := serveDownloads(t, nil)
	entry := entryFor(map[string]string{"scan": "binary"})
	entry.Repo = ""
	if _, err := releaseFile(context.Background(), "scan", entry, "scan"); err == nil {
		t.Fatal("a tool pinned without a repo was fetched")
	}
	if fd.downloads != 0 {
		t.Errorf("downloads = %d, want 0", fd.downloads)
	}
}

func TestADownloadCarriesNoToken(t *testing.T) {
	files := map[string]string{"scan": "binary"}
	fd := serveDownloads(t, files)
	if _, err := releaseFile(context.Background(), "scan", entryFor(files), "scan"); err != nil {
		t.Fatal(err)
	}
	if fd.downloads != 1 || fd.auth != "" {
		t.Errorf("%d download(s) with Authorization %q, want one with none", fd.downloads, fd.auth)
	}
}

// The binary inside a verified archive is extracted afresh over whatever sits
// at its path, through a temporary file that is renamed into place.
func TestAnArchiveBinaryIsExtractedAfreshAfterTheCheck(t *testing.T) {
	archive := tarGz(t, "scan", "real binary")
	files := map[string]string{"scan.tar.gz": archive}
	serveDownloads(t, files)
	withReleaseTools(t, map[string]releaseTool{"scan": {asset: func(string) string { return "scan.tar.gz" }, bin: "scan"}})
	swapped := filepath.Join(cacheRoot(), "scan-1.0.0", "scan")
	writeFile(t, filepath.Dir(swapped), "scan", "swapped binary")

	bin, err := releaseEnsure("scan")(context.Background(), entryFor(files), "")
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(bin) // #nosec G304 -- path is under the test's temp dir
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "real binary" {
		t.Errorf("binary = %q, want the archive's", body)
	}
	requireOnlyFiles(t, filepath.Dir(bin), "scan", "scan.tar.gz")
}

// requireOnlyFiles fails when dir holds anything but the named files: a
// temporary file left behind would show here.
func requireOnlyFiles(t *testing.T, dir string, names ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	slices.Sort(got)
	slices.Sort(names)
	if !slices.Equal(got, names) {
		t.Errorf("%s holds %v, want %v", dir, got, names)
	}
}

// One hash, one download and one extraction per tool per process: a later call
// reuses the checked path.
func TestAToolIsCheckedOncePerProcess(t *testing.T) {
	archive := tarGz(t, "scan", "real binary")
	files := map[string]string{"scan.tar.gz": archive}
	fd := serveDownloads(t, files)
	withReleaseTools(t, map[string]releaseTool{"scan": {asset: func(string) string { return "scan.tar.gz" }, bin: "scan"}})
	ensure := releaseEnsure("scan")

	first, err := ensure(context.Background(), entryFor(files), "")
	if err != nil {
		t.Fatal(err)
	}
	// A second call would hash and extract again; it would put the archive's
	// bytes back over this.
	writeFile(t, filepath.Dir(first), "scan", "changed after the check")
	second, err := ensure(context.Background(), entryFor(files), "")
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(second) // #nosec G304 -- path is under the test's temp dir
	if err != nil {
		t.Fatal(err)
	}
	if second != first || fd.downloads != 1 || string(body) != "changed after the check" {
		t.Errorf("second call: path %q (first %q), %d download(s), file %q; want the reused path after one download",
			second, first, fd.downloads, body)
	}
}

func TestAFailedCheckIsNotRemembered(t *testing.T) {
	fd := serveDownloads(t, map[string]string{"scan_linux": "doctored"})
	withReleaseTools(t, map[string]releaseTool{"scan": {asset: func(string) string { return "scan_linux" }}})
	ensure := releaseEnsure("scan")
	entry := entryFor(map[string]string{"scan_linux": "binary"})

	for i := 0; i < 2; i++ {
		if _, err := ensure(context.Background(), entry, ""); err == nil {
			t.Fatal("a doctored file was accepted")
		}
	}
	if fd.downloads != 4 {
		t.Errorf("downloads = %d, want the failure tried again (4 over two calls)", fd.downloads)
	}
}

func TestAPlainBinaryIsCheckedAndExecutable(t *testing.T) {
	files := map[string]string{"scan_linux": "binary"}
	serveDownloads(t, files)
	withReleaseTools(t, map[string]releaseTool{"scan": {asset: func(string) string { return "scan_linux" }}})

	bin, err := releaseEnsure("scan")(context.Background(), entryFor(files), "")
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

func TestReleaseScannersAreFetchedOnLinuxAmd64Only(t *testing.T) {
	files := map[string]string{"scan_linux": "binary"}
	fd := serveDownloads(t, files)
	withReleaseTools(t, map[string]releaseTool{"scan": {asset: func(string) string { return "scan_linux" }}})

	for _, c := range []struct{ os, arch string }{{"darwin", "arm64"}, {"linux", "arm64"}, {"linux", "386"}} {
		hostOS, hostArch = c.os, c.arch
		_, err := releaseEnsure("scan")(context.Background(), entryFor(files), "")
		if err == nil || !strings.Contains(err.Error(), "linux amd64") || !strings.Contains(err.Error(), c.os+"/"+c.arch) {
			t.Errorf("%s/%s: error = %v, want it to name linux amd64 and the host", c.os, c.arch, err)
		}
	}
	if fd.downloads != 0 {
		t.Errorf("downloads = %d, want 0", fd.downloads)
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
