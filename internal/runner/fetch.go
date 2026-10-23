package runner

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// pyToolPython is the interpreter uv installs Python-based tools under. Pinned
// to a stable version with wheels for all tool deps, not the newest release.
const pyToolPython = "3.13"

// maxArtifactBytes bounds a single extracted file, guarding against a
// decompression bomb. Headroom over the largest real scanner binary (trivy,
// ~150MB) while still capping a malicious archive.
const maxArtifactBytes = 1 << 30 // 1 GiB

// githubAPI is the base URL of the GitHub REST API, which publishes the sha256
// of every release file.
var githubAPI = "https://api.github.com"

// maxReleaseDocBytes bounds the release document read from the API.
const maxReleaseDocBytes = 16 << 20

// digestRx is a release file's digest as the API spells it.
var digestRx = regexp.MustCompile(`^sha256:([0-9a-f]{64})$`)

// cacheRoot is where fetched scanner binaries and the govulncheck installs land,
// reused across runs (on a persistent runner this means one download per pin).
func cacheRoot() string {
	if d := os.Getenv("SCANCTL_CACHE"); d != "" {
		return d
	}
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base = filepath.Join(os.TempDir(), "scanctl-cache")
	}
	return filepath.Join(base, "scanctl", "tools")
}

// asset is a release file as the GitHub API describes it: where to download it
// and the sha256 GitHub holds for it.
type asset struct {
	url, sha256 string
}

// githubToken is the token the API call carries: GH_TOKEN, else GITHUB_TOKEN.
// It lifts the API's rate limit and goes to no other host.
func githubToken() string {
	if t := os.Getenv("GH_TOKEN"); t != "" {
		return t
	}
	return os.Getenv("GITHUB_TOKEN")
}

// releaseAsset reads the release tag of repo from the GitHub API and returns
// the file called name. A file with no digest is an error: nothing could check
// it.
func releaseAsset(ctx context.Context, repo, tag, name string) (asset, error) {
	if repo == "" {
		return asset{}, fmt.Errorf("%s: tools.lock pins no repo", name)
	}
	endpoint := githubAPI + "/repos/" + repo + "/releases/tags/" + url.PathEscape(tag)
	tok := githubToken()
	resp, err := releaseRequest(ctx, endpoint, tok)
	if err != nil {
		return asset{}, err
	}
	// An organization with an IP allow list refuses a GitHub App installation
	// token, a job's GITHUB_TOKEN among them, even on its public repositories
	// (aquasecurity does); the same request with no token is answered.
	anonymous := false
	if resp.StatusCode == http.StatusForbidden && tok != "" && resp.Header.Get("X-RateLimit-Remaining") != "0" {
		resp.Body.Close()
		anonymous = true
		if resp, err = releaseRequest(ctx, endpoint, ""); err != nil {
			return asset{}, err
		}
	}
	defer resp.Body.Close()
	if anonymous && (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests) {
		return asset{}, fmt.Errorf("GET %s: status %d with the token and without it: the owner refuses the token and the API's limit for requests without one is spent", endpoint, resp.StatusCode)
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return asset{}, fmt.Errorf("GET %s: status %d, the GitHub API rate limit: set GH_TOKEN (or GITHUB_TOKEN) to lift it", endpoint, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return asset{}, fmt.Errorf("GET %s: status %d", endpoint, resp.StatusCode)
	}
	var rel struct {
		Assets []struct {
			Name   string `json:"name"`
			URL    string `json:"browser_download_url"`
			Digest string `json:"digest"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxReleaseDocBytes)).Decode(&rel); err != nil {
		return asset{}, fmt.Errorf("GET %s: %w", endpoint, err)
	}
	for _, a := range rel.Assets {
		if a.Name != name {
			continue
		}
		m := digestRx.FindStringSubmatch(a.Digest)
		if m == nil {
			return asset{}, fmt.Errorf("%s %s: GitHub publishes no sha256 digest for %s (got %q)", repo, tag, name, a.Digest)
		}
		return asset{url: a.URL, sha256: m[1]}, nil
	}
	return asset{}, fmt.Errorf("%s %s: no release file %s", repo, tag, name)
}

// releaseRequest sends one GET of the releases API, with tok when it is set.
func releaseRequest(ctx context.Context, endpoint, tok string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", endpoint, err)
	}
	return resp, nil
}

// download streams src into a new temporary file in dir (created if needed)
// and returns its path and the sha256 of the bytes written. Fails on non-200;
// a failed download leaves no file. The caller renames or removes the file.
func download(ctx context.Context, src, dir string) (string, string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("GET %s: %w", src, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("GET %s: status %d", src, resp.StatusCode)
	}
	f, err := os.CreateTemp(dir, ".download-*")
	if err != nil {
		return "", "", err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return "", "", err
	}
	return f.Name(), hex.EncodeToString(h.Sum(nil)), nil
}

// fileSHA256 returns the hex sha256 of the file at p.
func fileSHA256(p string) (string, error) {
	f, err := os.Open(p) // #nosec G304 -- p is under our own cache root
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// releaseFile returns the path of the release file name of tool's pinned
// release, kept at <cache>/<tool>-<version>/<name>. The file is hashed on every
// call and must match the digest GitHub publishes for it. A file that is absent
// or does not match is downloaded afresh into a temporary file, which replaces
// it by rename once its hash matches, so a running scanner never sees a partial
// file. A second mismatch is an error and leaves no file at the destination.
func releaseFile(ctx context.Context, tool string, e LockEntry, name string) (string, error) {
	a, err := releaseAsset(ctx, e.Repo, "v"+e.Version, name)
	if err != nil {
		return "", err
	}
	dest := filepath.Join(cacheRoot(), tool+"-"+e.Version, name)
	got := ""
	downloads := 2
	if sum, err := fileSHA256(dest); err == nil {
		if sum == a.sha256 {
			return dest, nil
		}
		got = sum
		_ = os.Remove(dest)
		downloads = 1
	}
	for i := 0; i < downloads; i++ {
		tmp, sum, err := download(ctx, a.url, filepath.Dir(dest))
		if err != nil {
			return "", err
		}
		if sum == a.sha256 {
			if err := os.Rename(tmp, dest); err != nil {
				_ = os.Remove(tmp)
				return "", err
			}
			return dest, nil
		}
		_ = os.Remove(tmp)
		got = sum
	}
	return "", fmt.Errorf("%s %s: sha256 is %s, GitHub publishes %s", e.Repo, name, got, a.sha256)
}

// checkedOnce remembers, for the life of the process, the path ensure returned
// for a tool version, so the release API is called and the file hashed once per
// tool per run. Only a success is remembered.
var (
	checkedMu   sync.Mutex
	checkedPath = map[string]string{}
)

func checkedOnce(tool string, e LockEntry, ensure func() (string, error)) (string, error) {
	key := cacheRoot() + "\x00" + tool + "\x00" + e.Version
	checkedMu.Lock()
	defer checkedMu.Unlock()
	if p, ok := checkedPath[key]; ok {
		return p, nil
	}
	p, err := ensure()
	if err == nil {
		checkedPath[key] = p
	}
	return p, err
}

// extractTarGz writes the single entry of the archive at archivePath named
// binInArchive to destBin (executable).
func extractTarGz(archivePath, binInArchive, destBin string) error {
	f, err := os.Open(archivePath) // #nosec G304 -- archivePath is under our own cache root
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gunzip %s: %w", archivePath, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("%s: %q not found in archive", archivePath, binInArchive)
		}
		if err != nil {
			return err
		}
		if filepath.Base(hdr.Name) != binInArchive {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(destBin), 0o750); err != nil {
			return err
		}
		// Written beside destBin and renamed over it, so a scanner running
		// the old file keeps it and never sees a partial one.
		out, err := os.CreateTemp(filepath.Dir(destBin), ".extract-*")
		if err != nil {
			return err
		}
		tmp := out.Name()
		// Bound the copy so a crafted archive cannot exhaust disk.
		n, err := io.Copy(out, io.LimitReader(tr, maxArtifactBytes+1))
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err == nil && n > maxArtifactBytes {
			err = fmt.Errorf("%s: %q exceeds %d bytes", archivePath, binInArchive, maxArtifactBytes)
		}
		if err == nil {
			err = os.Chmod(tmp, 0o755) // #nosec G302 -- a scanner binary must be executable
		}
		if err == nil {
			err = os.Rename(tmp, destBin)
		}
		if err != nil {
			_ = os.Remove(tmp)
		}
		return err
	}
}

// goInstall runs `go install <module>/<cmdSubpath>@v<version>` into a GOBIN
// under the cache and returns the resulting binary path. Used for govulncheck,
// which ships as a Go command rather than a release asset.
//
// It builds with the toolchain the scanned module at root selects. govulncheck
// type-checks the module's sources with the go/types of the toolchain that
// compiled it, so one built by an older toolchain cannot load code using newer
// language features. `go install pkg@version` runs outside any module and would use
// whatever go is on PATH, hence GOTOOLCHAIN. `go install` names the output
// after the command (base of cmdSubpath), so the tool version and toolchain
// are carried by the GOBIN directory, not the filename.
func goInstall(ctx context.Context, module, cmdSubpath, version, root string) (string, error) {
	toolchain, err := moduleToolchain(ctx, root)
	if err != nil {
		return "", err
	}
	binName := path.Base(cmdSubpath)
	gobin := filepath.Join(cacheRoot(), binName+"-"+version+"-"+toolchain)
	dest := filepath.Join(gobin, binName)
	if fi, err := os.Stat(dest); err == nil && !fi.IsDir() {
		return dest, nil
	}
	if err := os.MkdirAll(gobin, 0o750); err != nil {
		return "", err
	}
	pkg := fmt.Sprintf("%s/%s@v%s", module, cmdSubpath, version)
	// #nosec G204 -- pkg is built from the pinned tools.lock (module + version), not user input
	cmd := exec.CommandContext(ctx, "go", "install", pkg)
	cmd.Env = append(os.Environ(), "GOBIN="+gobin, "GOTOOLCHAIN="+toolchain)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go install %s: %w\n%s", pkg, err, out)
	}
	return dest, nil
}

// moduleToolchain is the Go toolchain the module at root selects (its go.mod
// toolchain line under GOTOOLCHAIN=auto), e.g. "go1.27.1". It sets
// GOTOOLCHAIN=auto itself: a runner may export GOTOOLCHAIN=local (setup-go
// does), under which go reports the version of whichever go comes first on
// PATH and skips the toolchain line.
func moduleToolchain(ctx context.Context, root string) (string, error) {
	// #nosec G204 -- fixed go subcommand; root is the scan target path
	cmd := exec.CommandContext(ctx, "go", "-C", root, "env", "GOVERSION")
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=auto")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go env GOVERSION in %s: %w", root, err)
	}
	v := strings.TrimSpace(string(out))
	if !goVersionRx.MatchString(v) {
		return "", fmt.Errorf("go env GOVERSION in %s: unexpected %q", root, v)
	}
	return v, nil
}

// goVersionRx is a released toolchain name, which GOTOOLCHAIN accepts and a
// cache directory name can carry.
var goVersionRx = regexp.MustCompile(`^go[0-9]+(\.[0-9]+)*(rc[0-9]+)?$`)

// pyInstall installs a pinned PyPI tool with `uv tool install pkg==version` into
// a per-version cache dir and returns the resolved entry-point path. uv is a
// runner prerequisite (the same uv that backs `uvx` in the existing per-repo
// workflows). The tool venv (UV_TOOL_DIR) and its console scripts
// (UV_TOOL_BIN_DIR) are isolated per pin so binName is stable across versions;
// the version is carried by the directory, like goInstall.
func pyInstall(ctx context.Context, pkg, version, binName string) (string, error) {
	toolDir := filepath.Join(cacheRoot(), pkg+"-"+version)
	binDir := filepath.Join(toolDir, "bin")
	dest := filepath.Join(binDir, binName)
	if fi, err := os.Stat(dest); err == nil && !fi.IsDir() {
		return dest, nil
	}
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		return "", err
	}
	spec := pkg + "==" + version
	// Pin the interpreter: the newest CPython often lacks wheels for a tool's
	// native deps (e.g. guarddog -> pygit2 has no cp314 wheel and its source
	// build fails), which would break the install on a runner defaulting to the
	// latest Python. uv fetches this version on demand.
	// #nosec G204 -- spec is built from the pinned tools.lock (pkg + version), not user input
	cmd := exec.CommandContext(ctx, "uv", "tool", "install", "--force", "--python", pyToolPython, spec)
	cmd.Env = append(os.Environ(), "UV_TOOL_DIR="+toolDir, "UV_TOOL_BIN_DIR="+binDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("uv tool install %s: %w\n%s", spec, err, out)
	}
	return dest, nil
}
