package runner

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
)

// maxArtifactBytes bounds a single extracted file, guarding against a
// decompression bomb. Headroom over the largest real scanner binary (trivy,
// ~150MB) while still capping a malicious archive.
const maxArtifactBytes = 1 << 30 // 1 GiB

// cacheRoot is where fetched scanner binaries and the govulncheck install land,
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

// download streams url to dest, creating parent dirs. Fails on non-200.
func download(ctx context.Context, url, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	f, err := os.Create(dest) // #nosec G304 -- dest is under our own cache root, not user-controlled
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return nil
}

// downloadBinary fetches a plain executable (no archive) to destBin and marks
// it executable.
func downloadBinary(ctx context.Context, url, destBin string) error {
	if err := download(ctx, url, destBin); err != nil {
		return err
	}
	return os.Chmod(destBin, 0o755) // #nosec G302 -- a scanner binary must be executable
}

// downloadTarGzBinary fetches a .tar.gz, extracts the single entry named
// binInArchive, and writes it to destBin (executable).
func downloadTarGzBinary(ctx context.Context, url, binInArchive, destBin string) error {
	tmp, err := os.CreateTemp("", "scanctl-dl-*.tar.gz")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close() // only the path is needed; download re-creates the file
	defer os.Remove(tmpPath)

	if err := download(ctx, url, tmpPath); err != nil {
		return err
	}
	f, err := os.Open(tmpPath) // #nosec G304 -- tmpPath is our own CreateTemp file
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gunzip %s: %w", url, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("%s: %q not found in archive", url, binInArchive)
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
		out, err := os.Create(destBin) // #nosec G304 -- destBin is under our own cache root
		if err != nil {
			return err
		}
		// Bound the copy so a crafted archive cannot exhaust disk.
		n, err := io.Copy(out, io.LimitReader(tr, maxArtifactBytes+1))
		if err != nil {
			_ = out.Close()
			return err
		}
		if n > maxArtifactBytes {
			_ = out.Close()
			return fmt.Errorf("%s: %q exceeds %d bytes", url, binInArchive, maxArtifactBytes)
		}
		if err := out.Close(); err != nil {
			return err
		}
		return os.Chmod(destBin, 0o755) // #nosec G302 -- a scanner binary must be executable
	}
}

// goInstall runs `go install <module>/<cmdSubpath>@v<version>` into a
// per-version GOBIN under the cache and returns the resulting binary path. Used
// for govulncheck, which ships as a Go command rather than a release asset.
// `go install` names the output after the command (base of cmdSubpath), so the
// version is carried by the GOBIN directory, not the filename.
func goInstall(ctx context.Context, module, cmdSubpath, version string) (string, error) {
	binName := path.Base(cmdSubpath)
	gobin := filepath.Join(cacheRoot(), binName+"-"+version)
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
	cmd.Env = append(os.Environ(), "GOBIN="+gobin)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go install %s: %w\n%s", pkg, err, out)
	}
	return dest, nil
}
