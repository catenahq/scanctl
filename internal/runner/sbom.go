package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// ensureSyft lazy-fetches the pinned syft release (CycloneDX SBOM generator).
// syft sits outside the SARIF registry because it emits a bill of materials,
// not findings; it feeds Dependency-Track (P3), not the merged report.
func ensureSyft(ctx context.Context, version string) (string, error) {
	fetch := ghTarGz("syft", func(v string) string {
		return fmt.Sprintf("https://github.com/anchore/syft/releases/download/v%s/syft_%s_linux_%s.tar.gz",
			v, v, runtime.GOARCH)
	}, "syft")
	return fetch(ctx, version)
}

// GenerateSBOM writes a CycloneDX JSON SBOM of root to outPath using syft.
func GenerateSBOM(ctx context.Context, root string, lock Lock, outPath string) error {
	version, err := lock.Version("syft")
	if err != nil {
		return err
	}
	bin, err := ensureSyft(ctx, version)
	if err != nil {
		return fmt.Errorf("syft fetch: %w", err)
	}
	// #nosec G204 -- bin is the pinned syft; root is the scan target path
	cmd := exec.CommandContext(ctx, bin, "scan", root, "-o", "cyclonedx-json="+outPath, "-q")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("syft scan: %w\n%s", err, out)
	}
	if fi, err := os.Stat(outPath); err != nil || fi.Size() == 0 {
		return fmt.Errorf("syft produced no SBOM at %s", outPath)
	}
	return nil
}
