package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

// GenerateSBOM writes a CycloneDX JSON SBOM of root to outPath using syft, the
// pinned release (lazy-fetched). syft writes a bill of materials for
// Dependency-Track, outside the SARIF registry.
func GenerateSBOM(ctx context.Context, root string, lock Lock, outPath string) error {
	entry, err := lock.Entry("syft")
	if err != nil {
		return err
	}
	bin, err := releaseEnsure("syft")(ctx, entry, "")
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
