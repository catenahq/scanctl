package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/catenahq/scanctl/internal/config"
)

// imageStep scans each container image ref in cfg.Images with trivy, reusing the
// pinned trivy binary fetched for the fs scan. It is skipped when Images is
// empty (only repos that ship images, e.g. dokploy-templates, configure it).
// Findings are tagged driver "trivy" so they gate under trivy's mode, while the
// step is recorded as "trivy-image" in out.Ran for visibility.
func imageStep(ctx context.Context, cfg config.Config, lock Lock, out *Outcome) {
	if len(cfg.Images) == 0 {
		return
	}
	tc, ok := cfg.Tools["trivy"]
	if !ok || !tc.Enabled {
		out.Skipped["trivy-image"] = "trivy disabled"
		return
	}
	version, err := lock.Version("trivy")
	if err != nil {
		out.Warnings = append(out.Warnings, err.Error())
		out.Skipped["trivy-image"] = "unpinned"
		return
	}
	bin, err := trivyEnsure(ctx, version)
	if err != nil {
		out.Warnings = append(out.Warnings, fmt.Sprintf("trivy-image: fetch failed: %v", err))
		out.Skipped["trivy-image"] = "fetch failed"
		return
	}

	ran := false
	for _, ref := range cfg.Images {
		outFile, err := os.CreateTemp("", "scanctl-trivy-image-*.sarif")
		if err != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf("trivy-image: temp file: %v", err))
			continue
		}
		outPath := outFile.Name()
		_ = outFile.Close()
		// #nosec G204 -- bin is the pinned trivy; ref comes from the operator's scanctl.yml
		cmd := exec.CommandContext(ctx, bin, "image", "--quiet", "--format", "sarif",
			"--ignore-unfixed", "--output", outPath, ref)
		if mergeSARIFRun("trivy", cmd, outPath, false, out) {
			ran = true
		}
		_ = os.Remove(outPath)
	}
	if ran {
		out.Ran = append(out.Ran, "trivy-image")
	}
}
