package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/catenahq/scanctl/internal/config"
)

// licenseStep runs trivy's license scanner over the repo as a separate pass and
// merges it under the driver "trivy-license". It is a distinct driver (not the
// main "trivy" fs scan) on purpose: license findings are advisory (copyleft /
// unknown licenses for review), so they default to report mode and must not
// inherit trivy's blocking vuln/misconfig/secret gate. Reuses the pinned trivy
// binary fetched for the fs scan.
func licenseStep(ctx context.Context, cfg config.Config, lock Lock, root string, out *Outcome) {
	tc, ok := cfg.Tools["trivy-license"]
	if !ok || !tc.Enabled {
		out.Skipped["trivy-license"] = "disabled"
		return
	}
	version, err := lock.Version("trivy")
	if err != nil {
		out.Warnings = append(out.Warnings, err.Error())
		out.Skipped["trivy-license"] = "unpinned"
		return
	}
	bin, err := trivyEnsure(ctx, version)
	if err != nil {
		out.Warnings = append(out.Warnings, fmt.Sprintf("trivy-license: fetch failed: %v", err))
		out.Skipped["trivy-license"] = "fetch failed"
		return
	}
	outFile, err := os.CreateTemp("", "scanctl-trivy-license-*.sarif")
	if err != nil {
		out.Warnings = append(out.Warnings, fmt.Sprintf("trivy-license: temp file: %v", err))
		return
	}
	outPath := outFile.Name()
	_ = outFile.Close()
	defer os.Remove(outPath)

	// #nosec G204 -- bin is the pinned trivy; root is the scan target path
	cmd := exec.CommandContext(ctx, bin, "fs", "--quiet", "--format", "sarif",
		"--output", outPath, "--scanners", "license", root)
	if mergeSARIFRun("trivy-license", cmd, outPath, false, out) {
		out.Ran = append(out.Ran, "trivy-license")
	}
}
