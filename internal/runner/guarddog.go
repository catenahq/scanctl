package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/catenahq/scanctl/internal/config"
)

// guarddogManifests maps a GuardDog ecosystem subcommand to the root manifest it
// verifies. GuardDog emits SARIF only from its `verify` subcommand, which is
// manifest-based, so the step runs once per supported manifest present at the
// repo root. Nested manifests and pyproject-only projects are out of scope for
// now (documented in the README).
var guarddogManifests = []struct {
	ecosystem string
	manifest  string
}{
	{"pypi", "requirements.txt"},
	{"npm", "package-lock.json"},
	{"go", "go.mod"},
}

// guarddogStep runs GuardDog (malicious-package heuristics) over each supported
// root manifest and merges the SARIF. It is gated on cfg.Tools["guarddog"] and
// skipped when no supported manifest is present. GuardDog is resale-clean, so it
// is not profile-restricted.
func guarddogStep(ctx context.Context, cfg config.Config, lock Lock, root string, out *Outcome) {
	tc, ok := cfg.Tools["guarddog"]
	if !ok || !tc.Enabled {
		out.Skipped["guarddog"] = "disabled"
		return
	}

	type job struct{ ecosystem, manifest string }
	var jobs []job
	for _, m := range guarddogManifests {
		if _, err := os.Stat(filepath.Join(root, m.manifest)); err == nil {
			jobs = append(jobs, job{m.ecosystem, m.manifest})
		}
	}
	if len(jobs) == 0 {
		out.Skipped["guarddog"] = "no supported root manifest (requirements.txt / package-lock.json / go.mod)"
		return
	}

	version, err := lock.Version("guarddog")
	if err != nil {
		out.Warnings = append(out.Warnings, err.Error())
		out.Skipped["guarddog"] = "unpinned"
		return
	}
	bin, err := pyInstall(ctx, "guarddog", version, "guarddog")
	if err != nil {
		out.Warnings = append(out.Warnings, fmt.Sprintf("guarddog: fetch failed: %v", err))
		out.Skipped["guarddog"] = "fetch failed"
		return
	}

	ran := false
	for _, j := range jobs {
		outFile, err := os.CreateTemp("", "scanctl-guarddog-*.sarif")
		if err != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf("guarddog: temp file: %v", err))
			continue
		}
		outPath := outFile.Name()
		_ = outFile.Close()
		// #nosec G204 -- bin is the pinned guarddog; ecosystem/manifest come from
		// the internal table, not user input
		cmd := exec.CommandContext(ctx, bin, j.ecosystem, "verify", j.manifest, "--output-format", "sarif")
		cmd.Dir = root
		if mergeSARIFRun("guarddog", cmd, outPath, true, out) {
			ran = true
		}
		_ = os.Remove(outPath)
	}
	if ran {
		out.Ran = append(out.Ran, "guarddog")
	}
}
