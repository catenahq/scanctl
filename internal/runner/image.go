package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/catenahq/scanctl/internal/config"
)

// imageStep scans each container image ref in cfg.Images -- plus every ref
// resolved out of cfg.ImagePins -- with trivy, reusing the pinned trivy binary
// fetched for the fs scan. It is skipped when neither is configured (only
// repos that ship or pin images set them). Findings are tagged driver "trivy"
// so they gate under trivy's mode, while the step is recorded as "trivy-image"
// in out.Ran for visibility.
//
// The returned error is reserved for a pin that resolves to nothing, which is
// a defect in scanctl.yml rather than a scan that went wrong: an unresolvable
// pin means an image silently goes unscanned and the run still reports clean.
// Transient scan failures stay warnings, like every other step.
func imageStep(ctx context.Context, cfg config.Config, lock Lock, root string, out *Outcome) error {
	refs, err := resolveImageRefs(cfg, root)
	if err != nil {
		return err
	}
	if len(refs) == 0 {
		return nil
	}
	tc, ok := cfg.Tools["trivy"]
	if !ok || !tc.Enabled {
		out.Skipped["trivy-image"] = "trivy disabled"
		return nil
	}
	version, err := lock.Version("trivy")
	if err != nil {
		out.Warnings = append(out.Warnings, err.Error())
		out.Skipped["trivy-image"] = "unpinned"
		return nil
	}
	bin, err := trivyEnsure(ctx, version)
	if err != nil {
		out.Warnings = append(out.Warnings, fmt.Sprintf("trivy-image: fetch failed: %v", err))
		out.Skipped["trivy-image"] = "fetch failed"
		return nil
	}

	ignore := trivyIgnoreFile(root)

	ran := false
	for _, ref := range refs {
		outFile, err := os.CreateTemp("", "scanctl-trivy-image-*.sarif")
		if err != nil {
			out.Warnings = append(out.Warnings, fmt.Sprintf("trivy-image: temp file: %v", err))
			continue
		}
		outPath := outFile.Name()
		_ = outFile.Close()
		args := []string{"image", "--quiet", "--format", "sarif",
			"--ignore-unfixed", "--output", outPath}
		if ignore != "" {
			args = append(args, "--ignorefile", ignore)
		}
		args = append(args, ref)
		// #nosec G204 -- bin is the pinned trivy; ref comes from the operator's
		// scanctl.yml or from a pin pattern it declares over the repo's own files
		cmd := exec.CommandContext(ctx, bin, args...)
		if mergeSARIFRun("trivy", cmd, outPath, false, out) {
			ran = true
		}
		_ = os.Remove(outPath)
	}
	if ran {
		out.Ran = append(out.Ran, "trivy-image")
	}
	return nil
}

// trivyIgnoreFile returns the repo's trivy ignore file, or "" when it has
// none. Named explicitly because trivy does NOT pick one up on its own for an
// image scan: against 0.74 a .trivyignore.yaml sitting in the working
// directory changed nothing until --ignorefile pointed at it. Left implicit,
// a repo's reviewed and time-boxed suppressions would silently not apply and
// the image gate would re-report every CVE the operator has already triaged.
//
// Read from the scanned root, so a --baseline-ref run applies the base
// branch's suppression list to the base branch's images. Adding a suppression
// therefore quiets both sides at once rather than reading as a fixed CVE.
func trivyIgnoreFile(root string) string {
	for _, name := range []string{".trivyignore.yaml", ".trivyignore.yml", ".trivyignore"} {
		p := filepath.Join(root, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// resolveImageRefs is cfg.Images plus every ref matched by cfg.ImagePins,
// deduplicated and ordered so a run is reproducible. Pin files are read
// relative to root, which is the tree being scanned -- the merge-base worktree
// on a --baseline-ref run, so the baseline resolves the pins as they stood on
// the base branch.
func resolveImageRefs(cfg config.Config, root string) ([]string, error) {
	seen := map[string]bool{}
	var refs []string
	add := func(ref string) {
		ref = strings.TrimSpace(ref)
		if ref == "" || seen[ref] {
			return
		}
		seen[ref] = true
		refs = append(refs, ref)
	}
	for _, ref := range cfg.Images {
		add(ref)
	}
	for _, pin := range cfg.ImagePins {
		found, err := ResolveImagePin(pin, root)
		if err != nil {
			return nil, err
		}
		for _, ref := range found {
			add(ref)
		}
	}
	sort.Strings(refs)
	return refs, nil
}

// ResolveImagePin returns every ref pin.Pattern captures in pin.File. An empty
// result is an error, not an empty list: a pin that matches nothing is the
// exact shape of an image that stopped being scanned without anyone noticing.
func ResolveImagePin(pin config.ImagePin, root string) ([]string, error) {
	if pin.File == "" || pin.Pattern == "" {
		return nil, fmt.Errorf("image_pins: an entry needs both file and pattern (got file=%q pattern=%q)", pin.File, pin.Pattern)
	}
	rx, err := regexp.Compile(pin.Pattern)
	if err != nil {
		return nil, fmt.Errorf("image_pins: %s: bad pattern %q: %w", pin.File, pin.Pattern, err)
	}
	if n := rx.NumSubexp(); n != 1 {
		return nil, fmt.Errorf("image_pins: %s: pattern %q has %d capturing groups, need exactly 1 yielding <repo>:<tag>", pin.File, pin.Pattern, n)
	}
	path := filepath.Join(root, filepath.FromSlash(pin.File))
	data, err := os.ReadFile(path) // #nosec G304 -- path is the operator-declared pin file inside the scanned tree
	if err != nil {
		return nil, fmt.Errorf("image_pins: %s: %w", pin.File, err)
	}
	matches := rx.FindAllStringSubmatch(string(data), -1)
	var refs []string
	for _, m := range matches {
		got := strings.TrimSpace(m[1])
		if got == "" {
			continue
		}
		if pin.Repo != "" {
			got = pin.Repo + ":" + got
		}
		refs = append(refs, got)
	}
	if len(refs) == 0 {
		return nil, fmt.Errorf("image_pins: %s: pattern %q matched no image ref -- the pin moved or was renamed, and leaving it unmatched would scan nothing and still report clean", pin.File, pin.Pattern)
	}
	return refs, nil
}
