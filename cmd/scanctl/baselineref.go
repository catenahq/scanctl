package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/catenahq/scanctl/internal/baseline"
	"github.com/catenahq/scanctl/internal/config"
	"github.com/catenahq/scanctl/internal/runner"
)

// baselineRefSet scans the merge-base of HEAD and ref in a temporary git
// worktree and returns its findings' fingerprint set plus the merge-base sha.
// Used on pull_request CI so only findings the PR INTRODUCES gate: everything
// already present on the base branch is suppressed (kind: external), while
// push/cron runs (no -baseline-ref) keep the full gate.
//
// cfgPath and profile are what main parsed, so the baseline scan can re-read
// the config from the worktree: settings that name things OUTSIDE the tree --
// `images`, above all -- do not rewind with the checked-out files, and reusing
// HEAD's config would scan HEAD's image on both sides of the diff and suppress
// every finding as pre-existing.
func baselineRefSet(ctx context.Context, root, sha, cfgPath, profile string, cfg config.Config, lock runner.Lock) (baseline.Set, error) {
	dir, err := os.MkdirTemp("", "scanctl-baseline-*")
	if err != nil {
		return nil, err
	}
	// worktree add refuses an existing dir; it only needs the path.
	if err := os.Remove(dir); err != nil {
		return nil, err
	}
	if _, err := gitOut(ctx, root, "worktree", "add", "--detach", dir, sha); err != nil {
		return nil, fmt.Errorf("worktree add %s: %w", sha, err)
	}
	defer func() {
		if _, err := gitOut(ctx, root, "worktree", "remove", "--force", dir); err != nil {
			os.RemoveAll(dir)
		}
	}()

	base := worktreeConfig(cfgPath, profile, root, dir, cfg)
	base = preresolveBasePins(base, dir)
	out, err := runner.Run(ctx, dir, base, lock)
	if err != nil {
		return nil, fmt.Errorf("baseline scan: %w", err)
	}
	for _, w := range out.Warnings {
		fmt.Fprintln(os.Stderr, "warning: baseline-ref:", w)
	}
	// Both roots: a tool scanning the linked worktree may report paths under
	// the MAIN checkout (it resolves the repo root through the shared gitdir),
	// so worktree- and main-rooted URIs must both normalize away.
	return baseline.FromReport(out.Report, absPath(dir), absPath(root)), nil
}

// mergeBase resolves the merge-base of HEAD and ref.
func mergeBase(ctx context.Context, root, ref string) (string, error) {
	sha, err := gitOut(ctx, root, "merge-base", "HEAD", ref)
	if err != nil {
		return "", fmt.Errorf("merge-base HEAD %s: %w", ref, err)
	}
	return sha, nil
}

// scopeImagePins drops the image pins whose file this change does not touch.
//
// An unchanged pin file resolves to the SAME ref on both sides of the diff, so
// scanning it twice can only produce findings that suppress each other.
// Dropping it does not weaken the gate; it declines to pull and scan an image
// twice to prove a zero, which on a repo pinning nine of them is most of a
// PR's runtime. A run without -baseline-ref (push, cron) keeps every pin and
// grades absolutely, and that is where debt in an image nobody touched is
// meant to surface.
//
// Compared against the WORKING TREE rather than HEAD, because the working tree
// is what the scan actually reads: an uncommitted edit to a pin file would
// otherwise be scanned but not scoped in.
func scopeImagePins(ctx context.Context, cfg config.Config, root, baseSha string) config.Config {
	if len(cfg.ImagePins) == 0 {
		return cfg
	}
	out, err := gitOut(ctx, root, "diff", "--name-only", baseSha)
	if err != nil {
		// Cannot tell what moved, so scan everything rather than nothing.
		fmt.Fprintln(os.Stderr, "warning: baseline-ref: changed-file scope:", err)
		return cfg
	}
	changed := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			changed[line] = true
		}
	}
	var kept []config.ImagePin
	for _, pin := range cfg.ImagePins {
		if changed[pin.File] {
			kept = append(kept, pin)
		}
	}
	if len(kept) != len(cfg.ImagePins) {
		fmt.Printf("image_pins: %d of %d pin file(s) changed since %.12s; "+
			"the rest resolve identically on both sides and are not rescanned\n",
			len(kept), len(cfg.ImagePins), baseSha)
	}
	cfg.ImagePins = kept
	return cfg
}

// preresolveBasePins turns the base branch's image_pins into literal refs and
// DROPS the ones that do not resolve there.
//
// On the HEAD scan an unresolvable pin fails the run, because it means an
// image is silently going unscanned. The base branch is the opposite case: a
// pin this change ADDS, or one whose file this change creates, correctly has
// nothing to resolve at the merge base. That is not a broken config, it is a
// pin with no baseline -- and a pin with no baseline should have every one of
// its findings gate, which is what an absent entry here produces.
//
// Resolving here rather than letting the runner do it also keeps one bad pin
// from costing the whole diff: a hard failure inside the baseline scan
// degrades the entire run to the full gate, so an unrelated PR that renamed a
// pin variable would suddenly gate on every pre-existing finding in the repo.
func preresolveBasePins(cfg config.Config, dir string) config.Config {
	if len(cfg.ImagePins) == 0 {
		return cfg
	}
	refs := append([]string(nil), cfg.Images...)
	for _, pin := range cfg.ImagePins {
		found, err := runner.ResolveImagePin(pin, dir)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"baseline-ref: no baseline for %s (%v); its findings will gate\n",
				pin.File, err)
			continue
		}
		refs = append(refs, found...)
	}
	cfg.Images = refs
	cfg.ImagePins = nil
	return cfg
}

// worktreeConfig re-reads scanctl.yml from the merge-base worktree so the
// baseline scan runs under the configuration the base branch declared. A
// config kept outside the scanned tree is shared by both sides and is returned
// unchanged, as is one that fails to re-read (a warning, then HEAD's config:
// the baseline suppresses less and the gate stays stricter).
//
// A config that does not exist at the merge base loads as defaults, which
// declare no images -- so a newly added pin has no baseline and every one of
// its findings gates. That is the right way round.
func worktreeConfig(cfgPath, profile, root, dir string, cur config.Config) config.Config {
	rel, err := filepath.Rel(absPath(root), absPath(cfgPath))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return cur
	}
	cfg, err := config.Load(filepath.Join(dir, rel))
	if err != nil {
		fmt.Fprintln(os.Stderr, "warning: baseline-ref: config:", err)
		return cur
	}
	if profile != "" {
		cfg.Profile = profile
	}
	return cfg
}

// gitOut runs a git subcommand in dir and returns its trimmed stdout.
func gitOut(ctx context.Context, dir string, args ...string) (string, error) {
	// #nosec G204 -- args are fixed git subcommands plus a ref/path from our own flags
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	b, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(b))
	if err != nil {
		return "", fmt.Errorf("git %s: %v: %s", args[0], err, s)
	}
	return s, nil
}

// absPath resolves p to an absolute, symlink-free path (worktrees under /tmp
// can differ from what tools report otherwise). Falls back to p on error.
func absPath(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if r, err := filepath.EvalSymlinks(a); err == nil {
		return r
	}
	return a
}
