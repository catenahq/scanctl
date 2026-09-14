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
func baselineRefSet(ctx context.Context, root, ref, cfgPath, profile string, cfg config.Config, lock runner.Lock) (baseline.Set, string, error) {
	sha, err := gitOut(ctx, root, "merge-base", "HEAD", ref)
	if err != nil {
		return nil, "", fmt.Errorf("merge-base HEAD %s: %w", ref, err)
	}

	dir, err := os.MkdirTemp("", "scanctl-baseline-*")
	if err != nil {
		return nil, "", err
	}
	// worktree add refuses an existing dir; it only needs the path.
	if err := os.Remove(dir); err != nil {
		return nil, "", err
	}
	if _, err := gitOut(ctx, root, "worktree", "add", "--detach", dir, sha); err != nil {
		return nil, "", fmt.Errorf("worktree add %s: %w", sha, err)
	}
	defer func() {
		if _, err := gitOut(ctx, root, "worktree", "remove", "--force", dir); err != nil {
			os.RemoveAll(dir)
		}
	}()

	out, err := runner.Run(ctx, dir, worktreeConfig(cfgPath, profile, root, dir, cfg), lock)
	if err != nil {
		return nil, "", fmt.Errorf("baseline scan: %w", err)
	}
	for _, w := range out.Warnings {
		fmt.Fprintln(os.Stderr, "warning: baseline-ref:", w)
	}
	// Both roots: a tool scanning the linked worktree may report paths under
	// the MAIN checkout (it resolves the repo root through the shared gitdir),
	// so worktree- and main-rooted URIs must both normalize away.
	return baseline.FromReport(out.Report, absPath(dir), absPath(root)), sha, nil
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
