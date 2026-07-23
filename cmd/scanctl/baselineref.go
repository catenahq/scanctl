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
func baselineRefSet(ctx context.Context, root, ref string, cfg config.Config, lock runner.Lock) (baseline.Set, string, error) {
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

	out, err := runner.Run(ctx, dir, cfg, lock)
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
