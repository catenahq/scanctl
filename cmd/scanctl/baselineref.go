package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/catenahq/scanctl/internal/baseline"
	"github.com/catenahq/scanctl/internal/config"
	"github.com/catenahq/scanctl/internal/runner"
	"github.com/catenahq/scanctl/internal/sarif"
)

// baselineRefSet scans the images pinned at the merge-base of HEAD and ref, in
// a temporary git worktree, and returns their findings' fingerprint set. An
// image finding already present there is suppressed (kind: external), so only
// the image CVEs a change INTRODUCES gate. Only images are diffed: a finding in
// the repo's own tree is fixable by a change to it, so it gates on every run.
// resolveBaseRef picks ref.
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
	base = scopeImagePins(ctx, base, root, sha)
	base = preresolveBasePins(base, dir)
	out, err := runner.ScanImages(ctx, dir, base, lock)
	if err != nil {
		return nil, fmt.Errorf("baseline scan: %w", err)
	}
	for _, w := range out.Warnings {
		fmt.Fprintln(os.Stderr, "warning: baseline-ref:", w)
	}
	// A base image that did not scan suppresses nothing, so its findings on
	// HEAD gate: stricter, never looser.
	for ref, why := range out.Failed {
		fmt.Fprintf(os.Stderr, "warning: baseline-ref: %s not scanned (%s); its findings gate\n", ref, why)
	}
	// Both roots: a tool scanning the linked worktree may report paths under
	// the MAIN checkout (it resolves the repo root through the shared gitdir),
	// so worktree- and main-rooted URIs must both normalize away.
	return baseline.FromReport(out.Report, absPath(dir), absPath(root)), nil
}

// resolveBaseRef decides what a run is compared against. An explicit
// -baseline-ref wins. Left empty inside GitHub Actions, the ref is read from
// the event: a pull request is compared with its target branch, a push with
// the commit the branch held before it, or with the default branch when that
// commit is not in the clone (the push created the branch, or force-pushed
// past it). Any other run -- scheduled, manual, outside Actions -- grades no
// change and is compared with nothing.
func resolveBaseRef(ctx context.Context, root, flag string) string {
	if flag != "" {
		return flag
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		return ""
	}
	switch os.Getenv("GITHUB_EVENT_NAME") {
	case "pull_request", "pull_request_target":
		if base := os.Getenv("GITHUB_BASE_REF"); base != "" {
			return "origin/" + base
		}
	case "push":
		ev := readPushEvent(os.Getenv("GITHUB_EVENT_PATH"))
		if ev.Before != "" {
			if _, err := gitOut(ctx, root, "cat-file", "-e", ev.Before+"^{commit}"); err == nil {
				return ev.Before
			}
		}
		if ev.Repository.DefaultBranch != "" {
			return "origin/" + ev.Repository.DefaultBranch
		}
	}
	return ""
}

// reportImageFindings marks every image-scan finding suppressed (kind:
// external) on a run that grades no change: a CVE in a third-party image is
// upstream's to fix, and with nothing changed this run introduced none of
// them. They stay in the report and the SARIF. Returns how many it marked.
func reportImageFindings(rep *sarif.Report) int {
	n := 0
	for ri := range rep.Runs {
		for i := range rep.Runs[ri].Results {
			r := &rep.Runs[ri].Results[i]
			if _, ok := r.Properties[sarif.ImageProperty]; ok && !r.Suppressed() {
				r.Suppressions = append(r.Suppressions, sarif.Suppression{Kind: "external", Justification: sarif.NoChange})
				n++
			}
		}
	}
	return n
}

// pushEvent is the part of a GitHub push event payload resolveBaseRef reads.
type pushEvent struct {
	Before     string `json:"before"`
	Repository struct {
		DefaultBranch string `json:"default_branch"`
	} `json:"repository"`
}

// readPushEvent loads the event payload at path; an unreadable one is empty,
// which resolves to no diff and the full gate.
func readPushEvent(path string) pushEvent {
	var ev pushEvent
	if data, err := os.ReadFile(path); err == nil { // #nosec G304 G703 -- GITHUB_EVENT_PATH, set by the Actions runner
		_ = json.Unmarshal(data, &ev)
	}
	return ev
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
// run. A run without -baseline-ref keeps every pin, which is how a scheduled
// run reports the CVEs in an image nobody touched.
//
// A glob pin becomes one pin per file it matches among the changed files, so a
// change to one of many files a glob covers scans that file's images only. A
// matched file the change deleted is left out: it has no image on HEAD.
//
// Compared against the WORKING TREE rather than HEAD, because the working tree
// is what the scan actually reads: an uncommitted edit to a pin file would
// otherwise be scanned but not scoped in. Both sides of the diff are scoped
// with the same call, so the baseline scans only what the report can match.
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
	var changed []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			changed = append(changed, line)
		}
	}
	sort.Strings(changed)
	var kept []config.ImagePin
	for _, pin := range cfg.ImagePins {
		for _, f := range changed {
			if ok, _ := path.Match(pin.File, f); !ok {
				continue
			}
			if runner.IsGlob(pin.File) {
				if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(f))); err != nil {
					continue
				}
			}
			kept = append(kept, config.ImagePin{File: f, Pattern: pin.Pattern, Repo: pin.Repo})
		}
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
// nothing to resolve at the merge base: it is a pin with no baseline, and every
// one of its findings gates, which is what an absent entry here produces.
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
