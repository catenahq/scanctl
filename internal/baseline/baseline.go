// Package baseline diffs a current SARIF report against a committed baseline so
// only NEW findings gate the build -- the capability that makes scanctl usable
// on a large repo without GitHub Advanced Security (which provides this dedup
// on public repos only). A finding present in the baseline is marked suppressed
// (kind: external) in the current report rather than dropped: the gate already
// skips suppressed findings, GitHub renders them dismissed, and the full set
// stays auditable in the SARIF and the dashboards.
package baseline

import (
	"os"
	"strings"

	"github.com/catenahq/scanctl/internal/sarif"
)

// Set is the fingerprint of every finding in a baseline report.
type Set map[string]struct{}

// Load reads a baseline SARIF file and returns its fingerprint set. A missing
// file is not an error: an empty set suppresses nothing, so a repo with no
// committed baseline behaves exactly as before.
func Load(path string) (Set, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return Set{}, nil
	}
	rep, err := sarif.Load(path)
	if err != nil {
		return nil, err
	}
	return fingerprints(rep), nil
}

func fingerprints(rep *sarif.Report) Set {
	return FromReport(rep, "")
}

// FromReport fingerprints every finding in rep. roots are absolute checkout
// roots stripped from artifact URIs and message text before fingerprinting,
// so the same finding matches across two different checkouts of the repo
// (tools like osv-scanner and gosec emit absolute file:// URIs that would
// otherwise never collide between a PR head and a merge-base worktree). Pass
// BOTH sides' roots to both FromReport and ApplyRoot: a tool scanning a
// linked git worktree may report paths under the main checkout instead of the
// worktree (it resolves the repo root through the shared gitdir).
func FromReport(rep *sarif.Report, roots ...string) Set {
	s := Set{}
	for _, run := range rep.Runs {
		tool := run.Tool.Driver.Name
		for _, r := range run.Results {
			s[fingerprintRoot(tool, r, roots)] = struct{}{}
		}
	}
	return s
}

// Apply marks every not-yet-suppressed result in rep whose fingerprint is in
// the baseline as suppressed (kind: external). Returns the count newly
// suppressed.
func Apply(rep *sarif.Report, base Set) int {
	return ApplyRoot(rep, base)
}

// ApplyRoot is Apply with the same root normalization as FromReport: base must
// have been built with FromReport and the same roots for the fingerprints to
// line up.
func ApplyRoot(rep *sarif.Report, base Set, roots ...string) int {
	if len(base) == 0 {
		return 0
	}
	n := 0
	for ri := range rep.Runs {
		tool := rep.Runs[ri].Tool.Driver.Name
		for i := range rep.Runs[ri].Results {
			r := &rep.Runs[ri].Results[i]
			if r.Suppressed() {
				continue
			}
			if _, ok := base[fingerprintRoot(tool, *r, roots)]; ok {
				r.Suppressions = append(r.Suppressions, sarif.Suppression{Kind: "external"})
				n++
			}
		}
	}
	return n
}

// fingerprintRoot fingerprints r with every root stripped from its primary-
// location URI and message. The tool-provided partialFingerprints hash is
// dropped in this mode: it is NOT checkout-independent (osv-scanner's
// primaryLocationLineHash differs between two checkouts of the identical
// tree, evidently folding the absolute path in), so cross-checkout matching
// must use the synthesized tool+rule+location+message fingerprint over
// normalized paths. r is a value copy, but Locations is a shared slice, so
// the primary location is cloned before rewriting.
func fingerprintRoot(tool string, r sarif.Result, roots []string) string {
	if len(roots) == 0 {
		return sarif.Fingerprint(tool, r)
	}
	r.PartialFingerprints = nil
	if len(r.Locations) > 0 {
		r.Locations = append([]sarif.Location(nil), r.Locations...)
		loc := &r.Locations[0].PhysicalLocation.ArtifactLocation
		loc.URI = stripRoots(loc.URI, roots)
	}
	r.Message.Text = stripRoots(r.Message.Text, roots)
	return sarif.Fingerprint(tool, r)
}

// stripRoots removes every occurrence of each checkout root (as a file:// URI
// or a plain absolute path) from s, leaving repo-relative paths.
func stripRoots(s string, roots []string) string {
	for _, root := range roots {
		if root == "" {
			continue
		}
		root = strings.TrimSuffix(root, "/")
		s = strings.ReplaceAll(s, "file://"+root+"/", "")
		s = strings.ReplaceAll(s, root+"/", "")
	}
	return s
}
