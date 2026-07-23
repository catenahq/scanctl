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

// Set counts every finding fingerprint in a baseline report. Counted (not a
// plain set) so a change that DUPLICATES an existing finding still gates: N
// baseline instances suppress at most N current matches.
type Set map[string]int

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
			s[fingerprintRoot(tool, r, roots)]++
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
	left := make(Set, len(base))
	for k, v := range base {
		left[k] = v
	}
	for ri := range rep.Runs {
		tool := rep.Runs[ri].Tool.Driver.Name
		for i := range rep.Runs[ri].Results {
			r := &rep.Runs[ri].Results[i]
			if r.Suppressed() {
				continue
			}
			if fp := fingerprintRoot(tool, *r, roots); left[fp] > 0 {
				left[fp]--
				r.Suppressions = append(r.Suppressions, sarif.Suppression{Kind: "external"})
				n++
			}
		}
	}
	return n
}

// fingerprintRoot fingerprints r with every root stripped from its primary-
// location URI and message. Two further fields are dropped in this mode
// because they are not stable across two checkouts of related trees:
//   - the tool-provided partialFingerprints hash (osv-scanner's
//     primaryLocationLineHash differs between two checkouts of the identical
//     tree, evidently folding the absolute path in);
//   - the line number (an edit higher up the same file -- e.g. a lockfile
//     dependency bump -- shifts every finding below it, which made trivy's
//     pre-existing lockfile CVEs gate on any PR touching the lockfile).
//
// The fingerprint is therefore tool+rule+file+message over normalized paths;
// duplicate instances are handled by the counted Set, not by line identity.
// r is a value copy, but Locations is a shared slice, so the primary
// location is cloned before rewriting.
func fingerprintRoot(tool string, r sarif.Result, roots []string) string {
	var rs []string
	for _, root := range roots {
		if root != "" {
			rs = append(rs, root)
		}
	}
	if len(rs) == 0 {
		return sarif.Fingerprint(tool, r)
	}
	roots = rs
	r.PartialFingerprints = nil
	if len(r.Locations) > 0 {
		r.Locations = append([]sarif.Location(nil), r.Locations...)
		pl := &r.Locations[0].PhysicalLocation
		pl.ArtifactLocation.URI = stripRoots(pl.ArtifactLocation.URI, roots)
		pl.Region = nil
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
