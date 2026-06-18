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
	s := Set{}
	for _, run := range rep.Runs {
		tool := run.Tool.Driver.Name
		for _, r := range run.Results {
			s[sarif.Fingerprint(tool, r)] = struct{}{}
		}
	}
	return s
}

// Apply marks every not-yet-suppressed result in rep whose fingerprint is in
// the baseline as suppressed (kind: external). Returns the count newly
// suppressed.
func Apply(rep *sarif.Report, base Set) int {
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
			if _, ok := base[sarif.Fingerprint(tool, *r)]; ok {
				r.Suppressions = append(r.Suppressions, sarif.Suppression{Kind: "external"})
				n++
			}
		}
	}
	return n
}
