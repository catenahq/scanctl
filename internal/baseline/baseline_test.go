package baseline

import (
	"testing"

	"github.com/catenahq/scanctl/internal/sarif"
)

func mk(tool, rule, uri string, line int) sarif.Run {
	return sarif.Run{
		Tool: sarif.Tool{Driver: sarif.Driver{Name: tool}},
		Results: []sarif.Result{{
			RuleID:  rule,
			Message: sarif.Message{Text: "m"},
			Locations: []sarif.Location{{PhysicalLocation: sarif.PhysicalLocation{
				ArtifactLocation: sarif.ArtifactLocation{URI: uri},
				Region:           &sarif.Region{StartLine: line},
			}}},
		}},
	}
}

func TestApplySuppressesKnownNotNew(t *testing.T) {
	base := fingerprints(&sarif.Report{Runs: []sarif.Run{mk("gosec", "G304", "a.go", 5)}})
	cur := &sarif.Report{Runs: []sarif.Run{
		mk("gosec", "G304", "a.go", 5), // in baseline -> suppressed
		mk("gosec", "G401", "b.go", 9), // new -> stays
	}}
	if n := Apply(cur, base); n != 1 {
		t.Fatalf("suppressed = %d, want 1", n)
	}
	if !cur.Runs[0].Results[0].Suppressed() {
		t.Error("known finding not suppressed")
	}
	if cur.Runs[1].Results[0].Suppressed() {
		t.Error("new finding wrongly suppressed")
	}
}

func TestEmptyBaselineIsNoop(t *testing.T) {
	cur := &sarif.Report{Runs: []sarif.Run{mk("gosec", "G304", "a.go", 5)}}
	if n := Apply(cur, Set{}); n != 0 {
		t.Errorf("empty baseline suppressed %d, want 0", n)
	}
}

func TestRootNormalizationMatchesAcrossCheckouts(t *testing.T) {
	// Same finding scanned in two checkouts: baseline from a worktree with
	// file:// URIs, current run with a plain absolute path. Root stripping must
	// make them collide; a genuinely new finding must survive.
	base := FromReport(&sarif.Report{Runs: []sarif.Run{
		mk("osv-scanner", "CVE-1", "file:///tmp/base-wt/package-lock.json", 1),
		// A tool scanning a linked worktree can report the MAIN checkout's
		// path (resolved through the shared gitdir); both roots are passed so
		// this normalizes identically.
		mk("osv-scanner", "CVE-3", "file:///home/ci/repo/package-lock.json", 1),
	}}, "/tmp/base-wt", "/home/ci/repo")
	cur := &sarif.Report{Runs: []sarif.Run{
		mk("osv-scanner", "CVE-1", "/home/ci/repo/package-lock.json", 1),
		mk("osv-scanner", "CVE-2", "/home/ci/repo/package-lock.json", 1),
		mk("osv-scanner", "CVE-3", "/home/ci/repo/package-lock.json", 1),
	}}
	if n := ApplyRoot(cur, base, "/home/ci/repo"); n != 2 {
		t.Fatalf("suppressed = %d, want 2", n)
	}
	if !cur.Runs[0].Results[0].Suppressed() {
		t.Error("pre-existing finding not suppressed across checkouts")
	}
	if cur.Runs[1].Results[0].Suppressed() {
		t.Error("new finding wrongly suppressed")
	}
	if !cur.Runs[2].Results[0].Suppressed() {
		t.Error("main-checkout-path finding not suppressed")
	}
}

func TestRootNormalizationIgnoresPathDependentToolHashes(t *testing.T) {
	// osv-scanner's primaryLocationLineHash differs between two checkouts of
	// the identical tree (it folds the absolute path in), so cross-checkout
	// matching must ignore partialFingerprints and use the normalized
	// synthetic fingerprint.
	withHash := func(uri, hash string) sarif.Run {
		r := mk("osv-scanner", "CVE-1", uri, 0)
		r.Results[0].PartialFingerprints = map[string]string{"primaryLocationLineHash": hash}
		return r
	}
	base := FromReport(&sarif.Report{Runs: []sarif.Run{
		withHash("file:///wt/package-lock.json", "hash-of-wt-path"),
	}}, "/wt")
	cur := &sarif.Report{Runs: []sarif.Run{
		withHash("file:///repo/package-lock.json", "hash-of-repo-path"),
	}}
	if n := ApplyRoot(cur, base, "/repo"); n != 1 {
		t.Fatalf("suppressed = %d, want 1", n)
	}
}

func TestRootNormalizationStripsMessagePaths(t *testing.T) {
	// Some tools embed the absolute checkout path in the message text too.
	mkMsg := func(uri, msg string) sarif.Run {
		r := mk("gosec", "G304", uri, 3)
		r.Results[0].Message.Text = msg
		return r
	}
	base := FromReport(&sarif.Report{Runs: []sarif.Run{
		mkMsg("file:///wt/a.go", "read of /wt/a.go"),
	}}, "/wt")
	cur := &sarif.Report{Runs: []sarif.Run{
		mkMsg("file:///repo/a.go", "read of /repo/a.go"),
	}}
	if n := ApplyRoot(cur, base, "/repo"); n != 1 {
		t.Fatalf("suppressed = %d, want 1", n)
	}
}

func TestLoadMissingFileIsEmptySet(t *testing.T) {
	s, err := Load("/nonexistent/baseline.sarif")
	if err != nil {
		t.Fatalf("missing baseline should not error: %v", err)
	}
	if len(s) != 0 {
		t.Errorf("missing baseline set len = %d, want 0", len(s))
	}
}
