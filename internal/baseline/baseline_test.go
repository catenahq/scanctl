package baseline

import (
	"testing"
	"time"

	"github.com/catenahq/scanctl/internal/sarif"
)

var today = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

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

// A CVE in an image the repo builds is the repo's to fix: the base commit
// having had it does not stop it gating.
func TestApplyRootNeverSuppressesAnOwnImageFinding(t *testing.T) {
	own := func() *sarif.Report {
		run := mk("trivy", "CVE-1", "usr/bin/restic", 1)
		run.Results[0].Properties = map[string]any{sarif.OwnImageProperty: "catena-admin:ci"}
		return &sarif.Report{Runs: []sarif.Run{run}}
	}
	cur := own()
	if n := ApplyRoot(cur, FromReport(own(), "/repo"), "/repo"); n != 0 {
		t.Errorf("suppressed = %d, want 0", n)
	}
	if cur.Runs[0].Results[0].Suppressed() {
		t.Error("own-image finding suppressed as present before the change")
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

func TestRootNormalizationIgnoresLineShift(t *testing.T) {
	// An edit higher up the same file (a lockfile bump) shifts every finding
	// below it; the same CVE on the same package must still match.
	base := FromReport(&sarif.Report{Runs: []sarif.Run{
		mk("trivy", "CVE-1", "/wt/package-lock.json", 3953),
	}}, "/wt")
	cur := &sarif.Report{Runs: []sarif.Run{
		mk("trivy", "CVE-1", "/repo/package-lock.json", 4104),
	}}
	if n := ApplyRoot(cur, base, "/repo"); n != 1 {
		t.Fatalf("suppressed = %d, want 1", n)
	}
}

func TestDuplicateInstancesBeyondBaselineCountStillGate(t *testing.T) {
	// Line identity is gone in cross-checkout mode, so duplicates are
	// bounded by COUNT: one baseline instance suppresses one current match;
	// a second identical instance the change introduces stays gating.
	base := FromReport(&sarif.Report{Runs: []sarif.Run{
		mk("zizmor", "unpinned", "/wt/.github/workflows/ci.yml", 10),
	}}, "/wt")
	cur := &sarif.Report{Runs: []sarif.Run{
		mk("zizmor", "unpinned", "/repo/.github/workflows/ci.yml", 10),
		mk("zizmor", "unpinned", "/repo/.github/workflows/ci.yml", 90),
	}}
	if n := ApplyRoot(cur, base, "/repo"); n != 1 {
		t.Fatalf("suppressed = %d, want 1", n)
	}
	if !cur.Runs[0].Results[0].Suppressed() {
		t.Error("first instance should be suppressed")
	}
	if cur.Runs[1].Results[0].Suppressed() {
		t.Error("second (new) instance must keep gating")
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

// The catena-ce oauth2-proxy bump PR, end to end: the advisory both images
// carry is suppressed, and the one only the new image carries still gates.
func TestABumpGatesOnlyOnTheAdvisoriesItAdds(t *testing.T) {
	vuln := func(cve, pkg, version, image string) sarif.Run {
		r := mk("trivy", cve, "oauth2-proxy/oauth2-proxy", 1)
		r.Results[0].Message.Text = "Package: " + pkg + "\nInstalled Version: " + version +
			"\nVulnerability " + cve + "\nSeverity: HIGH"
		r.Results[0].Properties = map[string]any{sarif.ImageProperty: image}
		return r
	}
	const before = "quay.io/oauth2-proxy/oauth2-proxy:v7.14.3-alpine"
	const after = "quay.io/oauth2-proxy/oauth2-proxy:v7.15.4-alpine"
	base := FromReport(&sarif.Report{Runs: []sarif.Run{
		vuln("CVE-2026-14456", "libssl3", "3.5.5-r0", before),
	}}, "/wt")
	cur := &sarif.Report{Runs: []sarif.Run{
		vuln("CVE-2026-14456", "libssl3", "3.5.7-r0", after),
		vuln("CVE-2026-99999", "libssl3", "3.5.7-r0", after),
	}}
	if n := ApplyRoot(cur, base, "/repo"); n != 1 {
		t.Fatalf("suppressed = %d, want 1", n)
	}
	if !cur.Runs[0].Results[0].Suppressed() {
		t.Error("the advisory the old image already carried gated the bump")
	}
	if cur.Runs[1].Results[0].Suppressed() {
		t.Error("the advisory the bump adds must keep gating")
	}
}

func TestLoadReportOfAMissingFileIsNil(t *testing.T) {
	rep, err := LoadReport("/nonexistent/baseline.sarif")
	if err != nil {
		t.Fatalf("missing baseline should not error: %v", err)
	}
	if rep != nil {
		t.Errorf("missing baseline = %v, want nil", rep)
	}
}

// A fixed finding leaves its accepted entry behind; the entry would silently
// accept the finding again if it came back.
func TestStaleNamesTheEntriesTheScanDoesNotProduce(t *testing.T) {
	base := &sarif.Report{Runs: []sarif.Run{
		mk("semgrep", "renovate-age", "renovate.json", 5),
		mk("semgrep", "renovate-age", "renovate.json", 5),
		mk("gosec", "G304", "a.go", 3),
	}}
	cur := &sarif.Report{Runs: []sarif.Run{
		mk("semgrep", "renovate-age", "renovate.json", 5),
	}}
	stale := Stale(base, cur, true)
	if len(stale) != 2 {
		t.Fatalf("stale = %v, want the second renovate-age instance and the gosec entry", stale)
	}
	if stale[0].Tool != "semgrep" || stale[1].Tool != "gosec" {
		t.Errorf("stale = %v", stale)
	}
}

// entry is a baseline result for tool; until is its acceptedUntil ("" for none)
// and image its image property ("" for a finding in the tree).
func entry(rule, until, image string) sarif.Run {
	r := mk("trivy", rule, "uv.lock", 1)
	props := map[string]any{}
	if until != "" {
		props[AcceptedUntil] = until
	}
	if image != "" {
		props[sarif.ImageProperty] = image
	}
	r.Results[0].Properties = props
	return r
}

func TestSplitKeepsAnEntryAcceptedUntilAFutureDate(t *testing.T) {
	live, expired := Split(&sarif.Report{Runs: []sarif.Run{entry("CVE-1", "2026-10-20", "")}}, today)
	if len(expired) != 0 || live.ResultCount() != 1 {
		t.Errorf("live = %d, expired = %v, want the entry live", live.ResultCount(), expired)
	}
}

func TestSplitExpiresAnEntryWhoseDateHasPassed(t *testing.T) {
	live, expired := Split(&sarif.Report{Runs: []sarif.Run{entry("CVE-1", "2026-10-18", "")}}, today)
	if len(expired) != 1 || live.ResultCount() != 0 {
		t.Errorf("live = %d, expired = %v, want the entry expired", live.ResultCount(), expired)
	}
}

func TestSplitExpiresAnImageEntryWithNoDate(t *testing.T) {
	_, expired := Split(&sarif.Report{Runs: []sarif.Run{entry("CVE-1/postgres", "", "postgres:18")}}, today)
	if len(expired) != 1 {
		t.Errorf("expired = %v, want the undated image entry", expired)
	}
}

func TestSplitKeepsAnUndatedEntryInTheTree(t *testing.T) {
	live, expired := Split(&sarif.Report{Runs: []sarif.Run{entry("CVE-1", "", "")}}, today)
	if len(expired) != 0 || live.ResultCount() != 1 {
		t.Errorf("live = %d, expired = %v, want the undated tree entry live", live.ResultCount(), expired)
	}
}

func TestSplitExpiresAnEntryWithAnUnparseableDate(t *testing.T) {
	_, expired := Split(&sarif.Report{Runs: []sarif.Run{entry("CVE-1", "2026-13-01", "")}}, today)
	if len(expired) != 1 {
		t.Errorf("expired = %v, want the entry with a month 13 expired", expired)
	}
}

func TestStaleSkipsAnUnmatchedImageEntryWhenNotEveryImageWasScanned(t *testing.T) {
	base := &sarif.Report{Runs: []sarif.Run{entry("CVE-1/postgres", "2026-12-01", "postgres:18"), entry("CVE-2", "", "")}}
	stale := Stale(base, &sarif.Report{}, false)
	if len(stale) != 1 || stale[0].Result.RuleID != "CVE-2" {
		t.Errorf("stale = %v, want the tree entry only", stale)
	}
}

func TestStaleReportsAnUnmatchedImageEntryWhenEveryImageWasScanned(t *testing.T) {
	base := &sarif.Report{Runs: []sarif.Run{entry("CVE-1/postgres", "2026-12-01", "postgres:18"), entry("CVE-2", "", "")}}
	if stale := Stale(base, &sarif.Report{}, true); len(stale) != 2 {
		t.Errorf("stale = %v, want both entries", stale)
	}
}

func TestApplyMarksTheBaselineAndTheDiffApart(t *testing.T) {
	cur := &sarif.Report{Runs: []sarif.Run{mk("gosec", "G304", "/repo/a.go", 5), mk("gosec", "G401", "/repo/b.go", 9)}}
	Apply(cur, fingerprints(&sarif.Report{Runs: []sarif.Run{mk("gosec", "G304", "/repo/a.go", 5)}}))
	ApplyRoot(cur, FromReport(&sarif.Report{Runs: []sarif.Run{mk("gosec", "G401", "/wt/b.go", 9)}}, "/wt"), "/repo")
	if got := cur.Runs[0].Results[0].Suppressions[0].Justification; got != sarif.AcceptedInBaseline {
		t.Errorf("baseline justification = %q", got)
	}
	if got := cur.Runs[1].Results[0].Suppressions[0].Justification; got != sarif.PresentBefore {
		t.Errorf("diff justification = %q", got)
	}
}
