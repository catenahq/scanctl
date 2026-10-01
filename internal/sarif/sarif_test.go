package sarif

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeRendersEmptyResultsArray(t *testing.T) {
	// A run with nil Results must marshal as [] not null (SARIF schema requires
	// an array; GitHub code scanning + DefectDojo reject null).
	r := &Report{Runs: []Run{{Tool: Tool{Driver: Driver{Name: "x"}}}}}
	r.Normalize()
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"results":null`) {
		t.Errorf("normalized SARIF still has null results: %s", data)
	}
	if !strings.Contains(string(data), `"results":[]`) {
		t.Errorf("expected empty results array: %s", data)
	}
}

func TestSuppressionsRoundTrip(t *testing.T) {
	// A semgrep nosemgrep finding arrives with suppressions; the merged output
	// must keep them so GitHub creates the alert dismissed, not open.
	in := []byte(`{"$schema":"x","version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},` +
		`"results":[{"ruleId":"r","level":"warning","message":{"text":"m"},` +
		`"suppressions":[{"kind":"inSource"}]}]}]}`)
	var rep Report
	if err := json.Unmarshal(in, &rep); err != nil {
		t.Fatal(err)
	}
	res := rep.Runs[0].Results[0]
	if !res.Suppressed() {
		t.Fatal("Suppressed() = false, want true")
	}
	out, err := json.Marshal(&rep)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"suppressions":[{"kind":"inSource"}]`) {
		t.Errorf("suppressions dropped on re-marshal: %s", out)
	}
}

func TestPropertiesAndFingerprintsRoundTrip(t *testing.T) {
	in := []byte(`{"runs":[{"tool":{"driver":{"name":"trivy","rules":[` +
		`{"id":"R","properties":{"security-severity":"7.5"}}]}},` +
		`"results":[{"ruleId":"R","level":"error","message":{"text":"m"},` +
		`"partialFingerprints":{"primaryLocationLineHash":"abc"},"properties":{"k":"v"}}]}]}`)
	var rep Report
	if err := json.Unmarshal(in, &rep); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(&rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"security-severity":"7.5"`, `"primaryLocationLineHash":"abc"`, `"k":"v"`} {
		if !strings.Contains(string(out), want) {
			t.Errorf("dropped %q on re-marshal: %s", want, out)
		}
	}
	if s, ok := SecuritySeverity(rep.Runs[0].Tool.Driver.Rules[0].Properties); !ok || s != 7.5 {
		t.Errorf("SecuritySeverity = %v,%v want 7.5,true", s, ok)
	}
	if _, ok := SecuritySeverity(map[string]any{}); ok {
		t.Error("SecuritySeverity ok on empty props")
	}
}

func TestFingerprint(t *testing.T) {
	r := Result{RuleID: "R", Message: Message{Text: "m"}, Locations: []Location{{
		PhysicalLocation: PhysicalLocation{
			ArtifactLocation: ArtifactLocation{URI: "a.go"}, Region: &Region{StartLine: 3}}}}}
	if Fingerprint("trivy", r) != Fingerprint("trivy", r) {
		t.Error("fingerprint not stable")
	}
	if Fingerprint("trivy", r) == Fingerprint("gosec", r) {
		t.Error("tool not part of fingerprint")
	}
	r2 := Result{RuleID: "R", PartialFingerprints: map[string]string{"primaryLocationLineHash": "h"}}
	if got := Fingerprint("trivy", r2); got != "trivy:R:h" {
		t.Errorf("partialFingerprint path = %q, want trivy:R:h", got)
	}
}

// trivyVuln is trivy's SARIF result for one advisory in one package at one
// installed version; image is the ref the runner tags it with ("" for the fs
// scan).
func trivyVuln(cve, pkg, version, uri, image string) Result {
	r := Result{
		RuleID: cve,
		Message: Message{Text: "Package: " + pkg + "\nInstalled Version: " + version +
			"\nVulnerability " + cve + "\nSeverity: HIGH\nFixed Version: 9.9.9\nLink: [" + cve + "](https://avd.aquasec.com)"},
		Locations: []Location{{PhysicalLocation: PhysicalLocation{
			ArtifactLocation: ArtifactLocation{URI: uri}, Region: &Region{StartLine: 1}}}},
	}
	if image != "" {
		r.Properties = map[string]any{ImageProperty: image}
	}
	return r
}

// osvVuln is osv-scanner's SARIF result for one advisory in one package. It
// ships its own primaryLocationLineHash, which differs per version.
func osvVuln(cve, spec, uri string) Result {
	return Result{
		RuleID:              cve,
		Message:             Message{Text: "Package '" + spec + "' is vulnerable to '" + cve + "' (also known as 'GO-2024-2687')."},
		Locations:           []Location{{PhysicalLocation: PhysicalLocation{ArtifactLocation: ArtifactLocation{URI: uri}}}},
		PartialFingerprints: map[string]string{"primaryLocationLineHash": "hash-of-" + spec},
	}
}

// catena-ce's oauth2-proxy bump moved libssl3 from 3.5.5 to 3.5.7 and both
// versions carry CVE-2026-14456. Same advisory, same package, same image: one
// vulnerability, whatever the version and tag.
func TestFingerprintKeepsAVulnAcrossAnImageBump(t *testing.T) {
	before := trivyVuln("CVE-2026-14456", "libssl3", "3.5.5-r0", "oauth2-proxy/oauth2-proxy",
		"quay.io/oauth2-proxy/oauth2-proxy:v7.14.3-alpine")
	after := trivyVuln("CVE-2026-14456", "libssl3", "3.5.7-r0", "oauth2-proxy/oauth2-proxy",
		"quay.io/oauth2-proxy/oauth2-proxy:v7.15.4-alpine")
	if Fingerprint("trivy", before) != Fingerprint("trivy", after) {
		t.Error("a bump that keeps the advisory in the same package must not read as a new vulnerability")
	}
}

// A jar inside an image is named for its version, so the in-image path trivy
// reports moves with the bump as well.
func TestFingerprintIgnoresTheInImagePath(t *testing.T) {
	before := trivyVuln("CVE-2026-68497", "com.fasterxml.jackson.core:jackson-databind", "2.21.1",
		"opt/keycloak/lib/jackson-databind-2.21.1.jar", "quay.io/phasetwo/phasetwo-keycloak:26.6.4")
	after := trivyVuln("CVE-2026-68497", "com.fasterxml.jackson.core:jackson-databind", "2.21.5",
		"opt/keycloak/lib/jackson-databind-2.21.5.jar", "quay.io/phasetwo/phasetwo-keycloak:26.6.7")
	if Fingerprint("trivy", before) != Fingerprint("trivy", after) {
		t.Error("the jar's versioned path must not split one vulnerability in two")
	}
}

func TestFingerprintSeparatesVulnsByAdvisoryPackageAndImage(t *testing.T) {
	base := trivyVuln("CVE-1", "libssl3", "3.5.7-r0", "a/a", "a/a:1")
	for name, other := range map[string]Result{
		"advisory": trivyVuln("CVE-2", "libssl3", "3.5.7-r0", "a/a", "a/a:1"),
		"package":  trivyVuln("CVE-1", "libcrypto3", "3.5.7-r0", "a/a", "a/a:1"),
		"image":    trivyVuln("CVE-1", "libssl3", "3.5.7-r0", "b/b", "b/b:1"),
	} {
		if Fingerprint("trivy", base) == Fingerprint("trivy", other) {
			t.Errorf("a different %s must be a different vulnerability", name)
		}
	}
}

// The fs scans name the manifest or lockfile, which stays put across a
// dependency bump; osv-scanner's own hash does not.
func TestFingerprintKeepsALockfileVulnAcrossADependencyBump(t *testing.T) {
	if Fingerprint("trivy", trivyVuln("CVE-1", "urllib3", "2.6.0", "uv.lock", "")) !=
		Fingerprint("trivy", trivyVuln("CVE-1", "urllib3", "2.6.1", "uv.lock", "")) {
		t.Error("trivy: a bump that keeps the advisory must not read as new")
	}
	if Fingerprint("osv-scanner", osvVuln("CVE-2023-45288", "golang.org/x/net@0.20.0", "go.mod")) !=
		Fingerprint("osv-scanner", osvVuln("CVE-2023-45288", "golang.org/x/net@0.21.0", "go.mod")) {
		t.Error("osv-scanner: a bump that keeps the advisory must not read as new")
	}
	if Fingerprint("osv-scanner", osvVuln("CVE-2023-45288", "golang.org/x/net@0.20.0", "go.mod")) ==
		Fingerprint("osv-scanner", osvVuln("CVE-2023-45288", "golang.org/x/net@0.20.0", "tools/go.mod")) {
		t.Error("the same package in another manifest is another vulnerability")
	}
}

func TestVulnPackageReadsAScopedNpmName(t *testing.T) {
	got, ok := vulnPackage("osv-scanner", "Package '@scope/pkg@1.2.3' is vulnerable to 'GHSA-x'.")
	if !ok || got != "@scope/pkg" {
		t.Errorf("vulnPackage = %q,%v want @scope/pkg,true", got, ok)
	}
}

// A trivy misconfig or secret finding names no package, so its message stays
// part of the fingerprint.
func TestFingerprintOfANonVulnFindingStillReadsTheMessage(t *testing.T) {
	a := Result{RuleID: "DS002", Message: Message{Text: "Artifact: Dockerfile\nType: dockerfile\nSpecified user is root"}}
	b := Result{RuleID: "DS002", Message: Message{Text: "Artifact: build/Dockerfile\nType: dockerfile\nSpecified user is root"}}
	if _, ok := vulnIdentity("trivy", a); ok {
		t.Error("a misconfig finding was read as a dependency vulnerability")
	}
	if Fingerprint("trivy", a) == Fingerprint("trivy", b) {
		t.Error("two different misconfig findings collided")
	}
}

func TestImageRepoDropsTagAndDigest(t *testing.T) {
	for ref, want := range map[string]string{
		"quay.io/oauth2-proxy/oauth2-proxy:v7.15.4-alpine": "quay.io/oauth2-proxy/oauth2-proxy",
		"postgres:18.6-alpine":                             "postgres",
		"postgres:18@sha256:abc":                           "postgres",
		"postgres@sha256:abc":                              "postgres",
		"localhost:5000/app:1.0":                           "localhost:5000/app",
		"localhost:5000/app":                               "localhost:5000/app",
		"postgres":                                         "postgres",
	} {
		if got := ImageRepo(ref); got != want {
			t.Errorf("ImageRepo(%q) = %q, want %q", ref, got, want)
		}
	}
}

func run(tool string, n int) Run {
	r := Run{Tool: Tool{Driver: Driver{Name: tool}}}
	for i := 0; i < n; i++ {
		r.Results = append(r.Results, Result{Level: LevelError, Message: Message{Text: "x"}})
	}
	return r
}

func TestMergePreservesRuns(t *testing.T) {
	dst := New()
	a := &Report{Runs: []Run{run("trivy", 2)}}
	b := &Report{Runs: []Run{run("gosec", 3)}}
	dst.Merge(a)
	dst.Merge(b)
	dst.Merge(nil) // nil is a no-op

	if len(dst.Runs) != 2 {
		t.Fatalf("runs = %d, want 2", len(dst.Runs))
	}
	if dst.ResultCount() != 5 {
		t.Errorf("result count = %d, want 5", dst.ResultCount())
	}
	if dst.Runs[0].Tool.Driver.Name != "trivy" || dst.Runs[1].Tool.Driver.Name != "gosec" {
		t.Error("per-tool run identity not preserved after merge")
	}
}
