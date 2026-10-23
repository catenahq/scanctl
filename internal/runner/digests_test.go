package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const committedLock = "../../tools.lock"

// readFile returns the contents of a file the test names.
func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p) // #nosec G304 -- path is the repo's own file or under the test's temp dir
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// lockCopy writes text to a tools.lock in a temp dir and returns its path.
func lockCopy(t *testing.T, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tools.lock")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// serveAt points the downloads at a server answering the URL paths in files
// (path -> bytes), 404 for any other; it returns the paths requested.
func serveAt(t *testing.T, files map[string]string) *[]string {
	t.Helper()
	var requested []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)
		body, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	saved := githubDownload
	githubDownload = srv.URL
	t.Cleanup(func() { githubDownload = saved })
	return &requested
}

// This is the check that fails a tools.lock bump whose digests were not
// refreshed.
func TestEveryReleaseFileOfThePinnedVersionsHasItsDigest(t *testing.T) {
	lock, err := LoadLock(committedLock)
	if err != nil {
		t.Fatal(err)
	}
	for tool := range releaseTools {
		e, ok := lock.Tools[tool]
		if !ok || e.Repo == "" {
			t.Errorf("tools.lock pins %q without a repo (pinned: %v)", tool, ok)
		}
	}
	if stale := staleDigests(lock); len(stale) != 0 {
		t.Errorf("tools.lock holds no digest for the pinned version of %v; run scanctl refresh-digests", stale)
	}
}

func TestTheCommittedLockIsInTheFormTheRefreshWrites(t *testing.T) {
	text := readFile(t, committedLock)
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	if buf.String() != text {
		t.Errorf("tools.lock differs from its re-encoding:\n%s", buf.String())
	}
}

func TestACurrentLockIsLeftAsItIs(t *testing.T) {
	requested := serveAt(t, nil)
	path := lockCopy(t, readFile(t, committedLock))

	var out bytes.Buffer
	if err := RefreshDigests(context.Background(), path, &out); err != nil {
		t.Fatal(err)
	}
	if len(*requested) != 0 || readFile(t, path) != readFile(t, committedLock) {
		t.Errorf("a current lock made %v requests or changed", *requested)
	}
}

func TestABumpedVersionGetsTheDigestOfItsFile(t *testing.T) {
	withReleaseTools(t, map[string]releaseTool{"scan": {asset: func(string) string { return "scan_amd64" }}})
	serveDownloads(t, map[string]string{"scan_amd64": "new bytes"})
	const before = "# header\ntools:\n  scan:\n    repo: o/r\n    # renovate: datasource=github-releases depName=o/r\n    version: 1.0.0\n    sha256:\n      v0.9.0/scan_amd64: " +
		"0000000000000000000000000000000000000000000000000000000000000000\n  other:\n    version: 2.0.0\n"
	path := lockCopy(t, before)

	var out bytes.Buffer
	if err := RefreshDigests(context.Background(), path, &out); err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(before, "v0.9.0/scan_amd64: 0000000000000000000000000000000000000000000000000000000000000000",
		"v1.0.0/scan_amd64: "+digestOf("new bytes"), 1)
	if got := readFile(t, path); got != want {
		t.Errorf("tools.lock after the refresh:\n%s\nwant:\n%s", got, want)
	}
	if !strings.Contains(out.String(), "scan 1.0.0") {
		t.Errorf("output = %q, want it to name the refreshed tool", out.String())
	}
}

func TestABumpedVersionWithNoDigestBlockGetsOne(t *testing.T) {
	withReleaseTools(t, map[string]releaseTool{"scan": {asset: func(string) string { return "scan_amd64" }}})
	serveDownloads(t, map[string]string{"scan_amd64": "new bytes"})
	path := lockCopy(t, "tools:\n  scan:\n    repo: o/r\n    # renovate: datasource=github-releases depName=o/r\n    version: 1.0.0\n  other:\n    version: 2.0.0\n")

	if err := RefreshDigests(context.Background(), path, io.Discard); err != nil {
		t.Fatal(err)
	}
	want := "tools:\n  scan:\n    repo: o/r\n    # renovate: datasource=github-releases depName=o/r\n    version: 1.0.0\n    sha256:\n      v1.0.0/scan_amd64: " +
		digestOf("new bytes") + "\n  other:\n    version: 2.0.0\n"
	if got := readFile(t, path); got != want {
		t.Errorf("tools.lock after the refresh:\n%s\nwant:\n%s", got, want)
	}
}

func TestARefreshKeepsRenovatesMarkers(t *testing.T) {
	committed := readFile(t, committedLock)
	lock, err := ParseLock([]byte(committed))
	if err != nil {
		t.Fatal(err)
	}
	trivy := lock.Tools["trivy"]
	key := expectedDigestKey("trivy", trivy.Version)
	block := "    sha256:\n      " + key + ": " + trivy.SHA256[key] + "\n"
	if !strings.Contains(committed, block) {
		t.Fatalf("tools.lock holds no trivy block %q", block)
	}
	path := lockCopy(t, strings.Replace(committed, block, "", 1))
	serveAt(t, map[string]string{"/aquasecurity/trivy/releases/download/" + key: "served bytes"})

	if err := RefreshDigests(context.Background(), path, io.Discard); err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(committed, trivy.SHA256[key], digestOf("served bytes"), 1)
	got := readFile(t, path)
	if got != want {
		t.Errorf("tools.lock after the refresh:\n%s\nwant:\n%s", got, want)
	}

	var cfg struct {
		CustomManagers []struct {
			MatchStrings []string `json:"matchStrings"`
		} `json:"customManagers"`
	}
	if err := json.Unmarshal([]byte(readFile(t, "../../renovate.json")), &cfg); err != nil {
		t.Fatal(err)
	}
	rx := regexp.MustCompile(cfg.CustomManagers[0].MatchStrings[0])
	versions := func(text string) []string {
		var vs []string
		for _, m := range rx.FindAllStringSubmatch(text, -1) {
			vs = append(vs, m[rx.SubexpIndex("depName")]+" "+m[rx.SubexpIndex("currentValue")])
		}
		return vs
	}
	if after, before := versions(got), versions(committed); len(after) != 9 || !slices.Equal(after, before) {
		t.Errorf("renovate's regex finds %v after the refresh, want the nine of %v", after, before)
	}
}

func TestADownloadFailureWritesNothing(t *testing.T) {
	withReleaseTools(t, map[string]releaseTool{"scan": {asset: func(string) string { return "scan_amd64" }}})
	serveDownloads(t, nil)
	const before = "tools:\n  scan:\n    repo: o/r\n    version: 1.0.0\n"
	path := lockCopy(t, before)

	err := RefreshDigests(context.Background(), path, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "/o/r/releases/download/v1.0.0/scan_amd64: status 404") {
		t.Fatalf("error = %v, want the download URL and its status", err)
	}
	if got := readFile(t, path); got != before {
		t.Errorf("tools.lock changed:\n%s", got)
	}
}

func TestStaleDigestsNamesMissingOldAndMalformedEntries(t *testing.T) {
	withReleaseTools(t, map[string]releaseTool{
		"current":   {asset: func(string) string { return "current_amd64" }},
		"missing":   {asset: func(string) string { return "missing_amd64" }},
		"old":       {asset: func(string) string { return "old_amd64" }},
		"malformed": {asset: func(string) string { return "malformed_amd64" }},
		"extra":     {asset: func(string) string { return "extra_amd64" }},
		"norepo":    {asset: func(string) string { return "norepo_amd64" }},
		"unpinned":  {asset: func(string) string { return "unpinned_amd64" }},
	})
	good := strings.Repeat("a", 64)
	lock := Lock{Tools: map[string]LockEntry{
		"current":   {Repo: "o/r", Version: "1.0.0", SHA256: map[string]string{"v1.0.0/current_amd64": good}},
		"missing":   {Repo: "o/r", Version: "1.0.0"},
		"old":       {Repo: "o/r", Version: "1.0.0", SHA256: map[string]string{"v0.9.0/old_amd64": good}},
		"malformed": {Repo: "o/r", Version: "1.0.0", SHA256: map[string]string{"v1.0.0/malformed_amd64": "sha256:" + good}},
		"extra":     {Repo: "o/r", Version: "1.0.0", SHA256: map[string]string{"v1.0.0/extra_amd64": good, "v0.9.0/extra_amd64": good}},
		"norepo":    {Version: "1.0.0", SHA256: map[string]string{"v1.0.0/norepo_amd64": good}},
	}}

	want := []string{"extra", "malformed", "missing", "norepo", "old"}
	if got := staleDigests(lock); !slices.Equal(got, want) {
		t.Errorf("staleDigests = %v, want %v", got, want)
	}
}
