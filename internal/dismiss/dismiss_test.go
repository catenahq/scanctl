package dismiss

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/catenahq/scanctl/internal/sarif"
)

func result(tool, rule, path string, line int, suppressed bool) sarif.Result {
	r := sarif.Result{
		RuleID: rule,
		Locations: []sarif.Location{{PhysicalLocation: sarif.PhysicalLocation{
			ArtifactLocation: sarif.ArtifactLocation{URI: path},
			Region:           &sarif.Region{StartLine: line},
		}}},
	}
	if suppressed {
		r.Suppressions = []sarif.Suppression{{Kind: "external"}}
	}
	_ = tool
	return r
}

func report(tool string, results ...sarif.Result) *sarif.Report {
	rep := sarif.New()
	rep.Runs = append(rep.Runs, sarif.Run{
		Tool:    sarif.Tool{Driver: sarif.Driver{Name: tool}},
		Results: results,
	})
	return rep
}

func TestDismissMatchesAndSkipsUnsuppressed(t *testing.T) {
	var dismissed []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/code-scanning/alerts"):
			if r.URL.Query().Get("state") != "open" {
				t.Errorf("state = %q, want open", r.URL.Query().Get("state"))
			}
			fmt.Fprint(w, `[
				{"number": 55, "rule": {"id": "renovate-missing-minimum-release-age"}, "tool": {"name": "semgrep"}, "most_recent_instance": {"location": {"path": "renovate.json", "start_line": 1}}},
				{"number": 60, "rule": {"id": "CVE-2026-1"}, "tool": {"name": "trivy"}, "most_recent_instance": {"location": {"path": "package-lock.json", "start_line": 4}}}
			]`)
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/code-scanning/alerts/"):
			var n int
			fmt.Sscanf(r.URL.Path, "/repos/o/r/code-scanning/alerts/%d", &n)
			dismissed = append(dismissed, n)
			auth := r.Header.Get("Authorization")
			if auth != "Bearer secret" {
				t.Errorf("auth = %q", auth)
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	// Only the semgrep/renovate.json:1 result is baseline-suppressed; the
	// trivy result at a DIFFERENT line is not, and must not be touched even
	// though an open alert with the same rule/tool/file exists at a
	// different line.
	rep := report("semgrep", result("semgrep", "renovate-missing-minimum-release-age", "renovate.json", 1, true))
	rep.Merge(report("trivy", result("trivy", "CVE-2026-1", "package-lock.json", 9, false)))

	c := Client{BaseURL: srv.URL, Owner: "o", Repo: "r", Token: "secret", HTTPClient: srv.Client()}
	n, err := c.Dismiss(context.Background(), rep)
	if err != nil {
		t.Fatalf("dismiss: %v", err)
	}
	if n != 1 {
		t.Errorf("dismissed count = %d, want 1", n)
	}
	if len(dismissed) != 1 || dismissed[0] != 55 {
		t.Errorf("dismissed alerts = %v, want [55]", dismissed)
	}
}

func TestDismissNoOpWhenNothingSuppressed(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	rep := report("trivy", result("trivy", "CVE-2026-1", "package-lock.json", 9, false))
	c := Client{BaseURL: srv.URL, Owner: "o", Repo: "r", Token: "secret", HTTPClient: srv.Client()}
	n, err := c.Dismiss(context.Background(), rep)
	if err != nil {
		t.Fatalf("dismiss: %v", err)
	}
	if n != 0 {
		t.Errorf("dismissed count = %d, want 0", n)
	}
	if called {
		t.Error("should not call the API when nothing is baseline-suppressed")
	}
}

func TestListOpenAlertsFollowsPagination(t *testing.T) {
	page := 0
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/repos/o/r/code-scanning/alerts", func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			w.Header().Set("Link", fmt.Sprintf(`<%s/repos/o/r/code-scanning/alerts?state=open&per_page=100&page=2>; rel="next"`, srv.URL))
			fmt.Fprint(w, `[{"number": 1, "rule": {"id": "r1"}, "tool": {"name": "t"}, "most_recent_instance": {"location": {"path": "a", "start_line": 1}}}]`)
			return
		}
		fmt.Fprint(w, `[{"number": 2, "rule": {"id": "r1"}, "tool": {"name": "t"}, "most_recent_instance": {"location": {"path": "b", "start_line": 1}}}]`)
	})
	c := Client{BaseURL: srv.URL, Owner: "o", Repo: "r", Token: "x", HTTPClient: srv.Client()}
	alerts, err := c.listOpenAlerts(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(alerts) != 2 {
		t.Fatalf("got %d alerts, want 2 (pagination not followed)", len(alerts))
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY", "")
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	if _, ok := FromEnv(); ok {
		t.Error("should be inactive with no repository/token")
	}

	t.Setenv("GITHUB_REPOSITORY", "catenahq/website")
	if _, ok := FromEnv(); ok {
		t.Error("should be inactive with no token")
	}

	t.Setenv("GH_TOKEN", "tok")
	c, ok := FromEnv()
	if !ok {
		t.Fatal("should be active")
	}
	if c.Owner != "catenahq" || c.Repo != "website" || c.Token != "tok" {
		t.Errorf("unexpected client: %+v", c)
	}
}
