// Package dismiss closes GitHub code-scanning alerts that scanctl's baseline
// diff marked suppressed (kind "external"). GitHub's SARIF ingestion honors
// in-source suppressions (e.g. a semgrep nosemgrep comment) and shows them
// dismissed on upload, but does NOT act on externally-asserted suppressions --
// confirmed empirically: a finding present in a committed .scanctl/baseline.sarif
// gets marked suppressed in the uploaded report (internal/baseline), yet stays
// open on the Security tab. Package dismiss closes that gap directly through
// the code-scanning alerts REST API instead of relying on the SARIF upload to
// do it.
package dismiss

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/catenahq/scanctl/internal/sarif"
)

// Client dismisses code-scanning alerts on one repo.
type Client struct {
	BaseURL     string // default https://api.github.com; overridable for tests
	Owner, Repo string
	Token       string
	HTTPClient  *http.Client
}

// FromEnv builds a client from the GitHub Actions environment: GITHUB_REPOSITORY
// for owner/repo, GH_TOKEN (falling back to GITHUB_TOKEN) for auth. ok is false
// (no error) when either is missing, so a caller running outside Actions -- or
// against a fork/PR context this feature deliberately excludes -- skips
// silently.
func FromEnv() (Client, bool) {
	owner, repo, ok := strings.Cut(os.Getenv("GITHUB_REPOSITORY"), "/")
	if !ok {
		return Client{}, false
	}
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		return Client{}, false
	}
	return Client{
		BaseURL:    "https://api.github.com",
		Owner:      owner,
		Repo:       repo,
		Token:      token,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}, true
}

type alert struct {
	Number int `json:"number"`
	Rule   struct {
		ID string `json:"id"`
	} `json:"rule"`
	Tool struct {
		Name string `json:"name"`
	} `json:"tool"`
	MostRecentInstance struct {
		Location struct {
			Path      string `json:"path"`
			StartLine int    `json:"start_line"`
		} `json:"location"`
	} `json:"most_recent_instance"`
}

// Dismiss closes every open alert matching a baseline-suppressed result in rep.
// Matching is coarser than sarif.Fingerprint (tool+rule+file+line, no message
// text): that's the only identity the alerts API exposes for a third-party
// result, and it is only ever used to LOCATE the live alert -- baseline.Apply
// already decided suppression on the finer-grained fingerprint. Returns the
// count dismissed.
func (c Client) Dismiss(ctx context.Context, rep *sarif.Report) (int, error) {
	wanted := map[string]bool{}
	for _, run := range rep.Runs {
		tool := run.Tool.Driver.Name
		for _, r := range run.Results {
			if !externallySuppressed(r) || len(r.Locations) == 0 {
				continue
			}
			pl := r.Locations[0].PhysicalLocation
			line := 0
			if pl.Region != nil {
				line = pl.Region.StartLine
			}
			wanted[matchKey(tool, r.RuleID, pl.ArtifactLocation.URI, line)] = true
		}
	}
	if len(wanted) == 0 {
		return 0, nil
	}

	alerts, err := c.listOpenAlerts(ctx)
	if err != nil {
		return 0, fmt.Errorf("dismiss: list alerts: %w", err)
	}

	n := 0
	for _, a := range alerts {
		k := matchKey(a.Tool.Name, a.Rule.ID, a.MostRecentInstance.Location.Path, a.MostRecentInstance.Location.StartLine)
		if !wanted[k] {
			continue
		}
		if err := c.dismissAlert(ctx, a.Number); err != nil {
			return n, fmt.Errorf("dismiss: alert #%d: %w", a.Number, err)
		}
		n++
	}
	return n, nil
}

func externallySuppressed(r sarif.Result) bool {
	for _, s := range r.Suppressions {
		if s.Kind == "external" {
			return true
		}
	}
	return false
}

func matchKey(tool, ruleID, path string, line int) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%d", tool, ruleID, path, line)
}

func (c Client) listOpenAlerts(ctx context.Context) ([]alert, error) {
	var all []alert
	url := fmt.Sprintf("%s/repos/%s/%s/code-scanning/alerts?state=open&per_page=100", c.BaseURL, c.Owner, c.Repo)
	for url != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		c.authorize(req)
		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			return nil, fmt.Errorf("status %d: %s", resp.StatusCode, snippet)
		}
		var page []alert
		err = json.NewDecoder(resp.Body).Decode(&page)
		next := nextLink(resp.Header.Get("Link"))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		url = next
	}
	return all, nil
}

// nextLink extracts the "next" URL from a GitHub-style RFC 5988 Link header
// (pagination); "" when there is no next page.
func nextLink(h string) string {
	for _, part := range strings.Split(h, ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		if len(fields) < 2 {
			continue
		}
		for _, rel := range fields[1:] {
			if strings.TrimSpace(rel) == `rel="next"` {
				return strings.Trim(strings.TrimSpace(fields[0]), "<>")
			}
		}
	}
	return ""
}

func (c Client) dismissAlert(ctx context.Context, number int) error {
	body, err := json.Marshal(map[string]any{
		"state":             "dismissed",
		"dismissed_reason":  "won't fix",
		"dismissed_comment": "matches committed scanctl baseline (.scanctl/baseline.sarif)",
	})
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/repos/%s/%s/code-scanning/alerts/%d", c.BaseURL, c.Owner, c.Repo, number)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.authorize(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("status %d: %s", resp.StatusCode, snippet)
	}
	return nil
}

func (c Client) authorize(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
}
