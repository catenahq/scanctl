package upload

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// DependencyTrack uploads a CycloneDX SBOM via PUT /api/v1/bom. autoCreate makes
// the project on first upload; subsequent uploads version the same project and
// feed DT's continuous OSV monitoring + license policy.
type DependencyTrack struct {
	BaseURL        string
	APIKey         string
	ProjectName    string
	ProjectVersion string
	HTTPClient     *http.Client
}

// DependencyTrackFromEnv builds a client from config + DEPENDENCYTRACK_APIKEY.
// ok is false (no error) when not configured, so the caller skips silently.
func DependencyTrackFromEnv(url, project, version string) (DependencyTrack, bool) {
	if url == "" {
		return DependencyTrack{}, false
	}
	key := os.Getenv("DEPENDENCYTRACK_APIKEY")
	if key == "" {
		return DependencyTrack{}, false
	}
	if project == "" {
		project = "scanctl"
	}
	if version == "" {
		version = "latest"
	}
	return DependencyTrack{
		BaseURL:        strings.TrimRight(url, "/"),
		APIKey:         key,
		ProjectName:    project,
		ProjectVersion: version,
		HTTPClient:     &http.Client{Timeout: 60 * time.Second},
	}, true
}

type bomRequest struct {
	ProjectName    string `json:"projectName"`
	ProjectVersion string `json:"projectVersion"`
	AutoCreate     bool   `json:"autoCreate"`
	BOM            string `json:"bom"`
}

// UploadBOM sends the CycloneDX file at path to Dependency-Track.
func (d DependencyTrack) UploadBOM(ctx context.Context, path string) error {
	raw, err := os.ReadFile(path) // #nosec G304 -- path is scanctl's own generated SBOM
	if err != nil {
		return err
	}
	body, err := json.Marshal(bomRequest{
		ProjectName:    d.ProjectName,
		ProjectVersion: d.ProjectVersion,
		AutoCreate:     true,
		BOM:            base64.StdEncoding.EncodeToString(raw),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, d.BaseURL+"/api/v1/bom", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", d.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("dependency-track upload: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("dependency-track upload: status %d: %s", resp.StatusCode, snippet)
	}
	return nil
}
