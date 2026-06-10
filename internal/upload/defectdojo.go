// Package upload pushes scan results to the aggregation plane: DefectDojo
// (findings) and Dependency-Track (SBOM). Both clients are thin HTTP wrappers
// with no dependency on a live server at construction, so request shaping is
// unit-testable against httptest.
package upload

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"
)

// DefectDojo imports findings via the import-scan API. The merged SARIF is sent
// once with scan_type "SARIF"; DefectDojo's parser splits it back per tool by
// the run driver name, and dedups across runs (auto_create_context builds the
// product/engagement on first import).
type DefectDojo struct {
	BaseURL        string
	Token          string
	ProductName    string
	EngagementName string
	HTTPClient     *http.Client
}

// DefectDojoFromEnv builds a client from config + the DEFECTDOJO_TOKEN env var.
// ok is false (no error) when the target is not configured, so the caller can
// skip silently rather than fail.
func DefectDojoFromEnv(url, product, engagement string) (DefectDojo, bool) {
	if url == "" {
		return DefectDojo{}, false
	}
	token := os.Getenv("DEFECTDOJO_TOKEN")
	if token == "" {
		return DefectDojo{}, false
	}
	if product == "" {
		product = "scanctl"
	}
	if engagement == "" {
		engagement = "scanctl"
	}
	return DefectDojo{
		BaseURL:        strings.TrimRight(url, "/"),
		Token:          token,
		ProductName:    product,
		EngagementName: engagement,
		HTTPClient:     &http.Client{Timeout: 60 * time.Second},
	}, true
}

// ImportSARIF uploads the SARIF at path to /api/v2/import-scan/.
func (d DefectDojo) ImportSARIF(ctx context.Context, path string) error {
	f, err := os.Open(path) // #nosec G304 -- path is scanctl's own merged report
	if err != nil {
		return err
	}
	defer f.Close()

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fields := map[string]string{
		"scan_type":           "SARIF",
		"product_name":        d.ProductName,
		"engagement_name":     d.EngagementName,
		"auto_create_context": "true",
		"active":              "true",
		"verified":            "false",
	}
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			return err
		}
	}
	fw, err := mw.CreateFormFile("file", "scanctl.sarif")
	if err != nil {
		return err
	}
	if _, err := io.Copy(fw, f); err != nil {
		return err
	}
	if err := mw.Close(); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.BaseURL+"/api/v2/import-scan/", &body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token "+d.Token)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("defectdojo import: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("defectdojo import: status %d: %s", resp.StatusCode, snippet)
	}
	return nil
}
