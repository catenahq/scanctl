package upload

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestUploadBOMPutsBase64(t *testing.T) {
	var gotPath, gotKey string
	var gotReq bomRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotKey = r.Header.Get("X-Api-Key")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotReq)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "sbom.cdx.json")
	if err := os.WriteFile(path, []byte(`{"bomFormat":"CycloneDX"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	d := DependencyTrack{
		BaseURL: srv.URL, APIKey: "k", ProjectName: "p", ProjectVersion: "1.0",
		HTTPClient: srv.Client(),
	}
	if err := d.UploadBOM(context.Background(), path); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if gotPath != "/api/v1/bom" {
		t.Errorf("path = %q", gotPath)
	}
	if gotKey != "k" {
		t.Errorf("api key = %q", gotKey)
	}
	if !gotReq.AutoCreate || gotReq.ProjectName != "p" || gotReq.ProjectVersion != "1.0" {
		t.Errorf("unexpected request: %+v", gotReq)
	}
	decoded, err := base64.StdEncoding.DecodeString(gotReq.BOM)
	if err != nil || string(decoded) != `{"bomFormat":"CycloneDX"}` {
		t.Errorf("bom not base64-roundtripped: %q (err %v)", decoded, err)
	}
}

func TestDependencyTrackFromEnv(t *testing.T) {
	t.Setenv("DEPENDENCYTRACK_APIKEY", "")
	if _, ok := DependencyTrackFromEnv("https://dt", "", ""); ok {
		t.Error("inactive without key")
	}
	t.Setenv("DEPENDENCYTRACK_APIKEY", "key")
	d, ok := DependencyTrackFromEnv("https://dt/", "", "")
	if !ok {
		t.Fatal("should be active")
	}
	if d.ProjectName != "scanctl" || d.ProjectVersion != "latest" {
		t.Errorf("unexpected defaults: %+v", d)
	}
}
