package upload

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImportSARIFPostsMultipart(t *testing.T) {
	var gotPath, gotAuth, gotScanType, gotProduct string
	var gotFile bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("parse multipart: %v", err)
		}
		gotScanType = r.FormValue("scan_type")
		gotProduct = r.FormValue("product_name")
		if _, _, err := r.FormFile("file"); err == nil {
			gotFile = true
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "scanctl.sarif")
	if err := os.WriteFile(path, []byte(`{"version":"2.1.0","runs":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	d := DefectDojo{
		BaseURL: srv.URL, Token: "secret", ProductName: "p", EngagementName: "e",
		HTTPClient: srv.Client(),
	}
	if err := d.ImportSARIF(context.Background(), path); err != nil {
		t.Fatalf("import: %v", err)
	}
	if gotPath != "/api/v2/import-scan/" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "Token secret" {
		t.Errorf("auth = %q", gotAuth)
	}
	if gotScanType != "SARIF" {
		t.Errorf("scan_type = %q", gotScanType)
	}
	if gotProduct != "p" {
		t.Errorf("product = %q", gotProduct)
	}
	if !gotFile {
		t.Error("missing file part")
	}
}

func TestImportSARIFErrorsOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad engagement"))
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "s.sarif")
	_ = os.WriteFile(path, []byte("{}"), 0o600)
	d := DefectDojo{BaseURL: srv.URL, Token: "x", HTTPClient: srv.Client()}
	err := d.ImportSARIF(context.Background(), path)
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Errorf("expected 400 error, got %v", err)
	}
}

func TestDefectDojoFromEnv(t *testing.T) {
	t.Setenv("DEFECTDOJO_TOKEN", "")
	if _, ok := DefectDojoFromEnv("https://dd", "", ""); ok {
		t.Error("should be inactive without token")
	}
	if _, ok := DefectDojoFromEnv("", "", ""); ok {
		t.Error("should be inactive without url")
	}
	t.Setenv("DEFECTDOJO_TOKEN", "tok")
	d, ok := DefectDojoFromEnv("https://dd/", "", "")
	if !ok {
		t.Fatal("should be active")
	}
	if d.BaseURL != "https://dd" || d.ProductName != "scanctl" {
		t.Errorf("unexpected defaults: %+v", d)
	}
}
