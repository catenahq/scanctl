package runner

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/catenahq/scanctl/internal/config"
	"github.com/catenahq/scanctl/internal/detect"
)

// stubTrivy swaps the registry's trivy for a script that appends its argv to a
// file, and returns that file's path.
func stubTrivy(t *testing.T) string {
	t.Helper()
	argv := filepath.Join(t.TempDir(), "argv")
	bin := filepath.Join(t.TempDir(), "trivy")
	writeFile(t, filepath.Dir(bin), "trivy", "#!/bin/sh\necho \"$@\" >> "+argv+"\n")
	if err := os.Chmod(bin, 0o700); err != nil { // #nosec G302 -- a test stand-in for the trivy binary
		t.Fatal(err)
	}
	saved := registry
	t.Cleanup(func() { registry = saved })
	registry = []toolDef{{
		name:   "trivy",
		ensure: func(context.Context, string, string) (string, error) { return bin, nil },
	}}
	return argv
}

// Without both flags trivy reports its install id, command and flags to its
// maker, so every trivy call carries them straight after the subcommand.
func requireNoTelemetryFlags(t *testing.T, args []string, subcommand string) {
	t.Helper()
	want := []string{subcommand, "--skip-version-check", "--disable-telemetry"}
	if len(args) < 3 || !slices.Equal(args[:3], want) {
		t.Errorf("trivy argv = %v, want it to start with %v", args, want)
	}
}

func TestTheFsScanSendsNothingToTheScannersMaker(t *testing.T) {
	for _, td := range registry {
		if td.name == "trivy" {
			requireNoTelemetryFlags(t, td.invoke("trivy", t.TempDir(), "out.sarif", detect.Result{}).args, "fs")
		}
	}
}

func TestTheLicenseScanSendsNothingToTheScannersMaker(t *testing.T) {
	argv := stubTrivy(t)
	cfg := config.Config{Tools: map[string]config.ToolConfig{"trivy-license": {Enabled: true}}}
	lock := Lock{Tools: map[string]LockEntry{"trivy": {Version: "1"}}}
	licenseStep(context.Background(), cfg, lock, t.TempDir(), newOutcome())
	got, err := os.ReadFile(argv) // #nosec G304 -- path is under the test's temp dir
	if err != nil {
		t.Fatal(err)
	}
	requireNoTelemetryFlags(t, strings.Fields(string(got)), "fs")
}

func TestTheImageScanSendsNothingToTheScannersMaker(t *testing.T) {
	argv := stubTrivy(t)
	cfg := config.Config{
		Images: []string{"nginx:1.31-alpine"},
		Tools:  map[string]config.ToolConfig{"trivy": {Enabled: true, Mode: config.ModeBlock}},
	}
	lock := Lock{Tools: map[string]LockEntry{"trivy": {Version: "1"}}}
	if _, err := ScanImages(context.Background(), t.TempDir(), cfg, lock); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(argv) // #nosec G304 -- path is under the test's temp dir
	if err != nil {
		t.Fatal(err)
	}
	requireNoTelemetryFlags(t, strings.Fields(string(got)), "image")
}

func goRepo() detect.Result {
	return detect.Result{Ecosystems: map[detect.Ecosystem]bool{detect.Go: true}}
}

func TestSemgrepConfigsPerEcosystem(t *testing.T) {
	cases := []struct {
		name string
		eco  []detect.Ecosystem
		want []string
	}{
		{"go", []detect.Ecosystem{detect.Go}, []string{"p/owasp-top-ten", "p/golang"}},
		{"python", []detect.Ecosystem{detect.Python}, []string{"p/owasp-top-ten", "p/python"}},
		{"node", []detect.Ecosystem{detect.Node}, []string{"p/owasp-top-ten", "p/javascript", "p/typescript"}},
		{"docker", []detect.Ecosystem{detect.Docker}, []string{"p/owasp-top-ten", "p/dockerfile"}},
		{"terraform", []detect.Ecosystem{detect.Terraform}, []string{"p/owasp-top-ten", "p/terraform"}},
		{"go+node", []detect.Ecosystem{detect.Go, detect.Node}, []string{"p/owasp-top-ten", "p/golang", "p/javascript", "p/typescript"}},
		{"none", nil, []string{"p/owasp-top-ten"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			det := detect.Result{Ecosystems: map[detect.Ecosystem]bool{}}
			for _, e := range c.eco {
				det.Ecosystems[e] = true
			}
			got := semgrepConfigs(det)
			if !slices.Equal(got, c.want) {
				t.Errorf("semgrepConfigs = %v, want %v", got, c.want)
			}
		})
	}
}

func TestNewToolsApplies(t *testing.T) {
	byName := map[string]toolDef{}
	for _, td := range registry {
		byName[td.name] = td
	}

	noWorkflows := detect.Result{Ecosystems: map[detect.Ecosystem]bool{detect.Go: true}}
	withWorkflows := detect.Result{Ecosystems: map[detect.Ecosystem]bool{detect.Go: true}, HasWorkflows: true}
	noSource := detect.Result{Ecosystems: map[detect.Ecosystem]bool{detect.Terraform: true}}

	if !byName["semgrep"].applies(goRepo()) {
		t.Error("semgrep should apply to a Go repo")
	}
	if byName["semgrep"].applies(noSource) {
		t.Error("semgrep should not apply to a source-less (Terraform-only) repo")
	}
	if !byName["semgrep"].fullOnly {
		t.Error("semgrep must be fullOnly (registry packs are resale-restricted)")
	}
	if !byName["zizmor"].applies(withWorkflows) {
		t.Error("zizmor should apply when workflows are present")
	}
	if byName["zizmor"].applies(noWorkflows) {
		t.Error("zizmor should not apply without workflows")
	}
}

func TestEmbeddedLockPinsNewScanners(t *testing.T) {
	lock, err := LoadLock("../../tools.lock")
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"semgrep", "zizmor", "guarddog"} {
		v, err := lock.Version(tool)
		if err != nil || v == "" {
			t.Errorf("tools.lock missing pin for %q (v=%q err=%v)", tool, v, err)
		}
	}
}
