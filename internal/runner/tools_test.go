package runner

import (
	"slices"
	"testing"

	"github.com/catenahq/scanctl/internal/detect"
)

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
