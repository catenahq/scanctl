package runner

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestZizmorPolicyExemptsFirstParty(t *testing.T) {
	// The bundled policy must let catenahq/* ref-pin (the intentional @main
	// reusable-workflow ref) while requiring everything else to hash-pin,
	// otherwise flipping zizmor to block self-gates every caller's security.yml.
	s := string(zizmorPolicy)
	for _, want := range []string{"unpinned-uses", "catenahq/*: ref-pin", `"*": hash-pin`} {
		if !strings.Contains(s, want) {
			t.Errorf("bundled zizmor policy missing %q", want)
		}
	}
}

func TestZizmorPolicyIgnoresDangerousTriggersForControlCallerOnly(t *testing.T) {
	var cfg struct {
		Rules map[string]struct {
			Ignore []string `yaml:"ignore"`
			Config struct {
				Policies map[string]string `yaml:"policies"`
			} `yaml:"config"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(zizmorPolicy, &cfg); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Rules["dangerous-triggers"].Ignore; len(got) != 1 || got[0] != "ci-control.yml" {
		t.Errorf("dangerous-triggers ignore = %v, want [ci-control.yml]", got)
	}
	pol := cfg.Rules["unpinned-uses"].Config.Policies
	if pol["catenahq/*"] != "ref-pin" || pol["*"] != "hash-pin" {
		t.Errorf("unpinned-uses policies = %v", pol)
	}
}

func TestZizmorConfigPathWritesPolicy(t *testing.T) {
	t.Setenv("SCANCTL_CACHE", t.TempDir())
	p, err := zizmorConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p) // #nosec G304 -- path is under our temp cache
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(zizmorPolicy) {
		t.Error("written config does not match the embedded policy")
	}
}

const controlCaller = `name: ci-control
on:
  pull_request_target:
    types: [opened, synchronize, reopened, edited, ready_for_review, auto_merge_enabled]
  workflow_run:
    workflows: [ci]
    types: [completed]
  push:
    branches: [main, release]
  schedule:
    - cron: '7 * * * *'
permissions: {}
jobs:
  control:
    uses: catenahq/contracts/.github/workflows/control.yml@0123456789abcdef0123456789abcdef01234567 # main
    permissions:
      contents: read
      actions: read
      checks: read
      statuses: write
      pull-requests: read
    with:
      runner: catena-ci
      apps: false
      release: false
`

const otherTarget = `name: other
on:
  pull_request_target:
    types: [opened]
permissions: {}
jobs:
  j:
    uses: catenahq/contracts/.github/workflows/control.yml@0123456789abcdef0123456789abcdef01234567 # main
`

// Integration: runs the real zizmor found on PATH; skipped without one.
func TestZizmorPolicyRealBinaryControlCaller(t *testing.T) {
	bin, err := exec.LookPath("zizmor")
	if err != nil {
		t.Skip("zizmor not on PATH")
	}
	t.Setenv("SCANCTL_CACHE", t.TempDir())
	cfg, err := zizmorConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	wf := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o750); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"ci-control.yml": controlCaller, "other.yml": otherTarget} {
		if err := os.WriteFile(filepath.Join(wf, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// #nosec G204 -- bin is the zizmor found on PATH; the args are fixed flags and temp paths
	out, err := exec.Command(bin, "--offline", "--format", "plain", "--persona", "regular", "--config", cfg, root).CombinedOutput()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) { // exit 1x means findings, not a failed run
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "dangerous-triggers") || !strings.Contains(s, "other.yml:3:3") {
		t.Errorf("want dangerous-triggers reported for other.yml, got:\n%s", s)
	}
	if strings.Contains(s, "ci-control.yml:") {
		t.Errorf("want no finding for ci-control.yml, got:\n%s", s)
	}
}
