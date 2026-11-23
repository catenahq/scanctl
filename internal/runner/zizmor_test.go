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
	// The bundled policy must let catenahq/* ref-pin while requiring
	// everything else to hash-pin, otherwise zizmor in block mode gates every
	// caller's workflows on first-party refs.
	s := string(zizmorPolicy)
	for _, want := range []string{"unpinned-uses", "catenahq/*: ref-pin", `"*": hash-pin`} {
		if !strings.Contains(s, want) {
			t.Errorf("bundled zizmor policy missing %q", want)
		}
	}
}

func TestZizmorPolicyIgnoresNoAudit(t *testing.T) {
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
	for rule, r := range cfg.Rules {
		if len(r.Ignore) != 0 {
			t.Errorf("rule %s ignores %v, want no ignores", rule, r.Ignore)
		}
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

const targetTrigger = `name: other
on:
  pull_request_target:
    types: [opened]
permissions: {}
jobs:
  j:
    uses: catenahq/contracts/.github/workflows/pr.yml@0123456789abcdef0123456789abcdef01234567 # main
`

// Integration: runs the real zizmor found on PATH; skipped without one.
func TestZizmorPolicyReportsDangerousTriggers(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(wf, "other.yml"), []byte(targetTrigger), 0o600); err != nil {
		t.Fatal(err)
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
}
