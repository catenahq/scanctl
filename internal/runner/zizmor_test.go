package runner

import (
	"os"
	"strings"
	"testing"
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
