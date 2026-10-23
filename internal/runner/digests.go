package runner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"

	"gopkg.in/yaml.v3"
)

// expectedDigestKey is the sha256 key of tool's release file at version.
func expectedDigestKey(tool, version string) string {
	return digestKey(version, releaseTools[tool].asset(version))
}

// staleDigests names the release tools l pins whose sha256 map is not exactly
// the digest of the file of their pinned version, or that pin no repo.
func staleDigests(l Lock) []string {
	var stale []string
	for tool := range releaseTools {
		e, ok := l.Tools[tool]
		if !ok {
			continue
		}
		key := expectedDigestKey(tool, e.Version)
		if e.Repo == "" || len(e.SHA256) != 1 || !sha256Rx.MatchString(e.SHA256[key]) {
			stale = append(stale, tool)
		}
	}
	sort.Strings(stale)
	return stale
}

// RefreshDigests rewrites the tools.lock at path so that every release tool it
// pins holds the sha256 of its release file at the pinned version. A tool whose
// map is already current is left as it is; for the others the file is
// downloaded, with no credential, and hashed as it streams. Nothing is written
// unless every download succeeds.
func RefreshDigests(ctx context.Context, path string, out io.Writer) error {
	data, err := os.ReadFile(path) // #nosec G304 -- path is the operator-provided tools.lock
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	lock, err := ParseLock(data)
	if err != nil {
		return err
	}
	stale := staleDigests(lock)
	if len(stale) == 0 {
		_, err := fmt.Fprintln(out, "every release file has its digest in", path)
		return err
	}
	sums := map[string]string{}
	for _, tool := range stale {
		e := lock.Tools[tool]
		if e.Repo == "" || e.Version == "" {
			return fmt.Errorf("%s: tools.lock pins no repo or no version", tool)
		}
		sum, err := fetchHashed(ctx, releaseURL(e.Repo, expectedDigestKey(tool, e.Version)), io.Discard)
		if err != nil {
			return err
		}
		sums[tool] = sum
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	tools := mappingValue(doc.Content[0], "tools")
	for _, tool := range stale {
		entry := mappingValue(tools, tool)
		e := lock.Tools[tool]
		setDigestMap(entry, expectedDigestKey(tool, e.Version), sums[tool])
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	// #nosec G306 -- tools.lock is a committed, non-sensitive file
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return err
	}
	for _, tool := range stale {
		fmt.Fprintf(out, "%s %s: 1 file(s) pinned\n", tool, lock.Tools[tool].Version)
	}
	return nil
}

// mappingValue returns the value node of key in the mapping node m.
func mappingValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// setDigestMap sets the sha256 map of the tool mapping entry to {key: sum},
// replacing the one it holds or adding it after the version line.
func setDigestMap(entry *yaml.Node, key, sum string) {
	value := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: sum},
	}}
	for i := 0; i+1 < len(entry.Content); i += 2 {
		if entry.Content[i].Value == "sha256" {
			entry.Content[i+1] = value
			return
		}
	}
	at := slices.IndexFunc(entry.Content, func(n *yaml.Node) bool { return n.Value == "version" }) + 2
	name := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "sha256"}
	entry.Content = slices.Insert(entry.Content, at, name, value)
}
