// Package scanctl exposes build-time embedded assets (the pinned tools.lock) so
// the single binary carries its scanner version pins with it.
package scanctl

import _ "embed"

// ToolsLock is the embedded tools.lock (pinned scanner versions).
//
//go:embed tools.lock
var ToolsLock []byte
