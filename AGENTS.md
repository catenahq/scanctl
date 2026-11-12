# AGENTS.md

scanctl is one config-driven binary that runs the security scanners a repo's contents call for and merges their
output into one SARIF report. README.md says what it runs.

## Gate

- The gate blocks every finding the change can fix; only a CVE inside a pinned third-party image is graded against
  the commit before the change.
- Gate logic lives in scanctl, never in a repo's workflow YAML or suppression file.
- A run with nothing to compare against (scheduled, manual, local) fails on fixable CRITICAL and HIGH image CVEs; a
  pull request or push run gates only on what the change adds.
