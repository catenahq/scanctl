# scanctl

One config-driven binary that bundles FOSS security scanners, runs the ones
that match a repo's contents, and merges their output into a single SARIF report
plus a markdown summary. v1 is serverless: no dashboard, no database.

> Working name. Brand-neutral on purpose so it can be installed on client infra
> or sold. See "Licensing & resale" below.

## What it runs (v1 core)

All resale-clean and SARIF-native; the runner invokes each as a subprocess
(never linked in), so their licenses never reach scanctl's own code.

| Tool | License | Covers | Runs when |
| --- | --- | --- | --- |
| [trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | dep CVEs + secrets + IaC misconfig + license (one binary) | always |
| [osv-scanner](https://github.com/google/osv-scanner) | Apache-2.0 | dependency CVEs, all ecosystems | a lockfile exists |
| [gitleaks](https://github.com/gitleaks/gitleaks) | MIT | secrets across git history | always |
| [gosec](https://github.com/securego/gosec) | Apache-2.0 | Go SAST (type-aware) | `go.mod` present |
| [govulncheck](https://golang.org/x/vuln) | BSD-3 | reachability-aware Go vulns | `go.mod` present |

Scanner versions are pinned in [`tools.lock`](tools.lock) (embedded in the
binary) and bumped by Renovate. The binaries are lazy-fetched on first use and
cached (set `SCANCTL_CACHE` to relocate).

## Usage

```sh
scanctl run .                 # detect, scan, merge SARIF, gate
scanctl run --no-gate .       # scan + report, always exit 0
scanctl run --out out.sarif --summary summary.md ./subdir
```

Exit code is non-zero when a tool in `block` mode produces a finding at or above
the configured gate floor. Config is optional ([`scanctl.example.yml`](scanctl.example.yml));
with no file, sensible defaults apply.

### In CI

Call the reusable workflow ([`ci/github-reusable.yml`](ci/github-reusable.yml)):

```yaml
jobs:
  security:
    uses: catenahq/scanctl/.github/workflows/github-reusable.yml@v0
    permissions:
      contents: read
      security-events: write
```

## Layout

```
cmd/scanctl       CLI (run | version)
internal/detect   manifest-glob router (which ecosystems are present)
internal/runner   lazy-fetch + subprocess orchestration + SARIF merge
internal/sarif    minimal SARIF 2.1.0 types
internal/report   merged SARIF writer + markdown summary
internal/gate     severity floor -> exit code
tools.lock        pinned scanner versions (Renovate-managed, embedded)
```

## Roadmap (designed, not built)

- **P2** DefectDojo (single dashboard): upload SARIF/native with scan types.
- **P3** Dependency-Track: push CycloneDX SBOM, license policy, monitoring.
- **P4** go-enry router, more scanners (bandit, Checkov/KICS, GuardDog,
  Scorecard + libyear + ecosyste.ms), and the `full` vs `sellable` profile split.

## Licensing & resale

scanctl's own code carries no OSS license yet (deliberate — it is intended to be
sellable). The bundled scanners keep their own licenses and are invoked as
separate processes (mere aggregation), which is what keeps that option open.
Resale-clean by construction: no Semgrep registry rules, no deps.dev/Google API.
Selling the install/expertise (client runs it on their own infra) is the cleanest
model; a redistributed product or multi-tenant SaaS has stricter obligations.
