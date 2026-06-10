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
| [trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | dep CVEs + secrets + IaC misconfig (one binary) | always |
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

## Aggregation plane (optional)

Serverless by default. Configure either target in `scanctl.yml` (+ its env
credential) to also push results; a missing credential is skipped with a
warning, never failing the scan.

- **DefectDojo** (findings) -- merged SARIF -> import-scan API. `DEFECTDOJO_TOKEN`.
  See [deploy/defectdojo/](deploy/defectdojo/).
- **Dependency-Track** (SBOM portfolio, license policy, continuous monitoring)
  -- syft CycloneDX -> `/api/v1/bom`. `DEPENDENCYTRACK_APIKEY`. See
  [deploy/dependency-track/](deploy/dependency-track/).

## Profiles

- `sellable` (default): resale-clean -- only permissively-licensed tools, no
  Semgrep registry rules, no deps.dev/Google API.
- `full`: also runs resale-restricted tools (`fullOnly`), for personal use or a
  client-operates-their-own-box engagement.

## Dependency policy (Renovate preset)

scanctl detects; it never updates. Remediation is Renovate's lane, and the
suite owns that policy once: [supply-chain.json](supply-chain.json) is a shared
Renovate preset. Any repo adopts it with a one-line config:

```json
{ "extends": ["github>catenahq/scanctl:supply-chain"] }
```

The preset enforces a **7-day adoption cooldown** (`minimumReleaseAge`) and --
critically -- holds PR *creation* until the release has aged
(`internalChecksFilter: strict` + `prCreation: not-pending`). Without that, the
PR opens on release day (scanners run on the day-0 version) and auto-merges 7
days later with no fresh scan; with it, the PR opens only after the cooldown, so
scanctl scans the exact version that will merge. Known-CVE fixes are exempt
(`vulnerabilityAlerts` automerges with no cooldown). The same cooldown governs
scanctl's own `tools.lock` scanner pins.

## Extending: the adapter seam

The router (go-enry: ecosystem detection + vendored/generated filtering +
language census) and the tool registry make new scanners a small addition. A
tool that emits SARIF needs only a registry entry; a JSON-only tool supplies a
`convert([]byte) (*sarif.Report, error)` adapter. Deferred scanners and why:

| Tool | Axis | Why not in core yet |
| --- | --- | --- |
| Checkov / KICS | IaC policy | trivy already covers IaC misconfig; adds overlap + a slow 68MB binary |
| bandit | Python SAST | pip-only runtime (no single-binary release) |
| GuardDog | malicious packages | pip-only; JSON output -> needs a convert adapter |
| OpenSSF Scorecard / libyear / ecosyste.ms | dependency health / obsolescence | binary+token or service deps; new axis, larger lift |
| Opengrep + rules / Semgrep registry | SAST breadth | engine is a clean binary but needs a maintained ruleset; Semgrep registry is `fullOnly` |

## Licensing & resale

scanctl's own code carries no OSS license yet (deliberate — it is intended to be
sellable). The bundled scanners keep their own licenses and are invoked as
separate processes (mere aggregation), which is what keeps that option open.
Resale-clean by construction: no Semgrep registry rules, no deps.dev/Google API.
Selling the install/expertise (client runs it on their own infra) is the cleanest
model; a redistributed product or multi-tenant SaaS has stricter obligations.
