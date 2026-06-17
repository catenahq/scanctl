# scanctl

One config-driven binary that bundles FOSS security scanners, runs the ones
that match a repo's contents, and merges their output into a single SARIF report
plus a markdown summary. v1 is serverless: no dashboard, no database.

> Working name. Brand-neutral on purpose so it can be installed on client infra
> or sold. See "Licensing & resale" below.

## What it runs

The runner invokes each scanner as a subprocess (never linked in), so their
licenses never reach scanctl's own code. The core is resale-clean; `semgrep` is
resale-restricted and runs only under the `full` profile (see Profiles).

| Tool | License | Covers | Runs when |
| --- | --- | --- | --- |
| [trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | dep CVEs + secrets + IaC misconfig (one binary) | always (fs); also `image` per `images:` ref |
| [osv-scanner](https://github.com/google/osv-scanner) | Apache-2.0 | dependency CVEs, all ecosystems | a lockfile exists |
| [gitleaks](https://github.com/gitleaks/gitleaks) | MIT | secrets across git history | always |
| [gosec](https://github.com/securego/gosec) | Apache-2.0 | Go SAST (type-aware) | `go.mod` present |
| [govulncheck](https://golang.org/x/vuln) | BSD-3 | reachability-aware Go vulns | `go.mod` present |
| [zizmor](https://github.com/zizmorcore/zizmor) | MIT/Apache-2.0 | GitHub Actions workflow audit | `.github/workflows/*.y{a,}ml` present |
| [guarddog](https://github.com/DataDog/guarddog) | Apache-2.0 | malicious PyPI/npm/Go packages (heuristics) | root `requirements.txt` / `package-lock.json` / `go.mod` |
| [semgrep](https://github.com/semgrep/semgrep) | LGPL-2.1 (registry packs restricted) | multi-language SAST (auto-selected packs) | source ecosystem present **and** `profile: full` |
| trivy (license) | Apache-2.0 | dependency license scan (copyleft/unknown), advisory | always (separate `trivy-license` driver, report-mode) |

Scanner versions are pinned in [`tools.lock`](tools.lock) (embedded in the
binary) and bumped by Renovate. Release-binary tools (trivy, osv-scanner,
gitleaks, gosec, zizmor) are lazy-fetched and cached (set `SCANCTL_CACHE` to
relocate); govulncheck is `go install`ed; the Python tools (semgrep, guarddog)
are installed with `uv tool install`. **Runner prerequisites:** `go` and `uv`
on `PATH` (the reusable workflow sets both up).

zizmor runs in **block** mode with a bundled policy ([`internal/runner/zizmor-policy.yml`](internal/runner/zizmor-policy.yml),
passed via `--config`): first-party `catenahq/*` actions may be ref-pinned, every
third-party `uses:` must be hash-pinned. This lets the reusable security workflow
stay at `@main` (auto-updating, guarded by branch protection on the scanctl repo
rather than a per-caller digest pin) while still gating on unpinned third-party
actions and every other high-severity workflow finding.

GuardDog's SARIF comes from its manifest-based `verify` subcommand, so it scans
only a root `requirements.txt` (PyPI), `package-lock.json` (npm), or `go.mod`
(Go); nested manifests and pyproject-only projects are out of scope for now.
The Go manifest support is what replaces Socket for Go repos (Socket was dropped
from the rollout).

The license scan is a second trivy pass under its own `trivy-license` driver
(report-mode by design: copyleft/unknown licenses are advisory and must not
inherit the fs scan's blocking gate). The reusable workflow also emits a syft
CycloneDX SBOM (`sbom.cdx.json`) and uploads it as an artifact -- together these
fold in the old standalone `licenses-sbom` workflow.

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

Call the reusable workflow ([`.github/workflows/github-reusable.yml`](.github/workflows/github-reusable.yml)):

```yaml
jobs:
  security:
    uses: catenahq/scanctl/.github/workflows/github-reusable.yml@main
    permissions:
      contents: read
      security-events: write
```

## Layout

```
cmd/scanctl       CLI (run | version)
internal/detect   manifest-glob router (ecosystems + workflows present)
internal/runner   lazy-fetch + subprocess orchestration + SARIF merge
                  (registry tools + guarddog/image per-manifest/per-ref steps)
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
- `full`: also runs resale-restricted tools (`fullOnly`, currently `semgrep`
  with its registry packs), for personal use or a client-operates-their-own-box
  engagement. Catena's own repos run `full` (via `-profile full` in the reusable
  workflow, or `profile: full` in `scanctl.yml`).

## Dependency policy (Renovate preset)

scanctl detects; it never updates. Remediation is Renovate's lane. scanctl
publishes a generic, parameter-free security baseline as a shared Renovate
preset: [secure-base.json](secure-base.json). Any repo adopts it with a one-line
config:

```json
{ "extends": ["github>catenahq/scanctl:secure-base"] }
```

The preset enforces a **7-day adoption cooldown** (`minimumReleaseAge`) and --
critically -- holds PR *creation* until the release has aged
(`internalChecksFilter: strict` + `prCreation: not-pending`). Without that, the
PR opens on release day (scanners run on the day-0 version) and auto-merges 7
days later with no fresh scan; with it, the PR opens only after the cooldown, so
scanctl scans the exact version that will merge. Pins (`pin`/`pinDigest`) carry
no release age and are exempt from the cooldown; github-actions same-tag
`digest` refreshes are disabled outright (a moved tag re-introduces the
mutable-tag risk that SHA-pinning prevents). Known-CVE fixes are also exempt
(`vulnerabilityAlerts` automerges with no cooldown). The same cooldown governs
scanctl's own `tools.lock` scanner pins.

`secure-base` carries no project-specific operational config (PR limits,
timezone, labels, schedules) -- layer those on top in your own config. Catena's
own org-wide Renovate policy lives in the public `github>catenahq/renovate-config`,
which extends this baseline.

## Extending: the adapter seam

The router (go-enry: ecosystem detection + vendored/generated filtering +
language census) and the tool registry make new scanners a small addition. A
tool that emits SARIF needs only a registry entry; a JSON-only tool supplies a
`convert([]byte) (*sarif.Report, error)` adapter. Deferred scanners and why:

| Tool | Axis | Why not in core yet |
| --- | --- | --- |
| Checkov / KICS | IaC policy | trivy already covers IaC misconfig; adds overlap + a slow 68MB binary |
| bandit | Python SAST | redundant once semgrep `p/python` runs (full profile); add later only for defense-in-depth |
| OpenSSF Scorecard / libyear / ecosyste.ms | dependency health / obsolescence | binary+token or service deps; new axis, larger lift |
| OWASP ZAP (`zap-baseline`) | DAST | scans a *running* app; a static `scanctl run .` cannot reach it -- explicit non-goal, stays a separate CI job |

## Licensing & resale

scanctl's own code is fair-code under the Sustainable Use model (see
[LICENSE.md](LICENSE.md)): free to run for your own purposes or on a client's
infra as part of a service you perform, but not to resell or offer as a managed
service. The bundled scanners keep their own licenses and are invoked as
separate processes (mere aggregation), which keeps that boundary clean.
Resale-clean by construction: the `sellable` profile uses no Semgrep registry
rules and no deps.dev/Google API (the `full` profile, used internally, does).
