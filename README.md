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
| [trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | dep CVEs + secrets + IaC misconfig (one binary) | always (fs); also `image` per `images:` / `image_pins:` ref |
| [osv-scanner](https://github.com/google/osv-scanner) | Apache-2.0 | dependency CVEs, all ecosystems | a lockfile exists |
| [gitleaks](https://github.com/gitleaks/gitleaks) | MIT | secrets in the scanned commit's history | always |
| [gosec](https://github.com/securego/gosec) | Apache-2.0 | Go SAST (type-aware) | `go.mod` present |
| [govulncheck](https://golang.org/x/vuln) | BSD-3 | reachability-aware Go vulns | `go.mod` present |
| [zizmor](https://github.com/zizmorcore/zizmor) | MIT/Apache-2.0 | GitHub Actions workflow audit | `.github/workflows/*.y{a,}ml` present |
| [guarddog](https://github.com/DataDog/guarddog) | Apache-2.0 | malicious PyPI/npm/Go packages (heuristics) | root `requirements.txt` / `package-lock.json` / `go.mod` |
| [semgrep](https://github.com/semgrep/semgrep) | LGPL-2.1 (registry packs restricted) | multi-language SAST (auto-selected packs) | source ecosystem present **and** `profile: full` |
| trivy (license) | Apache-2.0 | dependency license scan (copyleft/unknown), advisory | always (separate `trivy-license` driver, report-mode) |

Scanner versions are pinned in [`tools.lock`](tools.lock) (embedded in the
binary) and bumped by Renovate. Release-binary tools (trivy, osv-scanner,
gitleaks, gosec, zizmor) are lazy-fetched and cached (set `SCANCTL_CACHE` to
relocate); govulncheck is `go install`ed with the toolchain the scanned module
selects (its go.mod `toolchain` line), because it type-checks the module with
the go/types it was built with, and runs under that toolchain, so it grades
that toolchain's standard library even when the runner sets
`GOTOOLCHAIN=local`; the Python tools (semgrep, guarddog) are
installed with `uv tool install`. **Runner prerequisites:** `go` and `uv`
on `PATH` (the reusable workflow sets both up).

zizmor runs in **block** mode with a bundled policy ([`internal/runner/zizmor-policy.yml`](internal/runner/zizmor-policy.yml),
passed via `--config`): first-party `catenahq/*` actions may be ref-pinned, every
third-party `uses:` must be hash-pinned. This lets the reusable security workflow
stay at `@main` (auto-updating, guarded by branch protection on the scanctl repo
rather than a per-caller digest pin) while still gating on unpinned third-party
actions and every other high-severity workflow finding.

gitleaks scans the history of the commit being scanned, with a bundled config
([`internal/runner/gitleaks.toml`](internal/runner/gitleaks.toml)): gitleaks'
own rules plus an allowlist for version tags, which its generic-api-key rule
reads as secrets after a name containing "auth" (an `oauth2-proxy` image tag).
A repo's own `.gitleaks.toml` takes its place. The `ignore` list reaches
gitleaks as a generated config that extends that one and allowlists each
ignored directory. gitleaks owns secrets, so gosec runs without G101
(hardcoded credentials), which reads names such as settings keys as secrets.

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

## Install

```sh
go install github.com/catenahq/scanctl/cmd/scanctl@latest
```

Public module, so this needs nothing beyond `go` on `PATH` -- no `GOPRIVATE`,
no auth. Installs to `$(go env GOPATH)/bin`; put that on `PATH` (or invoke it
as `"$(go env GOPATH)/bin/scanctl"`, since a runner's own `PATH` isn't
guaranteed to include it). Pin `@vX.Y.Z` or a commit for a reproducible
one-off run. The reusable workflow installs the scanctl branch named like the
caller's when there is one, else its `scanctl-version` input (see "In CI").

## Usage

```sh
scanctl run .                 # detect, scan, merge SARIF, gate
scanctl run --no-gate .       # scan + report, always exit 0
scanctl run --out out.sarif --summary summary.md ./subdir
scanctl run --baseline-ref origin/main .            # image CVEs gate only if new vs the merge-base
scanctl run --baseline .scanctl/baseline.sarif .   # findings accepted for good never gate
scanctl run --import codeql.sarif .                 # fold in external SARIF
```

Exit code is non-zero when a tool in `block` mode produces a finding at or above
the configured gate floor, or when a `block`-mode scan produces no report at all
(unpinned, fetch failed, or exited non-zero without one; an image scan is
retried once first). Zero findings from a scanner that never ran is not a pass:
the summary lists those scans under "Scanners that did not run", and the run
carries on so the other scanners' findings still reach the report.

The floor is compared against each finding's CVSS `security-severity` when the
tool reports one (the same score GitHub uses), then a single severity tag on
its rule (gosec tags each rule HIGH, MEDIUM or LOW and emits every one at level
error), falling back to the SARIF level -- so the floor means what it says
rather than over- or under-gating on a coarse error/warning. gitleaks reports
no severity; a committed secret is critical. Config is optional
([`scanctl.example.yml`](scanctl.example.yml)); with no file, sensible defaults
apply: every tool blocks except `trivy-license`.

### Gating: what a change to the repo can fix

A finding in the repo's own tree -- a dependency CVE in a manifest or lockfile,
a SAST finding, a secret, a workflow or IaC finding, a malicious package --
is fixable by a change to the repo, so it gates on every run, whether or not
it was already there.

An image the repo builds itself is the repo's to fix too. `--own-image <ref>`
(repeatable) scans it with the other images, and its CVEs gate on every run:
no base scan suppresses them. It is a flag rather than config because the ref
exists only once the workflow has built it.

A CVE in a third-party image the repo pins (`images:` / `image_pins:`) is
upstream's to fix, so it gates only when a change introduces it.
`--baseline-ref <git-ref>` also scans the images pinned at the merge-base of
HEAD and the ref, in a temporary git worktree, and suppresses every image
finding they already have. Both sides are scanned in the same run with the
same scanner version and vulnerability database. A failed scan of the base
degrades to the full gate (stricter, never looser) with a warning.

Inside GitHub Actions, with no `--baseline-ref` given, scanctl reads the ref
from the event: a pull request diffs against `origin/<base>`, a push against
the commit the branch held before it (or the default branch, when the push
created the branch or that commit is not in the clone). A run with no ref --
scheduled, manual, or outside Actions -- grades no change, so it reports every
image finding without gating on it; that is where a CVE published against an
image nobody touched surfaces. Every caller, the reusable workflow or an
inline `scanctl run`, gets the same behaviour.

A dependency vulnerability in an image is matched across the two scans by
advisory, package, and image repository. The match ignores the installed
version, so a bump that keeps an advisory in the same package keeps the
finding, and a bump that adds an advisory adds one.

### Committed baseline (optional)

`--baseline <sarif>` suppresses, on every run, the findings recorded in a
committed SARIF: findings a human has reviewed and accepted for good. A finding
in it is marked suppressed (`kind: external`) in the merged SARIF -- the gate
skips it, and it stays in the SARIF for audit. An entry the scan no longer
produces fails the run and is listed under "Stale baseline entries": it would
accept the finding again if it came back, so it is removed instead. A missing
baseline file is a no-op. The reusable workflow exposes it as the `baseline`
input.

GitHub's code-scanning SARIF ingestion does **not** act on `kind: external`
suppressions -- confirmed empirically (a baselined finding stays open on the
Security tab after upload) and consistent with GitHub's own SARIF-support docs,
which list no `suppressions` property support for third-party uploads. (It
does honor `kind: inSource`, e.g. a tool's own `nosemgrep` comment -- that
class of suppression is untouched by any of this.) `--dismiss-baseline` closes
the gap: for every finding the baseline accepted it
looks up and closes the matching **open** GitHub code-scanning alert via the
REST API (`dismissed_reason: "won't fix"`), so the Security tab actually
reflects what the baseline says is already known. Matching is coarser than the
baseline's own fingerprint (tool + rule + file + line, no message text --
that's all the alerts API exposes), so it can only ever close an alert that
would already gate-pass; it never touches an unsuppressed finding. Requires
`GITHUB_REPOSITORY` + `GH_TOKEN`/`GITHUB_TOKEN` (both already present in
Actions); a no-op outside that environment, and always skipped on
`pull_request` events -- a feature-branch run is never the source of truth for
what the org has accepted repo-wide. The reusable workflow enables it by
default (`dismiss-baseline: true`) whenever `baseline` is set.

#### Seeding or regenerating a baseline

```sh
scanctl run --profile full --out current.sarif --sbom /tmp/sbom.json \
  --summary /dev/null .
python3 - <<'PY'
import json
rep = json.load(open("current.sarif"))
runs = [
    {"tool": {"driver": {"name": r["tool"]["driver"]["name"]}}, "results": r["results"]}
    for r in rep.get("runs", []) if r.get("results")
]
out = {"$schema": rep["$schema"], "version": rep["version"], "runs": runs}
json.dump(out, open(".scanctl/baseline.sarif", "w"), indent=2)
open(".scanctl/baseline.sarif", "a").write("\n")
PY
```

Review the diff before committing: every entry must be a finding a human has
confirmed is benign, not just "whatever the scan happened to produce." A
consumer repo's own `.scanctl/README.md` should record repo-specific context
(what's baselined here and why) and link back here for the mechanism, rather
than restating it -- see `catenahq/docs/.scanctl/README.md` for an example of
that split.

### Image scanning: `images` and `image_pins`

`images:` is a literal list of refs to scan with `trivy image` alongside the fs
scan. `image_pins:` reads the ref out of the file that already declares it:

```yaml
image_pins:
  - file: payload/engines/tier1/catalog.go
    pattern: 'c\.\w+Image = "([^"]+)"'
  - file: ansible/reconcile/roles/keycloak/defaults/main.yml
    pattern: 'keycloak_image_tag: "([^"]+)"'
    repo: quay.io/phasetwo/phasetwo-keycloak
```

Prefer the pin form. The tag a host runs is already declared somewhere, and a
literal entry here is a second copy that agrees with the first only by hand.
Each pattern needs exactly one capturing group and every match in the file is
scanned, so one entry covers a file pinning several images. The group is a
whole `<repo>:<tag>`, unless `repo:` is set -- then the group is the tag alone
and the two are joined, which is how a role default that splits them has to be
read. A pattern narrower than a bare `<repo>:<tag>` grep is deliberate: prose
in a neighbouring comment matches that shape too.

`file` may be a glob (`path.Match` syntax, slash-separated), and every file it
matches is read: one entry covers a catalog of compose files.

```yaml
image_pins:
  - file: blueprints/*/docker-compose.yml
    pattern: '(?m)^\s*image:\s*["'']?([^"''\s#]+)'
```

**A pin that matches nothing fails the run**, and so does a glob that matches
no file or whose files yield no ref. A moved file or a renamed variable would
otherwise scan no image and still report a clean gate -- which is exactly how
a repo can carry a green image-CVE gate that has not looked at an image in
weeks.

Pin files are read from the tree being scanned, so `--baseline-ref` resolves
the merge-base's pins from its worktree: a bump is graded on the delta between
the image it proposes and the image it replaces, and a CVE that survives the
bump does not gate it, whatever version of the package now carries it. Each
image-scan finding records its image ref in the `image` result property. The
baseline scan re-reads
`scanctl.yml` from that worktree too, so a literal `images:` list rewinds with
the branch the same way.

Under `--baseline-ref`, only the pins whose FILE the change touches are
scanned, on both sides. A glob pin is narrowed to the files it matches that
the change touches, one pin per file, leaving out a file the change deleted.
An untouched pin resolves to the same ref on both sides, so scanning it twice
can only produce findings that suppress each other -- and on a repo pinning
nine images, proving that zero is most of a run. A run without
`--baseline-ref` keeps every pin, which is how the scheduled report covers an
image nobody touched. A pin the change ADDS has nothing to resolve at the
merge base; that is a pin with no baseline, so all of its findings gate.

A repo's `.trivyignore.yaml` (or `.trivyignore.yml` / `.trivyignore`) at the
scanned root is passed to BOTH trivy passes as `--ignorefile`. trivy does not
pick one up on its own -- verified against 0.74, where a file sitting in the
working directory changed nothing until the flag named it -- so without this
the suppressions a repo has already reviewed and time-boxed would not apply.
The base side of a `--baseline-ref` diff scans its images with no ignore file,
so the diff compares what the images carry: a change that removes a
suppression gates only on the CVEs its own image changes bring in.

One file, one answer, on purpose: honouring it for images but not for the fs
scan means a suppression the operator wrote once takes effect in half the run,
with nothing in the output saying which half. The cost is that an entry
justified for one context applies in the other, so a CVE id suppressed because
an image vendors an unpatched copy also stops gating on a first-party
dependency of the same id. Keep the entries time-boxed (`expiredAt`): trivy
stops honouring an entry once it lapses, which is what bounds that.

### External SARIF (CodeQL and friends)

`--import <sarif>` (repeatable) folds an externally-produced SARIF into the merge
before the report, gate, and uploads. Run a deeper scanner in its own CI job and
hand scanctl its output -- e.g. CodeQL, which stays a separate job because it
owns a database lifecycle scanctl deliberately does not embed:

```yaml
  - uses: github/codeql-action/init@v4
    with: { languages: go }
  - uses: github/codeql-action/analyze@v4
    with: { upload: false, output: codeql-results }
  # then call scanctl with import-sarif: codeql-results/go.sarif
```

### In CI

Call the reusable workflow ([`.github/workflows/github-reusable.yml`](.github/workflows/github-reusable.yml)):

```yaml
jobs:
  security:
    uses: catenahq/scanctl/.github/workflows/github-reusable.yml@main
    permissions:
      contents: read
      security-events: write   # code-scanning upload (public / GHAS repos)
      pull-requests: write     # sticky findings comment (private-repo parity)
```

The SARIF scanctl writes holds one run per tool: the fs scan and every image
scan are one trivy run. Code scanning refuses a file holding two runs of one
tool and category, or more than 20 runs, so the upload goes through whatever
the number of images a scan covers.

On a private repo without Advanced Security the code-scanning upload is a
no-op, so the workflow also (a) posts the findings summary as one sticky PR
comment (updated in place) and (b) uploads `scanctl.sarif` + the SBOM as a
downloadable artifact. Together with `--baseline` these give private repos the
same triage surface as the public Security tab. Inputs: `baseline`,
`dismiss-baseline`, `import-sarif`, `profile`, `no-gate`, `path`, `runner`,
`scanctl-version`, and `pre-scan` + `own-images` for an image the repo builds
(`pre-scan` runs the build, `own-images` names the refs it produced). Optional
secrets `DOCKERHUB_USERNAME` + `DOCKERHUB_TOKEN` log the run in to Docker Hub
before the scan, for repos pinning more images than the anonymous pull limit
covers. A scanctl branch named like the caller's branch (a pull
request's head, then its base) takes precedence over `scanctl-version`, so a
scanctl change runs against every caller's branch of the same name before it
merges. The calling job must grant all three permissions above, or GitHub
refuses to start the run.

## Layout

```
cmd/scanctl       CLI (run | version)
internal/detect   manifest-glob router (ecosystems + workflows present)
internal/runner   lazy-fetch + subprocess orchestration + SARIF merge
                  (registry tools + guarddog/image per-manifest/per-ref steps)
internal/sarif    minimal SARIF 2.1.0 types (+ suppressions, properties,
                  fingerprints, security-severity)
internal/report   merged SARIF writer + markdown summary
internal/gate     security-severity / level floor -> exit code
internal/baseline fingerprint diff (base-commit scan or committed baseline)
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
