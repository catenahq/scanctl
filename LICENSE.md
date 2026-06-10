# Scanctl Sustainable Use License (fair-code)

scanctl is **fair-code**: the source is published and free to use, with
one boundary -- you may not offer scanctl to third parties as a hosted or
managed service, nor resell it as a product.

Pending finalization with counsel, the intended terms follow the n8n
**Sustainable Use License** model:

- **Free** to run for your own internal business purposes and for
  non-commercial use, on infrastructure you control (including running it
  in your own CI or on a client's infrastructure as part of a service you
  perform).
- **Source-available**: you may read, modify, and self-host the code.
- **Not** permitted: offering scanctl (modified or not) to third parties
  as a hosted or managed service, or redistributing it as a competing
  product.
- No time-based conversion to an OSI-approved open-source license (unlike
  BSL); this may be revisited.

> This file states intent. The binding license text is being finalized
> with a Quebec software-licensing specialist before any external release.
> Until then, treat this repository as source-available under the terms
> above.

The FOSS scanners scanctl orchestrates (trivy, osv-scanner, gitleaks,
gosec, govulncheck, semgrep, zizmor, guarddog, syft, and any others) each
carry their own license and are invoked as separate subprocesses (mere
aggregation); those licenses are unaffected by this file.
