# Third-party notices

This action's Docker image bundles the following external scanner binaries.
They are downloaded at image-build time from their own official GitHub
releases, pinned to an exact version and verified against that release's
own published SHA256 checksum (see `Dockerfile`) - they are not built from
source or vendored into this repo.

| Tool | License | Used for | Upstream |
|---|---|---|---|
| [Trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | Dependency/config CVE scanning feeding the heatmap | Aqua Security |
| [GitLeaks](https://github.com/gitleaks/gitleaks) | MIT | Secret-scanning feeding the heatmap | Gitleaks |

Both licenses permit redistribution here; this repo's own source is MIT
licensed (see `LICENSE`).

## Version pin note

`Dockerfile` pins Trivy to a version chosen after checking it against
[GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23),
a real supply-chain compromise of a Trivy release in March 2026 (malicious
`v0.69.4`). Re-check any future version bump against that advisory (or its
successor) before changing `TRIVY_VERSION` / `TRIVY_SHA256`.

## Rust dependencies

This crate's direct dependencies (serde, tree-sitter, thiserror, anyhow,
which, tempfile) are all MIT/Apache-2.0/BSD-class permissive licenses.
Run `cargo install cargo-license && cargo license` before shipping a new
release to generate a current transitive manifest.
