# Amber Shield Scan (GitHub Action)

Free, MIT-licensed GitHub Action version of [Amber Shield](https://www.ambershield.app)'s
vulnerability + secret heatmap scan. Runs [Trivy](https://github.com/aquasecurity/trivy)
(dependency/config CVEs) and [GitLeaks](https://github.com/gitleaks/gitleaks) (secrets)
against your repo in CI, scores every file with the same heatmap logic as the desktop
app, and fails the job when something at or above a severity you choose is found.

This is the CI/Marketplace edition, not the desktop app itself: no Tauri, no HUD, no
license key, no billing, no scan limit. It's a separate, free companion product - same
relationship as [create-ascodex-app](https://github.com/aurora-ember-bio-lab/ascodex-cli)
is to ASCodex.

## Usage

```yaml
name: security-scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aurora-ember-bio-lab/amber-shield-scan-action@v1
        with:
          path: '.'
          fail-on: 'critical'   # none | low | medium | high | critical
          format: 'json'        # json | sarif
```

### Uploading SARIF to the Security tab

```yaml
      - uses: aurora-ember-bio-lab/amber-shield-scan-action@v1
        id: scan
        with:
          format: 'sarif'
          fail-on: 'none'   # let the SARIF upload step be what surfaces findings
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.scan.outputs.report-path }}
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Path to scan, relative to the repo root. |
| `fail-on` | `critical` | Minimum severity that fails the job: `none`, `low`, `medium`, `high`, `critical`. A leaked secret always counts as `critical`. |
| `format` | `json` | Report format: `json` or `sarif`. |
| `report-path` | *(auto)* | Where to write the report. Defaults to `amber-shield-report.json` / `.sarif`. |

## Outputs

| Output | Description |
|---|---|
| `report-path` | Path to the generated report file. |
| `vulnerable-files` | Number of files the heatmap flagged `Vulnerable`. |
| `dependency-findings` | Number of Trivy findings. |
| `secret-findings` | Number of GitLeaks findings. |

## Architecture

```
amber-shield-scan-action/
  action.yml            the Action definition (Docker-based)
  Dockerfile             builds the CLI, bundles pinned+checksummed Trivy & GitLeaks
  src/
    main.rs              CLI entry point: arg parsing, report writing, exit-code gating
    codemap.rs            file heatmap scorer (vendored from Amber Shield Lite's core-engine)
    security/             Trivy & GitLeaks process wrappers (same, vendored)
```

`codemap.rs` and `security/` are copied from the already-MIT
[Amber Shield Lite](https://github.com/aurora-ember-bio-lab/Amber-Shield-releases)
`core-engine` crate - same license, same author, reused headlessly with no
Tauri/GUI dependency at all. This repo has no dependency on the desktop app;
it's a standalone binary.

## Local build & test

```bash
cargo build --release
cargo test --release
./target/release/amber-shield-scan . --fail-on none
```

Point at pinned scanner binaries instead of relying on `PATH` with
`AMBER_TRIVY_BIN=/path/to/trivy` / `AMBER_GITLEAKS_BIN=/path/to/gitleaks`.

## Publishing a new version

Marketplace listing itself is a **web UI step, not an API call** - GitHub
doesn't expose a REST/GraphQL endpoint for "publish this release to the
Marketplace" (only the checkbox on the release-draft page does it), so this
part can't be scripted end-to-end. Everything up to that point can:

```bash
git tag v1.0.0
git push origin v1.0.0
```

Then, in the browser:

1. Go to the repo's **Releases** page -> **Draft a new release**.
2. Choose the `v1.0.0` tag.
3. Check **"Publish this Action to the GitHub Marketplace"** (first time only:
   GitHub will ask you to accept the Developer Agreement).
4. Pick a category (Security), the icon/color already set in `action.yml`
   (`shield` / `orange`) will be suggested by default.
5. Fill in the release notes and click **Publish release**.

After that, also move (or add) a floating major-version tag so
`aurora-ember-bio-lab/amber-shield-scan-action@v1` keeps resolving to the
latest `v1.x.y` - the convention every Marketplace action follows:

```bash
git tag -f v1
git push origin v1 --force
```

## License

MIT - see `LICENSE`. Third-party binaries bundled into the Docker image are
covered under `THIRD_PARTY_NOTICES.md`.
