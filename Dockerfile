# Builds the amber-shield-scan CLI, then packages it with Trivy + GitLeaks
# into a small runtime image. GitHub builds this Dockerfile fresh on every
# workflow run for a `runs.using: docker` action - fine for a v1, but if
# scan time matters, publish this image once to GHCR/Docker Hub and point
# action.yml's `image:` at `docker://ghcr.io/<org>/amber-shield-scan:vX`
# instead, so runs pull a prebuilt layer rather than rebuilding.
#
# SECURITY NOTE: Trivy suffered a real supply-chain compromise in March
# 2026 (GHSA-69fq-xp46-6x23 / CVE-2026-33634) - a malicious v0.69.4 release
# briefly went out via GitHub releases, container registries, package
# managers, and the get.trivy.dev install script. Because of that:
#   - we do NOT `curl | sh` the install script (one of the affected
#     channels) - we download the pinned release tarball directly and
#     verify it against the project's own published SHA256 checksum file.
#   - versions below are pinned exactly, never "latest", and were checked
#     against the affected-version list before picking them. Re-verify
#     against the advisory before bumping across it:
#     https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23

# `slim-bookworm` (no version number) always resolves to the current
# stable Rust release rather than a version pinned at the moment this file
# was written. That matters here: Cargo.lock was generated with whatever
# toolchain built this crate, and an older pinned image can fail
# `cargo build --locked` outright once a dependency's MSRV moves past it
# (this happened once already - see git history / CI logs if curious).
# If you want a fully reproducible build later, pin an exact version tag
# that you've confirmed both exists on Docker Hub and is new enough to
# satisfy every dependency's MSRV, then re-test `docker build` before
# relying on it.
FROM rust:slim-bookworm AS build
WORKDIR /src

# tree-sitter grammars compile a small amount of C via the `cc` crate.
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl tar \
    && rm -rf /var/lib/apt/lists/*

# --- Trivy: pinned, direct download + checksum verification ---
ARG TRIVY_VERSION=0.74.0
ARG TRIVY_SHA256=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a
RUN curl -sSL -o /tmp/trivy.tar.gz \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    && echo "${TRIVY_SHA256}  /tmp/trivy.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm /tmp/trivy.tar.gz

# --- GitLeaks: pinned, direct download + checksum verification ---
ARG GITLEAKS_VERSION=8.28.0
ARG GITLEAKS_SHA256=a65b5253807a68ac0cafa4414031fd740aeb55f54fb7e55f386acb52e6a840eb
RUN curl -sSL -o /tmp/gitleaks.tar.gz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    && echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && rm /tmp/gitleaks.tar.gz

COPY --from=build /src/target/release/amber-shield-scan /usr/local/bin/amber-shield-scan

ENTRYPOINT ["/usr/local/bin/amber-shield-scan"]
