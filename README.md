# NullGate

NullGate provides shared DNS and explicit HTTP/HTTPS filtering with a Rust web interface. It supports mixed blocklists, immediate policy updates, manual file/remote imports, Administrator/Viewer authorization, local or OIDC login, a persistent inspection CA and aggregate metrics.

## Install and configure

The first release target is **Linux x86_64 GNU, Debian 12/glibc 2.36 baseline**. Candidate preparation produces a user tarball, an amd64 Debian package, build provenance and SHA256 checksums. No release has been published by this work.

Follow the [deployment guide](docs/deployment.md) for checksum verification, user/package installation, explicit first-run Administrator provisioning, listeners/upstreams, client proxy/DNS settings, CA trust/removal, dedicated HTTPS, upgrades and offline backups/recovery. There are no default credentials or pre-generated private keys. Normal package installation does not start an unprovisioned service.

All clients share one policy. Domain blocks return DNS NXDOMAIN; blocked HTTP/HTTPS messages receive an empty403. URL matching ignores queries and supports wildcards. Only HTTPS URL-listed hosts are inspected; unlisted hosts preserve their end-to-end certificates. Inspected clients must trust the public NullGate CA and support HTTP/1.1. URL-only rules do not block host DNS resolution.

NullGate filters traffic actually routed to its listeners. It does not transparently enforce routing, prevent alternate DNS/DoH/QUIC/direct connections, or authenticate proxy clients. Pinning and application-specific certificate stores can make inspection incompatible. See the [enforcement boundaries](docs/deployment.md#enforcement-boundaries).

## Prepare a reproducible candidate

Use Python3.11+, Docker on Linux amd64, the pinned Rust toolchain, and locked registry sources:

```bash
cargo fetch --locked
python3 -m unittest discover -s scripts -p test_release.py
python3 scripts/release.py --reproduce --output /tmp/nullgate-candidate
python3 scripts/rehearse_release.py --artifacts /tmp/nullgate-candidate/artifacts --report /tmp/nullgate-candidate/VALIDATION.json
(cd /tmp/nullgate-candidate/artifacts && sha256sum -c SHA256SUMS)
```

Both compiler and packager images are pinned by digest in `packaging/release.json`. Builds run offline against the fetched public Cargo registry; no Cargo credentials are mounted. Two independent clean target directories must produce identical checksums. Metadata records the input-tree hash, compiler/packager identities, normalized epoch, version and binary hash. Uncommitted candidates are explicitly marked dirty; use `--require-clean` for release preparation from a committed checkout.

The manual **Prepare release candidate** workflow first requires the full CI checks, then builds twice, runs packaged-executable E2E and clean installation rehearsals, and uploads candidates for review. It never creates a release, pushes a tag or publishes an environment. Read `VALIDATION.json` and `reproducibility.json` for actual results and validation limits. Full systemd boot and cross-version schema migration require separate host validation; a container process test does not prove either.

## Development and verification

```bash
cargo build --workspace --all-targets --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked
cargo test -p nullgate --test end_to_end --locked
```

The [system verification report](docs/system-verification.md) audits Tasks5–15 and describes the three real-executable scenarios and secret-free CI failure diagnostics. CI rejects missing/ignored/zero E2E coverage and unsuccessful Cargo completion. Release rehearsals use local upstreams, disposable state and isolated trust; the shared host's trust store is unchanged.

## Documentation and license

- [Deployment](docs/deployment.md): local/dedicated installation and operational commands.
- [Administration](docs/administration.md): roles, imports, certificates, authentication and metrics.
- [Filtering rules](docs/filtering-rules.md): exact/wildcard matching and examples.
- [Architecture](docs/architecture.md): crate responsibilities and dependency direction.
- [Implementation decisions](docs/implementation-decisions.md): confirmed contracts and implementation records.
- [Plan](docs/superpowers/plans/2026-11-09-nullgate-implementation.md): delivery checkpoints.

NullGate is licensed under [MIT](LICENSE). Dependency notices accompany the prepared artifacts.
