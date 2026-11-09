# NullGate

NullGate is a Rust project for blocking unwanted domains and specific HTTP and HTTPS URLs. It combines a DNS proxy, an HTTP proxy, a proxy orchestrator, and a web interface.

Run NullGate on the same machine as your browser or on a dedicated server serving multiple devices. All devices share the same blocking rules.

## Project status

This repository contains the initial Rust workspace scaffold and documentation of the intended behavior. The executable currently reports scaffold status and exits; proxy services and the web interface are not implemented. Undecided features and operational details are marked **TBD**.

## Features

- Block exact domains or wildcard subdomains.
- Block exact URLs or URL patterns with wildcards, ignoring query parameters.
- Filter HTTPS URLs using a locally trusted CA, inspecting only domains derived from URL blocklists.
- Create mixed domain/URL blocklists in the web interface, enter rules manually, or import them from files and remote URLs.
- Apply saved rule changes immediately and refresh remote sources on demand.
- Manage access with Administrator and Viewer roles.
- Use username/password authentication by default, optional external authentication, or explicitly disable authentication.
- View metrics in the web interface; the metrics themselves are TBD.

## How filtering works

Domain rules match DNS names. A blocked DNS query receives **NXDOMAIN**. The HTTP proxy returns an empty **403 Forbidden** response when it blocks an HTTP or HTTPS request.

For HTTPS URL filtering, configure the client to use the HTTP proxy and install NullGate's generated CA certificate as trusted. This enables TLS inspection on domains appearing in URL rules. Other domains pass through without decryption.

```text
# Block this domain, but not its subdomains
example.com

# Block subdomains, but not the parent domain
*.tracking.example.com

# Block exactly this path, ignoring query parameters
https://news.example.com/ads

# Block this path and everything beneath it
https://news.example.com/sponsored/*
```

## Documentation

- [Architecture](docs/architecture.md): components and responsibilities.
- [Filtering rules](docs/filtering-rules.md): blocklist format and matching examples.
- [Administration](docs/administration.md): blocklists, authentication, roles, and certificates.
- [Deployment](docs/deployment.md): local and shared-server operation, client configuration, and open decisions.
- [Implementation plan](docs/superpowers/plans/2026-11-09-nullgate-implementation.md): prioritized tasks, dependencies, and acceptance checks.

## Development

All components use Rust 2024. Install [Rust through rustup](https://rustup.rs/); `rust-toolchain.toml` pins the toolchain and requests rustfmt and Clippy. Run commands from the repository root.

```text
crates/
├── nullgate/               # Executable entry point
├── nullgate-core/          # Shared rules, configuration, and types
├── nullgate-dns/           # DNS proxy boundary
├── nullgate-http/          # HTTP proxy and HTTPS inspection boundary
├── nullgate-orchestrator/  # Lifecycle and rule coordination boundary
└── nullgate-web/           # Web administration boundary
```

```sh
cargo build --workspace --all-targets --locked
cargo run --locked --bin nullgate
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo doc --workspace --no-deps --locked
```

The libraries contain documentation-only placeholders. The executable does not open network ports or perform filtering. There are no behavioral tests yet; the test command currently checks that the scaffold's test targets compile and run. CI runs the commands above, with documentation warnings treated as errors.

The scaffold uses only local workspace dependencies. Web frameworks, async runtimes, DNS/TLS libraries, supported deployment platforms, and release artifacts remain undecided.
