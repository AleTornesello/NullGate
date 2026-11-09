# NullGate

NullGate is a Rust project for blocking unwanted domains and specific HTTP and HTTPS URLs. It combines a DNS proxy, an HTTP proxy, a proxy orchestrator, and a web interface.

Run NullGate on the same machine as your browser or on a dedicated server serving multiple devices. All devices share the same blocking rules.

## Project status

This repository contains the Rust workspace scaffold and the shared rule engine in `nullgate-core`, with tested parsing, normalization, domain/URL matching and HTTPS inspection-target selection, plus versioned TOML configuration, transactional SQLite blocklist storage and coordinated live policy snapshots. The executable currently reports scaffold status and exits; proxy services and the web interface are not implemented. Undecided features and operational details are marked **TBD**.

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

The service libraries remain placeholders. The executable does not open network ports or perform filtering. Behavioral tests run with `cargo test -p nullgate-core --test rules --locked` and `cargo test -p nullgate-core --test storage --locked`; `cargo test -p nullgate-orchestrator --test policy_updates --locked` checks publication and failure recovery. The workspace test command includes all three suites. CI runs the commands above, with documentation warnings treated as errors.

Task 1 selected dependencies and matching contracts in [implementation decisions](docs/implementation-decisions.md). Task 2 activates `idna` in core; Task 3 adds rusqlite (bundled SQLite), Serde, TOML and safe configuration-path diagnostics. Task 4 activates Tokio in core and orchestration for subscriptions and the bounded writer. Other selected dependencies remain inactive until their owning tasks. The first release targets Linux x86_64; packaging remains to be decided.


The non-secret [example configuration](config/nullgate.example.toml) describes schema 1. `AppConfig::load` validates it and resolves relative data/TLS paths against its directory. The blocking repository stores named mixed lists, source memberships and latest import summaries with revision-checked transactions. Core supplies immutable policy subscriptions and an injectable management trait. The orchestrator’s bounded worker now coordinates storage, activation acknowledgements and complete snapshot publication. These remain library APIs: the scaffold executable does not load configuration, start services or publish rule changes yet.
