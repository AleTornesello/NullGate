# Architecture

NullGate consists of four components, all written in Rust. The initial scaffold uses separate library crates and one executable. Task 1 selects runtime and interface contracts in [implementation decisions](implementation-decisions.md); the shared rule engine, TOML configuration, SQLite repository, live-policy coordinator and cancellable DNS/HTTP library services with opaque CONNECT passthrough are implemented; executable startup, TLS inspection and web services remain unimplemented.

## DNS proxy

The DNS proxy evaluates domain blocking rules. It returns NXDOMAIN for blocked names and forwards permitted requests to upstream DNS servers configured by an administrator.

An exact rule applies only to the named domain. A wildcard rule such as `*.example.com` applies to subdomains, including nested subdomains, but excludes `example.com` itself.

Initial DNS uses UDP and TCP, retries truncated UDP replies over TCP, and tries configured upstreams in order within bounded deadlines. No caching, DoH or DoT is selected. Task 5 implements these DNS transports with isolated associated upstream exchanges, request/connection bounds, cancellation and core lifecycle monitors. See decision T2 and the Task 5 protocol contracts.

## HTTP proxy

Clients select the HTTP proxy through browser or operating system proxy settings. The proxy enforces domain and URL rules and returns an empty HTTP 403 response when a request is blocked. It does not display a block page.

The library currently supports unencrypted HTTP filtering and opaque CONNECT tunnels. It reports HTTPS URL filtering as unavailable through `HttpService::capabilities()` and a successful CONNECT response header; URL-only hosts stay permitted. Existing tunnels close on domain blocks or inspection-selection changes. The HTTP tunnel control implements core policy activation for acknowledgement after selective cleanup; Task 8 must inject it into the coordinator. The executable still does not start these services.

For unencrypted HTTP, the proxy can evaluate URL paths directly. For HTTPS, URL paths are encrypted, so matching them requires TLS inspection:

1. NullGate derives inspection targets from the exact hosts present in active HTTPS URL rules (HTTP-only rules do not select inspection).
2. A client configured to use NullGate must trust its generated CA certificate.
3. For an inspection target, NullGate terminates client TLS and establishes a separate TLS connection to the destination, allowing it to evaluate the URL path.
4. For other domains, HTTPS traffic passes through without decryption.

A domain with an exact blocked URL can still serve other URLs. Whole-domain rules take precedence in effect: a matching URL cannot make a blocked domain accessible.

Domain rules do not require decryption. The proxy rejects blocked CONNECT targets with an empty 403 and closes affected existing tunnels after policy changes. Inspected TLS verifies upstream certificates and authority/SNI agreement; passthrough retains end-to-end TLS.

## Proxy orchestrator

The orchestrator is responsible for:

- Starting and stopping the DNS and HTTP proxies.
- Verifying blocking rules.
- Restarting failed proxies automatically.

Saved rule changes commit transactionally to SQLite, then publish one immutable versioned snapshot through a core-owned subscription. Task 4 implements a bounded serialized writer and an immutable active-or-unavailable watch state, with injectable idempotent activation acknowledgements. Success follows publication and required tunnel invalidation acknowledgements; in-flight work has the boundary defined by decisions S7–S9. Stale edits conflict. Post-commit activation failure is reported distinctly from an unsaved edit. Services share readiness/cancellation/failure contracts; restart backoff is bounded (T1).

Malformed imported rules are reported and ignored; valid rules are accepted.

## Web interface

The web interface provides blocklist management, metrics, and administration. Administrators can create lists, add rules, import lists, trigger remote updates, and download the public CA certificate. Viewers can read metrics and blocklists without changing them.

Selected stack: Tokio, Hickory protocol support, Hyper, rustls/tokio-rustls, rcgen, Axum/Maud, SQLite, TOML and tracing. A revision-aware `/api/v1` management API and Rust-rendered HTML call the same injected core management interface; web never depends on the orchestrator. The confirmed metrics are process-lifetime aggregates without request history. Details and tests are recorded in implementation decisions. See [Administration](administration.md) for access rules.

## Workspace dependency direction

- `nullgate` → `nullgate-orchestrator`.
- `nullgate-orchestrator` → `nullgate-core`, `nullgate-dns`, `nullgate-http`, and `nullgate-web`.
- Each service crate → `nullgate-core`.
- `nullgate-core` has no internal workspace dependencies; third-party libraries may provide normalization, configuration and storage.

These manifest dependencies reserve the component boundaries. Core now exposes typed normalization, import reports, immutable matching, startup configuration and transactional blocklist repository and policy read/write APIs. Orchestration implements the core-owned object-safe management trait; service crates receive subscriptions and never depend on the orchestrator. Service wiring remains unimplemented. See the [README](../README.md#development) for build and check commands.
