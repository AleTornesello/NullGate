# NullGate Implementation Plan

> **For agentic workers:** Use `superpowers:executing-plans` or `superpowers:subagent-driven-development` to implement one task at a time. This document is a prioritized delivery plan, not authorization to implement all tasks. Complete each task's acceptance checks before marking it done.

**Goal:** Turn the Rust scaffold into a usable DNS/HTTP filtering application with selective HTTPS inspection and web administration.

**Architecture:** Keep the approved six-crate workspace and single executable. Core owns shared configuration and rules; proxies and web consume shared contracts; the orchestrator owns lifecycle and publication of verified rule changes. Web operations must reach orchestration through injected interfaces, avoiding a dependency cycle.

**Tech Stack:** Rust 2024, pinned Rust toolchain, Cargo, rustfmt, Clippy, GitHub Actions. Runtime, protocol, TLS, persistence, and UI dependencies must be selected in Task 1; the current workspace contains no external dependencies.

**Spec:** [Filtering rules](../../filtering-rules.md), [architecture](../../architecture.md), [administration](../../administration.md), and [deployment](../../deployment.md). These documents contain the agreed requirements. Recommendations below are not additional confirmed user requirements.

## Priority and execution order

The numbered order is the recommended implementation order. Dependencies take precedence over parallel work. All tasks are needed for the documented initial release unless explicitly identified as a decision or future work.

- **P0 — foundations:** Tasks 1–4 establish contracts, correct matching, durable state, and live rule publication.
- **P1 — filtering and administration:** Tasks 5–13 deliver proxies, supervision, access control, blocklist management, and HTTPS inspection.
- **P2 — complete and ship:** Tasks 14–17 deliver external login, metrics, system verification, and distribution.

The scaffold and its CI already exist; do not recreate them. Task checkboxes below track future implementation, not completed work.

## Global constraints

- All components are written in Rust; one global set of rules applies to all devices.
- Domain rules are exact; `*.example.com` includes nested subdomains but excludes the parent domain.
- URL matching ignores query parameters. `*` matches zero or more path characters including `/`; trailing `/*` also matches the parent path.
- URL rules must not cause the DNS proxy to block their entire host.
- Derive HTTPS inspection targets from URL blocklists. Other HTTPS traffic passes through without decryption.
- Return NXDOMAIN for blocked DNS queries and an empty HTTP 403 for blocked HTTP/HTTPS requests. Do not display a block page.
- Accept valid imported rules; report malformed rules and ignore them.
- Saved changes take effect immediately; remote lists update only on user action.
- Generate a CA locally. Administrators can download its public certificate; never expose its private key.
- Username/password authentication is the default. Also support external login and explicitly configured no-authentication mode.
- Administrator and Viewer are the only roles. With authentication disabled, everyone has Administrator permissions.
- Preserve the crate dependency direction and update documentation as decisions become implemented behavior.

## Review focus

These failure modes need deliberate coverage in the tasks below:

1. URL normalization must not silently broaden exact rules or let equivalent hostnames bypass domain rules (Tasks 1–2).
2. A saved rule change must affect running proxies and existing relevant connections, without partially published state (Tasks 4, 7, 13).
3. Imported lists and failed remote refreshes must not destroy the last usable ruleset (Tasks 3, 10–11).
4. HTTPS inspection must neither decrypt unlisted domains nor trust invalid upstream certificates (Tasks 12–13).
5. Authentication, role checks, and certificate downloads must hold at the server boundary, including crafted requests bypassing the UI (Tasks 9–10, 12, 14).

## Validation convention

For each behavior-changing task: write a focused test, observe its expected failure, implement the smallest working change, and rerun it. Use local upstream services, temporary storage, ephemeral ports, and isolated test certificates. Tests must not depend on public DNS, Internet websites, or a user's installed CA trust.

Before completing each task, run its focused tests plus `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, and `cargo test --workspace --locked`. Update `Cargo.lock` intentionally when adding dependencies. Build documentation with `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked` when public interfaces change. Commit independently reviewable changes; push only when authorized.

Commands and test filenames listed below are implementation targets, not tests that exist today.

## Ordered task list

### 1. Resolve contracts and select dependencies — P0

- [x] Record implementation decisions before adding behavior. See [implementation decisions](../../implementation-decisions.md) for selected contracts, confirmed product choices, dependency compatibility evidence and owning-task prerequisites.

**Depends on:** Nothing.
**Files:** Create `docs/implementation-decisions.md`; update the four specification documents and workspace manifests when selections are made.
**Deliverable:** A consistent set of normalization, configuration, persistence, transport, and API decisions.

Decide hostname case/trailing dots/IDNA, URL ports, encoded paths and dot segments, whitespace/comments, duplicates, and handling of unsupported rule syntax. Define how failed saves and live publication are reported. Specify remote-refresh replacement/merge behavior and preservation of manual entries. Resolve HTTP-only URL rules' effect on HTTPS inspection selection. Confirm external login protocol, role mapping, metrics scope, and target release platforms before their owning tasks.

Recommended starting stack: Tokio, Hickory DNS protocol support, Hyper, rustls/tokio-rustls, rcgen, Axum with Rust-rendered HTML, SQLite, TOML configuration, and structured tracing. Evaluate maintained versions and compatibility with the pinned toolchain before selecting them. Prefer OIDC for external sign-in. These are proposals, not prior user decisions.

**Acceptance:** Publish a decision table with selected behavior, rationale, and affected tests. Unresolved product choices remain explicit prerequisites for their owning tasks; they do not block unrelated work. No implementer should need to guess matching semantics in Task 2.

### 2. Implement parsing, verification, and matching — P0

- [x] Build the shared rule engine. See [Task 2 matching clarifications and validation](../../implementation-decisions.md#task-2-matching-clarifications-and-implementation-record).

**Depends on:** Task 1's matching decisions.
**Files:** `crates/nullgate-core/src/{lib,rules,matching}.rs`; `crates/nullgate-core/tests/rules.rs`.
**Interfaces:** Core exposes `parse_blocklist(input: &str) -> ImportReport`; the report contains accepted typed rules and malformed-rule diagnostics with line numbers. A compiled `RuleSet` exposes separate domain matching, URL matching, and inspection-host selection. Final signatures and normalization types are recorded alongside Task 1 decisions before consumers are implemented.

**Acceptance:** Table-driven tests cover every example in `docs/filtering-rules.md`, query stripping, scheme/host separation, nested wildcard domains, exact `/ads` versus `/ads/`, `/ads/*` excluding `/adsense`, comments, empty input, mixed valid/invalid lines, and chosen normalization boundaries. Confirm a URL-only rule does not block DNS for its host. Bound wildcard matching work for long/adversarial patterns.

**Check:** `cargo test -p nullgate-core --test rules`.

### 3. Add configuration and durable blocklist storage — P0

- [x] Persist named mixed blocklists, settings, and source metadata. See [Task 3 contracts and validation](../../implementation-decisions.md#task-3-storage-and-configuration-contracts) and the [example configuration](../../../config/nullgate.example.toml).

**Depends on:** Tasks 1–2.
**Files:** `crates/nullgate-core/src/{config,storage,blocklists}.rs`; `crates/nullgate-core/tests/storage.rs`; `config/nullgate.example.toml`.
**Interfaces:** A repository interface provides list CRUD, source provenance, import reports, and transactional updates. Store enough information to refresh imported sources without losing manual entries under the Task 1 policy. Configuration includes listener addresses, data path, DNS upstreams, and authentication mode.

**Acceptance:** Restart preserves rules and settings; malformed configuration is actionable; failed writes leave prior state usable; mixed imports retain valid entries and report ignored lines. Use configurable unprivileged ports in examples and tests. No hardcoded passwords, CA keys, or production secrets in examples.

**Check:** `cargo test -p nullgate-core --test storage`.

### 4. Publish live rulesets safely — P0

- [x] Coordinate validation, persistence, and immediate publication. See [Task 4 contracts and validation](../../implementation-decisions.md#task-4-policy-publication-contracts).

**Depends on:** Tasks 2–3.
**Files:** `crates/nullgate-core/src/policy.rs`; `crates/nullgate-orchestrator/src/{lib,policy}.rs`; `crates/nullgate-orchestrator/tests/policy_updates.rs`.
**Interfaces:** Define a shared immutable, versioned policy snapshot and subscription handle in core. Orchestration owns the write path. DNS, HTTP, and web receive injected read/write interfaces without depending back on the orchestrator crate.

**Acceptance:** A successful save publishes a complete snapshot before acknowledging success; reads never observe half a list. Invalid imports publish their valid subset with diagnostics. Storage failure does not publish an unsaved snapshot. Concurrent edits have a defined conflict policy. Tests observe updated domain, URL, and inspection-host decisions through existing handles.

**Check:** `cargo test -p nullgate-orchestrator --test policy_updates`.

### 5. Implement the DNS proxy — P1

- [x] Serve blocked responses and forward permitted queries. See [Task 5 transport contracts and validation](../../implementation-decisions.md#task-5-dns-transport-contracts).

**Depends on:** Tasks 1 and 4.
**Files:** `crates/nullgate-dns/src/{lib,server,upstream}.rs`; `crates/nullgate-dns/tests/dns_proxy.rs`.
**Interfaces:** A startable, cancellable service takes listener/upstream configuration and a policy subscription; it reports readiness and failures to orchestration.

**Acceptance:** Exact/wildcard domain blocks return correctly formed NXDOMAIN responses; allowed A/AAAA queries reach a local upstream; URL-only hosts still resolve. Cover UDP and TCP DNS, malformed packets, response association, timeouts, and live updates. Preserve relevant DNS protocol fields. Caching and additional upstream transports are separate decisions, not prerequisites to forwarding.

**Check:** `cargo test -p nullgate-dns --test dns_proxy`.

### 6. Implement unencrypted HTTP filtering — P1

- [ ] Forward allowed HTTP traffic and reject blocked requests.

**Depends on:** Tasks 1 and 4.
**Files:** `crates/nullgate-http/src/{lib,server,forward}.rs`; `crates/nullgate-http/tests/http_proxy.rs`.
**Interfaces:** Cancellable proxy service accepts listener configuration and a policy subscription. Separate request policy evaluation from forwarding for reuse during TLS inspection.

**Acceptance:** Local upstream tests verify domain blocking, exact/wildcard URLs, query ignoring, permitted sibling paths, and empty 403 responses. Cover streaming bodies, hop-by-hop headers, malformed authorities, upstream errors, and policy changes between requests on a keep-alive connection. Preserve normal forwarding semantics rather than buffering all bodies.

**Check:** `cargo test -p nullgate-http --test http_proxy`.

### 7. Add HTTPS CONNECT passthrough — P1

- [ ] Tunnel permitted HTTPS traffic without decryption.

**Depends on:** Task 6.
**Files:** `crates/nullgate-http/src/tunnel.rs`; `crates/nullgate-http/tests/connect_proxy.rs`.
**Acceptance:** Blocked domains receive an empty 403 to CONNECT. Allowed tunnels preserve end-to-end TLS, transfer bytes both ways, and shut down cleanly. Validate authorities and ports. Track tunnels so later domain blocks can close affected connections. Until Task 13 implements inspection, explicitly report HTTPS URL filtering as unavailable; do not claim path rules are enforced in passthrough traffic.

**Check:** `cargo test -p nullgate-http --test connect_proxy`.

### 8. Wire service lifecycle and executable — P1

- [ ] Start, supervise, stop, and restart proxies through the orchestrator.

**Depends on:** Tasks 3–7.
**Files:** `crates/nullgate-orchestrator/src/{lib,supervisor}.rs`; `crates/nullgate/src/main.rs`; `crates/nullgate-orchestrator/tests/lifecycle.rs`.
**Interfaces:** Service readiness, cancellation, health, and exit events have one contract; the binary loads configuration and delegates to orchestration.

**Acceptance:** Both proxies start with configured listeners; readiness follows successful binding; shutdown drains/cancels work. A failed proxy is restarted with bounded backoff and no duplicated listener. Initial bind errors fail clearly instead of silently reporting readiness. Deterministic tests inject failures and time progression. Structured logs omit credentials and private keys.

**Check:** `cargo test -p nullgate-orchestrator --test lifecycle`; run the binary with test configuration and exercise both proxies locally.

### 9. Implement local authentication and roles — P1

- [ ] Protect web administration before adding management endpoints.

**Depends on:** Tasks 1 and 3.
**Files:** `crates/nullgate-web/src/{lib,auth,authorization,session}.rs`; `crates/nullgate-web/tests/access_control.rs`; user storage modules in core.
**Interfaces:** Authenticated identity has an Administrator or Viewer role; server middleware enforces permissions. Define injected application state for future management handlers.

**Acceptance:** Username/password is the default; first-run administrator provisioning is explicit with no shared default password. Store salted password hashes and protect sessions and mutating browser requests. Test invalid credentials, expired sessions, logout, Viewer write rejection, and explicit no-auth mode granting Administrator. Define protected transport/cookie behavior for local and dedicated-server deployments. Keep proxy-client authentication separate from web login.

**Check:** `cargo test -p nullgate-web --test access_control`.

### 10. Build blocklist API and Rust web interface — P1

- [ ] Deliver list management with manual entry and file imports.

**Depends on:** Tasks 4, 8, and 9.
**Files:** `crates/nullgate-web/src/{routes,blocklists,views}.rs`; `crates/nullgate-web/tests/blocklists.rs`; orchestrator web-service wiring.
**Interfaces:** Web handlers call the injected blocklist/policy management interface, not direct proxy internals. Report accepted entries and line-specific malformed entries after imports.

**Acceptance:** Administrators create/edit/delete lists and enter/import mixed rules. Changes persist and immediately affect running proxies. Viewers can read lists but cannot modify them through crafted direct requests. Render imported text safely. Bound upload/request sizes. Add the web service to startup and shutdown without introducing a crate dependency cycle.

**Check:** `cargo test -p nullgate-web --test blocklists`; browser smoke test creates a rule and observes its filtering effect.

### 11. Add manual remote blocklist refresh — P1

- [ ] Fetch remote sources on explicit administrator action only.

**Depends on:** Tasks 1 and 10.
**Files:** `crates/nullgate-orchestrator/src/imports.rs`; `crates/nullgate-web/src/imports.rs`; `crates/nullgate-orchestrator/tests/remote_imports.rs`.
**Acceptance:** Use the same parser as manual/file imports, preserve source metadata, and apply the Task 1 refresh policy. Cover partial-invalid content, timeouts, non-success status, oversized responses, redirect limits, and failed refresh preserving the previous usable rules. Validate every redirect destination under a documented fetch policy to prevent unexpected access to internal services. No scheduler or background refresh is introduced.

**Check:** `cargo test -p nullgate-orchestrator --test remote_imports` using a local fixture server and an explicit test fetch policy.

### 12. Generate and manage the inspection CA — P1

- [ ] Create persistent CA material and expose public-certificate download.

**Depends on:** Tasks 3 and 9–10.
**Files:** `crates/nullgate-http/src/ca.rs`; `crates/nullgate-web/src/certificates.rs`; `crates/nullgate-http/tests/ca.rs`; `crates/nullgate-web/tests/certificates.rs`.
**Interfaces:** A CA provider supports hostname leaf issuance for Task 13. A separate read interface exposes only public certificate bytes to web handlers.

**Acceptance:** Generate once, reuse after restart, issue correctly named leaf certificates, and protect private-key storage. Administrators can download the public CA; Viewers and unauthenticated callers cannot in authenticated modes. Test that downloads and logs never include private key material. Corrupt CA files fail clearly rather than silently replacing the trust root. Document certificate lifetime and recovery/rotation behavior before release.

**Check:** `cargo test -p nullgate-http --test ca`; `cargo test -p nullgate-web --test certificates`.

### 13. Implement selective HTTPS URL filtering — P1

- [ ] Inspect only URL-listed hosts and reuse HTTP rule enforcement.

**Depends on:** Tasks 4, 6–7, and 12.
**Files:** `crates/nullgate-http/src/{inspection,tls}.rs`; `crates/nullgate-http/tests/https_filtering.rs`.
**Acceptance:** Isolated clients trust the test CA. An exact `/ads` rule blocks `/ads` and its query variants but permits `/news`; `/ads/*` also blocks descendants. Listed hosts receive NullGate-issued leaf certificates; unlisted hosts retain the upstream certificate through passthrough. Verify upstream hostname/chain validation and rejection of invalid certificates. Reject inspected requests whose authority differs from the CONNECT target; do not allow SNI/Host mismatches to bypass policy. Missing client trust produces a clear TLS failure, not a misleading success.

**Live updates:** Reevaluate each inspected request. When new URL rules require inspecting a previously tunneled host, close its existing passthrough tunnels so subsequent connections can be inspected. Test both adding and removing targets and new domain blocks; document in-flight request boundaries rather than promising to undo responses already sent.

**Check:** `cargo test -p nullgate-http --test https_filtering`; confirm the executable now enforces both HTTP and HTTPS URL rules.

### 14. Add external identity-provider login — P2

- [ ] Support the confirmed external authentication protocol and two-role mapping.

**Depends on:** Tasks 1 and 9.
**Files:** `crates/nullgate-web/src/oidc.rs` if OIDC is confirmed; `crates/nullgate-web/tests/external_login.rs`; configuration and administration documentation.
**Acceptance:** Test authorization flow, state/nonce/PKCE where applicable, issuer/audience/signature/expiry validation, logout/session behavior, and provider failures. Map trusted provider claims to Administrator/Viewer using explicit configuration; unknown identities must not become administrators accidentally. Validate against a local provider fixture and a representative Keycloak integration. Keep local and no-auth modes working.

**Check:** `cargo test -p nullgate-web --test external_login`; document exact Keycloak configuration after protocol confirmation.

### 15. Implement agreed metrics and dashboard — P2

- [ ] Define metrics, instrument services, and show them in the web interface.

**Depends on:** Task 1's metrics decision and Tasks 8–10, 13.
**Files:** `crates/nullgate-core/src/metrics.rs`; proxy/orchestrator instrumentation; `crates/nullgate-web/src/metrics.rs`; `crates/nullgate-web/tests/metrics.rs`.
**Proposed minimum:** Allowed/blocked DNS and HTTP requests, proxy health/restart counts, active connections, and import outcomes. These values, retention, and aggregation require confirmation; they are not already agreed requirements.

**Acceptance:** Deterministic request sequences produce expected counts; both roles can view metrics; collection stays bounded and does not expose credentials or query parameters. Avoid unbounded per-domain/URL labels. Dashboard states distinguish unavailable services from zero traffic. Document retention/reset behavior.

**Check:** `cargo test -p nullgate-web --test metrics` plus instrumentation tests in the owning crates.

### 16. Verify the complete system and failure recovery — P2

- [ ] Add release-blocking end-to-end tests and complete CI coverage.

**Depends on:** Tasks 5–15.
**Files:** `crates/nullgate/tests/end_to_end.rs`; local fixtures under `crates/nullgate/tests/support/`; `.github/workflows/ci.yml`.
**Acceptance:** Launch the real executable on ephemeral ports with temporary state. Verify DNS upstream forwarding/NXDOMAIN, domain and URL wildcard boundaries, empty HTTP/HTTPS 403s, permitted sibling URLs, unlisted TLS passthrough, immediate updates, rejected malformed rules, role enforcement, certificate download, persistence across restart, and failed-proxy recovery. Include two clients sharing rules, concurrent edits, interrupted imports, and startup failures. Use readiness probes and bounded waits, not fixed sleeps. CI must actually execute nonzero behavioral tests and preserve useful failure logs without secrets.

**Check:** `cargo test --workspace --locked`; `cargo test -p nullgate --test end_to_end`; full build/format/Clippy/documentation checks.

### 17. Package and document a reproducible release — P2

- [ ] Produce installable artifacts and verified operator instructions.

**Depends on:** Task 16 and confirmed supported platforms.
**Files:** release workflow under `.github/workflows/`; packaging files appropriate to selected targets; `README.md`; `docs/deployment.md`; `docs/administration.md`.
**Acceptance:** A clean machine can install an artifact, provision an administrator, configure upstream DNS and both clients, trust the public CA, create a mixed list, and verify permitted/blocked traffic. Exercise local and dedicated-server setups. Document listen addresses, permissions, data locations, upgrades/backups, CA trust/removal, recovery, and authentication modes. Explain certificate pinning, application-specific trust stores, DNS caching, DoH/HTTP3, and traffic bypassing configured proxies. Describe which bypasses are out of scope rather than claiming transparent network enforcement.

**Check:** Rehearse the published commands against clean state on every supported target; run release smoke tests and verify artifact checksums.

## Delivery checkpoints

| After task | Demonstrable outcome |
| --- | --- |
| 4 | Correct, persistent rules and immediate policy publication, tested without network services |
| 8 | Supervised DNS and HTTP filtering, with HTTPS domain blocking/passthrough |
| 11 | Locally authenticated web blocklist management and user-triggered imports |
| 13 | Selective HTTPS URL blocking with a downloadable generated CA |
| 15 | All agreed authentication modes and the confirmed metrics dashboard |
| 17 | End-to-end validated and documented initial release |

## Future work outside this initial plan

Automatic remote-list schedules, per-device policies, additional roles, transparent interception, and user-supplied CA support are not part of the agreed initial scope. DNS caching, additional DNS transports, proxy-client authentication, and richer metrics require separate scope decisions; do not silently add them.
