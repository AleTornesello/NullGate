# Deployment

## Supported deployment models

NullGate is intended to run either on the browser's own machine or on a dedicated server serving multiple devices. The confirmed first release target is Linux x86_64 (`x86_64-unknown-linux-gnu`). The supported distro/glibc baseline and packaging remain prerequisites for Task 17; other platforms are not promised.

All devices use the same blocking rules.

## Setup outline

The following is the intended setup flow, not an executable installation guide. Binaries, exact CLI flags, runtime defaults and service packaging are not implemented. Core now loads the schema-1 configuration shown in the example below; the executable is not wired to it yet. Task 1 selects versioned TOML startup configuration and SQLite persistent state; see [implementation decisions](implementation-decisions.md).

1. Install and start NullGate on the selected machine.
2. Configure the DNS and HTTP proxy listen addresses and ports.
3. Configure upstream DNS servers for permitted DNS queries.
4. Configure web authentication; username/password is the default.
5. Create blocklists in the web interface and add or import rules.
6. Point client DNS settings to NullGate's DNS proxy.
7. Configure the browser or operating system to use NullGate's HTTP proxy.
8. Download the public CA certificate from the web interface as an administrator and install it as trusted on each client requiring HTTPS URL filtering.

For a local installation, client settings point to the local NullGate instance. For a dedicated server, client settings point to its reachable network address. Exact configuration steps depend on the browser and operating system and remain to be documented.

## HTTPS behavior

NullGate inspects HTTPS only for exact hosts derived from active HTTPS URL rules. HTTP-only URL rules do not select inspection. Other HTTPS traffic passes through without decryption. Trusting the generated CA allows NullGate to inspect traffic for selected domains; distribute only the public certificate to clients.

Applications with certificate pinning or a separate trust store may require additional configuration or may be incompatible with inspection. Missing client trust causes TLS failure. Invalid upstream chains or hostnames are rejected with no insecure passthrough fallback for an inspection target.

Domain-only filtering does not require HTTPS path inspection.

## Operational behavior

- The orchestrator starts and stops both proxies and restarts failed proxies.
- Rule changes take effect immediately after saving.
- Remote blocklist updates require an explicit user action.
- Blocked DNS queries receive NXDOMAIN; blocked HTTP/HTTPS requests receive an empty 403 response.

Clients must actually route their relevant DNS and HTTP traffic through NullGate for its rules to apply. Browser/OS settings are the intended integration; transparent interception is not specified.

## Details still to define

- Installation artifacts and Linux x86_64 distro/glibc baseline.
- Release build and packaging workflow (scaffold build/check commands are in the README).
- Exact listen defaults and persistent data paths; TOML startup config and SQLite are selected.
- HTTPS certificate/proxy configuration: public/shared administration requires HTTPS; cleartext administration is loopback-only (T5).
- Exact first-run provisioning CLI and OIDC provider registration/claim configuration.
- Operator-facing DNS configuration: initial UDP/TCP, bounded timeout/failover and no caching are selected (T2).
- Proxy authentication, if any; web interface authentication does not define client proxy authentication.
- CA storage, backup, rotation, and recovery.
- Operator-facing settings and guidance for tracing, bounds, health and restart behavior selected in implementation decisions. Metrics are process-lifetime aggregates with no request history.
- Handling of client DNS caches, DNS-over-HTTPS, HTTP/3, and software bypassing configured proxies.

## Validation once an implementation exists

Verify a permitted request, an exact domain block, a wildcard subdomain block, an exact HTTPS URL block, and a wildcard URL block. Confirm that queries are ignored, sibling URLs remain permitted, and unlisted HTTPS domains are not inspected. Also verify malformed-rule reporting, immediate rule updates, upstream DNS forwarding, access restrictions for Viewers, and failed-proxy restarts.

These are acceptance scenarios for future tests; they have not been executed against an implementation.


## Implemented configuration and storage APIs (Task 3)

[config/nullgate.example.toml](../config/nullgate.example.toml) is a non-secret, loopback-only example with unprivileged ports. Its required startup settings include listener socket addresses, ordered DNS upstreams and a data directory. Local web authentication is the default; `oidc` and `none` select future authentication behavior only. Schema version and unknown fields are validated, and errors identify a field path/line without echoing its value.

Relative data and TLS-file references resolve against the configuration file’s directory. The database path is `<data_dir>/nullgate.sqlite3`. DNS attempt/total deadlines default to 2000/5000ms. Cleartext administration binds loopback only; non-loopback web addresses require paired TLS file references. This validation does not read TLS keys or start a TLS service. Startup setting changes require rereading the configuration/restarting once Task 8 integrates startup.

The core repository uses SQLite WAL with FULL synchronous mode and transactional schema version 1. Reopening validates stored rules and provenance; unsupported schemas/corruption fail instead of resetting data. Newly created directories/files are private on Unix (0700/0600). Existing directory permissions remain the operator’s responsibility. Do not copy only an active WAL database file as a backup; release backup/restore procedures remain part of Task 17.

Repository methods are blocking. Task 4 now runs them on a bounded storage worker and publishes the returned complete compiled policy before acknowledging saves. A storage commit by itself does not mean running proxies have updated.


## Implemented policy coordination API (Task 4)

`PolicyCoordinator::open` opens/loads the repository on its dedicated blocking task. Applications choose the queue bound (normally `limits.storage_queue_capacity`) and an activation deadline (default 5s). The binary does not invoke this API yet. Runtime startup remains Task 8.

A successful library save means the durable revision is published to all existing read handles. Readers capture one immutable snapshot per request; watch notifications can coalesce, so the latest complete revision is authoritative. A retained old snapshot is only for work admitted before a change. Failed validation/writes preserve the active snapshot. Expected-revision conflicts are explicit; the coordinator never automatically retries an edit.

Future connection managers must register idempotent activation hooks and acknowledge required invalidations. While activation is pending or failed after commit, new policy reads are unavailable; a failure reports `CommittedNotActive` with its durable revision. Explicit recovery reloads durable state and repeats activation before publishing. Worker loss makes reads unavailable; an accepted request whose reply is lost has `OutcomeUnknown` and must be reconciled before retry. Repository writes outside the coordinator are unsupported while it owns the policy.

Graceful shutdown drains commands ahead of its stop marker, makes read handles unavailable and joins the worker. Real proxy responses to unavailable policy and tunnel invalidation behavior remain their protocol/lifecycle tasks; Task 4 starts no listeners.
