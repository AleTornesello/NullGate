# System verification

Task 16 audits and exercises the existing implementation; it does not add release packaging or change environment publication.

## Prerequisite audit

No missing production prerequisite was found in Tasks 5–15:

| Task | Existing feature | Verification |
| --- | --- | --- |
| 5 | Cancellable UDP/TCP DNS forwarding and NXDOMAIN filtering | DNS owning suite plus real executable UDP/TCP A/AAAA and boundary checks |
| 6–7 | HTTP policy evaluation, streaming forwarding, CONNECT passthrough and invalidation | Owning suites plus two persistent clients and real TLS passthrough |
| 8 | Binding-based readiness, supervised restart/backoff and termination cleanup | Lifecycle suite plus child-process descriptor exhaustion and readiness/health probes |
| 9–10 | Explicit local provisioning, sessions, Administrator/Viewer authorization, durable management API and Rust UI | Authentication/management suites plus real login, direct role denial and shared policy saves |
| 11 | Explicit remote imports/refreshes with bounded validated fetching and provenance | Local RemoteService fixtures use an explicit test fetch policy; the executable retains its production policy denying private/internal fetch destinations |
| 12 | Persistent CA, protected keys and Administrator-only certificate download | CA suite plus certificate download, client chain/hostname verification and unchanged CA after process restart |
| 13 | Selective inspected HTTPS and end-to-end passthrough, per-request reevaluation | HTTPS suite plus real executable trusted-client connections, immediate invalidation, wildcard/query/sibling decisions and unchanged unlisted origin certificates |
| 14 | OIDC/PKCE, explicit trusted roles and provider logout | Local signed-provider suite; representative Keycloak smoke remains available separately in `scripts/keycloak_smoke.py` as documented in administration |
| 15 | Bounded process aggregates, live health and read-only dashboard/API | Metrics suites plus Viewer read access, recovery/restart counts and fresh-process reset |

Viewer fixture accounts are seeded through the existing trusted offline repository, then authenticated through the real login endpoint. Account-management UI is not a prerequisite and is not added here. All filtering changes under test use the management API.

## Executable scenarios

`cargo test -p nullgate --test end_to_end --locked` runs three non-ignored scenarios against `CARGO_BIN_EXE_nullgate`. Fixtures use private temporary storage, ephemeral loopback ports, local DNS/HTTP/TLS upstreams, custom upstream trust only in child-process environment variables, and explicit isolated client root stores. They never install a machine trust root or query public DNS.

The combined scenario checks DNS forwarding and exact/nested wildcard boundaries over UDP/TCP; URL-only DNS resolution; empty HTTP/HTTPS 403s; query-independent exact/path-wildcard matching and sibling permissions; two existing proxy clients sharing API updates; selective inspection and original certificates for unlisted passthrough; inspected keep-alive reevaluation and tunnel invalidation; line-specific malformed-rule reports; Administrator/Viewer/anonymous restrictions; public CA download; concurrent stale-revision conflicts; and persisted rules, accounts/sessions and CA material across a real process restart. An incomplete upload is terminated before its declared body length and must not change the revision or filtering. A separate import response is abandoned after success headers; its already acknowledged policy remains published and durable.

The recovery scenario uses Linux `prlimit --nofile=64:64` for the child only. Idle client connections exhaust that child's descriptors, triggering an actual HTTP listener `ListenerIo` failure. Tests observe the restart event, release clients, await a post-failure readiness event and live ready/restart metrics, then probe filtering and exclusive listener ownership. This tests the existing production supervision path without adding a fault-injection API or hook. Linux x86_64 is the confirmed first-release target; `prlimit`, `kill` and Python 3 are checked explicitly in CI.

Startup cases verify occupied listeners and malformed configuration exit unsuccessfully without claiming readiness or logging fixture secrets. All waits are bounded, condition-driven log/socket/API probes; polling intervals are not delays used as proof of completion. Child processes and fixture tasks have cleanup guards.

## CI and diagnostic retention

CI builds all targets, checks formatting and Clippy, runs the entire workspace suite, builds documentation with warnings denied, and verifies executable metadata. The test pipeline explicitly selects Bash with `pipefail`, so `tee` cannot hide a Cargo abort. The artifact environment variable is an absolute workspace path, independent of Cargo’s package-root test working directory. The CI guard rejects successful zero-test stubs, absent/ignored/failed executable scenarios, fewer than three passing executable scenarios, failed workspace tests, or a missing successful Cargo completion marker. Python tests exercise the guard's rejection and secret-exclusion behavior.

On failure, CI uploads only `target/e2e-artifacts/*.json` for seven days: numeric test totals and per-scenario static stage names, panic status, and allowlisted lifecycle-event counts. Unknown log text is not copied into these reports. Raw child logs, raw Cargo capture files, configuration, account/session databases, passwords, request headers/queries, certificates and private keys are excluded from uploaded artifacts. Raw child logs are checked for fixture secrets, kept only in temporary test state, then deleted. Sanitized scenario summaries are also generated on successful local runs for inspection.

Task 17 release artifacts and installation packaging remain separate.
