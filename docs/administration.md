# Administration

## Blocklists

Administrators create blocklists through the web interface. Each list can contain both domain and URL rules, populated by:

- Entering rules manually.
- Importing a plain-text file.
- Importing from a remote URL.

All three methods use the [same rule format](filtering-rules.md). Valid imported rules are accepted. Malformed rules are reported and ignored.

Saved changes take effect immediately. All devices share one global set of rules; per-device policies are outside the agreed scope.

Remote sources refresh only when an administrator triggers an update. Automatic scheduled refreshes are outside the initial scope. A refresh replaces only that remote source’s memberships and preserves manual/file entries and other sources. Mixed valid/invalid content replaces with the valid subset and reports diagnostics. Failed downloads or responses with no valid rules preserve previous entries. Explicit source clear/removal is separate from refresh. Remote fetches have bounded size/time/redirects and reject private destinations by default (decisions S4–S6 and T4).

## Authentication

The web interface supports three configurable modes:

| Mode | Behavior |
| --- | --- |
| Username and password | Default mode. Users sign in with local credentials. |
| External authentication | Sign-in through an external OpenID Connect provider, such as Keycloak. |
| No authentication | Everyone accessing the interface receives Administrator permissions. |

OpenID Connect authorization code with PKCE S256 is confirmed. Explicit trusted-claim mappings grant Administrator or Viewer; unmapped identities are denied. Provider issuer/client registration and exact claim names remain deployment configuration. Local login requires explicit first-run administrator provisioning with no default password; Argon2id, revocable opaque sessions and server-side CSRF/role checks are selected (T5). Exact account CLI and session lifetimes must be documented before Task 9.

## Roles

| Capability | Administrator | Viewer |
| --- | --- | --- |
| View metrics | Yes | Yes |
| View blocklists | Yes | Yes |
| Create, edit, and import blocklists | Yes | No |
| Trigger remote list updates | Yes | No |
| Manage proxy settings and certificates | Yes | No |
| Manage user access | Yes | No |

There are two roles only. There is no separate blocklist-editor role.

## Certificates

NullGate generates its own CA for HTTPS inspection. Administrators can download the public CA certificate through the web interface and install it as trusted on client devices.

The private CA key remains on the NullGate server and is not part of the client download. Selected generation uses rcgen/rustls; persistent material is reused on restart and the key has owner-only permissions. Corrupt or incomplete existing CA material fails clearly rather than silently replacing trust. Rotation, backup and certificate lifetimes must be decided before Task 12.

## Metrics

The confirmed first dashboard shows aggregate allowed/blocked DNS and HTTP(S) counts, service health/restarts, active connections and import outcomes. Values reset when the process restarts; both roles may view them. There is no individual request history or per-domain/URL/user metric label. Allowed passthrough tunnels do not reveal or count encrypted inner requests. See decision T7 for counting boundaries.

## Save outcomes

The future management API returns a policy revision and accepted/duplicate/malformed diagnostics. Concurrent stale edits return a conflict. Validation or storage failure before commit preserves the old policy. If durable commit succeeds but activation fails, the response explicitly identifies the committed revision as `committed_not_active`; affected traffic remains unavailable until recovery. A successful rule save means the complete revision is active, with in-flight request boundaries described in [implementation decisions](implementation-decisions.md#configuration-persistence-and-publication).


## Implemented repository behavior (Task 3)

Core stores named lists and independent Manual/File/Remote source memberships; there is no management UI yet. Manual/file imports add rules. Explicit replacement is separate from import; source/list removal and source clearing are explicit commands. Remote import replaces only its own memberships when valid rules are present. An empty/all-invalid response or recorded fetch failure preserves previous memberships while storing the attempt outcome and advancing the durable revision.

Each source retains its latest import counts, last attempt/success timestamps and up to 1000 safe malformed-line diagnostics. The immediate commit result includes the complete parser report. Batch accepted counts differ from membership additions when importing rules already present in that source. Cross-source duplicates remain independent, so removing a remote source cannot remove a manual rule.

The repository requires the caller’s expected revision for every edit. Validation, capacity, busy, read-only and transactional write failures leave prior state usable; no partial valid subset is committed if the database write itself fails. Task 4 now implements library-level publication; HTTP outcome mapping remains Tasks 10/11.


## Policy save coordination (Task 4)

The orchestrator now implements the core management interface as a bounded, serialized queue. Successful saves return the published snapshot and full parser diagnostics; malformed lines do not prevent valid entries from becoming active. Queue-full and already-stopped requests are rejected before acceptance. Cancelling a request after acceptance does not cancel its durable update/publication; reconcile its revision before retrying.

Pre-commit storage failure retains the active policy. Post-commit activation error, panic or deadline expiry reports the committed revision as inactive, blocks new policy admissions and refuses further edits until explicit recovery succeeds. These are implemented library outcomes; HTTP routes and connection invalidation consumers remain later tasks.


## Local authentication library (Task 9)

Local username/password authentication is the configuration default. Provision the first Administrator explicitly before web integration; there is no shared default password or remote bootstrap endpoint. Create a regular password file with owner-only permissions (0600) in a trusted directory, containing your unique password and an optional final newline, then run:

```sh
cargo run --locked --bin nullgate -- provision-admin --config config/nullgate.example.toml --username your-admin-name --password-file /secure/path/nullgate-password
```

The command reads and hashes the password without placing it in process arguments or logs. Symlinks, non-regular files, group/other permissions and oversized input are rejected. First-run provisioning is transactional and refuses to overwrite any existing account. Subsequent accounts are created through the Administrator-authorized library API using a live session token; cached role/identity objects are not authority. Web listener and blocklist UI integration are implemented in Task 10; account-management UI remains unimplemented.

Usernames are case-insensitive ASCII, 1–64 letters/digits/dot/underscore/hyphen. Passwords contain 12–1024 UTF-8 bytes, without trimming. Argon2id uses a distinct random salt per password. Sessions are opaque, stored only as SHA256 digests, rotate on login, expire after eight hours and are revoked on logout. There is no sliding idle expiry. Roles and disabled-account state are checked for every request; account creation rechecks Administrator session authority in its write transaction. Authentication changes do not advance the filtering-policy revision.

`nullgate-web::WebState` injects authentication, explicit transport/origin policy and the core management interface. `router(state, management_routes)` protects all supplied routes and fallback handlers, with authenticated `Identity` in request extensions. Viewers may read but cannot mutate through direct requests. Explicit no-authentication mode grants Administrator permissions while retaining trusted Host/Origin and CSRF checks. OIDC remains unavailable until Task 14; proxy-client authentication is separate.

The library provides `/api/v1/auth/csrf`, `/login`, `/logout` and `/me` beneath the same `/api/v1/auth` prefix. Obtain the JSON CSRF proof first; send its cookie and `X-CSRF-Token` plus the configured Origin for login and browser mutations. Login returns a new proof and host-only HttpOnly session cookie; logout clears and revokes it. Authentication responses are `Cache-Control: no-store`. There is no permissive CORS policy.

Cleartext cookies are allowed only for loopback HTTP. Dedicated deployments must serve the router through HTTPS; cookies then use Secure and a `__Host-` prefix, with HttpOnly, SameSite=Lax, Path=/ and no Domain attribute. An explicit loopback TLS reverse-proxy context accepts a configured HTTPS public origin, never inferred forwarding headers. Task 10 supplies this trusted context and binds the corresponding transport.


## Blocklist interface and API (Task 10)

After local Administrator provisioning, start the executable and open its logged `web_origin`. Administrators create/rename/delete lists, add domain and URL rules together, import UTF-8 text files, remove individual memberships and explicitly replace/delete sources. Viewers see the same lists without write controls; server middleware independently rejects their direct write requests. Existing policy is loaded on restart, and successful saves mean the complete revision has been persisted and published to the running proxies.

Manual entries share a Manual provenance group; repeated file imports add to the same filename group. Imports accept valid entries and show original one-based malformed-line diagnostics. All-malformed source replacement preserves its previous rules; an explicit empty replacement clears that source. Replacement wording and confirmation distinguish it from additive import. Sources larger than64KiB are not preloaded into the replacement editor: paste a complete replacement. Names, rule text and diagnostics are escaped; the browser never inserts imported HTML. Native forms use POST even when JavaScript is unavailable, keeping credentials out of URLs; JavaScript is required for the protected editing workflow.

| Method and path | Operation |
| --- | --- |
| `GET /api/v1/lists?offset=&limit=` | Paginated list summaries and revision |
| `POST /api/v1/lists` | Create list (`expected_revision`, `name`) |
| `GET/PATCH/DELETE /api/v1/lists/{id}` | Read sources, rename or delete list |
| `POST /api/v1/lists/{id}/rules` | Add manual rules (`expected_revision`, `text`) |
| `POST /api/v1/lists/{id}/imports?expected_revision=&filename=` | Import raw `text/plain` UTF-8 bytes |
| `GET/PUT /api/v1/sources/{id}/entries` | Paginated entries or explicit complete replacement |
| `POST /api/v1/sources/{id}/remove` | Remove one membership (`expected_revision`, `rule`) |
| `DELETE /api/v1/sources/{id}` | Remove a Manual/File source |

Mutations require current revision, session/role, Origin and CSRF checks. Conflicts are409 and never automatically retried; inputs remain in the editor. Capacity/no-valid-replacement failures are422. Storage unavailability, unknown outcomes and committed-but-inactive revisions use distinct machine codes so callers can reconcile rather than blindly repeat a save. Response diagnostics are capped at1,000 with total/truncation indicators; API pages cap at100 items and HTML pages use smaller bounds. Raw file bytes cap at4MiB, manual encoded JSON at4MiB+8192; small mutations have tighter bounds.

Direct cleartext is loopback-only. Set `web.public_origin` for wildcard listen addresses and dedicated hostnames; direct HTTPS requires certificate/key references, with owner-only private-key files. `web.tls_terminated_by_proxy=true` is an explicit loopback-only alternative with an HTTPS public origin and no direct TLS files. Forwarded headers are ignored. Startup fails and releases already-bound peers if web binding/TLS setup fails. All three services participate in readiness, supervision and cancellation. Remote URL importing/refresh is not included in this milestone.

With Python Playwright and Chromium available, run `python3 scripts/browser_smoke.py` after building the binary. It provisions temporary local state, creates rules through a real browser, verifies local proxy decisions, imports a file and checks removal/shutdown. It uses no public upstreams and writes screenshots/metadata to its artifact directory.
