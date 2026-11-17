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

OpenID Connect authorization code with PKCE S256 is confirmed. Explicit trusted-claim mappings grant Administrator or Viewer; unmapped identities are denied. Provider issuer/client registration and exact claim names remain deployment configuration. Local login requires explicit first-run administrator provisioning with no default password; Argon2id, revocable opaque sessions and server-side CSRF/role checks are selected (T5). The provisioning command, bounded sessions and protected file requirements are documented below and in the deployment guide.

## Roles

| Capability | Administrator | Viewer |
| --- | --- | --- |
| View metrics | Yes | Yes |
| View blocklists | Yes | Yes |
| Create, edit, and import blocklists | Yes | No |
| Trigger remote list updates | Yes | No |
| Download the public inspection CA | Yes | No |

There are two roles only. Startup/proxy settings are operator-managed configuration files, not web settings. Additional local account-management UI/CLI is not exposed; OIDC maps trusted provider roles explicitly.

## Certificates

On first startup NullGate generates a local ECDSA P-256 CA and reuses that exact identity on every restart. The executable now inspects only hosts derived from HTTPS URL rules. Clients accessing those hosts must explicitly trust the public NullGate CA; unlisted hosts retain end-to-end TLS. No operating-system or browser trust store is changed automatically.

Administrators use **Download public CA** or `GET /api/v1/certificates/ca` to download `nullgate-inspection-ca.pem`. Authenticated Viewers and unauthenticated clients cannot download it; explicit no-authentication mode grants Administrator access as documented above. The download contains only the public certificate, with attachment/no-store headers. Web code receives no signer, private key or private-file operation. There is no private-key download or leaf-issuance endpoint.

The CA is valid for3650days (ten365-day years). Host-specific leaf certificates last seven days, capped at CA expiry. A five-minute not-before allowance handles small clock differences. DNS names and IP addresses receive their correct SAN types; leaves are server-authentication certificates, with private keys held in memory only. CA expiry or a clock before the validity window prevents startup/issuance. A new leaf is issued per inspected connection through bounded signing workers; there is no leaf cache.

Private state resides at `<data_dir>/inspection-ca/material.bin`, a versioned bundle containing the certificate and PKCS8 private key. Keep the inspection-ca directory0700 and the material file0600, without symlinks or hard links, under a service-owned data directory that untrusted users cannot modify. Ancestors must be owned by the service or privileged system user, and must not be group/world-writable unless protected by sticky-directory semantics. Symlinks in any path component are rejected; ordinary safe `/tmp` fixture directories are supported. Storage uses pinned directory handles rather than resolving validated paths again. The fixed bundle is never a static/downloadable asset. Startup rejects malformed, truncated, mismatched, non-CA or expired material, unsafe permissions and incomplete creation. Errors identify the failure category without certificate/key contents. An interrupted first creation can leave an empty directory or partial bundle and requires the same explicit recovery procedure.

**Backup and recovery:** stop NullGate and back up the entire inspection-ca directory to protected offline storage, preserving permissions and ownership. The bundle is unencrypted on disk and a backup therefore carries the signing authority; protect it as a private key. To recover, keep the process stopped and restore the complete directory from that backup. Do not reconstruct only one component or delete corrupt state to make startup succeed. Restore the expected identity, correct permissions/clock, then restart. Loss of every complete backup requires explicit rotation and client trust redistribution.

**Rotation:** there is no automatic renewal or online rotation action. During a planned offline maintenance window, archive the previous identity securely, deliberately move its entire inspection-ca directory out of the data location, and restart to generate a new identity. Distribute and verify the new public certificate on managed clients, then remove the old trust according to the deployment's rollout plan. Never retain old client trust after a suspected key compromise. Offline deletion/replacement is an operator action; the application never silently performs it.

**Deferred decisions:** expiry warnings, managed/encrypted backup tooling, an assisted rotation workflow and a possible future leaf-cache/renewal policy remain to be designed. The confirmed first-release policy is offline recovery/rotation, with no background root replacement. No automatic trust-store modification is performed by the application or its tests.

## Metrics

The confirmed first dashboard shows aggregate allowed/blocked DNS and HTTP(S) counts, service health/restarts, active connections and import outcomes. Values reset when the process restarts; both roles may view them. There is no individual request history or per-domain/URL/user metric label. Allowed passthrough tunnels do not reveal or count encrypted inner requests. See decision T7 for counting boundaries.

## Save outcomes

The management API returns a policy revision and accepted/duplicate/malformed diagnostics. Concurrent stale edits return a conflict. Validation or storage failure before commit preserves the old policy. If durable commit succeeds but activation fails, the response explicitly identifies the committed revision as `committed_not_active`; affected traffic remains unavailable until recovery. A successful rule save means the complete revision is active, with in-flight request boundaries described in [implementation decisions](implementation-decisions.md#configuration-persistence-and-publication).


## Local authentication

Local username/password authentication is the configuration default. Provision the first Administrator explicitly before first login; there is no shared default password or remote bootstrap endpoint. Create a regular password file with owner-only permissions (0600) in a trusted directory, containing your unique password and an optional final newline, then run:

```sh
cargo run --locked --bin nullgate -- provision-admin --config config/nullgate.example.toml --username your-admin-name --password-file /secure/path/nullgate-password
```

The command reads and hashes the password without placing it in process arguments or logs. Symlinks, non-regular files, group/other permissions and oversized input are rejected. First-run provisioning is transactional and refuses to overwrite any existing account. Subsequent accounts are created through the Administrator-authorized library API using a live session token; cached role/identity objects are not authority. Web listener and blocklist UI integration are implemented in Task 10; account-management UI remains unimplemented.

Usernames are case-insensitive ASCII, 1–64 letters/digits/dot/underscore/hyphen. Passwords contain 12–1024 UTF-8 bytes, without trimming. Argon2id uses a distinct random salt per password. Sessions are opaque, stored only as SHA256 digests, rotate on login, expire after eight hours and are revoked on logout. There is no sliding idle expiry. Roles and disabled-account state are checked for every request; account creation rechecks Administrator session authority in its write transaction. Authentication changes do not advance the filtering-policy revision.

`nullgate-web::WebState` injects authentication, explicit transport/origin policy and the core management interface. `router(state, management_routes)` protects all supplied routes and fallback handlers, with authenticated `Identity` in request extensions. Viewers may read but cannot mutate through direct requests. Explicit no-authentication mode grants Administrator permissions while retaining trusted Host/Origin and CSRF checks. OIDC is enabled by the explicit provider configuration below; proxy-client authentication remains separate.

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

### Manual remote imports and refresh

Administrators can add a public HTTP(S) text URL to a list, then explicitly refresh its source. Prefer HTTPS. Viewers can read provenance and results but cannot fetch or refresh. No startup, scheduled or background refresh occurs. Each successful refresh replaces only that URL source; manual, file and other remote entries remain. Mixed content accepts valid lines and reports malformed line numbers. Empty, comment-only, all-malformed and failed downloads retain previous usable rules. Attempts are recorded with a new revision, including failures; reload before retrying. Concurrent edits reject the stale download with a revision conflict.

Fetches use a ten-second total deadline, a four-MiB UTF-8 body limit, at most three redirects, and only complete HTTP 200 responses with identity encoding. HTTPS cannot redirect to HTTP. Credentials, fragments and non-HTTP(S) URLs are rejected. Every redirect resolves and checks all destination addresses, then pins those addresses for the connection while keeping hostname and TLS certificate verification. Production permits public unicast destinations and rejects private, loopback, link-local, shared, reserved, documentation and IP transition ranges; there is no private-network exception setting. Ambient proxies, cookies, automatic retries and decompression are disabled. Tests inject an explicit local address-and-port policy and test certificates.

The API exposes `POST /api/v1/lists/{id}/remote` with `expected_revision` and `url`, and `POST /api/v1/sources/{id}/refresh` with `expected_revision`. Both require Administrator permission and the normal CSRF proof. A failed fetch returns 502; no valid rules returns 422. Their error envelope contains the recorded revision. A 409 conflict does not record the stale attempt. Source deletion explicitly removes that source's memberships; remote entries cannot be edited individually.


## Selective HTTPS filtering

HTTPS URL rules select their exact host for inspection, independently of path/port. An HTTP-only URL rule does not select HTTPS inspection. Domain rules still block CONNECT directly; a URL-only rule never blocks its entire host in DNS. Configure clients as explicit HTTP proxy clients and distribute the public CA only to managed clients. Missing CA trust produces a TLS certificate failure. Unlisted hosts keep the origin certificate and opaque end-to-end encryption.

Inspected traffic supports TLS1.2/1.3 and HTTP/1.1. Only `http/1.1` is advertised through ALPN; clients without ALPN can use HTTP/1.1. HTTP2-only negotiation fails, HTTP/1.0 receives505, and HTTP3/QUIC, nested CONNECT and WebSocket/Upgrade are unsupported on inspected connections. Opaque TCP passthrough can carry end-to-end HTTP2 and WebSocket, but does not transport native QUIC/HTTP3. DNS SNI must match the normalized CONNECT hostname; DNS clients omitting SNI are rejected. IP CONNECT clients must omit SNI. The inner Host/absolute URI must match the CONNECT host and port; authority changes receive an empty421 (or400 for malformed/conflicting headers) and close. There is no fallback to unchecked passthrough.

Every inner request applies the shared rule engine. Exact `/ads` blocks its query variants but permits `/ads/` and `/news`; `/ads/*` also blocks `/ads`, `/ads/` and descendants. Query parameters remain on forwarded permitted requests. Blocked requests return empty403 before connecting upstream. Permitted requests use verified upstream chains/hostnames with the server's normal system roots, loaded at application startup; restart the application to reload them. Standard `SSL_CERT_FILE`/`SSL_CERT_DIR` root selection may be configured for the process; tests set these only on isolated fixture children. No insecure verifier, ambient proxy or automatic downgrade is used. Upstream certificate failures return502, connection/TLS deadline failures504. CONNECT200 only acknowledges admission; the inner request must still succeed.

A request captures a policy snapshot after validated headers. Path-rule edits affect the next request on the same inspected keep-alive connection; an already admitted response may finish. New domain blocks or changes in inspection membership close affected existing tunnels/inspected connections and join nested upstream work before a successful save acknowledgment. Sent bytes cannot be recalled. Removing the final HTTPS URL rule closes inspection so the next connection presents the origin certificate again.

Client and upstream handshakes have bounded connect deadlines; existing HTTP header/admission/streaming limits apply inside TLS. Issuance is bounded to four jobs, with a fresh certificate per inspected connection and no disk leaf keys. Upstream connections are per request with resumption disabled for fresh validation. HTTP2/3 support, pooling, leaf caching and additional expiry/operational tooling remain future work.


## External login (OpenID Connect / Keycloak)

Use [the non-secret OIDC example](../config/nullgate.oidc.example.toml): set `[auth] mode="oidc"` and a complete `[oidc]` block. Local/no-auth modes must omit that block. `web.public_origin` is explicit, and `redirect_uri` must be exactly its `/api/v1/auth/oidc/callback` URL. Use dedicated HTTPS or explicit loopback TLS offload in production. Issuer, authorization/token/JWKS/logout endpoints must use the same provider origin; HTTPS is required except local loopback HTTP. Different-origin endpoint layouts and ID-token algorithms other than RS256 are not currently supported. There is no permissive redirect/TLS/proxy fallback.

For a confidential client, `client_secret_file` references an existing service-owned regular file, at most 4096 bytes, with owner-only permissions (normally 0600). Ancestors must be protected, links/special files are rejected, and one final LF/CRLF is removed. Resolve relative paths against the configuration directory. Keep actual secret contents outside source control/TOML/logs, and protect backups. Omit this field for a public client configured to require PKCE S256. Do not send production secrets through chat. Provider metadata is fetched lazily, so an IdP outage does not stop the filtering proxies or grant password/no-auth fallback.

The signed ID token alone supplies identity/roles. Set `role_claim` to a JSON Pointer such as `/realm_access/roles` or `/resource_access/nullgate/roles`. The value must be a string or an array of strings. Configure exact, case-sensitive, disjoint `administrator_values` and `viewer_values`; Administrator wins only when an explicitly mapped Administrator value exists. Never select a self-editable profile field as authorization authority. Missing/unmapped claims are denied, not defaulted to Administrator or Viewer. User identity is exact `(issuer,sub)`; matching email/display names never merge external and local accounts.

Sessions use existing opaque, hashed, revocable cookies and server-side authorization/CSRF checks. They expire at the earlier of ID-token expiry or eight hours. No refresh/access/ID tokens are retained after login; there is no background renewal. Provider role changes are observed on re-login, not through polling: a verified changed role revokes older sessions; an unmapped verified re-login revokes prior credentials. Configuration changes invalidate sessions bound to the old issuer/client/role-policy fingerprint. Disabled accounts stay disabled. Local and external session types cannot authenticate the other mode, and changing back to local mode permits explicit first Administrator provisioning when only external accounts exist.

Sign-in starts with a CSRF-protected POST to `/api/v1/auth/oidc/start`. The one-shot callback at `/api/v1/auth/oidc/callback` requires the ten-minute state/browser binding, nonce and S256 verification. Signature, issuer, audience, azp, expiry, issued/not-before times and access-token hash (when present) are validated. In-progress redirects are memory-only and do not survive application restart. Provider cancellation consumes its authorization attempt. Callback URLs/codes/provider errors are not logged or echoed in error messages.

**Logout:** the CSRF-protected `/api/v1/auth/logout` first durably revokes the presented NullGate session and clears its cookies/unconsumed browser authorization attempts, then returns a validated provider-logout redirect. The browser follows `end_session_endpoint?client_id=...&post_logout_redirect_uri=.../login`. No stored ID-token hint is needed, so Keycloak may ask the user to confirm logout. A failed provider request never restores local authentication; if discovery is unavailable, the login page explains that provider SSO may still be active. A callback already admitted before logout is a separate login attempt; logout is not a global cancellation of concurrent logins. This release has RP-initiated logout, not a back/front-channel logout receiver. Other existing NullGate sessions retain their own bounded expiry/revocation semantics. Provider logout can end SSO for other applications according to provider behavior.

### Keycloak client setup

1. Create an OpenID Connect client with client ID matching `client_id`. Enable **Standard flow**; disable implicit flow, direct-access grants and service accounts. Require **S256** PKCE. Enable client authentication for a confidential client and put its secret in the protected file, or use a public client without a secret file.
2. Register the exact callback URL, with no wildcard. Register `<web.public_origin>/login` as the valid post-logout redirect URI (`post.logout.redirect.uris`). Set the public web origin explicitly. Keycloak's discovery issuer must exactly match `issuer`, for example `https://sso.example/realms/nullgate`.
3. Create dedicated realm roles such as `nullgate-admin` and `nullgate-viewer`, assigning them only to intended users. Add an **ID-token** realm-role protocol mapper: `oidc-usermodel-realm-role-mapper`, `claim.name=realm_access.roles`, `multivalued=true`, `jsonType.label=String`, `id.token.claim=true`. The built-in access-token roles alone are insufficient; NullGate does not authorize from access tokens or userinfo. For client roles, use the equivalent client-role mapper and configure the matching JSON Pointer.
4. Configure the explicit NullGate role values and test Administrator, Viewer and an unmapped user. The first login does not create an Administrator unless its verified role maps explicitly. Keep a documented operator recovery procedure for IdP/configuration outages; there is no automatic fallback to local passwords.

`scripts/keycloak_smoke.py` tests a representative Keycloak 26.4.5 confidential client, Standard flow/S256, the ID-token realm-role mapper, exact callback/post-logout registration, Administrator/Viewer/unmapped behavior, direct Viewer write rejection, provider logout confirmation and credential-free logs. It generates all test credentials into private temporary files, runs a loopback-only temporary container on `localhost` with NullGate on `127.0.0.1` to exercise cross-site provider returns, and removes it afterward. Its clients/realm are fixtures, not deployment credentials. Local signed-provider tests additionally cover invalid callbacks/tokens, expiry, role/context isolation and failure handling. No machine trust-store change or reusable environment publication is involved.

## Aggregate traffic dashboard

Open **Dashboard** in the navigation, or `/dashboard`. Administrators and Viewers have identical read access; unauthenticated users must sign in. `GET /api/v1/metrics` returns the same aggregate snapshot as JSON. There is no reset or write endpoint. Use **Refresh metrics** to update the page; this release does not retain chart samples or poll historical traffic.

All counters reset when the NullGate process restarts, including when durable lists and accounts are restored. Supervised proxy restarts preserve these counters. Uptime starts during application initialization. Storage is bounded to fixed numeric counters and current supervisor health, with saturating totals; no domain/URL/user labels, credentials, query parameters or individual request history are collected.

Allowed/blocked counts describe policy decisions, not successful upstream responses. A permitted request whose upstream times out or returns 403 still counts as allowed. Invalid requests and policy-unavailable errors rejected before evaluation count as neither. DNS counts each evaluated query once, regardless of upstream retries. HTTP and inspected HTTPS messages are separate; each inspected keep-alive request is counted independently. CONNECT counts admission decisions separately, including connections whose later connect/TLS handshake fails. Encrypted messages inside passthrough tunnels are invisible and are not included in inspected HTTPS totals.

Active connection gauges count admitted DNS client TCP and HTTP/CONNECT client TCP sockets, including idle keep-alive and upgraded connections; they exclude UDP datagrams, upstream sockets and the web management listener. Restart counts are supervisor replacement attempts. Health comes from the live supervisor and policy subscription, with explicit starting/backoff/stopping/stopped/failed and policy-unavailable states. Zero counters alone never establish readiness; cumulative counters remain available during recovery. Missing telemetry returns 503 `metrics_unavailable`; missing health is displayed as unavailable rather than ready.

Import outcomes count completed policy-worker commands in the current runtime, not the current number of stored lists/reports. Mixed valid/malformed input is partially valid; all-malformed input and remote empty/comment-only refreshes are rejected. Explicit empty local source clearing succeeds. Recorded download failures, conflicts and failed writes/activation count as failed. Requests rejected before reaching the worker are excluded. Accepted and malformed line totals sum returned parser reports; failed operations without a report contribute no line totals, and duplicate lines do not add accepted lines. Durable prior import reports remain visible on source pages but are not replayed into dashboard counters.

## Release operations

Follow the [deployment guide](deployment.md) for package/user installation, service ownership, first provisioning, upgrades, full offline backups, trust installation/removal and recovery. Startup settings require a restart; web edits publish live policy. Runtime metrics reset on process restart, while lists, accounts and CA identity persist.
