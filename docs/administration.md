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
