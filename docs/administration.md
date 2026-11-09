# Administration

## Blocklists

Administrators create blocklists through the web interface. Each list can contain both domain and URL rules, populated by:

- Entering rules manually.
- Importing a plain-text file.
- Importing from a remote URL.

All three methods use the [same rule format](filtering-rules.md). Valid imported rules are accepted. Malformed rules are reported and ignored.

Saved changes take effect immediately. All devices share one global set of rules; per-device policies are outside the agreed scope.

Remote sources refresh only when an administrator triggers an update. Automatic scheduled refreshes are outside the initial scope. Whether a refresh replaces or merges existing entries, how manual edits interact with imported entries, and what happens on download failure are TBD.

## Authentication

The web interface supports three configurable modes:

| Mode | Behavior |
| --- | --- |
| Username and password | Default mode. Users sign in with local credentials. |
| External authentication | Sign-in through an external OAuth 2.0 service, such as Keycloak. |
| No authentication | Everyone accessing the interface receives Administrator permissions. |

OpenID Connect over OAuth 2.0 is the recommended external sign-in protocol; the exact protocol and integration settings remain to be confirmed. Initial administrator provisioning, local account management, session behavior, and external role mapping are TBD.

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

The private CA key remains on the NullGate server and is not part of the client download. Storage, rotation, backup, certificate lifetime, and certificate generation details are TBD.

## Metrics

The interface will display metrics. The metrics collected, retention, aggregation, and visibility of individual requests are TBD; no specific dashboard values are promised yet.
