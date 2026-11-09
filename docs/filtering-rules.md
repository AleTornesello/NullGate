# Filtering rules

Each blocklist may contain both domain and URL rules. All active rules apply globally to all devices using NullGate.

## Input format

Manual entry, file imports, and remote URL imports use the same plain-text format:

- One rule per line.
- Blank lines are ignored.
- Lines beginning with `#` are comments.
- A rule beginning with `http://` or `https://` is a URL rule.
- Domain rules contain a domain name, optionally prefixed with `*.`.

```text
# Exact domain
example.com

# All subdomains, excluding the parent
*.tracking.example.com

# Exact URL path
https://news.example.com/ads

# Path and descendants
https://news.example.com/sponsored/*
```

Malformed rules are reported as malformed and ignored. An import still accepts its valid rules. Saved changes take effect immediately.

## Domain matching

| Rule | Blocked | Not blocked by this rule |
| --- | --- | --- |
| `example.com` | `example.com` | `www.example.com`, `api.example.com` |
| `*.example.com` | `www.example.com`, `a.b.example.com` | `example.com`, `otherexample.com` |

To block both a parent domain and all its subdomains, enter both rules:

```text
example.com
*.example.com
```

A domain rule blocks access to the entire matching domain, regardless of the URL path.

## URL matching

URL rules select a scheme, exact hostname, and path. Wildcards apply to the path; domain wildcards belong in domain rules. A rule using `https://` targets HTTPS URLs, while a rule using `http://` targets HTTP URLs.

Query parameters are ignored during matching. Thus, `https://example.com/ads` also blocks `https://example.com/ads?campaign=summer`.

### Wildcards

`*` matches zero or more path characters, including `/`. A trailing `/*` additionally matches the parent path without its trailing slash.

| Rule | Blocked examples | Not blocked by this rule |
| --- | --- | --- |
| `https://example.com/ads` | `/ads`, `/ads?campaign=summer` | `/ads/`, `/ads/banner.png`, `/adsense` |
| `https://example.com/ads/*` | `/ads`, `/ads/`, `/ads/banner.png`, `/ads/images/banner.png` | `/adsense`, `/news` |
| `https://example.com/*/banner.png` | `/ads/banner.png`, `/a/b/banner.png` | `/ads/banner.jpg` |
| `https://example.com/ads*` | `/ads`, `/adsense`, `/ads/banner.png` | `/news` |

All path examples in this table use HTTPS and the exact host `example.com`. Query parameters do not change the results.

Only raw `*` is a path wildcard. `%2A` remains literal encoded data. There is no regex, character-class, or wildcard-escape syntax; `?` starts the ignored query. Unsupported formats are reported as malformed.

## HTTPS inspection targets

NullGate derives domains requiring TLS inspection from active HTTPS URL rules, without a separate inspection list. HTTP-only URL rules do not select a host for HTTPS inspection. Selection applies to the exact host across CONNECT ports; URL blocking still checks the rule’s scheme and effective port. For example, `https://example.com/ads` requires inspection for `example.com`, allowing other paths such as `/news` unless another rule blocks them. It does not select `www.example.com` for inspection.

Clients must trust NullGate's CA to use this feature. See [Deployment](deployment.md).

## Blocked responses

- DNS: NXDOMAIN.
- HTTP/HTTPS: HTTP 403 Forbidden with an empty response body.
- No block page is displayed.

## Normalization contract

Task 1 selects the matching behavior in [implementation decisions, M1–M12](implementation-decisions.md#matching-and-import-contracts-task-2). These contracts are implemented and tested in `nullgate-core` by Task 2. The DNS/HTTP services do not yet enforce them on live traffic.

- Hostnames normalize to lowercase IDNA A-labels; one final dot is removed. Invalid labels are rejected. The same normalization applies to rules and requests.
- URL matching includes scheme and effective port: omitted ports equal HTTP 80 or HTTPS 443; other ports remain distinct. Domain rules apply at all ports.
- Paths are case-sensitive. Empty path means `/`; repeated and trailing slashes remain distinct. Percent hex is uppercased, only unreserved ASCII is decoded, then complete dot segments are removed. Encoded separators remain encoded; escapes are never recursively decoded.
- Queries are ignored. Literal fragments in rules are malformed because requests do not transmit them. Userinfo, invalid escapes, controls and backslashes are rejected.
- UTF-8 input accepts LF/CRLF and an initial BOM. Trim outer ASCII spaces/tabs; ignore blank lines and full-line `#` comments. Inline comments are unsupported.
- Canonical duplicates are reported separately, while source memberships are preserved. Unsupported syntax is diagnosed rather than converted. Import and matching resource bounds are defined in M12.

The decision table includes exact examples and test obligations for every boundary. URL rules never cause the DNS proxy to block their entire host.
