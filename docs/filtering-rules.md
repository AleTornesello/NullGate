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

Only `*` is currently specified as a path wildcard. Regular expressions, `?` wildcards, character classes, and wildcard escaping are not defined.

## HTTPS inspection targets

NullGate derives domains requiring TLS inspection from URL blocklists, without a separate inspection list. For example, `https://example.com/ads` requires inspection for `example.com`, allowing other paths such as `/news` unless another rule blocks them. It does not select `www.example.com` for inspection.

Clients must trust NullGate's CA to use this feature. See [Deployment](deployment.md).

## Blocked responses

- DNS: NXDOMAIN.
- HTTP/HTTPS: HTTP 403 Forbidden with an empty response body.
- No block page is displayed.

## Matching details still to define

Case and hostname normalization, internationalized domain names, explicit/default ports, percent-encoded paths, dot segments, whitespace handling, inline comments, literal asterisks, and duplicate rules are TBD. URL fragments are not transmitted in HTTP requests and cannot be used for proxy filtering.
