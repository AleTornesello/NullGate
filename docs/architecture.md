# Architecture

NullGate consists of four components, all written in Rust. Their process boundaries and communication protocols are TBD.

## DNS proxy

The DNS proxy evaluates domain blocking rules. It returns NXDOMAIN for blocked names and forwards permitted requests to upstream DNS servers configured by an administrator.

An exact rule applies only to the named domain. A wildcard rule such as `*.example.com` applies to subdomains, including nested subdomains, but excludes `example.com` itself.

Supported upstream protocols, caching behavior, and upstream failover are TBD.

## HTTP proxy

Clients select the HTTP proxy through browser or operating system proxy settings. The proxy enforces domain and URL rules and returns an empty HTTP 403 response when a request is blocked. It does not display a block page.

For unencrypted HTTP, the proxy can evaluate URL paths directly. For HTTPS, URL paths are encrypted, so matching them requires TLS inspection:

1. NullGate derives inspection targets from the domains present in URL rules.
2. A client configured to use NullGate must trust its generated CA certificate.
3. For an inspection target, NullGate terminates client TLS and establishes a separate TLS connection to the destination, allowing it to evaluate the URL path.
4. For other domains, HTTPS traffic passes through without decryption.

A domain with an exact blocked URL can still serve other URLs. Whole-domain rules take precedence in effect: a matching URL cannot make a blocked domain accessible.

Domain rules do not, by themselves, require decryption of HTTPS traffic. The precise mechanics for enforcing them on HTTPS tunnels are TBD.

## Proxy orchestrator

The orchestrator is responsible for:

- Starting and stopping the DNS and HTTP proxies.
- Verifying blocking rules.
- Restarting failed proxies automatically.

Saved rule changes take effect immediately in the running filtering system. How the orchestrator distributes these changes, ensures consistency between proxies, and handles restart backoff is TBD.

Malformed imported rules are reported and ignored; valid rules are accepted.

## Web interface

The web interface provides blocklist management, metrics, and administration. Administrators can create lists, add rules, import lists, trigger remote updates, and download the public CA certificate. Viewers can read metrics and blocklists without changing them.

Metrics, backend API design, persistence format, and UI implementation are TBD. See [Administration](administration.md) for access rules.
