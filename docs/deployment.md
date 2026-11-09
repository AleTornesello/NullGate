# Deployment

## Supported deployment models

NullGate is intended to run either on the browser's own machine or on a dedicated server serving multiple devices. This describes deployment topology; supported operating systems and CPU architectures are TBD.

All devices use the same blocking rules.

## Setup outline

The following is the intended setup flow, not an executable installation guide. Binaries, commands, configuration keys, default ports, and service packaging are TBD.

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

NullGate inspects HTTPS only for domains derived from URL rules. Other HTTPS traffic passes through without decryption. Trusting the generated CA allows NullGate to inspect traffic for selected domains; distribute only the public certificate to clients.

Applications with certificate pinning or a separate trust store may require additional configuration or may be incompatible with inspection. Behavior when a client does not trust the CA, or when upstream certificate validation fails, is TBD.

Domain-only filtering does not require HTTPS path inspection.

## Operational behavior

- The orchestrator starts and stops both proxies and restarts failed proxies.
- Rule changes take effect immediately after saving.
- Remote blocklist updates require an explicit user action.
- Blocked DNS queries receive NXDOMAIN; blocked HTTP/HTTPS requests receive an empty 403 response.

Clients must actually route their relevant DNS and HTTP traffic through NullGate for its rules to apply. Browser/OS settings are the intended integration; transparent interception is not specified.

## Details still to define

- Installation artifacts and supported platforms.
- Release build and packaging workflow (scaffold build/check commands are in the README).
- Listen addresses, ports, configuration format, and persistent data locations.
- Web interface transport security and exposure settings.
- First-run administrator setup and external identity integration.
- Upstream DNS transports, timeouts, caching, and failover.
- Proxy authentication, if any; web interface authentication does not define client proxy authentication.
- CA storage, backup, rotation, and recovery.
- Logging, metrics, resource limits, health checks, and restart policy.
- Handling of client DNS caches, DNS-over-HTTPS, HTTP/3, and software bypassing configured proxies.

## Validation once an implementation exists

Verify a permitted request, an exact domain block, a wildcard subdomain block, an exact HTTPS URL block, and a wildcard URL block. Confirm that queries are ignored, sibling URLs remain permitted, and unlisted HTTPS domains are not inspected. Also verify malformed-rule reporting, immediate rule updates, upstream DNS forwarding, access restrictions for Viewers, and failed-proxy restarts.

These are acceptance scenarios for future tests; they have not been executed against an implementation.
