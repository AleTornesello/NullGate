# NullGate

NullGate is a Rust project for blocking unwanted domains and specific HTTP and HTTPS URLs. It combines a DNS proxy, an HTTP proxy, a proxy orchestrator, and a web interface.

Run NullGate on the same machine as your browser or on a dedicated server serving multiple devices. All devices share the same blocking rules.

## Project status

This repository currently documents the intended behavior. It does not yet contain an implementation, installation commands, or executable tests. Undecided features and operational details are marked **TBD**.

## Features

- Block exact domains or wildcard subdomains.
- Block exact URLs or URL patterns with wildcards, ignoring query parameters.
- Filter HTTPS URLs using a locally trusted CA, inspecting only domains derived from URL blocklists.
- Create mixed domain/URL blocklists in the web interface, enter rules manually, or import them from files and remote URLs.
- Apply saved rule changes immediately and refresh remote sources on demand.
- Manage access with Administrator and Viewer roles.
- Use username/password authentication by default, optional external authentication, or explicitly disable authentication.
- View metrics in the web interface; the metrics themselves are TBD.

## How filtering works

Domain rules match DNS names. A blocked DNS query receives **NXDOMAIN**. The HTTP proxy returns an empty **403 Forbidden** response when it blocks an HTTP or HTTPS request.

For HTTPS URL filtering, configure the client to use the HTTP proxy and install NullGate's generated CA certificate as trusted. This enables TLS inspection on domains appearing in URL rules. Other domains pass through without decryption.

```text
# Block this domain, but not its subdomains
example.com

# Block subdomains, but not the parent domain
*.tracking.example.com

# Block exactly this path, ignoring query parameters
https://news.example.com/ads

# Block this path and everything beneath it
https://news.example.com/sponsored/*
```

## Documentation

- [Architecture](docs/architecture.md): components and responsibilities.
- [Filtering rules](docs/filtering-rules.md): blocklist format and matching examples.
- [Administration](docs/administration.md): blocklists, authentication, roles, and certificates.
- [Deployment](docs/deployment.md): local and shared-server operation, client configuration, and open decisions.

## Development

All project components are to be written in Rust. Workspace structure, dependencies, supported platforms, build commands, test commands, and release artifacts are TBD. No particular Rust framework or runtime has been selected in these documents.
