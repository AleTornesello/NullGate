# Installation and deployment

## Release scope

The first release targets **Linux x86_64 GNU**, with a Debian 12/glibc 2.36 baseline. Other CPU architectures, musl, macOS and Windows artifacts are not provided. The release build uses pinned compiler/packager container digests, Rust 1.99.1, Cargo.lock, a fixed SOURCE_DATE_EPOCH, portable x86-64 code generation and deterministic tar/deb metadata. Panic unwinding remains enabled so supervision can observe worker failures.

Candidate files are `nullgate-0.1.0-x86_64-unknown-linux-gnu.tar.gz`, `nullgate_0.1.0_amd64.deb`, `BUILD-MANIFEST.json` and `SHA256SUMS`. The MIT license and dependency notices are included. No account database, passwords, private keys or pre-generated inspection CA are packaged. Checksums detect changed bytes; release signing is not implemented. Local candidates identify dirty source explicitly; the preparation workflow requires a clean checkout. Nothing in that workflow creates a GitHub release or pushes a tag.

## Local user installation

These commands are for Bash as your normal user. Install Python 3 for the user installer; the runtime binary itself does not require Python. Obtain the candidate files and checksums through your trusted distribution channel, then:

```bash
sha256sum -c SHA256SUMS
mkdir -p "$HOME/.cache/nullgate-install"
tar -xzf nullgate-0.1.0-x86_64-unknown-linux-gnu.tar.gz -C "$HOME/.cache/nullgate-install"
python3 "$HOME/.cache/nullgate-install/nullgate-0.1.0-x86_64-unknown-linux-gnu/install-user.py"
"$HOME/.local/bin/nullgate" --version
```

The installer atomically replaces `$HOME/.local/bin/nullgate`, creates `$HOME/.config/nullgate/nullgate.toml` only if absent, and uses `$HOME/.local/share/nullgate` for state. Configuration/data directories must be owned by you with mode0700; the configuration is0600. Existing configuration and state are preserved on reinstall. Custom `--prefix`, `--config-dir`, and `--data-dir` paths are supported by the installer. Do not run this installer with sudo.

Provision the first Administrator before starting; there are no shared default credentials. Choose a unique 12–1024-byte password. The password file must be a regular0600 file under a protected directory:

```bash
umask 077
read -r -s -p 'Administrator password: ' nullgate_admin_password
printf '\n'
printf '%s\n' "$nullgate_admin_password" > "$HOME/.config/nullgate/admin-password"
unset nullgate_admin_password
"$HOME/.local/bin/nullgate" provision-admin --config "$HOME/.config/nullgate/nullgate.toml" --username admin --password-file "$HOME/.config/nullgate/admin-password"
rm -- "$HOME/.config/nullgate/admin-password"
"$HOME/.local/bin/nullgate" --config "$HOME/.config/nullgate/nullgate.toml"
```

The stock local listeners are DNS UDP/TCP `127.0.0.1:5353`, HTTP/CONNECT `127.0.0.1:8080`, and administration `http://127.0.0.1:8081`. Configure ordered DNS upstreams in the file before startup. Relative paths in configuration resolve against the configuration file, not the shell directory. Wait for `runtime ready` and probe the web login before configuring clients. Ctrl-C/SIGTERM joins active work and closes tunnels; startup failures exit unsuccessfully, while later proxy failures retry with bounded1–30-second backoff.

## Dedicated Debian server

Verify the same checksum file, then install the package and its declared dependencies:

```bash
sha256sum -c SHA256SUMS
sudo apt-get install ./nullgate_0.1.0_amd64.deb
```

The package creates the `nullgate` service identity, installs `/usr/bin/nullgate`, preserves `/etc/nullgate/nullgate.toml` as a conffile, creates `/var/lib/nullgate`0700 and installs `nullgate.service`. It does **not** start the service. Defaults are loopback-only until you configure trusted access. The configuration is root:nullgate0640 in root:nullgate0750 `/etc/nullgate`; state belongs to nullgate. Private TLS/OIDC key files must meet the owner-only rules in [administration](administration.md).

For normal client DNS settings, bind DNS UDP and TCP to your trusted server LAN address on port53; most OS DNS settings cannot specify5353. The unit grants only CAP_NET_BIND_SERVICE for privileged ports. Bind the HTTP proxy to that LAN address on8080. Restrict both services to approved LAN/VPN clients using network policy/firewall rules before starting: proxy-client authentication is not implemented, and web login does not authenticate proxy clients.

For remote administration configure trusted HTTPS, for example:

```toml
[web]
listen = "0.0.0.0:8443"
public_origin = "https://nullgate.example:8443"
[web.tls]
certificate_file = "/etc/nullgate/web-cert.pem"
private_key_file = "/etc/nullgate/web-key.pem"
```

Use a certificate valid for that management hostname, issued by a CA trusted by administrators. Install its private key as nullgate:nullgate0600; the public certificate can be0644. This management certificate is separate from the inspection CA. Never expose cleartext management on a non-loopback listener; startup rejects it. An existing trusted reverse proxy can instead terminate HTTPS in front of an explicitly configured loopback-only backend (`web.tls_terminated_by_proxy=true`). Forwarded headers alone are not trusted.

Provision as the service user so the database and private state have the correct owner:

```bash
sudo install -d -o nullgate -g nullgate -m 0700 /run/nullgate-provision
read -r -s -p 'Administrator password: ' nullgate_admin_password
printf '\n'
printf '%s\n' "$nullgate_admin_password" | sudo -u nullgate tee /run/nullgate-provision/password >/dev/null
unset nullgate_admin_password
sudo chmod 0600 /run/nullgate-provision/password
sudo -u nullgate /usr/bin/nullgate provision-admin --config /etc/nullgate/nullgate.toml --username admin --password-file /run/nullgate-provision/password
sudo rm -- /run/nullgate-provision/password
sudo systemctl enable --now nullgate.service
sudo systemctl status nullgate.service
sudo journalctl -u nullgate.service --no-pager -n 30
```

Readiness follows successful binding of DNS, proxy and web listeners with active policy. A running process alone is not a readiness probe. `/dashboard` and `/api/v1/metrics` show health after authentication. The unit keeps the service unprivileged, constrains writes to `/var/lib/nullgate`, and supplies the low-port capability. Custom data locations require corresponding systemd write-path changes.

## Configure clients and verify filtering

Point the client's DNS resolver to the server's DNS listener and configure **both HTTP and HTTPS** to use the HTTP proxy host/port. HTTPS uses CONNECT through the same HTTP proxy; this listener is not a SOCKS proxy or an HTTPS-wrapped proxy. Browser/OS proxy exceptions must not exempt the sites you want filtered.

The local unprivileged5353 example is suitable for explicit probes such as `dig @127.0.0.1 -p 5353 example.com`. For system DNS use port53 through the packaged service, or configure an existing local resolver to forward to5353. Merely setting a nameserver to127.0.0.1 does not select5353.

Create a mixed list through the authenticated web interface. Include an exact domain, `*.tracking.example`, an HTTP URL and an HTTPS URL such as `https://site.example/ads/*`. Test an allowed request, NXDOMAIN for blocked names, empty403 for blocked HTTP/HTTPS paths, query variants, and permitted sibling paths. Remote refreshes are manual and preserve other provenance. All devices share the same rules. Use known local fixtures for automated tests; do not use production traffic as a destructive test.

For a per-command client trust store:

```bash
curl --proxy http://127.0.0.1:8080 --cacert nullgate-inspection-ca.pem https://site.example/sibling
```

Download the inspection CA as Administrator over the trusted management connection. Verify its SHA256 fingerprint against the operator's trusted copy before distributing it. Only the public PEM goes to clients; never copy `<data_dir>/inspection-ca/material.bin` to a client.

On Debian clients, system-wide trust and removal use:

```bash
sudo install -m 0644 nullgate-inspection-ca.pem /usr/local/share/ca-certificates/nullgate-inspection.crt
sudo update-ca-certificates
# To remove that trust later:
sudo rm -- /usr/local/share/ca-certificates/nullgate-inspection.crt
sudo update-ca-certificates --fresh
```

Restart affected clients to reload trust and close existing sessions. Per-application stores (Firefox/NSS, Java, Python certifi, containers and mobile applications) may need separate import/removal; an OS trust update does not establish that those applications trust the CA. Certificate-pinned applications can reject inspection despite correct CA installation. Do not disable their TLS verification: remove the relevant inspection selection if permitted by your policy, or treat that application as incompatible. Unlisted hosts preserve the original end-to-end TLS certificate.

## Enforcement boundaries

NullGate filters traffic actually sent to its configured DNS and explicit proxy listeners. It is not a transparent interceptor or a network firewall. Applications ignoring proxy settings, direct IP connections, alternate resolvers, VPNs, DoH/DoT, and native HTTP3/QUIC can bypass these listeners. Enforce routing/resolver restrictions elsewhere if required; the application does not install such rules.

DNS caches in browsers, OS resolvers and other forwarders can delay new DNS results; NullGate itself has no DNS cache. Flush the relevant client cache (for example `resolvectl flush-caches` with systemd-resolved) and retry a new connection. DNS changes do not recall previously returned addresses. Proxy policy is reevaluated at the documented request boundaries; already admitted bytes cannot be recalled.

Inspected traffic supports TLS1.2/1.3 and HTTP/1.1, with strict CONNECT/SNI/Host authority binding and verified upstream certificates. HTTP2-only inspection, HTTP3/QUIC, nested CONNECT and WebSocket/Upgrade inspection are unsupported. Opaque passthrough can carry end-to-end HTTP2/WebSocket over TCP, without observing their request paths. Managed clients may need QUIC/secure-DNS policy changes; no universal fallback or transparent enforcement is promised.

## Upgrades, backups and recovery

Stop the application first and confirm it exited before copying state. Back up the **entire** state directory, configuration, referenced management/OIDC secrets and the previous verified package. Keep backup storage private and encrypted where appropriate: CA state includes an unencrypted signing key. Do not copy only a live SQLite main file and omit its WAL.

For the packaged service:

```bash
sudo systemctl stop nullgate.service
sudo install -d -m 0700 /root/nullgate-backups
sudo sh -c 'umask 077; tar -czf /root/nullgate-backups/state-and-config.tar.gz -C / var/lib/nullgate etc/nullgate'
sudo apt-get install ./nullgate_NEW_VERSION_amd64.deb
# Keep the existing conffile and inspect any .dpkg-dist version before changing it.
sudo systemctl start nullgate.service
```

For the user install, stop its foreground/service process, then use a protected archive of `$HOME/.local/share/nullgate` and `$HOME/.config/nullgate` before rerunning the new bundle's user installer. It preserves existing configuration/data. Include any external referenced secret/key files separately; verify backups before deleting originals.

To recover, keep the service stopped, move the failed state aside, restore the full matching configuration/state backup, restore nullgate ownership and0700/0600 permissions, and start the matching previously verified binary/package. A schema upgrade may prevent binary-only downgrade; restore its matching state backup too. First-release rehearsals cover backup/restore and same-version reinstall; cross-version data migrations are not claimed validated.

A corrupt/incomplete/expired inspection CA fails clearly and is never silently replaced. Restore the complete original CA bundle with the rest of the backup. Deliberate rotation is an offline operation: stop, securely archive the entire old inspection-ca directory, explicitly remove it from the active data location, restart to generate a new identity, redistribute new public trust, and remove old client trust. Do not delete CA state merely to suppress an error. There is no automatic rotation or password-reset endpoint. For lost local passwords, restore a backup whose credentials are known, or explicitly configure trusted OIDC access while stopped; do not discard the policy database to reset accounts.

## Authentication and validation evidence

Local username/password is the default; first Administrator provisioning is explicit and does not overwrite an existing local account set. Sessions are revocable and bounded to eight hours. Additional local account-management UI/CLI is not provided in this release. Viewer access can be assigned through explicit OIDC role mappings; the existing trusted application interface supports local roles but is not an operator management endpoint. See [administration](administration.md) for OIDC/PKCE, protected client-secret files, provider logout, role refresh and no-auth mode. Explicit `mode="none"` grants Administrator and should be limited to deliberately isolated deployments; CSRF protections remain active.

The release rehearsal exercises clean local-user and dedicated non-root/TLS configurations with local upstreams, first provisioning, mixed rules, CA trust/removal, backup/restore and persistent identity. System trust changes are confined to disposable test containers, never the build host. The exact tested targets and any unvalidated init/platform paths are recorded in the release validation report. A container process rehearsal does not establish that a systemd unit boots on a full machine; verify service activation on the intended host before rollout.
