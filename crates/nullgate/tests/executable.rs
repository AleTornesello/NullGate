//! Run the real executable with local upstream fixtures; no public DNS/HTTP is used.
use nullgate_core::{BlocklistRepository, Mutation, SourceKind, SqliteRepository};
use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "nullgate-executable-{}-{stamp}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(
        &self,
        upstream: std::net::SocketAddr,
        http: std::net::SocketAddr,
        web: std::net::SocketAddr,
    ) -> PathBuf {
        let path = self.0.join("runtime.toml");
        std::fs::write(
            &path,
            format!(
                r#"schema_version = 1
data_dir = "data"
[dns]
udp_listen = "127.0.0.1:0"
tcp_listen = "127.0.0.1:0"
upstreams = ["{upstream}"]
[http]
listen = "{http}"
[web]
listen = "{web}"
# Authentication and web serving are now active; TLS requires explicit files.
# NEVER-LOG-PRIVATE-KEY
"#
            ),
        )
        .unwrap();
        path
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("executable operation timed out")
}
async fn request(address: std::net::SocketAddr, target: &str, host: &str) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer NEVER-LOG-CREDENTIAL\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = Vec::new();
    bounded(stream.read_to_end(&mut response)).await.unwrap();
    response
}
fn seed(scratch: &Scratch, target: &str) {
    let mut repo = SqliteRepository::open(scratch.0.join("data/nullgate.sqlite3")).unwrap();
    repo.apply(
        0,
        Mutation::CreateList {
            name: "binary smoke".into(),
        },
    )
    .unwrap();
    let commit = repo
        .apply(
            1,
            Mutation::AddSource {
                list_id: 1,
                kind: SourceKind::Manual,
            },
        )
        .unwrap();
    let id = commit.snapshot.lists[0].sources[0].id;
    repo.apply(
        2,
        Mutation::Import {
            source_id: id,
            text: format!("blocked.invalid\n{target}/blocked"),
            at: 0,
        },
    )
    .unwrap();
}

#[tokio::test]
async fn real_binary_filters_both_proxies_and_sigterm_cleans_up_tunnels() {
    let scratch = Scratch::new();
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let dns_job = tokio::spawn(async move {
        let mut query = [0; 512];
        let (size, peer) = upstream.recv_from(&mut query).await.unwrap();
        let mut answer = query[..size].to_vec();
        answer[2] = 0x81;
        answer[3] = 0x80;
        answer[6] = 0;
        answer[7] = 1;
        answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 7]);
        upstream.send_to(&answer, peer).await.unwrap();
    });
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_address = origin.local_addr().unwrap();
    let target = format!("http://{origin_address}");
    seed(&scratch, &target);
    let http_job = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(stream.read_u8().await.unwrap());
        }
        assert!(header.starts_with(b"GET /allowed?kept=1 HTTP/1.1"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nupstream ok",
            )
            .await
            .unwrap();
    });
    // A separate reserved socket remains untouched; web binds its own ephemeral listener.
    let _web = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let path = scratch.config(
        upstream_address,
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    );
    let log = scratch.0.join("runtime.log");
    let output = std::fs::File::create(&log).unwrap();
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_nullgate"))
            .arg("--config")
            .arg(path)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(output))
            .spawn()
            .unwrap(),
    );
    let addresses = bounded(async {
        let mut interval = tokio::time::interval(Duration::from_millis(10));
        loop {
            interval.tick().await;
            let text = std::fs::read_to_string(&log).unwrap();
            if let Some(line) = text.lines().find(|line| line.contains("runtime ready")) {
                let parse = |key: &str| {
                    line.split_whitespace()
                        .find_map(|word| word.strip_prefix(key))
                        .unwrap()
                        .parse::<std::net::SocketAddr>()
                        .unwrap()
                };
                break (parse("dns_udp="), parse("dns_tcp="), parse("http="));
            }
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "binary exited before readiness: {text}"
            );
        }
    })
    .await;
    let (dns_udp, dns_tcp, http) = addresses;
    let blocked = request(
        http,
        &format!("{target}/blocked?ignored=1"),
        &origin_address.to_string(),
    )
    .await;
    assert!(blocked.starts_with(b"HTTP/1.1 403"));
    assert!(blocked.ends_with(b"\r\n\r\n"));
    let allowed = request(
        http,
        &format!("{target}/allowed?kept=1"),
        &origin_address.to_string(),
    )
    .await;
    assert!(allowed.starts_with(b"HTTP/1.1 200"));
    assert!(allowed.ends_with(b"upstream ok"));
    bounded(http_job).await.unwrap();
    let mut query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    query.extend_from_slice(b"\x07blocked\x07invalid\x00\x00\x01\x00\x01");
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(&query, dns_udp).await.unwrap();
    let mut answer = [0; 512];
    let size = bounded(client.recv(&mut answer)).await.unwrap();
    assert!(size >= 12);
    assert_eq!(answer[3] & 15, 3);
    query[13..20].copy_from_slice(b"allowed");
    client.send_to(&query, dns_udp).await.unwrap();
    let size = bounded(client.recv(&mut answer)).await.unwrap();
    assert_eq!(&answer[..2], &[0x12, 0x34]);
    assert_eq!(answer[3] & 15, 0);
    assert!(answer[..size].ends_with(&[192, 0, 2, 7]));
    bounded(dns_job).await.unwrap();
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = echo.local_addr().unwrap();
    let echo_job = tokio::spawn(async move {
        let (mut stream, _) = echo.accept().await.unwrap();
        assert!(stream.read_u8().await.is_err());
    });
    let mut tunnel = TcpStream::connect(http).await.unwrap();
    tunnel
        .write_all(format!("CONNECT {endpoint} HTTP/1.1\r\nHost: {endpoint}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(bounded(tunnel.read_u8()).await.unwrap());
    }
    assert!(header.starts_with(b"HTTP/1.1 200"));
    assert!(
        Command::new("kill")
            .args(["-TERM", &child.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let exit = bounded(async {
        let mut interval = tokio::time::interval(Duration::from_millis(10));
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            interval.tick().await;
        }
    })
    .await;
    assert!(exit.success());
    assert!(bounded(tunnel.read_u8()).await.is_err());
    bounded(echo_job).await.unwrap();
    assert!(TcpListener::bind(http).await.is_ok());
    assert!(TcpListener::bind(dns_tcp).await.is_ok());
    assert!(UdpSocket::bind(dns_udp).await.is_ok());
    let text = std::fs::read_to_string(log).unwrap();
    for secret in ["NEVER-LOG-PRIVATE-KEY", "NEVER-LOG-CREDENTIAL"] {
        assert!(!text.contains(secret));
    }
    assert!(text.contains("runtime stopped"));
}

#[test]
fn invalid_cli_and_malformed_configuration_fail_without_echoing_values() {
    let output = Command::new(env!("CARGO_BIN_EXE_nullgate"))
        .arg("NEVER-LOG-CREDENTIAL")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("NEVER-LOG-CREDENTIAL"));
    let scratch = Scratch::new();
    let path = scratch.0.join("bad.toml");
    std::fs::write(&path,"schema_version = 1\ndata_dir = 'NEVER-LOG-PRIVATE-KEY'\n[dns]\nupstreams = ['not an address']").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_nullgate"))
        .arg("--config")
        .arg(path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("NEVER-LOG-PRIVATE-KEY"));
}

#[test]
fn initial_bind_failure_exits_unsuccessfully_without_readiness() {
    let scratch = Scratch::new();
    let upstream = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let config = scratch.config(
        upstream.local_addr().unwrap(),
        occupied.local_addr().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_nullgate"))
        .arg("--config")
        .arg(config)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let log = String::from_utf8(output.stderr).unwrap();
    assert!(
        log.contains("Initial startup failed: Http service Bind failure"),
        "{log}"
    );
    assert!(!log.contains("runtime ready"));
    assert!(!log.contains("NEVER-LOG-PRIVATE-KEY"));
}

#[test]
fn explicit_first_administrator_provisioning_has_no_default_or_password_argument() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = Scratch::new();
    let config = scratch.config(
        "127.0.0.1:5353".parse().unwrap(),
        "127.0.0.1:8080".parse().unwrap(),
        "127.0.0.1:8081".parse().unwrap(),
    );
    let password = scratch.0.join("password.txt");
    std::fs::write(&password, "NEVER-LOG-AUTH-PASSWORD\n").unwrap();
    std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_nullgate"))
            .arg("provision-admin")
            .arg("--config")
            .arg(&config)
            .args(["--username", "admin", "--password-file"])
            .arg(&password)
            .output()
            .unwrap()
    };
    let output = run();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains("NEVER-LOG-AUTH-PASSWORD"));
    let repo =
        nullgate_core::AuthRepository::open(scratch.0.join("data/nullgate.sqlite3")).unwrap();
    let user = repo.user("admin").unwrap().unwrap();
    assert_eq!(user.role, nullgate_core::Role::Administrator);
    assert!(user.password_hash.starts_with("$argon2id$"));
    assert!(!user.password_hash.contains("NEVER-LOG-AUTH-PASSWORD"));
    assert!(!run().status.success());
}

#[test]
fn provisioning_rejects_a_fifo_without_waiting_for_a_writer() {
    let scratch = Scratch::new();
    let config = scratch.config(
        "127.0.0.1:5353".parse().unwrap(),
        "127.0.0.1:8080".parse().unwrap(),
        "127.0.0.1:8081".parse().unwrap(),
    );
    let fifo = scratch.0.join("password.fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_nullgate"))
            .arg("provision-admin")
            .arg("--config")
            .arg(config)
            .args(["--username", "admin", "--password-file"])
            .arg(fifo)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    let outcome = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break Some(status);
        }
        if std::time::Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(
        outcome.is_some(),
        "non-regular password file blocked provisioning"
    );
    assert!(!outcome.unwrap().success());
}

#[tokio::test]
async fn real_binary_selectively_filters_https_with_isolated_upstream_and_client_trust() {
    use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let scratch = Scratch::new();
    let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = origin.local_addr().unwrap();
    let certificate =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".into(), "localhost".into()]).unwrap();
    let root_file = scratch.0.join("upstream-roots.pem");
    std::fs::write(&root_file, certificate.cert.pem()).unwrap();
    let empty = scratch.0.join("empty-roots");
    std::fs::create_dir(&empty).unwrap();
    let origin_der = certificate.cert.der().clone();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![origin_der.clone()],
        PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()).into(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let count = Arc::new(AtomicUsize::new(0));
    let requests = count.clone();
    let origin_job = tokio::spawn(async move {
        let mut jobs = tokio::task::JoinSet::new();
        loop {
            let (stream, _) = origin.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let count = count.clone();
            jobs.spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let mut head = vec![];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read_u8().await {
                        Ok(byte) => head.push(byte),
                        Err(_) => return,
                    }
                }
                count.fetch_add(1, Ordering::SeqCst);
                assert!(head.starts_with(b"GET /allowed?kept=1 HTTP/1.1"));
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\norigin",
                    )
                    .await
                    .unwrap();
                let _ = stream.shutdown().await;
            });
        }
    });
    seed(&scratch, &format!("https://{address}"));
    let config = scratch.config(
        dns.local_addr().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    );
    let log = scratch.0.join("https-runtime.log");
    let output = std::fs::File::create(&log).unwrap();
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_nullgate"))
            .arg("--config")
            .arg(config)
            .env("SSL_CERT_FILE", &root_file)
            .env("SSL_CERT_DIR", &empty)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(output))
            .spawn()
            .unwrap(),
    );
    let proxy = bounded(async {
        let mut interval = tokio::time::interval(Duration::from_millis(10));
        loop {
            interval.tick().await;
            let text = std::fs::read_to_string(&log).unwrap();
            if let Some(line) = text.lines().find(|line| line.contains("runtime ready")) {
                assert!(line.contains("https_url_filtering=true"));
                break line
                    .split_whitespace()
                    .find_map(|part| part.strip_prefix("http="))
                    .unwrap()
                    .parse::<std::net::SocketAddr>()
                    .unwrap();
            }
            assert!(child.0.try_wait().unwrap().is_none(), "{text}");
        }
    })
    .await;
    let ca = nullgate_http::ca::CaProvider::open(&scratch.0.join("data")).unwrap();
    let public = ca.public_certificate().certificate_pem();
    let root = pem::parse(public).unwrap().into_contents();
    for (host, path, status, inspected) in [
        ("127.0.0.1", "/blocked?ignored=1", 403, true),
        ("127.0.0.1", "/allowed?kept=1", 200, true),
        ("localhost", "/allowed?kept=1", 200, false),
    ] {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream
            .write_all(
                format!(
                    "CONNECT {host}:{} HTTP/1.1\r\nHost: {host}:{}\r\n\r\n",
                    address.port(),
                    address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut head = vec![];
        while !head.ends_with(b"\r\n\r\n") {
            head.push(bounded(stream.read_u8()).await.unwrap());
        }
        assert!(head.starts_with(b"HTTP/1.1 200"));
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(if inspected {
                root.clone().into()
            } else {
                origin_der.clone()
            })
            .unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mut tls = bounded(
            tokio_rustls::TlsConnector::from(Arc::new(config))
                .connect(ServerName::try_from(host.to_owned()).unwrap(), stream),
        )
        .await
        .unwrap();
        assert_eq!(
            tls.get_ref().1.peer_certificates().unwrap()[0] == origin_der,
            !inspected
        );
        tls.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}:{}\r\nAuthorization: Bearer NEVER-LOG-HTTPS-CREDENTIAL\r\nConnection: close\r\n\r\n",address.port()).as_bytes()).await.unwrap();
        let mut bytes = vec![];
        bounded(tls.read_to_end(&mut bytes)).await.unwrap();
        assert!(bytes.starts_with(format!("HTTP/1.1 {status}").as_bytes()));
        if status == 403 {
            assert!(bytes.ends_with(b"\r\n\r\n"));
        } else {
            assert!(bytes.ends_with(b"origin"));
        }
    }
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    assert!(
        Command::new("kill")
            .args(["-TERM", &child.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let exit = bounded(async {
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(exit.success());
    origin_job.abort();
    let text = std::fs::read_to_string(log).unwrap();
    assert!(text.contains("runtime stopped"));
    assert!(!text.contains("NEVER-LOG-HTTPS-CREDENTIAL"));
    assert!(!text.contains("PRIVATE KEY"));
}
