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
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "nullgate-executable-{}-{stamp}",
            std::process::id()
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
[web.tls]
certificate_file = "UNREAD-CERT.pem"
private_key_file = "NEVER-LOG-PRIVATE-KEY.pem"
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
    // Web is deliberately occupied and its key files do not exist: Task8 must not use them.
    let web = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let path = scratch.config(
        upstream_address,
        "127.0.0.1:0".parse().unwrap(),
        web.local_addr().unwrap(),
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
