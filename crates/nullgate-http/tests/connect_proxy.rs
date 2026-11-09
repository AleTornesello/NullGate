use nullgate_core::{
    BlocklistRepository, HttpConfig, Mutation, PolicyPublisher, PolicySnapshot, PolicySubscription,
    SourceKind, SqliteRepository, policy_channel,
};
use nullgate_http::{HttpOptions, HttpService};
use std::{
    future::Future,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("local CONNECT operation timed out")
}
struct PolicyFixture {
    repo: SqliteRepository,
    publisher: PolicyPublisher,
    reader: PolicySubscription,
    source: i64,
    revision: u64,
    path: PathBuf,
}
impl PolicyFixture {
    fn new(text: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "nullgate-http-{}-{time}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        let mut repo = SqliteRepository::open(path.join("state.sqlite3")).unwrap();
        repo.apply(
            0,
            Mutation::CreateList {
                name: "HTTP".into(),
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
        let source = commit.snapshot.lists[0].sources[0].id;
        let commit = repo
            .apply(
                2,
                Mutation::Import {
                    source_id: source,
                    text: text.into(),
                    at: 1,
                },
            )
            .unwrap();
        let (snapshot, _) = PolicySnapshot::from_commit(commit);
        let (publisher, reader) = policy_channel(snapshot);
        Self {
            repo,
            publisher,
            reader,
            source,
            revision: 3,
            path,
        }
    }
    fn update(&mut self, text: &str) {
        let commit = self
            .repo
            .apply(
                self.revision,
                Mutation::ReplaceEntries {
                    source_id: self.source,
                    text: text.into(),
                    at: 2,
                },
            )
            .unwrap();
        self.revision = commit.snapshot.revision;
        let (snapshot, _) = PolicySnapshot::from_commit(commit);
        self.publisher.publish(Arc::new(snapshot));
    }
    fn candidate(&mut self, text: &str) -> Arc<PolicySnapshot> {
        let commit = self
            .repo
            .apply(
                self.revision,
                Mutation::ReplaceEntries {
                    source_id: self.source,
                    text: text.into(),
                    at: 3,
                },
            )
            .unwrap();
        self.revision = commit.snapshot.revision;
        Arc::new(PolicySnapshot::from_commit(commit).0)
    }
}
impl Drop for PolicyFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

async fn start(policy: &PolicyFixture) -> HttpService {
    HttpService::start(
        HttpConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
        },
        policy.reader.clone(),
        HttpOptions::default(),
        CancellationToken::new(),
    )
    .await
    .unwrap()
}
async fn head(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(bounded(stream.read_u8()).await.unwrap());
    }
    String::from_utf8(bytes).unwrap()
}
async fn request(proxy: SocketAddr, target: &str, host: &str, fields: &str) -> (TcpStream, String) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {host}\r\n{fields}\r\n").as_bytes())
        .await
        .unwrap();
    let response = head(&mut stream).await;
    (stream, response)
}
fn status(head: &str) -> u16 {
    head.split_whitespace().nth(1).unwrap().parse().unwrap()
}
struct Echo {
    address: SocketAddr,
    cancel: CancellationToken,
    job: JoinHandle<()>,
}
impl Echo {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        let job = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {_=token.cancelled()=>break,Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},accepted=listener.accept()=>{let(mut stream,_)=accepted.unwrap();tasks.spawn(async move{let (mut read,mut write)=stream.split();let _=tokio::io::copy(&mut read,&mut write).await;});}}
            }
            tasks.shutdown().await;
        });
        Self {
            address,
            cancel,
            job,
        }
    }
}
impl Drop for Echo {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.job.abort();
    }
}
async fn echo(stream: &mut TcpStream, bytes: &[u8]) {
    stream.write_all(bytes).await.unwrap();
    let mut result = vec![0; bytes.len()];
    bounded(stream.read_exact(&mut result)).await.unwrap();
    assert_eq!(result, bytes);
}

#[tokio::test]
async fn allowed_tunnel_transfers_binary_data_and_half_closes() {
    let origin = Echo::new().await;
    let policy = PolicyFixture::new("");
    let proxy = start(&policy).await;
    let (mut stream, response) = request(
        proxy.local_addr(),
        &origin.address.to_string(),
        &origin.address.to_string(),
        "",
    )
    .await;
    assert_eq!(status(&response), 200);
    assert!(!response.to_ascii_lowercase().contains("content-length"));
    assert!(
        response
            .to_ascii_lowercase()
            .contains("nullgate-https-url-filtering: unavailable")
    );
    echo(&mut stream, b"\x00\xffGET /opaque#payload HTTP/1.1\r\n\r\n").await;
    let data = vec![42; 128 * 1024];
    echo(&mut stream, &data).await;
    stream.shutdown().await.unwrap();
    assert_eq!(
        bounded(stream.read_u8()).await.unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn exact_and_nested_wildcard_domains_get_empty_403_before_resolution() {
    let policy = PolicyFixture::new("blocked.invalid\n*.tracking.invalid");
    let proxy = start(&policy).await;
    for host in [
        "BLOCKED.invalid.",
        "a.tracking.invalid",
        "a.b.tracking.invalid",
    ] {
        let target = format!("{host}:8443");
        let (mut stream, response) = request(proxy.local_addr(), &target, &target, "").await;
        assert_eq!(status(&response), 403);
        assert!(response.to_ascii_lowercase().contains("content-length: 0"));
        let mut rest = Vec::new();
        bounded(stream.read_to_end(&mut rest)).await.unwrap();
        assert!(rest.is_empty());
    }
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn malformed_targets_host_and_body_framing_get_400() {
    let policy = PolicyFixture::new("");
    let proxy = start(&policy).await;
    for target in [
        "example.invalid",
        "example.invalid:0",
        "example.invalid:65536",
        "example.invalid:-1",
        "http://example.invalid:443/",
        "user@example.invalid:443",
        "example.invalid:443/path",
        "example.invalid:443?x",
        "example.invalid:443#x",
        "127.1:443",
        "::1:443",
        "[::1]:",
        "[::1%25eth0]:443",
    ] {
        let (_, response) = request(proxy.local_addr(), target, target, "").await;
        assert_eq!(status(&response), 400, "{target}");
    }
    for fields in [
        "Host: example.invalid:443\r\n",
        "Content-Length: 1\r\n",
        "Transfer-Encoding: chunked\r\n",
        "Upgrade: websocket\r\n",
    ] {
        let (_, response) = request(
            proxy.local_addr(),
            "example.invalid:443",
            "example.invalid:443",
            fields,
        )
        .await;
        assert_eq!(status(&response), 400, "{fields}");
    }
    let (_, response) = request(
        proxy.local_addr(),
        "example.invalid:443",
        "different.invalid:443",
        "",
    )
    .await;
    assert_eq!(status(&response), 400);
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn upstream_refusal_is_empty_502() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let policy = PolicyFixture::new("");
    let proxy = start(&policy).await;
    let (mut stream, response) = request(
        proxy.local_addr(),
        &address.to_string(),
        &address.to_string(),
        "",
    )
    .await;
    assert_eq!(status(&response), 502);
    let mut body = Vec::new();
    bounded(stream.read_to_end(&mut body)).await.unwrap();
    assert!(body.is_empty());
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn bytes_sent_with_connect_headers_are_preserved() {
    let origin = Echo::new().await;
    let policy = PolicyFixture::new("");
    let proxy = start(&policy).await;
    let mut stream = TcpStream::connect(proxy.local_addr()).await.unwrap();
    let mut packet = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        origin.address, origin.address
    )
    .into_bytes();
    packet.extend_from_slice(b"\x16\x03\x01opaque#earlybytes");
    stream.write_all(&packet).await.unwrap();
    assert_eq!(status(&head(&mut stream).await), 200);
    let mut bytes = [0; 20];
    bounded(stream.read_exact(&mut bytes)).await.unwrap();
    assert_eq!(&bytes, b"\x16\x03\x01opaque#earlybytes");
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn allowed_tls_tunnel_preserves_origin_certificate_and_bidirectional_tls() {
    use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = certified.cert.der().clone();
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.clone()],
            PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.clone()).unwrap();
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let job = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(server))
            .accept(stream)
            .await
            .unwrap();
        tls.write_all(b"origin greeting").await.unwrap();
        let mut data = [0; 11];
        tls.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"client data");
        tls.write_all(b"origin reply").await.unwrap();
        tls.shutdown().await.unwrap();
    });
    let policy = PolicyFixture::new(&format!("https://127.0.0.1:{}/blocked/*", address.port()));
    let proxy = start(&policy).await;
    let (stream, response) = request(
        proxy.local_addr(),
        &address.to_string(),
        &address.to_string(),
        "",
    )
    .await;
    assert_eq!(status(&response), 200);
    let mut tls = bounded(
        tokio_rustls::TlsConnector::from(Arc::new(client))
            .connect(ServerName::try_from("localhost").unwrap(), stream),
    )
    .await
    .unwrap();
    assert_eq!(tls.get_ref().1.peer_certificates().unwrap(), &[certificate]);
    let mut greeting = [0; 15];
    bounded(tls.read_exact(&mut greeting)).await.unwrap();
    assert_eq!(&greeting, b"origin greeting");
    tls.write_all(b"client data").await.unwrap();
    let mut reply = Vec::new();
    bounded(tls.read_to_end(&mut reply)).await.unwrap();
    assert_eq!(reply, b"origin reply");
    bounded(job).await.unwrap();
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn published_domain_blocks_close_existing_tunnels_but_not_unrelated_hosts() {
    let origin = Echo::new().await;
    let mut policy = PolicyFixture::new("");
    let proxy = start(&policy).await;
    let host = format!("localhost:{}", origin.address.port());
    let (mut affected, response) = request(proxy.local_addr(), &host, &host, "").await;
    assert_eq!(status(&response), 200);
    let ip = origin.address.to_string();
    let (mut unaffected, response) = request(proxy.local_addr(), &ip, &ip, "").await;
    assert_eq!(status(&response), 200);
    echo(&mut affected, b"before").await;
    policy.update("localhost");
    assert!(bounded(affected.read_u8()).await.is_err());
    echo(&mut unaffected, b"after").await;
    let (_, response) = request(proxy.local_addr(), &host, &host, "").await;
    assert_eq!(status(&response), 403);
    proxy.shutdown().await.unwrap();
    assert!(bounded(unaffected.read_u8()).await.is_err());
}

#[tokio::test]
async fn activation_acknowledges_completed_selective_tunnel_cleanup() {
    use nullgate_core::{PolicyActivation, UnavailableReason};
    let origin = Echo::new().await;
    let mut policy = PolicyFixture::new("");
    let proxy = start(&policy).await;
    let control = proxy.tunnels();
    let host = format!("localhost:{}", origin.address.port());
    let (mut affected, response) = request(proxy.local_addr(), &host, &host, "").await;
    assert_eq!(status(&response), 200);
    let ip = origin.address.to_string();
    let (mut unaffected, response) = request(proxy.local_addr(), &ip, &ip, "").await;
    assert_eq!(status(&response), 200);
    assert_eq!(control.active_count(), 2);
    let previous = policy.reader.current().unwrap();
    let candidate = policy.candidate("localhost");
    policy
        .publisher
        .unavailable(candidate.revision(), UnavailableReason::Activating);
    bounded(control.activate(previous, candidate.clone()))
        .await
        .unwrap();
    assert_eq!(control.active_count(), 1);
    assert!(bounded(affected.read_u8()).await.is_err());
    policy.publisher.publish(candidate);
    echo(&mut unaffected, b"unaffected").await;
    drop(unaffected);
    bounded(control.wait_idle()).await;
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn url_only_rules_never_block_hosts_and_inspection_membership_changes_reconnect() {
    let origin = Echo::new().await;
    let mut policy = PolicyFixture::new("");
    let proxy = start(&policy).await;
    assert!(proxy.capabilities().https_connect_passthrough);
    assert!(!proxy.capabilities().https_url_filtering);
    let host = format!("localhost:{}", origin.address.port());
    let (mut stream, response) = request(proxy.local_addr(), &host, &host, "").await;
    assert_eq!(status(&response), 200);
    policy.update(&format!("http://{host}/ads"));
    echo(&mut stream, b"HTTP-only does not select inspection").await;
    policy.update(&format!("https://{host}/ads"));
    assert!(bounded(stream.read_u8()).await.is_err());
    let (mut stream, response) = request(proxy.local_addr(), &host, &host, "").await;
    assert_eq!(status(&response), 200);
    echo(&mut stream, b"still opaque").await;
    policy.update("");
    assert!(bounded(stream.read_u8()).await.is_err());
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_owner_drop_and_policy_owner_loss_close_tunnels() {
    for lose_policy in [false, true] {
        let origin = Echo::new().await;
        let policy = PolicyFixture::new("");
        let proxy = start(&policy).await;
        let control = proxy.tunnels();
        let address = proxy.local_addr();
        let ip = origin.address.to_string();
        let (mut stream, response) = request(address, &ip, &ip, "").await;
        assert_eq!(status(&response), 200);
        if lose_policy {
            drop(policy);
            bounded(control.wait_idle()).await;
            let (_, response) = request(address, &ip, &ip, "").await;
            assert_eq!(status(&response), 503);
            proxy.shutdown().await.unwrap();
        } else {
            drop(proxy);
            bounded(control.wait_idle()).await;
        }
        assert!(bounded(stream.read_u8()).await.is_err());
    }
}

#[tokio::test]
async fn upgraded_tunnels_hold_connection_and_request_admission_until_cleanup() {
    let origin = Echo::new().await;
    let policy = PolicyFixture::new("");
    let proxy = HttpService::start(
        HttpConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
        },
        policy.reader.clone(),
        HttpOptions {
            max_connections: 1,
            max_requests: 1,
            ..HttpOptions::default()
        },
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let control = proxy.tunnels();
    let ip = origin.address.to_string();
    let (stream, response) = request(proxy.local_addr(), &ip, &ip, "").await;
    assert_eq!(status(&response), 200);
    let mut excess = TcpStream::connect(proxy.local_addr()).await.unwrap();
    assert!(bounded(excess.read_u8()).await.is_err());
    drop(stream);
    bounded(control.wait_idle()).await;
    let (mut stream, response) = request(proxy.local_addr(), &ip, &ip, "").await;
    assert_eq!(status(&response), 200);
    echo(&mut stream, b"permit recovered").await;
    proxy.shutdown().await.unwrap();
    assert_eq!(control.active_count(), 0);
}
