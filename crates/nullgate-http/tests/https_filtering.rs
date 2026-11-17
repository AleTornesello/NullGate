use http_body_util::{BodyExt, Full};
use hyper::{
    Request, Response,
    body::{Bytes, Incoming},
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use nullgate_core::{
    BlocklistRepository, HttpConfig, Mutation, PolicyPublisher, PolicySnapshot, PolicySubscription,
    SourceKind, SqliteRepository, policy_channel,
};
use nullgate_http::{HttpOptions, HttpService, ca::CaProvider, inspection::Inspection};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName},
};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_util::sync::CancellationToken;
async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(8), future)
        .await
        .expect("local HTTPS operation timed out")
}
struct Policy {
    path: PathBuf,
    repo: SqliteRepository,
    publisher: PolicyPublisher,
    reader: PolicySubscription,
    source: i64,
    revision: u64,
}
impl Policy {
    fn new(text: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "nullgate-inspection-{}-{stamp}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        let mut repo = SqliteRepository::open(path.join("state.sqlite3")).unwrap();
        repo.apply(
            0,
            Mutation::CreateList {
                name: "HTTPS".into(),
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
        let (publisher, reader) = policy_channel(PolicySnapshot::from_commit(commit).0);
        Self {
            path,
            repo,
            publisher,
            reader,
            source,
            revision: 3,
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
        self.publisher
            .publish(Arc::new(PolicySnapshot::from_commit(commit).0));
    }
    fn ca(&self) -> Arc<CaProvider> {
        Arc::new(CaProvider::open(&self.path).unwrap())
    }
}
impl Drop for Policy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
struct Origin {
    address: SocketAddr,
    certificate: CertificateDer<'static>,
    requests: Arc<AtomicUsize>,
    targets: Arc<Mutex<Vec<String>>>,
    cancel: CancellationToken,
    job: tokio::task::JoinHandle<()>,
}
impl Origin {
    async fn new(names: Vec<String>) -> Self {
        Self::certificate(rcgen::generate_simple_self_signed(names).unwrap()).await
    }
    async fn certificate(certified: rcgen::CertifiedKey<rcgen::KeyPair>) -> Self {
        let certificate = certified.cert.der().clone();
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.clone()],
            PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()).into(),
        )
        .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        let targets = Arc::new(Mutex::new(vec![]));
        let recorded = targets.clone();
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let job = tokio::spawn(async move {
            let mut clients = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                 _=stop.cancelled()=>break,
                 Some(_)=clients.join_next(),if !clients.is_empty()=>{},
                 accepted=listener.accept()=>{let(stream,_)=accepted.unwrap();let acceptor=acceptor.clone();let count=count.clone();let recorded=recorded.clone();clients.spawn(async move {let Ok(stream)=acceptor.accept(stream).await else{return;};let service=service_fn(move|request:Request<Incoming>|{let count=count.clone();let recorded=recorded.clone();async move {count.fetch_add(1,Ordering::SeqCst);recorded.lock().unwrap().push(request.uri().to_string());let bytes=request.into_body().collect().await.unwrap().to_bytes();let body=if bytes.is_empty(){Bytes::from_static(b"origin")}else{bytes};Ok::<_,std::convert::Infallible>(Response::new(Full::new(body)))}});let _=hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream),service).await;});}
                }
            }
            clients.shutdown().await;
        });
        Self {
            address,
            certificate,
            requests,
            targets,
            cancel,
            job,
        }
    }
    fn url(&self, host: &str, path: &str) -> String {
        format!("https://{host}:{}{path}", self.address.port())
    }
    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.certificate.clone()).unwrap();
        roots
    }
}
impl Drop for Origin {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.job.abort();
    }
}
fn client(roots: RootCertStore) -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}
fn ca_roots(ca: &CaProvider) -> RootCertStore {
    let pem = ca.public_certificate().certificate_pem();
    let der = pem::parse(pem).unwrap().into_contents();
    let mut roots = RootCertStore::empty();
    roots.add(der.into()).unwrap();
    roots
}
async fn proxy(policy: &Policy, origin: &Origin, ca: Arc<CaProvider>) -> HttpService {
    let inspection = Inspection::new(ca, origin.roots()).unwrap();
    HttpService::start_with_inspection(
        HttpConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
        },
        policy.reader.clone(),
        HttpOptions {
            connect_timeout: Duration::from_secs(2),
            ..HttpOptions::default()
        },
        CancellationToken::new(),
        nullgate_http::TunnelControl::default(),
        inspection,
    )
    .await
    .unwrap()
}
async fn head<S: AsyncRead + Unpin>(io: &mut S) -> String {
    let mut bytes = vec![];
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(bounded(io.read_u8()).await.unwrap());
        assert!(bytes.len() < 32768);
    }
    String::from_utf8(bytes).unwrap()
}
async fn connect(proxy: SocketAddr, host: &str, port: u16) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(
            format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let header = head(&mut stream).await;
    assert!(header.starts_with("HTTP/1.1 200"), "{header}");
    stream
}
async fn tls(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    roots: RootCertStore,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let stream = connect(proxy, host, port).await;
    bounded(
        tokio_rustls::TlsConnector::from(client(roots))
            .connect(ServerName::try_from(host.to_owned()).unwrap(), stream),
    )
    .await
    .unwrap()
}
async fn request<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    host: &str,
    path: &str,
) -> (u16, Vec<u8>) {
    io.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    response(io).await
}
async fn response<S: AsyncRead + Unpin>(io: &mut S) -> (u16, Vec<u8>) {
    let header = head(io).await;
    let status = header.split_whitespace().nth(1).unwrap().parse().unwrap();
    let length = header
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|s| s.trim().parse::<usize>().unwrap())
        })
        .unwrap();
    let mut bytes = vec![0; length];
    bounded(io.read_exact(&mut bytes)).await.unwrap();
    (status, bytes)
}
#[tokio::test]
async fn exact_wildcard_queries_and_siblings_reuse_current_policy_per_request() {
    let origin = Origin::new(vec!["127.0.0.1".into()]).await;
    let mut policy = Policy::new(&origin.url("127.0.0.1", "/ads"));
    let ca = policy.ca();
    let proxy = proxy(&policy, &origin, ca.clone()).await;
    assert!(proxy.capabilities().https_url_filtering);
    let mut io = tls(
        proxy.local_addr(),
        "127.0.0.1",
        origin.address.port(),
        ca_roots(&ca),
    )
    .await;
    assert_ne!(
        io.get_ref().1.peer_certificates().unwrap()[0],
        origin.certificate
    );
    let authority = origin.address.to_string();
    for path in ["/ads", "/ads?token=ignored"] {
        assert_eq!(request(&mut io, &authority, path).await, (403, vec![]));
    }
    assert_eq!(origin.requests.load(Ordering::SeqCst), 0);
    assert_eq!(
        request(&mut io, &authority, "/news?keep=1").await,
        (200, b"origin".to_vec())
    );
    assert_eq!(origin.targets.lock().unwrap()[0], "/news?keep=1");
    policy.update(&origin.url("127.0.0.1", "/ads/*"));
    assert_eq!(
        request(&mut io, &authority, "/ads/deeper/banner").await,
        (403, vec![])
    );
    assert_eq!(request(&mut io, &authority, "/ads").await.0, 403);
    assert_eq!(request(&mut io, &authority, "/news").await.0, 200);
    proxy.shutdown().await.unwrap();
}
#[tokio::test]
async fn targets_added_removed_and_domain_blocks_close_connections_restore_original_certificate() {
    let origin = Origin::new(vec!["localhost".into()]).await;
    let mut policy = Policy::new("");
    let ca = policy.ca();
    let proxy = proxy(&policy, &origin, ca.clone()).await;
    let mut passthrough = tls(
        proxy.local_addr(),
        "localhost",
        origin.address.port(),
        origin.roots(),
    )
    .await;
    assert_eq!(
        passthrough.get_ref().1.peer_certificates().unwrap()[0],
        origin.certificate
    );
    policy.update(&origin.url("localhost", "/ads"));
    let mut byte = [0];
    assert!(bounded(passthrough.read(&mut byte)).await.unwrap_or(0) == 0);
    let mut inspected = tls(
        proxy.local_addr(),
        "localhost",
        origin.address.port(),
        ca_roots(&ca),
    )
    .await;
    assert_eq!(
        request(
            &mut inspected,
            &format!("localhost:{}", origin.address.port()),
            "/ads"
        )
        .await
        .0,
        403
    );
    policy.update("");
    assert!(bounded(inspected.read(&mut byte)).await.unwrap_or(0) == 0);
    let mut restored = tls(
        proxy.local_addr(),
        "localhost",
        origin.address.port(),
        origin.roots(),
    )
    .await;
    assert_eq!(
        restored.get_ref().1.peer_certificates().unwrap()[0],
        origin.certificate
    );
    policy.update("localhost");
    assert!(bounded(restored.read(&mut byte)).await.unwrap_or(0) == 0);
    let tunnels = proxy.tunnels();
    proxy.shutdown().await.unwrap();
    assert_eq!(tunnels.active_count(), 0);
}
#[tokio::test]
async fn missing_client_trust_and_wrong_sni_fail_tls_without_origin_requests() {
    let origin = Origin::new(vec!["localhost".into()]).await;
    let policy = Policy::new(&origin.url("localhost", "/ads"));
    let ca = policy.ca();
    let proxy = proxy(&policy, &origin, ca.clone()).await;
    for name in ["localhost", "wrong.invalid"] {
        let stream = connect(proxy.local_addr(), "localhost", origin.address.port()).await;
        let roots = if name == "localhost" {
            RootCertStore::empty()
        } else {
            ca_roots(&ca)
        };
        let error = bounded(
            tokio_rustls::TlsConnector::from(client(roots))
                .connect(ServerName::try_from(name.to_owned()).unwrap(), stream),
        )
        .await
        .err()
        .unwrap();
        let tls = error
            .get_ref()
            .and_then(|error| error.downcast_ref::<rustls::Error>());
        if name == "wrong.invalid" {
            assert!(
                matches!(
                    tls,
                    Some(rustls::Error::AlertReceived(
                        rustls::AlertDescription::AccessDenied
                    ))
                ),
                "{error}"
            );
        } else {
            assert!(
                matches!(tls, Some(rustls::Error::InvalidCertificate(_))),
                "{error}"
            );
        }
    }
    let mut config = (*client(ca_roots(&ca))).clone();
    config.enable_sni = false;
    let stream = connect(proxy.local_addr(), "localhost", origin.address.port()).await;
    let error = bounded(
        tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("localhost").unwrap(), stream),
    )
    .await
    .err()
    .unwrap();
    assert!(
        matches!(
            error
                .get_ref()
                .and_then(|error| error.downcast_ref::<rustls::Error>()),
            Some(rustls::Error::AlertReceived(
                rustls::AlertDescription::AccessDenied
            ))
        ),
        "{error}"
    );
    assert_eq!(origin.requests.load(Ordering::SeqCst), 0);
    proxy.shutdown().await.unwrap();
}
#[tokio::test]
async fn inspected_authorities_cannot_escape_connect_binding() {
    let origin = Origin::new(vec!["127.0.0.1".into()]).await;
    let policy = Policy::new(&origin.url("127.0.0.1", "/ads"));
    let ca = policy.ca();
    let proxy = proxy(&policy, &origin, ca.clone()).await;
    for (host, path) in [
        ("other.invalid:443", "/news"),
        ("127.0.0.1:1", "/news"),
        ("other.invalid:443", "https://other.invalid/news"),
    ] {
        let mut io = tls(
            proxy.local_addr(),
            "127.0.0.1",
            origin.address.port(),
            ca_roots(&ca),
        )
        .await;
        assert_eq!(request(&mut io, host, path).await, (421, vec![]));
    }
    assert_eq!(origin.requests.load(Ordering::SeqCst), 0);
    proxy.shutdown().await.unwrap();
}
#[tokio::test]
async fn upstream_certificate_hostname_and_chain_errors_are_rejected() {
    let origin = Origin::new(vec!["wrong.invalid".into()]).await;
    let policy = Policy::new(&origin.url("127.0.0.1", "/ads"));
    let ca = policy.ca();
    let proxy = proxy(&policy, &origin, ca.clone()).await;
    let mut io = tls(
        proxy.local_addr(),
        "127.0.0.1",
        origin.address.port(),
        ca_roots(&ca),
    )
    .await;
    assert_eq!(
        request(&mut io, &origin.address.to_string(), "/news").await,
        (502, vec![])
    );
    assert_eq!(origin.requests.load(Ordering::SeqCst), 0);
    proxy.shutdown().await.unwrap();
    let origin = Origin::new(vec!["127.0.0.1".into()]).await;
    let unrelated = Origin::new(vec!["127.0.0.1".into()]).await;
    let policy = Policy::new(&origin.url("127.0.0.1", "/ads"));
    let ca = policy.ca();
    let inspection = Inspection::new(ca.clone(), unrelated.roots()).unwrap();
    let proxy = HttpService::start_with_inspection(
        HttpConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
        },
        policy.reader.clone(),
        HttpOptions::default(),
        CancellationToken::new(),
        nullgate_http::TunnelControl::default(),
        inspection,
    )
    .await
    .unwrap();
    let mut io = tls(
        proxy.local_addr(),
        "127.0.0.1",
        origin.address.port(),
        ca_roots(&ca),
    )
    .await;
    assert_eq!(
        request(&mut io, &origin.address.to_string(), "/news").await,
        (502, vec![])
    );
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn inspected_http_streams_large_bodies_and_rejects_upgrades_and_malformed_headers() {
    let origin = Origin::new(vec!["127.0.0.1".into()]).await;
    let policy = Policy::new(&origin.url("127.0.0.1", "/ads"));
    let ca = policy.ca();
    let proxy = proxy(&policy, &origin, ca.clone()).await;
    let mut io = tls(
        proxy.local_addr(),
        "127.0.0.1",
        origin.address.port(),
        ca_roots(&ca),
    )
    .await;
    let body = vec![b'x'; 1024 * 1024];
    io.write_all(format!("POST /upload HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: x-secret\r\nX-Secret: remove\r\n\r\n",origin.address,body.len()).as_bytes()).await.unwrap();
    bounded(io.write_all(&body)).await.unwrap();
    assert_eq!(response(&mut io).await, (200, body));
    for (raw, status) in [
        (
            format!("GET /news HTTP/1.0\r\nHost: {}\r\n\r\n", origin.address),
            505,
        ),
        (
            format!(
                "GET /news HTTP/1.1\r\nHost: {}\r\nHost: {}\r\n\r\n",
                origin.address, origin.address
            ),
            400,
        ),
        (
            format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                origin.address, origin.address
            ),
            501,
        ),
        (
            format!(
                "GET /news HTTP/1.1\r\nHost: {}\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
                origin.address
            ),
            501,
        ),
    ] {
        let mut io = tls(
            proxy.local_addr(),
            "127.0.0.1",
            origin.address.port(),
            ca_roots(&ca),
        )
        .await;
        io.write_all(raw.as_bytes()).await.unwrap();
        assert_eq!(response(&mut io).await, (status, vec![]));
    }
    proxy.shutdown().await.unwrap();
}
#[tokio::test]
async fn alpn_http2_only_and_ip_sni_are_rejected_but_no_alpn_http1_works() {
    let origin = Origin::new(vec!["127.0.0.1".into()]).await;
    let policy = Policy::new(&origin.url("127.0.0.1", "/ads"));
    let ca = policy.ca();
    let proxy = proxy(&policy, &origin, ca.clone()).await;
    let mut config = (*client(ca_roots(&ca))).clone();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let stream = connect(proxy.local_addr(), "127.0.0.1", origin.address.port()).await;
    let error = bounded(
        tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("127.0.0.1").unwrap(), stream),
    )
    .await
    .err()
    .unwrap();
    assert!(
        matches!(
            error
                .get_ref()
                .and_then(|e| e.downcast_ref::<rustls::Error>()),
            Some(rustls::Error::AlertReceived(
                rustls::AlertDescription::NoApplicationProtocol
            ))
        ),
        "{error}"
    );
    let stream = connect(proxy.local_addr(), "127.0.0.1", origin.address.port()).await;
    let error = bounded(
        tokio_rustls::TlsConnector::from(client(ca_roots(&ca)))
            .connect(ServerName::try_from("localhost").unwrap(), stream),
    )
    .await
    .err()
    .unwrap();
    assert!(
        matches!(
            error
                .get_ref()
                .and_then(|e| e.downcast_ref::<rustls::Error>()),
            Some(rustls::Error::AlertReceived(
                rustls::AlertDescription::AccessDenied
            ))
        ),
        "{error}"
    );
    let mut config = (*client(ca_roots(&ca))).clone();
    config.alpn_protocols.clear();
    let stream = connect(proxy.local_addr(), "127.0.0.1", origin.address.port()).await;
    let mut io = bounded(
        tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("127.0.0.1").unwrap(), stream),
    )
    .await
    .unwrap();
    assert_eq!(
        request(&mut io, &origin.address.to_string(), "/ads").await,
        (403, vec![])
    );
    proxy.shutdown().await.unwrap();
}
#[tokio::test]
async fn http_only_rules_do_not_inspect_and_shutdown_cleans_up_pending_tls() {
    let origin = Origin::new(vec!["127.0.0.1".into()]).await;
    let policy = Policy::new(&origin.url("127.0.0.1", "/ads").replace("https:", "http:"));
    let ca = policy.ca();
    let service = proxy(&policy, &origin, ca.clone()).await;
    let io = tls(
        service.local_addr(),
        "127.0.0.1",
        origin.address.port(),
        origin.roots(),
    )
    .await;
    assert_eq!(
        io.get_ref().1.peer_certificates().unwrap()[0],
        origin.certificate
    );
    service.shutdown().await.unwrap();
    let policy = Policy::new(&origin.url("127.0.0.1", "/ads"));
    let ca = policy.ca();
    let service = proxy(&policy, &origin, ca).await;
    let mut pending = connect(service.local_addr(), "127.0.0.1", origin.address.port()).await;
    let tunnels = service.tunnels();
    bounded(service.shutdown()).await.unwrap();
    let mut byte = [0];
    assert_eq!(bounded(pending.read(&mut byte)).await.unwrap_or(0), 0);
    assert_eq!(tunnels.active_count(), 0);
}

#[tokio::test]
async fn activation_acknowledges_inspected_cleanup_before_new_policy_publication() {
    use nullgate_core::{PolicyActivation, UnavailableReason};
    let origin = Origin::new(vec!["localhost".into()]).await;
    let mut policy = Policy::new(&origin.url("localhost", "/ads"));
    let ca = policy.ca();
    let proxy = proxy(&policy, &origin, ca.clone()).await;
    let mut io = tls(
        proxy.local_addr(),
        "localhost",
        origin.address.port(),
        ca_roots(&ca),
    )
    .await;
    assert_eq!(
        request(
            &mut io,
            &format!("localhost:{}", origin.address.port()),
            "/news"
        )
        .await
        .0,
        200
    );
    let old = policy.reader.current().unwrap();
    let commit = policy
        .repo
        .apply(
            policy.revision,
            Mutation::ClearSource {
                source_id: policy.source,
            },
        )
        .unwrap();
    let candidate = Arc::new(PolicySnapshot::from_commit(commit).0);
    policy
        .publisher
        .unavailable(candidate.revision(), UnavailableReason::Activating);
    let tunnels = proxy.tunnels();
    bounded(tunnels.activate(old, candidate.clone()))
        .await
        .unwrap();
    assert_eq!(tunnels.active_count(), 0);
    let mut byte = [0];
    assert_eq!(bounded(io.read(&mut byte)).await.unwrap_or(0), 0);
    policy.publisher.publish(candidate);
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn expired_upstream_certificate_is_not_accepted_even_as_fixture_trust_anchor() {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
    params.not_before = rcgen::date_time_ymd(2000, 1, 1);
    params.not_after = rcgen::date_time_ymd(2001, 1, 1);
    let cert = params.self_signed(&key).unwrap();
    let origin = Origin::certificate(rcgen::CertifiedKey {
        cert,
        signing_key: key,
    })
    .await;
    let policy = Policy::new(&origin.url("127.0.0.1", "/ads"));
    let ca = policy.ca();
    let service = proxy(&policy, &origin, ca.clone()).await;
    let mut io = tls(
        service.local_addr(),
        "127.0.0.1",
        origin.address.port(),
        ca_roots(&ca),
    )
    .await;
    assert_eq!(
        request(&mut io, &origin.address.to_string(), "/news").await,
        (502, vec![])
    );
    assert_eq!(origin.requests.load(Ordering::SeqCst), 0);
    service.shutdown().await.unwrap();
}
#[tokio::test]
async fn stalled_upstream_tls_handshake_returns_timeout_and_releases_connection() {
    let origin = Origin::new(vec!["127.0.0.1".into()]).await;
    let stalled = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = stalled.local_addr().unwrap();
    let job = tokio::spawn(async move {
        let (mut stream, _) = stalled.accept().await.unwrap();
        let mut bytes = vec![];
        let _ = stream.read_to_end(&mut bytes).await;
    });
    let policy = Policy::new(&format!("https://{address}/ads"));
    let ca = policy.ca();
    let inspection = Inspection::new(ca.clone(), origin.roots()).unwrap();
    let service = HttpService::start_with_inspection(
        HttpConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
        },
        policy.reader.clone(),
        HttpOptions {
            connect_timeout: Duration::from_secs(1),
            max_requests: 1,
            ..HttpOptions::default()
        },
        CancellationToken::new(),
        nullgate_http::TunnelControl::default(),
        inspection,
    )
    .await
    .unwrap();
    let mut io = tls(
        service.local_addr(),
        "127.0.0.1",
        address.port(),
        ca_roots(&ca),
    )
    .await;
    assert_eq!(
        request(&mut io, &address.to_string(), "/news").await,
        (504, vec![])
    );
    bounded(job).await.unwrap();
    service.shutdown().await.unwrap();
}

#[derive(Default)]
struct SignGate {
    blocking: std::sync::atomic::AtomicBool,
    released: Mutex<bool>,
    resume: std::sync::Condvar,
    entered: tokio::sync::Notify,
}
struct GateClock(Arc<SignGate>);
impl nullgate_http::ca::CaClock for GateClock {
    fn unix_seconds(&self) -> Result<i64, nullgate_http::ca::CaError> {
        if self.0.blocking.load(Ordering::SeqCst) {
            self.0.entered.notify_one();
            let mut released = self.0.released.lock().unwrap();
            while !*released {
                released = self.0.resume.wait(released).unwrap();
            }
        }
        Ok(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64)
    }
}
struct ReleaseGate(Arc<SignGate>);
impl Drop for ReleaseGate {
    fn drop(&mut self) {
        *self.0.released.lock().unwrap() = true;
        self.0.resume.notify_all();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn activation_waits_for_pending_signing_work_after_client_socket_closes() {
    use nullgate_core::{PolicyActivation, UnavailableReason};
    let origin = Origin::new(vec!["127.0.0.1".into()]).await;
    let mut policy = Policy::new(&origin.url("127.0.0.1", "/ads"));
    let gate = Arc::new(SignGate::default());
    let release = ReleaseGate(gate.clone());
    let ca = Arc::new(
        CaProvider::open_with_clock(&policy.path, Arc::new(GateClock(gate.clone()))).unwrap(),
    );
    let service = proxy(&policy, &origin, ca.clone()).await;
    gate.blocking.store(true, Ordering::SeqCst);
    let stream = connect(service.local_addr(), "127.0.0.1", origin.address.port()).await;
    let config = client(ca_roots(&ca));
    let connecting = tokio::spawn(async move {
        tokio_rustls::TlsConnector::from(config)
            .connect(ServerName::try_from("127.0.0.1").unwrap(), stream)
            .await
    });
    bounded(gate.entered.notified()).await;
    let old = policy.reader.current().unwrap();
    let commit = policy
        .repo
        .apply(
            policy.revision,
            Mutation::ClearSource {
                source_id: policy.source,
            },
        )
        .unwrap();
    let candidate = Arc::new(PolicySnapshot::from_commit(commit).0);
    policy
        .publisher
        .unavailable(candidate.revision(), UnavailableReason::Activating);
    let tunnels = service.tunnels();
    let next = candidate.clone();
    let mut activating = tokio::spawn(async move { tunnels.activate(old, next).await });
    assert!(bounded(connecting).await.unwrap().is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(40), &mut activating)
            .await
            .is_err(),
        "activation acknowledged while signing work was still live"
    );
    drop(release);
    bounded(activating).await.unwrap().unwrap();
    policy.publisher.publish(candidate);
    let tunnels = service.tunnels();
    service.shutdown().await.unwrap();
    assert_eq!(tunnels.active_count(), 0);
}
#[tokio::test]
async fn activation_joins_a_live_upstream_body_driver_before_acknowledgment() {
    use nullgate_core::{PolicyActivation, UnavailableReason};
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = certified.cert.der().clone();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.clone()],
        PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()).into(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let job = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut io = acceptor.accept(stream).await.unwrap();
        let _ = head(&mut io).await;
        io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nx")
            .await
            .unwrap();
        io.flush().await.unwrap();
        let mut remaining = vec![];
        let _ = io.read_to_end(&mut remaining).await;
    });
    let mut policy = Policy::new(&format!("https://localhost:{}/ads", address.port()));
    let ca = policy.ca();
    let mut roots = RootCertStore::empty();
    roots.add(certificate).unwrap();
    let inspection = Inspection::new(ca.clone(), roots).unwrap();
    let service = HttpService::start_with_inspection(
        HttpConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
        },
        policy.reader.clone(),
        HttpOptions::default(),
        CancellationToken::new(),
        nullgate_http::TunnelControl::default(),
        inspection,
    )
    .await
    .unwrap();
    let mut io = tls(
        service.local_addr(),
        "localhost",
        address.port(),
        ca_roots(&ca),
    )
    .await;
    io.write_all(
        format!(
            "GET /slow HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
            address.port()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    assert!(head(&mut io).await.starts_with("HTTP/1.1 200"));
    assert_eq!(bounded(io.read_u8()).await.unwrap(), b'x');
    let old = policy.reader.current().unwrap();
    let commit = policy
        .repo
        .apply(
            policy.revision,
            Mutation::ClearSource {
                source_id: policy.source,
            },
        )
        .unwrap();
    let candidate = Arc::new(PolicySnapshot::from_commit(commit).0);
    policy
        .publisher
        .unavailable(candidate.revision(), UnavailableReason::Activating);
    let tunnels = service.tunnels();
    bounded(tunnels.activate(old, candidate.clone()))
        .await
        .unwrap();
    assert_eq!(tunnels.active_count(), 0);
    bounded(job).await.unwrap();
    let mut byte = [0];
    assert_eq!(bounded(io.read(&mut byte)).await.unwrap_or(0), 0);
    policy.publisher.publish(candidate);
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn metrics_distinguish_inspected_requests_from_connect_admission() {
    use nullgate_core::metrics::{Metrics, MetricsSource};
    let origin = Origin::new(vec!["127.0.0.1".into()]).await;
    let policy = Policy::new(&origin.url("127.0.0.1", "/ads"));
    let ca = policy.ca();
    let metrics = Metrics::default();
    let proxy = HttpService::start_with_inspection(
        HttpConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
        },
        policy.reader.clone(),
        HttpOptions {
            metrics: metrics.clone(),
            ..HttpOptions::default()
        },
        CancellationToken::new(),
        nullgate_http::TunnelControl::default(),
        Inspection::new(ca.clone(), origin.roots()).unwrap(),
    )
    .await
    .unwrap();
    let mut io = tls(
        proxy.local_addr(),
        "127.0.0.1",
        origin.address.port(),
        ca_roots(&ca),
    )
    .await;
    for path in ["/ads?secret=discard", "/ads"] {
        assert_eq!(
            request(&mut io, &origin.address.to_string(), path).await.0,
            403
        );
    }
    assert_eq!(
        request(&mut io, &origin.address.to_string(), "/news")
            .await
            .0,
        200
    );
    let snapshot = metrics.snapshot();
    assert_eq!((snapshot.https.allowed, snapshot.https.blocked), (1, 2));
    assert_eq!((snapshot.connect.allowed, snapshot.http.allowed), (1, 0));
    assert_eq!(snapshot.active_http_connections, 1);
    proxy.shutdown().await.unwrap();
    assert_eq!(metrics.snapshot().active_http_connections, 0);
}
