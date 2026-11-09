use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::{
    Request, Response, StatusCode, Uri,
    body::{Bytes, Frame, Incoming},
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use nullgate_core::{
    BlocklistRepository, HttpConfig, Mutation, PolicyPublisher, PolicySnapshot, PolicySubscription,
    ServiceStatus, SourceKind, SqliteRepository, UnavailableReason, policy_channel,
};
use nullgate_http::{HttpOptions, HttpService};
use std::{
    convert::Infallible,
    future::Future,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Notify, mpsc},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
type BoxError = Box<dyn std::error::Error + Send + Sync>;
type TestBody = UnsyncBoxBody<Bytes, BoxError>;
fn full(bytes: impl Into<Bytes>) -> TestBody {
    Full::new(bytes.into())
        .map_err(|never: Infallible| match never {})
        .boxed_unsync()
}
async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("local HTTP operation timed out")
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
}
impl Drop for PolicyFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
struct Fixture {
    address: SocketAddr,
    cancel: CancellationToken,
    job: JoinHandle<()>,
}
impl Fixture {
    async fn new<F, Fut>(handler: F) -> Self
    where
        F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Response<TestBody>> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        let handler = Arc::new(handler);
        let job = tokio::spawn(async move {
            let mut clients = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                 _=token.cancelled()=>break,
                 Some(_)=clients.join_next(),if !clients.is_empty()=>{},
                 accepted=listener.accept()=>{let(stream,_)=accepted.unwrap();let handler=handler.clone();let token=token.clone();clients.spawn(async move{let service=service_fn(move|request|{let future=handler(request);async move{Ok::<_,Infallible>(future.await)}});let connection=hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream),service);tokio::select!{_=token.cancelled()=>{},_=connection=>{}}});}
                }
            }
            clients.shutdown().await;
        });
        Self {
            address,
            cancel,
            job,
        }
    }
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.job.abort();
    }
}
struct Client {
    sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    job: JoinHandle<()>,
}
impl Client {
    async fn new(address: SocketAddr) -> Self {
        let stream = TcpStream::connect(address).await.unwrap();
        let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        let job = tokio::spawn(async move {
            let _ = connection.await;
        });
        Self { sender, job }
    }
    async fn send(&mut self, target: &str) -> (StatusCode, hyper::HeaderMap, Vec<u8>) {
        let uri: Uri = target.parse().unwrap();
        let request = Request::builder()
            .uri(uri.clone())
            .header("Host", uri.authority().unwrap().as_str())
            .body(Full::new(Bytes::new()))
            .unwrap();
        self.sender.ready().await.unwrap();
        let response = bounded(self.sender.send_request(request)).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = bounded(response.into_body().collect())
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        (status, headers, body)
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.job.abort();
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
async fn raw(address: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut bytes = Vec::new();
    bounded(stream.read_to_end(&mut bytes)).await.unwrap();
    bytes
}
fn raw_status(bytes: &[u8]) -> u16 {
    std::str::from_utf8(bytes)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}
async fn read_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await.unwrap());
    }
    bytes
}

#[tokio::test]
async fn exact_wildcard_query_and_sibling_paths_are_filtered_without_a_block_page() {
    let origin =
        Fixture::new(|request| async move { Response::new(full(request.uri().to_string())) }).await;
    let policy = PolicyFixture::new(&format!(
        "{}\n{}\n{}",
        origin.url("/ads"),
        origin.url("/sponsored/*"),
        origin.url("/*/banner.png")
    ));
    let proxy = start(&policy).await;
    let mut client = Client::new(proxy.local_addr()).await;
    for (path, blocked) in [
        ("/ads", true),
        ("/ads?campaign=1", true),
        ("/ads/", false),
        ("/adsense", false),
        ("/sponsored", true),
        ("/sponsored/a/b", true),
        ("/sponsoredness", false),
        ("/x/y/banner.png", true),
        ("/x/banner.jpg", false),
        ("/news?keep=%2f", false),
    ] {
        let (status, headers, body) = client.send(&origin.url(path)).await;
        assert_eq!(
            status,
            if blocked {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::OK
            },
            "{path}"
        );
        if blocked {
            assert!(body.is_empty());
            assert_eq!(headers["content-length"], "0");
        } else {
            assert_eq!(body, path.as_bytes());
        }
    }
    proxy.shutdown().await.unwrap();
}
#[tokio::test]
async fn domain_blocks_do_not_require_dns_and_origin_form_is_supported() {
    let policy = PolicyFixture::new("blocked.invalid\n*.tracking.invalid");
    let proxy = start(&policy).await;
    for host in ["BLOCKED.invalid.", "a.b.tracking.invalid"] {
        let request = format!(
            "GET http://{host}/anything HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(
            raw_status(&raw(proxy.local_addr(), request.as_bytes()).await),
            403
        );
    }
    let origin =
        Fixture::new(|request| async move { Response::new(full(request.uri().to_string())) }).await;
    let request = format!(
        "GET /origin?query=kept HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        origin.address
    );
    let bytes = raw(proxy.local_addr(), request.as_bytes()).await;
    assert_eq!(raw_status(&bytes), 200);
    assert!(bytes.ends_with(b"/origin?query=kept"));
    proxy.shutdown().await.unwrap();
}
#[tokio::test]
async fn live_policy_changes_are_seen_on_one_existing_keep_alive_connection() {
    let origin = Fixture::new(|_| async { Response::new(full("allowed")) }).await;
    let mut policy = PolicyFixture::new("");
    let proxy = start(&policy).await;
    let mut client = Client::new(proxy.local_addr()).await;
    let target = origin.url("/ads");
    assert_eq!(client.send(&target).await.0, StatusCode::OK);
    policy.update(&target);
    assert_eq!(client.send(&target).await.0, StatusCode::FORBIDDEN);
    policy.update("");
    assert_eq!(client.send(&target).await.0, StatusCode::OK);
    policy
        .publisher
        .unavailable(policy.revision, UnavailableReason::CommittedNotActive);
    assert_eq!(
        client.send(&target).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    proxy.shutdown().await.unwrap();
}
#[tokio::test]
async fn hop_headers_and_connection_nominations_are_removed_in_both_directions() {
    let seen = Arc::new(Mutex::new(None));
    let captured = seen.clone();
    let origin = Fixture::new(move |request| {
        let seen = captured.clone();
        async move {
            *seen.lock().unwrap() = Some(request.headers().clone());
            let mut response = Response::new(full("ok"));
            for (name, value) in [
                ("connection", "x-secret, keep-alive"),
                ("x-secret", "remove"),
                ("keep-alive", "timeout=100"),
                ("proxy-authenticate", "Basic realm=private"),
                ("x-end-to-end", "retained"),
            ] {
                response.headers_mut().insert(
                    hyper::header::HeaderName::from_static(name),
                    value.parse().unwrap(),
                );
            }
            response
        }
    })
    .await;
    let policy = PolicyFixture::new("");
    let proxy = start(&policy).await;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close, x-private\r\nX-Private: secret\r\nProxy-Connection: keep-alive\r\nKeep-Alive: timeout=100\r\nProxy-Authorization: Basic secret\r\nTE: trailers\r\nTrailer: x-hidden\r\nAuthorization: Bearer end-to-end\r\nX-End-To-End: kept\r\n\r\n",
        origin.url("/"),
        origin.address
    );
    let bytes = raw(proxy.local_addr(), request.as_bytes()).await;
    let text = String::from_utf8(bytes).unwrap().to_ascii_lowercase();
    assert!(text.starts_with("http/1.1 200"));
    assert!(!text.contains("x-secret"));
    assert!(!text.contains("keep-alive"));
    assert!(!text.contains("proxy-authenticate"));
    assert!(text.contains("x-end-to-end: retained"));
    let headers = seen.lock().unwrap().clone().unwrap();
    for name in [
        "x-private",
        "proxy-connection",
        "keep-alive",
        "proxy-authorization",
        "trailer",
    ] {
        assert!(!headers.contains_key(name), "{name}");
    }
    assert_eq!(headers["te"], "trailers");
    assert_eq!(headers["connection"], "te");
    assert_eq!(headers["authorization"], "Bearer end-to-end");
    assert_eq!(headers["x-end-to-end"], "kept");
    assert_eq!(headers["host"], origin.address.to_string());
    assert!(headers.contains_key("via"));
    proxy.shutdown().await.unwrap();
}
#[tokio::test]
async fn malformed_authorities_and_unsupported_transports_never_connect() {
    let policy = PolicyFixture::new("");
    let proxy = start(&policy).await;
    for (target, host, status) in [
        ("http://user:pass@127.0.0.1/", "127.0.0.1", 400),
        ("http://127.0.0.1:0/", "127.0.0.1:0", 400),
        ("http://127.0.0.1:65536/", "127.0.0.1:65536", 400),
        ("http://127.1/", "127.1", 400),
        ("http://exa%6dple.invalid/", "exa%6dple.invalid", 400),
        ("http://example.invalid/", "different.invalid", 400),
        ("http://example.invalid/#fragment", "example.invalid", 400),
        ("http://example.invalid/%GG", "example.invalid", 400),
        ("https://example.invalid/", "example.invalid", 501),
        ("ftp://example.invalid/", "example.invalid", 400),
    ] {
        let request = format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        let bytes = raw(proxy.local_addr(), request.as_bytes()).await;
        assert_eq!(raw_status(&bytes), status, "{target}");
        assert!(bytes.ends_with(b"\r\n\r\n"));
    }
    for request in [
        "GET / HTTP/1.1\r\nConnection: close\r\n\r\n",
        "GET http://example.invalid/ HTTP/1.1\r\nHost: example.invalid\r\nHost: example.invalid\r\nConnection: close\r\n\r\n",
        "CONNECT example.invalid HTTP/1.1\r\nHost: example.invalid:443\r\nConnection: close\r\n\r\n",
        "GET http://example.invalid/ HTTP/1.1\r\nHost: example.invalid\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\n\r\n",
    ] {
        let status = raw_status(&raw(proxy.local_addr(), request.as_bytes()).await);
        assert!(status == 400 || status == 501);
    }
    proxy.shutdown().await.unwrap();
}
#[tokio::test]
async fn request_body_is_streamed_before_the_upload_finishes() {
    let first = Arc::new(Notify::new());
    let signal = first.clone();
    let origin = Fixture::new(move |request| {
        let first = signal.clone();
        async move {
            let mut body = request.into_body();
            let mut part = Vec::new();
            while part.len() < b"first#GET /not-a-request\r\n".len() {
                part.extend_from_slice(&body.frame().await.unwrap().unwrap().into_data().unwrap());
            }
            assert_eq!(&part[..], b"first#GET /not-a-request\r\n");
            first.notify_one();
            let rest = body.collect().await.unwrap().to_bytes();
            let mut all = part.to_vec();
            all.extend_from_slice(&rest);
            Response::new(full(all))
        }
    })
    .await;
    let policy = PolicyFixture::new("");
    let proxy = start(&policy).await;
    let mut stream = TcpStream::connect(proxy.local_addr()).await.unwrap();
    let initial = b"first#GET /not-a-request\r\n";
    let header = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
        origin.url("/upload"),
        origin.address,
        initial.len()
    );
    stream.write_all(header.as_bytes()).await.unwrap();
    stream.write_all(initial).await.unwrap();
    stream.write_all(b"\r\n").await.unwrap();
    bounded(first.notified()).await;
    stream
        .write_all(b"4;extension=yes\r\nlast\r\n0\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    bounded(stream.read_to_end(&mut response)).await.unwrap();
    assert_eq!(raw_status(&response), 200);
    assert!(response.windows(4).any(|part| part == b"last"));
    proxy.shutdown().await.unwrap();
}
struct FrameReceiver(mpsc::Receiver<Frame<Bytes>>);
impl hyper::body::Body for FrameReceiver {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.poll_recv(cx).map(|frame| frame.map(Ok))
    }
}
#[tokio::test]
async fn response_body_is_streamed_before_upstream_completion() {
    let (sender, receiver) = mpsc::channel(1);
    let body = Arc::new(Mutex::new(Some(receiver)));
    let origin = Fixture::new(move |_| {
        let receiver = body.lock().unwrap().take().unwrap();
        async move {
            Response::new(
                FrameReceiver(receiver)
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
        }
    })
    .await;
    let policy = PolicyFixture::new("");
    let proxy = start(&policy).await;
    let mut client = Client::new(proxy.local_addr()).await;
    let target = origin.url("/stream");
    let uri: Uri = target.parse().unwrap();
    let request = Request::builder()
        .uri(uri.clone())
        .header("Host", uri.authority().unwrap().as_str())
        .body(Full::new(Bytes::new()))
        .unwrap();
    let mut response = bounded(client.sender.send_request(request)).await.unwrap();
    sender
        .send(Frame::data(Bytes::from_static(b"first")))
        .await
        .unwrap();
    let part = bounded(response.body_mut().frame())
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(&part[..], b"first");
    sender
        .send(Frame::data(Bytes::from_static(b"second")))
        .await
        .unwrap();
    drop(sender);
    assert_eq!(
        &bounded(response.into_body().collect())
            .await
            .unwrap()
            .to_bytes()[..],
        b"second"
    );
    proxy.shutdown().await.unwrap();
}
#[tokio::test]
async fn ingress_tracks_fixed_chunked_and_trailer_boundaries_between_requests() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let data = seen.clone();
    let origin = Fixture::new(move |request| {
        let seen = data.clone();
        async move {
            let bytes = request.into_body().collect().await.unwrap().to_bytes();
            seen.lock().unwrap().push(bytes.to_vec());
            Response::new(full("ok"))
        }
    })
    .await;
    let policy = PolicyFixture::new("");
    let proxy = start(&policy).await;
    let mut client = TcpStream::connect(proxy.local_addr()).await.unwrap();
    let body = b"GET /x#fragment HTTP/1.1\r\n\r\n\x00\xff";
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\r\n",
        origin.url("/fixed"),
        origin.address,
        body.len()
    );
    client.write_all(request.as_bytes()).await.unwrap();
    client.write_all(body).await.unwrap();
    let head = bounded(read_head(&mut client)).await;
    assert_eq!(raw_status(&head), 200);
    let mut ok = [0; 2];
    client.read_exact(&mut ok).await.unwrap();
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-End: trailer\r\n\r\nGET {}/bad#fragment HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        origin.url("/chunked"),
        origin.address,
        origin.url(""),
        origin.address
    );
    client.write_all(request.as_bytes()).await.unwrap();
    let mut responses = Vec::new();
    bounded(client.read_to_end(&mut responses)).await.unwrap();
    let text = String::from_utf8(responses).unwrap();
    assert!(text.contains("200 OK"));
    assert!(text.contains("400 Bad Request"));
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        [body.to_vec(), b"abc".to_vec()]
    );
    proxy.shutdown().await.unwrap();
}
#[tokio::test]
async fn ambiguous_framing_and_oversized_targets_are_rejected() {
    let policy = PolicyFixture::new("");
    let proxy = start(&policy).await;
    for fields in [
        "Content-Length: 1\r\nContent-Length: 1",
        "Content-Length: 1\r\nTransfer-Encoding: chunked",
    ] {
        let request = format!(
            "POST http://example.invalid/ HTTP/1.1\r\nHost: example.invalid\r\n{fields}\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(
            raw_status(&raw(proxy.local_addr(), request.as_bytes()).await),
            400
        );
    }
    let request = format!(
        "GET http://example.invalid/{} HTTP/1.1\r\nHost: example.invalid\r\nConnection: close\r\n\r\n",
        "a".repeat(9000)
    );
    assert_eq!(
        raw_status(&raw(proxy.local_addr(), request.as_bytes()).await),
        414
    );
    proxy.shutdown().await.unwrap();
}
#[tokio::test]
async fn refused_malformed_and_silent_upstreams_have_empty_error_responses() {
    let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = unavailable.local_addr().unwrap();
    drop(unavailable);
    let policy = PolicyFixture::new("");
    let proxy = start(&policy).await;
    let mut client = Client::new(proxy.local_addr()).await;
    let (status, _, body) = client.send(&format!("http://{address}/")).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(body.is_empty());
    proxy.shutdown().await.unwrap();
    for silent in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let entered = Arc::new(Notify::new());
        let signal = entered.clone();
        let job = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = read_head(&mut stream).await;
            signal.notify_one();
            if silent {
                std::future::pending::<()>().await;
            } else {
                stream
                    .write_all(b"not an HTTP response\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        let options = HttpOptions {
            upstream_header_timeout: Duration::from_millis(100),
            ..HttpOptions::default()
        };
        let proxy = HttpService::start(
            HttpConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
            },
            policy.reader.clone(),
            options,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let mut client = Client::new(proxy.local_addr()).await;
        let (status, _, body) = client.send(&format!("http://{address}/")).await;
        assert_eq!(
            status,
            if silent {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::BAD_GATEWAY
            }
        );
        assert!(body.is_empty());
        bounded(entered.notified()).await;
        proxy.shutdown().await.unwrap();
        job.abort();
    }
}
#[tokio::test]
async fn readiness_and_cancellation_close_client_and_upstream_connections() {
    let entered = Arc::new(Notify::new());
    let signal = entered.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let closed = Arc::new(Notify::new());
    let close_signal = closed.clone();
    let job = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_head(&mut stream).await;
        signal.notify_one();
        assert!(stream.read_u8().await.is_err());
        close_signal.notify_one();
    });
    let policy = PolicyFixture::new("");
    let proxy = start(&policy).await;
    let proxy_address = proxy.local_addr();
    let monitor = proxy.monitor();
    assert!(matches!(monitor.current(), ServiceStatus::Ready(_)));
    let mut client = TcpStream::connect(proxy_address).await.unwrap();
    client
        .write_all(format!("GET http://{address}/ HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    bounded(entered.notified()).await;
    bounded(proxy.shutdown()).await.unwrap();
    bounded(closed.notified()).await;
    assert_eq!(monitor.current(), ServiceStatus::Stopped);
    assert!(TcpListener::bind(proxy_address).await.is_ok());
    job.await.unwrap();
}

#[tokio::test]
async fn invalid_connection_tokens_are_rejected_before_upstream_contact() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let policy = PolicyFixture::new("");
    let proxy = start(&policy).await;
    let request = format!(
        "GET http://{address}/ HTTP/1.1\r\nHost: {address}\r\nConnection: close, invalid token\r\n\r\n"
    );
    assert_eq!(
        raw_status(&raw(proxy.local_addr(), request.as_bytes()).await),
        400
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    proxy.shutdown().await.unwrap();
}

#[test]
fn reusable_validation_uses_the_trusted_transport_scheme() {
    use nullgate_core::HttpScheme;
    use nullgate_http::policy::{Decision, ValidatedTarget, evaluate};
    let policy = PolicyFixture::new("https://example.invalid/ads");
    let mut headers = hyper::HeaderMap::new();
    headers.insert("host", "EXAMPLE.invalid:443".parse().unwrap());
    let target = ValidatedTarget::parse(
        "/ads?q=ignored",
        &headers,
        hyper::Version::HTTP_11,
        HttpScheme::Https,
    )
    .unwrap();
    assert_eq!(
        evaluate(&policy.reader.current().unwrap(), target.normalized()),
        Decision::Blocked
    );
    assert_eq!(target.origin_uri(), "/ads?q=ignored");
    assert_eq!(target.authority(), "example.invalid:443");
    assert!(
        ValidatedTarget::parse(
            "http://example.invalid/ads",
            &headers,
            hyper::Version::HTTP_11,
            HttpScheme::Https
        )
        .is_err()
    );
    headers.insert("host", "[::1]:8080".parse().unwrap());
    assert_eq!(
        ValidatedTarget::parse("/", &headers, hyper::Version::HTTP_11, HttpScheme::Http)
            .unwrap()
            .authority(),
        "[::1]:8080"
    );
}

#[tokio::test]
async fn method_status_headers_and_redirects_are_preserved() {
    let origin = Fixture::new(|request| async move {
        assert!(request.method() == hyper::Method::HEAD || request.method() == hyper::Method::GET);
        Response::builder()
            .status(307)
            .header("location", "http://redirect.invalid/")
            .header("content-length", "7")
            .body(full("payload"))
            .unwrap()
    })
    .await;
    let policy = PolicyFixture::new("");
    let proxy = start(&policy).await;
    for method in ["HEAD", "GET"] {
        let request = format!(
            "{method} {} HTTP/1.0\r\nConnection: close\r\n\r\n",
            origin.url("/redirect")
        );
        let response = raw(proxy.local_addr(), request.as_bytes()).await;
        assert_eq!(raw_status(&response), 307);
        let text = String::from_utf8(response).unwrap();
        assert!(text.contains("http://redirect.invalid/"));
        assert_eq!(text.ends_with("payload"), method == "GET");
    }
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nVia: 1.1 nullgate\r\nConnection: close\r\n\r\n",
        origin.url("/"),
        origin.address
    );
    assert_eq!(
        raw_status(&raw(proxy.local_addr(), request.as_bytes()).await),
        508
    );
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn startup_rejects_invalid_limits_and_occupied_listeners() {
    let policy = PolicyFixture::new("");
    let config = HttpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
    };
    let options = HttpOptions {
        max_requests: 0,
        ..HttpOptions::default()
    };
    assert!(
        HttpService::start(
            config.clone(),
            policy.reader.clone(),
            options,
            CancellationToken::new()
        )
        .await
        .is_err()
    );
    let token = CancellationToken::new();
    token.cancel();
    assert!(
        HttpService::start(config, policy.reader.clone(), HttpOptions::default(), token)
            .await
            .is_err()
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    assert!(
        HttpService::start(
            HttpConfig {
                listen: listener.local_addr().unwrap()
            },
            policy.reader.clone(),
            HttpOptions::default(),
            CancellationToken::new()
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn declared_end_to_end_trailers_survive_both_directions() {
    let seen = Arc::new(Mutex::new(None));
    let captured = seen.clone();
    let origin = Fixture::new(move |request| {
        let captured = captured.clone();
        async move {
            let collected = request.into_body().collect().await.unwrap();
            *captured.lock().unwrap() = collected.trailers().cloned();
            let mut trailers = hyper::HeaderMap::new();
            trailers.insert("x-result", "retained".parse().unwrap());
            trailers.insert("x-private", "removed".parse().unwrap());
            trailers.insert("proxy-authorization", "secret".parse().unwrap());
            let body = Full::new(Bytes::from_static(b"ok"))
                .with_trailers(async move { Some(Ok::<_, Infallible>(trailers)) })
                .map_err(|never| match never {})
                .boxed_unsync();
            Response::builder()
                .header("connection", "x-private")
                .header("transfer-encoding", "chunked")
                .header("trailer", "x-result, x-private, proxy-authorization")
                .body(body)
                .unwrap()
        }
    })
    .await;
    let policy = PolicyFixture::new("");
    let proxy = start(&policy).await;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close, x-private\r\nTE: trailers\r\nTransfer-Encoding: chunked\r\nTrailer: x-check, x-private, proxy-authorization\r\n\r\n3\r\nabc\r\n0\r\nX-Check: retained\r\nX-Private: removed\r\nProxy-Authorization: secret\r\n\r\n",
        origin.url("/trailers"),
        origin.address
    );
    let response = raw(proxy.local_addr(), request.as_bytes()).await;
    assert_eq!(raw_status(&response), 200);
    let trailers = seen.lock().unwrap().clone().expect("request trailers");
    assert_eq!(trailers["x-check"], "retained");
    assert!(!trailers.contains_key("x-private"));
    assert!(!trailers.contains_key("proxy-authorization"));
    let text = String::from_utf8(response).unwrap().to_ascii_lowercase();
    assert!(text.contains("x-result: retained"), "{text}");
    assert!(!text.contains("x-private"));
    assert!(!text.contains("secret"));
    proxy.shutdown().await.unwrap();
}

#[tokio::test]
async fn truncated_upstream_body_is_reported_as_a_stream_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let job = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_head(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort")
            .await
            .unwrap();
    });
    let policy = PolicyFixture::new("");
    let proxy = start(&policy).await;
    let mut client = Client::new(proxy.local_addr()).await;
    let request = Request::builder()
        .uri(format!("http://{address}/"))
        .header("host", address.to_string())
        .body(Full::new(Bytes::new()))
        .unwrap();
    // Hyper may notice the broken body before flushing response headers, in which
    // case closing the connection is also correct; it must never report success.
    if let Ok(response) = bounded(client.sender.send_request(request)).await {
        assert!(bounded(response.into_body().collect()).await.is_err());
    }
    bounded(job).await.unwrap();
    proxy.shutdown().await.unwrap();
}
