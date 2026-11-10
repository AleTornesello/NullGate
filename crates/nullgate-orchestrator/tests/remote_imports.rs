use nullgate_core::{
    FetchFailure, Mutation, PolicyError, PolicyFuture, PolicyManagement, RemoteManagement,
    RemoteOutcome, SourceKind, normalize_host,
};
use nullgate_orchestrator::imports::{
    FetchOptions, FetchPolicy, PublicFetchPolicy, RemoteFetcher, RemoteService,
};
use nullgate_orchestrator::{PolicyCoordinator, PolicyOptions};
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
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Notify,
};
use tokio_util::sync::CancellationToken;
#[derive(Clone)]
struct Plan {
    status: u16,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
    stall: bool,
    truncated: bool,
    gate: Option<Arc<Notify>>,
}
impl Plan {
    fn text(text: &str) -> Self {
        Self {
            status: 200,
            body: text.as_bytes().to_vec(),
            headers: vec![],
            stall: false,
            truncated: false,
            gate: None,
        }
    }
}
struct Fixture {
    address: SocketAddr,
    plan: Arc<Mutex<Plan>>,
    requests: Arc<AtomicUsize>,
    entered: Arc<Notify>,
    job: tokio::task::JoinHandle<()>,
    cancel: CancellationToken,
}
impl Fixture {
    async fn new(text: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let plan = Arc::new(Mutex::new(Plan::text(text)));
        let state = plan.clone();
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        let entered = Arc::new(Notify::new());
        let signal = entered.clone();
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let job = tokio::spawn(async move {
            let mut clients = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    Some(_) = clients.join_next(), if !clients.is_empty() => {},
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        clients.spawn(serve_fixture(stream,state.clone(),count.clone(),signal.clone()));
                    }
                }
            }
            clients.shutdown().await;
        });
        Self {
            address,
            plan,
            requests,
            entered,
            job,
            cancel,
        }
    }
    fn url(&self, path: &str) -> String {
        format!("http://fixture.invalid:{}{path}", self.address.port())
    }
}
async fn serve_fixture(
    mut stream: tokio::net::TcpStream,
    state: Arc<Mutex<Plan>>,
    count: Arc<AtomicUsize>,
    signal: Arc<Notify>,
) {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read_u8().await {
            Ok(byte) => head.push(byte),
            Err(_) => return,
        }
        if head.len() > 16384 {
            return;
        }
    }
    let text = String::from_utf8_lossy(&head).to_ascii_lowercase();
    assert!(!text.contains("authorization:"));
    assert!(!text.contains("cookie:"));
    assert!(text.contains("accept-encoding: identity"));
    count.fetch_add(1, Ordering::SeqCst);
    let plan = state.lock().unwrap().clone();
    signal.notify_one();
    if let Some(gate) = plan.gate {
        gate.notified().await;
    }
    if plan.stall {
        std::future::pending::<()>().await;
    }
    let mut header = format!(
        "HTTP/1.1 {} OK\r\nContent-Length: {}\r\nConnection: close\r\n",
        plan.status,
        plan.body.len() + if plan.truncated { 10 } else { 0 }
    );
    for (name, value) in plan.headers {
        header.push_str(&format!("{name}: {value}\r\n"));
    }
    header.push_str("\r\n");
    let _ = stream.write_all(header.as_bytes()).await;
    let _ = stream.write_all(&plan.body).await;
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.job.abort();
    }
}
struct LocalPolicy {
    addresses: Vec<SocketAddr>,
    answers: Mutex<Option<Vec<SocketAddr>>>,
    resolves: AtomicUsize,
    roots: Vec<Vec<u8>>,
}
impl LocalPolicy {
    fn new(addresses: Vec<SocketAddr>) -> Self {
        Self {
            addresses,
            answers: Mutex::new(None),
            resolves: AtomicUsize::new(0),
            roots: vec![],
        }
    }
}
impl FetchPolicy for LocalPolicy {
    fn resolve(
        &self,
        _host: nullgate_core::NormalizedHost,
        port: u16,
    ) -> PolicyFuture<'_, Result<Vec<SocketAddr>, FetchFailure>> {
        self.resolves.fetch_add(1, Ordering::SeqCst);
        let addresses = self.answers.lock().unwrap().clone().unwrap_or_else(|| {
            self.addresses
                .iter()
                .filter(|address| address.port() == port)
                .copied()
                .collect()
        });
        Box::pin(async move { Ok(addresses) })
    }
    fn permits(&self, address: SocketAddr) -> bool {
        self.addresses.contains(&address)
    }
    fn extra_roots(&self) -> Vec<Vec<u8>> {
        self.roots.clone()
    }
}
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("nullgate-remote-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
async fn setup(
    fixture: &Fixture,
    options: FetchOptions,
) -> (
    Scratch,
    PolicyCoordinator,
    RemoteService,
    Arc<LocalPolicy>,
    i64,
) {
    let scratch = Scratch::new();
    let coordinator =
        PolicyCoordinator::open(scratch.0.join("state.sqlite3"), PolicyOptions::default())
            .await
            .unwrap();
    coordinator
        .handle()
        .save(
            0,
            Mutation::CreateList {
                name: "Remote".into(),
            },
        )
        .await
        .unwrap();
    let list = coordinator.reader().current().unwrap().repository().lists[0].id;
    coordinator
        .handle()
        .save(
            1,
            Mutation::ImportList {
                list_id: list,
                kind: SourceKind::Manual,
                text: "manual.invalid\nshared.invalid".into(),
                at: 0,
            },
        )
        .await
        .unwrap();
    let policy = Arc::new(LocalPolicy::new(vec![fixture.address]));
    let fetcher = RemoteFetcher::new(policy.clone(), options).unwrap();
    let service = RemoteService::new(Arc::new(coordinator.handle()), fetcher);
    (scratch, coordinator, service, policy, list)
}
fn remote_id(coordinator: &PolicyCoordinator) -> i64 {
    coordinator.reader().current().unwrap().repository().lists[0]
        .sources
        .iter()
        .find(|source| matches!(source.kind, SourceKind::Remote { .. }))
        .unwrap()
        .id
}
#[tokio::test]
async fn partial_invalid_refresh_replaces_only_its_source_and_publishes() {
    let fixture =
        Fixture::new("old.invalid\nshared.invalid\nhttp://site.invalid/ads\nbad rule").await;
    let (_scratch, coordinator, service, policy, list) =
        setup(&fixture, FetchOptions::default()).await;
    let reader = coordinator.reader();
    let result = service
        .import_url(2, list, fixture.url("/rules?version=1"))
        .await
        .unwrap();
    assert_eq!(result.outcome, RemoteOutcome::Applied);
    assert_eq!(result.saved.snapshot.revision(), 3);
    assert_eq!(result.saved.import_report.unwrap().malformed[0].line, 4);
    assert!(
        reader
            .current()
            .unwrap()
            .rules()
            .blocks_domain(&normalize_host("old.invalid").unwrap())
    );
    assert!(
        !reader
            .current()
            .unwrap()
            .rules()
            .blocks_domain(&normalize_host("site.invalid").unwrap())
    );
    let id = remote_id(&coordinator);
    *fixture.plan.lock().unwrap() =
        Plan::text("new.invalid\nshared.invalid\nnew.invalid\nbad rule");
    let result = service.refresh(3, id).await.unwrap();
    assert_eq!(result.outcome, RemoteOutcome::Applied);
    assert_eq!(result.saved.import_report.unwrap().duplicates.len(), 1);
    let snapshot = reader.current().unwrap();
    assert!(
        snapshot
            .rules()
            .blocks_domain(&normalize_host("manual.invalid").unwrap())
    );
    assert!(
        snapshot
            .rules()
            .blocks_domain(&normalize_host("new.invalid").unwrap())
    );
    assert!(
        !snapshot
            .rules()
            .blocks_domain(&normalize_host("old.invalid").unwrap())
    );
    assert_eq!(snapshot.repository().source(id).unwrap().entries.len(), 2);
    assert_eq!(policy.resolves.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 2);
    coordinator.shutdown().await.unwrap();
}
#[tokio::test]
async fn empty_invalid_and_failed_responses_preserve_previous_rules() {
    let fixture = Fixture::new("old.invalid").await;
    let (_scratch, coordinator, service, _policy, list) = setup(
        &fixture,
        FetchOptions {
            max_bytes: 64,
            timeout: Duration::from_millis(150),
            ..FetchOptions::default()
        },
    )
    .await;
    service
        .import_url(2, list, fixture.url("/rules"))
        .await
        .unwrap();
    let id = remote_id(&coordinator);
    let original = coordinator
        .reader()
        .current()
        .unwrap()
        .repository()
        .source(id)
        .unwrap()
        .entries
        .clone();
    for body in ["", "# comment\n", "not a valid rule"] {
        *fixture.plan.lock().unwrap() = Plan::text(body);
        let revision = coordinator.reader().current().unwrap().revision();
        let result = service.refresh(revision, id).await.unwrap();
        assert_eq!(result.outcome, RemoteOutcome::NoValidRules);
        assert_eq!(
            result
                .saved
                .snapshot
                .repository()
                .source(id)
                .unwrap()
                .entries,
            original
        );
    }
    for expected in [
        FetchFailure::HttpStatus,
        FetchFailure::InvalidUtf8,
        FetchFailure::Encoding,
        FetchFailure::TooLarge,
        FetchFailure::Network,
        FetchFailure::Timeout,
    ] {
        let mut plan = Plan::text("new.invalid");
        match expected {
            FetchFailure::HttpStatus => plan.status = 500,
            FetchFailure::InvalidUtf8 => plan.body = vec![255],
            FetchFailure::Encoding => plan
                .headers
                .push(("Content-Encoding".into(), "gzip".into())),
            FetchFailure::TooLarge => plan.body = vec![b'x'; 65],
            FetchFailure::Network => plan.truncated = true,
            FetchFailure::Timeout => plan.stall = true,
            _ => unreachable!(),
        };
        *fixture.plan.lock().unwrap() = plan;
        let revision = coordinator.reader().current().unwrap().revision();
        let result = service.refresh(revision, id).await.unwrap();
        assert_eq!(result.outcome, RemoteOutcome::FetchFailed(expected));
        assert_eq!(
            result
                .saved
                .snapshot
                .repository()
                .source(id)
                .unwrap()
                .entries,
            original
        );
        assert!(
            result
                .saved
                .snapshot
                .rules()
                .blocks_domain(&normalize_host("manual.invalid").unwrap())
        );
    }
    coordinator.shutdown().await.unwrap();
}
#[tokio::test]
async fn redirects_revalidate_destinations_and_limit_loops() {
    let fixture = Fixture::new("old.invalid").await;
    let (_scratch, coordinator, service, _policy, list) =
        setup(&fixture, FetchOptions::default()).await;
    service
        .import_url(2, list, fixture.url("/rules"))
        .await
        .unwrap();
    let id = remote_id(&coordinator);
    let other = Fixture::new("must.not.fetch").await;
    let mut plan = Plan::text("");
    plan.status = 302;
    plan.headers
        .push(("Location".into(), other.url("/internal")));
    *fixture.plan.lock().unwrap() = plan;
    let result = service.refresh(3, id).await.unwrap();
    assert_eq!(
        result.outcome,
        RemoteOutcome::FetchFailed(FetchFailure::DestinationDenied)
    );
    assert_eq!(other.requests.load(Ordering::SeqCst), 0);
    fixture.plan.lock().unwrap().headers = vec![("Location".into(), "/loop".into())];
    let result = service.refresh(4, id).await.unwrap();
    assert_eq!(
        result.outcome,
        RemoteOutcome::FetchFailed(FetchFailure::RedirectLimit)
    );
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 6);
    coordinator.shutdown().await.unwrap();
}
#[tokio::test]
async fn checked_dns_answers_are_pinned_and_mixed_private_answers_are_denied() {
    let fixture = Fixture::new("pinned.invalid").await;
    let (_scratch, coordinator, service, policy, list) =
        setup(&fixture, FetchOptions::default()).await;
    service
        .import_url(2, list, fixture.url("/pinned"))
        .await
        .unwrap();
    assert_eq!(policy.resolves.load(Ordering::SeqCst), 1);
    *policy.answers.lock().unwrap() = Some(vec![
        fixture.address,
        SocketAddr::new("10.0.0.1".parse().unwrap(), fixture.address.port()),
    ]);
    let result = service.refresh(3, remote_id(&coordinator)).await.unwrap();
    assert_eq!(
        result.outcome,
        RemoteOutcome::FetchFailed(FetchFailure::DestinationDenied)
    );
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 1);
    coordinator.shutdown().await.unwrap();
}
#[tokio::test]
async fn delayed_refresh_conflicts_instead_of_overwriting_concurrent_edits() {
    let fixture = Fixture::new("old.invalid").await;
    let (_scratch, coordinator, service, _policy, list) =
        setup(&fixture, FetchOptions::default()).await;
    service
        .import_url(2, list, fixture.url("/rules"))
        .await
        .unwrap();
    let id = remote_id(&coordinator);
    let gate = Arc::new(Notify::new());
    let mut plan = Plan::text("stale.invalid");
    plan.gate = Some(gate.clone());
    *fixture.plan.lock().unwrap() = plan;
    let service = Arc::new(service);
    let refresh = tokio::spawn(async move { service.refresh(3, id).await });
    fixture.entered.notified().await;
    while fixture.requests.load(Ordering::SeqCst) < 2 {
        tokio::task::yield_now().await;
    }
    coordinator
        .handle()
        .save(
            3,
            Mutation::ImportList {
                list_id: list,
                kind: SourceKind::Manual,
                text: "concurrent.invalid".into(),
                at: 1,
            },
        )
        .await
        .unwrap();
    gate.notify_one();
    assert!(matches!(
        refresh.await.unwrap(),
        Err(nullgate_core::RemoteError::Policy(PolicyError::Storage(
            nullgate_core::StorageError::Conflict { .. }
        )))
    ));
    let current = coordinator.reader().current().unwrap();
    assert_eq!(current.revision(), 4);
    assert!(
        current
            .rules()
            .blocks_domain(&normalize_host("old.invalid").unwrap())
    );
    assert!(
        !current
            .rules()
            .blocks_domain(&normalize_host("stale.invalid").unwrap())
    );
    coordinator.shutdown().await.unwrap();
}
#[test]
fn production_policy_rejects_internal_reserved_and_transition_addresses() {
    let policy = PublicFetchPolicy;
    for address in [
        "127.0.0.1:80",
        "10.0.0.1:443",
        "172.16.0.1:80",
        "192.168.1.1:80",
        "169.254.169.254:80",
        "100.64.0.1:80",
        "0.0.0.0:80",
        "192.0.2.1:80",
        "198.18.0.1:80",
        "198.51.100.1:80",
        "203.0.113.1:80",
        "224.0.0.1:80",
        "240.0.0.1:80",
        "[::1]:80",
        "[fc00::1]:80",
        "[fe80::1]:80",
        "[::ffff:127.0.0.1]:80",
        "[2001:db8::1]:80",
        "[2002:a00:1::1]:80",
    ] {
        assert!(!policy.permits(address.parse().unwrap()), "{address}");
    }
    assert!(policy.permits("8.8.8.8:443".parse().unwrap()));
    assert!(policy.permits("[2001:4860:4860::8888]:443".parse().unwrap()));
}

#[tokio::test]
async fn remote_refresh_updates_a_running_http_proxy_and_survives_reopen() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_address = origin.local_addr().unwrap();
    let origin_job = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .await
            .unwrap();
    });
    let fixture = Fixture::new(&format!(
        "https://inspect.invalid/ads\nhttp://{origin_address}/ads"
    ))
    .await;
    let (scratch, coordinator, service, _policy, list) =
        setup(&fixture, FetchOptions::default()).await;
    let proxy = nullgate_http::HttpService::start(
        nullgate_core::HttpConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
        },
        coordinator.reader(),
        nullgate_http::HttpOptions::default(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    service
        .import_url(2, list, fixture.url("/rules"))
        .await
        .unwrap();
    async fn request(address: SocketAddr, origin: SocketAddr) -> String {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.write_all(format!("GET http://{origin}/ads?ignored=1 HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        String::from_utf8(bytes).unwrap()
    }
    assert!(
        request(proxy.local_addr(), origin_address)
            .await
            .starts_with("HTTP/1.1 403")
    );
    assert!(
        coordinator
            .reader()
            .current()
            .unwrap()
            .rules()
            .requires_inspection(&normalize_host("inspect.invalid").unwrap())
    );
    let id = remote_id(&coordinator);
    *fixture.plan.lock().unwrap() = Plan::text("different.invalid");
    service.refresh(3, id).await.unwrap();
    assert!(
        request(proxy.local_addr(), origin_address)
            .await
            .starts_with("HTTP/1.1 200")
    );
    origin_job.await.unwrap();
    assert!(
        !coordinator
            .reader()
            .current()
            .unwrap()
            .rules()
            .requires_inspection(&normalize_host("inspect.invalid").unwrap())
    );
    proxy.shutdown().await.unwrap();
    coordinator.shutdown().await.unwrap();
    let mut reopened =
        nullgate_core::SqliteRepository::open(scratch.0.join("state.sqlite3")).unwrap();
    use nullgate_core::BlocklistRepository;
    let snapshot = reopened.snapshot().unwrap();
    assert_eq!(snapshot.revision, 4);
    assert_eq!(snapshot.source(id).unwrap().entries.len(), 1);
    assert!(snapshot.source(id).unwrap().last_success.is_some());
}

#[tokio::test]
async fn refresh_keeps_existing_source_identity_when_locator_normalizes() {
    let fixture = Fixture::new("updated.invalid").await;
    let (_scratch, coordinator, service, _policy, list) =
        setup(&fixture, FetchOptions::default()).await;
    let raw = fixture.url("");
    coordinator
        .handle()
        .save(
            2,
            Mutation::AddSource {
                list_id: list,
                kind: SourceKind::Remote { url: raw.clone() },
            },
        )
        .await
        .unwrap();
    let id = remote_id(&coordinator);
    service.refresh(3, id).await.unwrap();
    let snapshot = coordinator.reader().current().unwrap();
    assert_eq!(snapshot.repository().lists[0].sources.len(), 2);
    assert_eq!(snapshot.repository().source(id).unwrap().entries.len(), 1);
    coordinator.shutdown().await.unwrap();
}

#[tokio::test]
async fn https_verifies_certificates_and_refuses_downgrade_redirects() {
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use std::sync::atomic::AtomicBool;
    let plain = Fixture::new("never.invalid").await;
    let cert = rcgen::generate_simple_self_signed(vec!["fixture.invalid".into()]).unwrap();
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let downgrade = Arc::new(AtomicBool::new(false));
    let redirect = downgrade.clone();
    let location = plain.url("/private");
    let job = tokio::spawn(async move {
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let Ok(mut stream) = acceptor.accept(stream).await else {
                continue;
            };
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
            }
            let response = if redirect.load(Ordering::SeqCst) {
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nsecure.invalid"
                    .into()
            };
            stream.write_all(response.as_bytes()).await.unwrap();
            let _ = stream.shutdown().await;
        }
    });
    let (_scratch, coordinator, _service, _policy, list) =
        setup(&plain, FetchOptions::default()).await;
    let mut policy = LocalPolicy::new(vec![address, plain.address]);
    policy.roots.push(cert.cert.der().to_vec());
    let service = RemoteService::new(
        Arc::new(coordinator.handle()),
        RemoteFetcher::new(Arc::new(policy), FetchOptions::default()).unwrap(),
    );
    let url = format!("https://fixture.invalid:{}/rules", address.port());
    assert_eq!(
        service.import_url(2, list, url).await.unwrap().outcome,
        RemoteOutcome::Applied
    );
    let id = remote_id(&coordinator);
    downgrade.store(true, Ordering::SeqCst);
    assert_eq!(
        service.refresh(3, id).await.unwrap().outcome,
        RemoteOutcome::FetchFailed(FetchFailure::Downgrade)
    );
    assert_eq!(plain.requests.load(Ordering::SeqCst), 0);
    let untrusted = RemoteService::new(
        Arc::new(coordinator.handle()),
        RemoteFetcher::new(
            Arc::new(LocalPolicy::new(vec![address])),
            FetchOptions::default(),
        )
        .unwrap(),
    );
    assert_eq!(
        untrusted.refresh(4, id).await.unwrap().outcome,
        RemoteOutcome::FetchFailed(FetchFailure::Network)
    );
    job.abort();
    coordinator.shutdown().await.unwrap();
}

#[tokio::test]
async fn invalid_locators_and_stale_revisions_do_not_fetch_or_create_provenance() {
    let fixture = Fixture::new("valid.invalid").await;
    let (_scratch, coordinator, service, _policy, list) =
        setup(&fixture, FetchOptions::default()).await;
    for url in [
        "file:///etc/passwd",
        "http://user:secret@example.com/rules",
        "http://127.1/rules",
        "https://example.com/rules#fragment",
        "http://example.com:0/",
    ] {
        assert!(matches!(
            service.import_url(2, list, url.into()).await,
            Err(nullgate_core::RemoteError::InvalidUrl)
        ));
    }
    assert!(matches!(
        service.import_url(1, list, fixture.url("/rules")).await,
        Err(nullgate_core::RemoteError::Policy(PolicyError::Storage(
            nullgate_core::StorageError::Conflict { .. }
        )))
    ));
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 0);
    assert_eq!(coordinator.reader().current().unwrap().revision(), 2);
    coordinator.shutdown().await.unwrap();
}

#[tokio::test]
async fn failed_persistence_preserves_the_live_and_durable_remote_source() {
    let fixture = Fixture::new("old.invalid").await;
    let (scratch, coordinator, service, _policy, list) =
        setup(&fixture, FetchOptions::default()).await;
    service
        .import_url(2, list, fixture.url("/rules"))
        .await
        .unwrap();
    let id = remote_id(&coordinator);
    let before = coordinator.reader().current().unwrap().repository().clone();
    let lock = rusqlite::Connection::open(scratch.0.join("state.sqlite3")).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    *fixture.plan.lock().unwrap() = Plan::text("must.not.replace");
    assert!(matches!(
        service.refresh(3, id).await,
        Err(nullgate_core::RemoteError::Policy(PolicyError::Storage(
            nullgate_core::StorageError::Busy
        )))
    ));
    assert_eq!(
        coordinator.reader().current().unwrap().repository(),
        &before
    );
    lock.execute_batch("ROLLBACK").unwrap();
    coordinator.shutdown().await.unwrap();
    use nullgate_core::BlocklistRepository;
    let mut reopened =
        nullgate_core::SqliteRepository::open(scratch.0.join("state.sqlite3")).unwrap();
    assert_eq!(reopened.snapshot().unwrap(), before);
}
