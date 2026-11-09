use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        DNSClass, Name, RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use nullgate_core::{
    BlocklistRepository, DnsConfig, FailureStage, Mutation, PolicyPublisher, PolicySnapshot,
    PolicySubscription, ServiceStatus, ServiceTransport, SourceKind, SqliteRepository,
    UnavailableReason, policy_channel,
};
use nullgate_dns::{DnsOptions, DnsService};
use std::{
    net::{Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("local operation timed out")
}
fn query(name: &str, kind: RecordType) -> Message {
    let mut message = Message::query();
    message.metadata.id = 1234;
    message.metadata.recursion_desired = true;
    message
        .queries
        .push(Query::query(Name::from_utf8(name).unwrap(), kind));
    message
}
async fn write_frame(stream: &mut TcpStream, bytes: &[u8]) {
    stream.write_u16(bytes.len() as u16).await.unwrap();
    stream.write_all(bytes).await.unwrap();
}
async fn read_frame(stream: &mut TcpStream) -> Vec<u8> {
    let size = stream.read_u16().await.unwrap();
    let mut bytes = vec![0; size as usize];
    stream.read_exact(&mut bytes).await.unwrap();
    bytes
}
async fn udp_bytes(address: SocketAddr, bytes: &[u8]) -> Vec<u8> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(address).await.unwrap();
    socket.send(bytes).await.unwrap();
    let mut response = vec![0; 65535];
    let size = bounded(socket.recv(&mut response)).await.unwrap();
    response.truncate(size);
    response
}
async fn udp(address: SocketAddr, message: &Message) -> Message {
    Message::from_vec(&udp_bytes(address, &message.to_vec().unwrap()).await).unwrap()
}
async fn tcp(address: SocketAddr, message: &Message) -> Message {
    let mut stream = TcpStream::connect(address).await.unwrap();
    write_frame(&mut stream, &message.to_vec().unwrap()).await;
    Message::from_vec(&bounded(read_frame(&mut stream)).await).unwrap()
}

struct PolicyFixture {
    repo: SqliteRepository,
    publisher: PolicyPublisher,
    reader: PolicySubscription,
    source: i64,
    revision: u64,
    directory: PathBuf,
}
impl PolicyFixture {
    fn new(text: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "nullgate-dns-{}-{stamp}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let mut repo = SqliteRepository::open(directory.join("state.sqlite3")).unwrap();
        repo.apply(0, Mutation::CreateList { name: "DNS".into() })
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
            directory,
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
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
#[derive(Clone, Copy)]
enum Mode {
    Normal,
    Silent,
    WrongThenGood,
    Truncated,
    Large,
}
struct Fixture {
    address: SocketAddr,
    seen: Arc<Mutex<Vec<(ServiceTransport, Message)>>>,
    cancel: CancellationToken,
    jobs: Vec<JoinHandle<()>>,
    request_seen: Arc<tokio::sync::Notify>,
}
impl Fixture {
    async fn new(mode: Mode) -> Self {
        let (tcp, udp) = loop {
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            match UdpSocket::bind(tcp.local_addr().unwrap()).await {
                Ok(udp) => break (tcp, udp),
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => continue,
                Err(e) => panic!("fixture bind: {e}"),
            }
        };
        let address = tcp.local_addr().unwrap();
        let udp = Arc::new(udp);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let cancel = CancellationToken::new();
        let request_seen = Arc::new(tokio::sync::Notify::new());
        let udp_task = {
            let seen = seen.clone();
            let request_seen = request_seen.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                let mut bytes = vec![0; 65535];
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        received = udp.recv_from(&mut bytes) => {
                            let (size, peer) = received.unwrap();
                            let message = Message::from_vec(&bytes[..size]).unwrap();
                            seen.lock().unwrap().push((ServiceTransport::Udp, message.clone()));
                            request_seen.notify_one();
                            for response in responses(&message, mode, ServiceTransport::Udp) {
                                if matches!(mode, Mode::WrongThenGood) {
                                    let rogue = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                                    let mut wrong = response.clone();
                                    wrong.metadata.response_code = ResponseCode::Refused;
                                    rogue.send_to(&wrong.to_vec().unwrap(), peer).await.unwrap();
                                }
                                udp.send_to(&response.to_vec().unwrap(), peer).await.unwrap();
                            }
                        }
                    }
                }
            })
        };
        let tcp_task = {
            let seen = seen.clone();
            let request_seen = request_seen.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                let mut clients = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        Some(_) = clients.join_next(), if !clients.is_empty() => {},
                        accepted = tcp.accept() => {
                            let (mut stream, _) = accepted.unwrap();
                            let seen = seen.clone();
                            let request_seen = request_seen.clone();
                            let cancel = cancel.clone();
                            clients.spawn(async move {
                                let work = async {
                                    let size = stream.read_u16().await.ok()?;
                                    let mut bytes = vec![0; size as usize];
                                    stream.read_exact(&mut bytes).await.ok()?;
                                    let message = Message::from_vec(&bytes).ok()?;
                                    seen.lock().unwrap().push((ServiceTransport::Tcp, message.clone()));
                                    request_seen.notify_one();
                                    for response in responses(&message, mode, ServiceTransport::Tcp) {
                                        write_frame(&mut stream, &response.to_vec().unwrap()).await;
                                    }
                                    if matches!(mode, Mode::Silent) { std::future::pending::<()>().await; }
                                    Some(())
                                };
                                tokio::select! { _ = cancel.cancelled() => {}, _ = work => {} }
                            });
                        }
                    }
                }
                clients.shutdown().await;
            })
        };
        Self {
            address,
            seen,
            cancel,
            jobs: vec![udp_task, tcp_task],
            request_seen,
        }
    }
    fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.cancel.cancel();
        for job in &self.jobs {
            job.abort();
        }
    }
}
fn responses(query: &Message, mode: Mode, transport: ServiceTransport) -> Vec<Message> {
    if matches!(mode, Mode::Silent) {
        return vec![];
    }
    let mut response = Message::response(query.metadata.id, query.metadata.op_code);
    response.queries = query.queries.clone();
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.authentic_data = true;
    response.metadata.checking_disabled = query.metadata.checking_disabled;
    response.edns = query.edns.clone();
    if matches!(mode, Mode::Truncated) && transport == ServiceTransport::Udp {
        response.metadata.truncation = true;
        return vec![response];
    }
    let count = if matches!(mode, Mode::Large) { 100 } else { 1 };
    for _ in 0..count {
        let q = &query.queries[0];
        let data = match q.query_type() {
            RecordType::A => Some(RData::A(A::new(192, 0, 2, 42))),
            RecordType::AAAA => Some(RData::AAAA(AAAA(Ipv6Addr::LOCALHOST))),
            _ => None,
        };
        if let Some(data) = data {
            response
                .answers
                .push(Record::from_rdata(q.name().clone(), 17, data));
        }
    }
    if matches!(mode, Mode::WrongThenGood) {
        let mut wrong = Vec::new();
        let mut changed = response.clone();
        changed.metadata.id = changed.metadata.id.wrapping_add(1);
        wrong.push(changed);
        let mut changed = response.clone();
        changed.queries[0].set_name(Name::from_ascii("wrong.example.").unwrap());
        wrong.push(changed);
        let mut changed = response.clone();
        changed.queries[0].set_query_type(RecordType::MX);
        wrong.push(changed);
        let mut changed = response.clone();
        changed.queries[0].set_query_class(DNSClass::CH);
        wrong.push(changed);
        let mut changed = response.clone();
        changed.metadata.message_type = MessageType::Query;
        wrong.push(changed);
        let mut changed = response.clone();
        changed.metadata.op_code = OpCode::Status;
        wrong.push(changed);
        wrong.push(response);
        wrong
    } else {
        vec![response]
    }
}
fn config(upstreams: Vec<SocketAddr>) -> DnsConfig {
    DnsConfig {
        udp_listen: "127.0.0.1:0".parse().unwrap(),
        tcp_listen: "127.0.0.1:0".parse().unwrap(),
        upstreams,
        attempt_timeout_ms: 100,
        total_timeout_ms: 400,
    }
}
async fn start(policy: &PolicyFixture, upstreams: Vec<SocketAddr>) -> DnsService {
    DnsService::start(
        config(upstreams),
        policy.reader.clone(),
        DnsOptions::default(),
        CancellationToken::new(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn exact_wildcard_and_url_only_rules_apply_on_udp_and_tcp() {
    let upstream = Fixture::new(Mode::Normal).await;
    let policy = PolicyFixture::new("blocked.example\n*.tracking.example\nhttps://url.example/ads");
    let service = start(&policy, vec![upstream.address]).await;
    assert!(matches!(
        service.monitor().current(),
        ServiceStatus::Ready(_)
    ));
    for (name, blocked) in [
        ("blocked.example.", true),
        ("BLOCKED.EXAMPLE.", true),
        ("a.tracking.example.", true),
        ("a.b.tracking.example.", true),
        ("tracking.example.", false),
        ("nottracking.example.", false),
        ("url.example.", false),
        ("child.blocked.example.", false),
    ] {
        for transport in [ServiceTransport::Udp, ServiceTransport::Tcp] {
            let request = query(name, RecordType::A);
            let response = if transport == ServiceTransport::Udp {
                udp(service.udp_addr(), &request).await
            } else {
                tcp(service.tcp_addr(), &request).await
            };
            assert_eq!(
                response.metadata.response_code,
                if blocked {
                    ResponseCode::NXDomain
                } else {
                    ResponseCode::NoError
                },
                "{name}"
            );
            assert_eq!(response.metadata.id, request.metadata.id);
            assert_eq!(response.queries, request.queries);
        }
    }
    assert_eq!(upstream.count(), 8);
    service.shutdown().await.unwrap();
}
#[tokio::test]
async fn allowed_a_aaaa_preserve_upstream_records_and_relevant_flags() {
    let upstream = Fixture::new(Mode::Normal).await;
    let policy = PolicyFixture::new("");
    let service = start(&policy, vec![upstream.address]).await;
    for kind in [RecordType::A, RecordType::AAAA] {
        for tcp_client in [false, true] {
            let mut request = query("allowed.example.", kind);
            request.metadata.checking_disabled = true;
            let response = if tcp_client {
                tcp(service.tcp_addr(), &request).await
            } else {
                udp(service.udp_addr(), &request).await
            };
            assert_eq!(response.metadata.message_type, MessageType::Response);
            assert!(response.metadata.recursion_desired);
            assert!(response.metadata.recursion_available);
            assert!(response.metadata.checking_disabled);
            assert!(response.metadata.authentic_data);
            assert_eq!(response.answers.len(), 1);
            assert_eq!(response.answers[0].ttl, 17);
            assert_eq!(response.answers[0].record_type(), kind);
        }
    }
    service.shutdown().await.unwrap();
}
#[tokio::test]
async fn synthetic_nxdomain_has_correct_flags_and_edns() {
    let upstream = Fixture::new(Mode::Normal).await;
    let policy = PolicyFixture::new("blocked.example");
    let service = start(&policy, vec![upstream.address]).await;
    let mut request = query("blocked.example.", RecordType::AAAA);
    request.metadata.checking_disabled = true;
    request.metadata.authentic_data = true;
    let mut edns = Edns::new();
    edns.set_dnssec_ok(true).set_max_payload(4096);
    request.edns = Some(edns);
    let response = udp(service.udp_addr(), &request).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    assert!(!response.metadata.authoritative);
    assert!(!response.metadata.authentic_data);
    assert!(!response.metadata.truncation);
    assert!(response.metadata.checking_disabled);
    assert!(response.metadata.recursion_available);
    assert!(response.answers.is_empty());
    assert!(response.authorities.is_empty());
    assert!(response.additionals.is_empty());
    let edns = response.edns.unwrap();
    assert_eq!(edns.version(), 0);
    assert!(edns.flags().dnssec_ok);
    assert!(edns.max_payload() <= 1232);
    assert_eq!(upstream.count(), 0);
    service.shutdown().await.unwrap();
}
#[tokio::test]
async fn malformed_queries_do_not_kill_service_or_reach_upstream() {
    let upstream = Fixture::new(Mode::Normal).await;
    let policy = PolicyFixture::new("");
    let service = start(&policy, vec![upstream.address]).await;
    let good = query("valid.example.", RecordType::A);
    let mut extra = good.to_vec().unwrap();
    extra.push(0);
    let mut broken = good.to_vec().unwrap();
    broken.truncate(14);
    let mut multiple = good.clone();
    multiple.queries.push(good.queries[0].clone());
    let mut empty = good.clone();
    empty.queries.clear();
    for bytes in [
        extra,
        broken,
        multiple.to_vec().unwrap(),
        empty.to_vec().unwrap(),
    ] {
        let response = Message::from_vec(&udp_bytes(service.udp_addr(), &bytes).await).unwrap();
        assert_eq!(response.metadata.id, good.metadata.id);
        assert_eq!(response.metadata.response_code, ResponseCode::FormErr);
    }
    let mut unsupported = good.clone();
    unsupported.metadata.op_code = OpCode::Status;
    assert_eq!(
        udp(service.udp_addr(), &unsupported)
            .await
            .metadata
            .response_code,
        ResponseCode::NotImp
    );
    let mut edns = Edns::new();
    edns.set_version(1);
    let mut version = good.clone();
    version.edns = Some(edns);
    assert_eq!(
        u16::from(
            udp(service.udp_addr(), &version)
                .await
                .metadata
                .response_code
        ),
        16
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(&[1, 2, 3], service.udp_addr())
        .await
        .unwrap();
    let mut response_packet = good.clone();
    response_packet.metadata.message_type = MessageType::Response;
    socket
        .send_to(&response_packet.to_vec().unwrap(), service.udp_addr())
        .await
        .unwrap();
    socket
        .send_to(&good.to_vec().unwrap(), service.udp_addr())
        .await
        .unwrap();
    let mut buffer = vec![0; 65535];
    let (size, _) = bounded(socket.recv_from(&mut buffer)).await.unwrap();
    assert_eq!(
        Message::from_vec(&buffer[..size])
            .unwrap()
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    assert_eq!(upstream.count(), 1);
    service.shutdown().await.unwrap();
}
#[tokio::test]
async fn response_id_question_opcode_and_peer_are_all_associated() {
    let upstream = Fixture::new(Mode::WrongThenGood).await;
    let policy = PolicyFixture::new("");
    let service = start(&policy, vec![upstream.address]).await;
    for use_tcp in [false, true] {
        let request = query("association.example.", RecordType::A);
        let response = if use_tcp {
            tcp(service.tcp_addr(), &request).await
        } else {
            udp(service.udp_addr(), &request).await
        };
        assert_eq!(response.metadata.id, 1234);
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.queries, request.queries);
        assert_eq!(response.answers.len(), 1);
    }
    service.shutdown().await.unwrap();
}
#[tokio::test]
async fn simultaneous_clients_with_the_same_id_do_not_cross_answers() {
    let upstream = Fixture::new(Mode::Normal).await;
    let policy = PolicyFixture::new("");
    let service = start(&policy, vec![upstream.address]).await;
    let mut jobs = tokio::task::JoinSet::new();
    for i in 0..24 {
        let address = service.udp_addr();
        jobs.spawn(async move {
            let request = query(&format!("c{i}.example."), RecordType::A);
            let response = udp(address, &request).await;
            assert_eq!(response.queries, request.queries);
            assert_eq!(response.metadata.id, 1234);
        });
    }
    while let Some(result) = jobs.join_next().await {
        result.unwrap();
    }
    assert_eq!(upstream.count(), 24);
    service.shutdown().await.unwrap();
}
#[tokio::test]
async fn truncated_udp_retries_tcp_and_large_udp_is_validly_truncated() {
    let upstream = Fixture::new(Mode::Truncated).await;
    let policy = PolicyFixture::new("");
    let service = start(&policy, vec![upstream.address]).await;
    assert_eq!(
        udp(
            service.udp_addr(),
            &query("fallback.example.", RecordType::A)
        )
        .await
        .answers
        .len(),
        1
    );
    let seen = upstream
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|(t, _)| *t)
        .collect::<Vec<_>>();
    assert_eq!(seen, [ServiceTransport::Udp, ServiceTransport::Tcp]);
    service.shutdown().await.unwrap();
    let large = Fixture::new(Mode::Large).await;
    let service = start(&policy, vec![large.address]).await;
    let request = query("large.example.", RecordType::A);
    let bytes = udp_bytes(service.udp_addr(), &request.to_vec().unwrap()).await;
    assert!(bytes.len() <= 512);
    let response = Message::from_vec(&bytes).unwrap();
    assert!(response.metadata.truncation);
    assert_eq!(response.queries, request.queries);
    assert_eq!(tcp(service.tcp_addr(), &request).await.answers.len(), 100);
    service.shutdown().await.unwrap();
}
#[tokio::test]
async fn ordered_upstream_failover_and_exhaustion_return_expected_results() {
    let silent = Fixture::new(Mode::Silent).await;
    let good = Fixture::new(Mode::Normal).await;
    let policy = PolicyFixture::new("");
    let service = start(&policy, vec![silent.address, good.address]).await;
    for use_tcp in [false, true] {
        let request = query("forward.example.", RecordType::AAAA);
        let response = if use_tcp {
            tcp(service.tcp_addr(), &request).await
        } else {
            udp(service.udp_addr(), &request).await
        };
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    }
    assert_eq!(silent.count(), 2);
    assert_eq!(good.count(), 2);
    service.shutdown().await.unwrap();
    let service = start(&policy, vec![silent.address]).await;
    assert_eq!(
        udp(
            service.udp_addr(),
            &query("timeout.example.", RecordType::A)
        )
        .await
        .metadata
        .response_code,
        ResponseCode::ServFail
    );
    service.shutdown().await.unwrap();
}
#[tokio::test]
async fn live_updates_apply_to_existing_tcp_connections_and_unavailable_policy_fails_closed() {
    let upstream = Fixture::new(Mode::Normal).await;
    let mut policy = PolicyFixture::new("https://later.example/ads");
    let service = start(&policy, vec![upstream.address]).await;
    let mut stream = TcpStream::connect(service.tcp_addr()).await.unwrap();
    let request = query("later.example.", RecordType::A);
    write_frame(&mut stream, &request.to_vec().unwrap()).await;
    assert_eq!(
        Message::from_vec(&read_frame(&mut stream).await)
            .unwrap()
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    policy.update("later.example");
    write_frame(&mut stream, &request.to_vec().unwrap()).await;
    assert_eq!(
        Message::from_vec(&read_frame(&mut stream).await)
            .unwrap()
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(
        udp(service.udp_addr(), &request)
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    policy.update("");
    assert_eq!(
        udp(service.udp_addr(), &request)
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    policy
        .publisher
        .unavailable(policy.revision, UnavailableReason::CommittedNotActive);
    assert_eq!(
        udp(service.udp_addr(), &request)
            .await
            .metadata
            .response_code,
        ResponseCode::ServFail
    );
    assert_eq!(upstream.count(), 2);
    service.shutdown().await.unwrap();
}
#[tokio::test]
async fn generic_dns_labels_root_and_idna_follow_domain_boundaries() {
    let upstream = Fixture::new(Mode::Normal).await;
    let policy = PolicyFixture::new("*.tracking.example\nbücher.example");
    let service = start(&policy, vec![upstream.address]).await;
    for (name, kind, code) in [
        (
            "_srv._tcp.tracking.example.",
            RecordType::SRV,
            ResponseCode::NXDomain,
        ),
        (
            "_srv._tcp.allowed.example.",
            RecordType::SRV,
            ResponseCode::NoError,
        ),
        (".", RecordType::NS, ResponseCode::NoError),
        ("bücher.example.", RecordType::A, ResponseCode::NXDomain),
    ] {
        assert_eq!(
            udp(service.udp_addr(), &query(name, kind))
                .await
                .metadata
                .response_code,
            code,
            "{name}"
        );
    }
    let mut binary = query("placeholder.example.", RecordType::A);
    binary.queries[0]
        .set_name(Name::from_labels([b"a.b".as_slice(), b"tracking", b"example"]).unwrap());
    assert_eq!(
        udp(service.udp_addr(), &binary)
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    service.shutdown().await.unwrap();
}
#[tokio::test]
async fn readiness_bind_failure_and_clean_cancellation_release_all_resources() {
    let upstream = Fixture::new(Mode::Silent).await;
    let policy = PolicyFixture::new("");
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = occupied.local_addr().unwrap();
    let mut cfg = config(vec![upstream.address]);
    cfg.udp_listen = address;
    cfg.tcp_listen = address;
    let error = DnsService::start(
        cfg,
        policy.reader.clone(),
        DnsOptions::default(),
        CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.stage, FailureStage::Bind);
    assert_eq!(error.transport, Some(ServiceTransport::Tcp));
    let released = UdpSocket::bind(address).await.unwrap();
    drop(released);
    drop(occupied);
    let cancel = CancellationToken::new();
    let service = DnsService::start(
        config(vec![upstream.address]),
        policy.reader.clone(),
        DnsOptions::default(),
        cancel.clone(),
    )
    .await
    .unwrap();
    let udp_address = service.udp_addr();
    let tcp_address = service.tcp_addr();
    let mut monitor = service.monitor();
    let mut idle = TcpStream::connect(tcp_address).await.unwrap();
    idle.write_all(&[0]).await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(
            &query("pending.example.", RecordType::A).to_vec().unwrap(),
            udp_address,
        )
        .await
        .unwrap();
    bounded(upstream.request_seen.notified()).await;
    cancel.cancel();
    bounded(service.shutdown()).await.unwrap();
    assert_eq!(monitor.current(), ServiceStatus::Stopped);
    assert!(matches!(
        bounded(idle.read_u8()).await.unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
    ));
    assert!(UdpSocket::bind(udp_address).await.is_ok());
    assert!(TcpListener::bind(tcp_address).await.is_ok());
    assert_eq!(monitor.changed().await, ServiceStatus::Stopped);
}

#[tokio::test]
async fn malformed_header_counts_and_reserved_bits_are_bounded() {
    let upstream = Fixture::new(Mode::Normal).await;
    let policy = PolicyFixture::new("");
    let service = start(&policy, vec![upstream.address]).await;
    let mut many = query("many.example.", RecordType::A);
    many.queries = vec![many.queries[0].clone(); 300];
    let bytes = udp_bytes(service.udp_addr(), &many.to_vec().unwrap()).await;
    assert!(bytes.len() <= 512);
    assert_eq!(
        Message::from_vec(&bytes).unwrap().metadata.response_code,
        ResponseCode::FormErr
    );
    let mut reserved = query("reserved.example.", RecordType::A).to_vec().unwrap();
    reserved[3] |= 0x40;
    assert_eq!(
        Message::from_vec(&udp_bytes(service.udp_addr(), &reserved).await)
            .unwrap()
            .metadata
            .response_code,
        ResponseCode::FormErr
    );
    assert_eq!(upstream.count(), 0);
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn tcp_framing_and_compression_errors_are_isolated_to_the_request() {
    let upstream = Fixture::new(Mode::Normal).await;
    let policy = PolicyFixture::new("");
    let service = start(&policy, vec![upstream.address]).await;
    let mut stream = TcpStream::connect(service.tcp_addr()).await.unwrap();
    let mut looped = query("loop.example.", RecordType::A).to_vec().unwrap();
    looped.truncate(12);
    looped.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
    write_frame(&mut stream, &looped).await;
    assert_eq!(
        Message::from_vec(&bounded(read_frame(&mut stream)).await)
            .unwrap()
            .metadata
            .response_code,
        ResponseCode::FormErr
    );
    let request = query("valid.example.", RecordType::AAAA);
    write_frame(&mut stream, &request.to_vec().unwrap()).await;
    assert_eq!(
        Message::from_vec(&bounded(read_frame(&mut stream)).await)
            .unwrap()
            .answers
            .len(),
        1
    );
    stream.write_u16(0).await.unwrap();
    assert!(bounded(stream.read_u8()).await.is_err());
    assert_eq!(upstream.count(), 1);
    assert!(
        upstream
            .seen
            .lock()
            .unwrap()
            .iter()
            .all(|(_, message)| message.metadata.id != 1234)
    );
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn total_deadline_prevents_attempting_all_silent_upstreams() {
    let silent = Fixture::new(Mode::Silent).await;
    let policy = PolicyFixture::new("");
    let mut cfg = config(vec![silent.address; 3]);
    cfg.attempt_timeout_ms = 100;
    cfg.total_timeout_ms = 150;
    let service = DnsService::start(
        cfg,
        policy.reader.clone(),
        DnsOptions::default(),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(
        udp(
            service.udp_addr(),
            &query("deadline.example.", RecordType::A)
        )
        .await
        .metadata
        .response_code,
        ResponseCode::ServFail
    );
    assert!((1..=2).contains(&silent.count()));
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn tcp_connection_limit_and_invalid_options_are_enforced() {
    let upstream = Fixture::new(Mode::Normal).await;
    let policy = PolicyFixture::new("");
    let options = DnsOptions {
        max_tcp_connections: 1,
        ..DnsOptions::default()
    };
    let service = DnsService::start(
        config(vec![upstream.address]),
        policy.reader.clone(),
        options,
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let mut first = TcpStream::connect(service.tcp_addr()).await.unwrap();
    let request = query("first.example.", RecordType::A);
    write_frame(&mut first, &request.to_vec().unwrap()).await;
    assert_eq!(
        Message::from_vec(&bounded(read_frame(&mut first)).await)
            .unwrap()
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    let mut excess = TcpStream::connect(service.tcp_addr()).await.unwrap();
    assert!(bounded(excess.read_u8()).await.is_err());
    write_frame(&mut first, &request.to_vec().unwrap()).await;
    assert_eq!(
        Message::from_vec(&bounded(read_frame(&mut first)).await)
            .unwrap()
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    service.shutdown().await.unwrap();
    let options = DnsOptions {
        max_requests: 0,
        ..DnsOptions::default()
    };
    let error = DnsService::start(
        config(vec![upstream.address]),
        policy.reader.clone(),
        options,
        CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.stage, FailureStage::Configure);
}

#[tokio::test]
async fn monitor_reports_worker_loss_and_owner_drop_stops_listeners() {
    let (sender, monitor) = nullgate_core::service_status_channel(nullgate_core::ServiceKind::Dns);
    drop(sender);
    assert!(
        matches!(monitor.current(),ServiceStatus::Failed(failure) if failure.code==nullgate_core::FailureCode::WorkerLost)
    );
    let upstream = Fixture::new(Mode::Normal).await;
    let policy = PolicyFixture::new("");
    let service = start(&policy, vec![upstream.address]).await;
    let address = service.udp_addr();
    let mut monitor = service.monitor();
    drop(service);
    loop {
        if monitor.current() == ServiceStatus::Stopped {
            break;
        }
        bounded(monitor.changed()).await;
    }
    assert!(UdpSocket::bind(address).await.is_ok());
}

#[tokio::test]
async fn embedded_dots_are_never_interpreted_as_dns_label_boundaries() {
    let upstream = Fixture::new(Mode::Normal).await;
    let policy = PolicyFixture::new("a.b.example\n*.tracking.example");
    let service = start(&policy, vec![upstream.address]).await;
    for labels in [
        vec![b"a.b".as_slice(), b"example"],
        vec![b"x.tracking".as_slice(), b"example"],
    ] {
        let mut request = query("placeholder.example.", RecordType::A);
        request.queries[0].set_name(Name::from_labels(labels).unwrap());
        assert_eq!(
            udp(service.udp_addr(), &request)
                .await
                .metadata
                .response_code,
            ResponseCode::NoError
        );
    }
    assert_eq!(
        udp(service.udp_addr(), &query("a.b.example.", RecordType::A))
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(
        udp(
            service.udp_addr(),
            &query("x.tracking.example.", RecordType::A)
        )
        .await
        .metadata
        .response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(upstream.count(), 2);
    service.shutdown().await.unwrap();
}
