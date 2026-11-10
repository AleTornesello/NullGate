use nullgate_core::{
    BoundListener, FailureCode, FailureStage, PolicyFuture, PolicySnapshot, PolicySubscription,
    RepositorySnapshot, ServiceFailure, ServiceKind, ServiceMonitor, ServiceReadiness,
    ServiceStatus, ServiceTransport, policy_channel, service_status_channel,
};
use nullgate_orchestrator::{ManagedProxy, ProxyFactory, ProxyPhase, Supervisor};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::TcpListener, sync::Notify};
use tokio_util::sync::CancellationToken;
fn index(kind: ServiceKind) -> usize {
    match kind {
        ServiceKind::Dns => 0,
        ServiceKind::Http => 1,
        _ => panic!("web is outside Task8"),
    }
}
fn failure(kind: ServiceKind) -> ServiceFailure {
    ServiceFailure {
        service: kind,
        stage: FailureStage::Run,
        transport: Some(ServiceTransport::Tcp),
        code: FailureCode::ListenerIo,
        io_kind: None,
    }
}
#[derive(Default)]
struct Control {
    attempts: [usize; 2],
    stops: [usize; 2],
    live: [usize; 2],
    senders: [Option<tokio::sync::watch::Sender<ServiceStatus>>; 2],
    address: [Option<SocketAddr>; 2],
    fail_next: [usize; 2],
    gate: [Option<Arc<Notify>>; 2],
}
#[derive(Default)]
struct Factory {
    control: Arc<Mutex<Control>>,
}
impl Factory {
    fn fail(&self, kind: ServiceKind) {
        self.control.lock().unwrap().senders[index(kind)]
            .as_ref()
            .unwrap()
            .send_replace(ServiceStatus::Failed(failure(kind)));
    }
    fn attempts(&self, kind: ServiceKind) -> usize {
        self.control.lock().unwrap().attempts[index(kind)]
    }
}
struct FakeProxy {
    kind: ServiceKind,
    listener: Option<TcpListener>,
    monitor: ServiceMonitor,
    control: Arc<Mutex<Control>>,
}
impl ManagedProxy for FakeProxy {
    fn monitor(&self) -> ServiceMonitor {
        self.monitor.clone()
    }
    fn shutdown(mut self: Box<Self>) -> PolicyFuture<'static, Result<(), ServiceFailure>> {
        Box::pin(async move {
            let gate = {
                let mut control = self.control.lock().unwrap();
                control.stops[index(self.kind)] += 1;
                control.gate[index(self.kind)].clone()
            };
            if let Some(gate) = gate {
                gate.notified().await;
            }
            drop(self.listener.take());
            self.control.lock().unwrap().live[index(self.kind)] -= 1;
            Ok(())
        })
    }
}
impl ProxyFactory for Factory {
    fn start(
        &self,
        kind: ServiceKind,
        _cancel: CancellationToken,
    ) -> PolicyFuture<'_, Result<Box<dyn ManagedProxy>, ServiceFailure>> {
        Box::pin(async move {
            let address = {
                let mut control = self.control.lock().unwrap();
                let i = index(kind);
                control.attempts[i] += 1;
                assert_eq!(control.live[i], 0, "replacement overlapped old listener");
                if control.fail_next[i] > 0 {
                    control.fail_next[i] -= 1;
                    return Err(failure(kind));
                }
                control.address[i].unwrap_or_else(|| "127.0.0.1:0".parse().unwrap())
            };
            let listener = TcpListener::bind(address).await.unwrap();
            let address = listener.local_addr().unwrap();
            let (sender, monitor) = service_status_channel(kind);
            sender.send_replace(ServiceStatus::Ready(ServiceReadiness {
                service: kind,
                listeners: vec![BoundListener {
                    transport: ServiceTransport::Tcp,
                    address,
                }],
            }));
            {
                let mut control = self.control.lock().unwrap();
                let i = index(kind);
                control.live[i] += 1;
                control.address[i] = Some(address);
                control.senders[i] = Some(sender);
            }
            Ok(Box::new(FakeProxy {
                kind,
                listener: Some(listener),
                monitor,
                control: self.control.clone(),
            }) as Box<dyn ManagedProxy>)
        })
    }
}
fn policy() -> (nullgate_core::PolicyPublisher, PolicySubscription) {
    policy_channel(
        PolicySnapshot::from_repository(RepositorySnapshot {
            revision: 0,
            lists: vec![],
        })
        .unwrap(),
    )
}
async fn spin(mut ready: impl FnMut() -> bool) {
    for _ in 0..300 {
        if ready() {
            return;
        }
        tokio::task::yield_now().await;
    }
    assert!(ready(), "deterministic lifecycle event did not occur");
}

#[tokio::test(start_paused = true)]
async fn readiness_follows_binding_and_shutdown_releases_all_listeners() {
    let (_publisher, policy) = policy();
    let factory = Arc::new(Factory::default());
    let supervisor = Supervisor::start(factory.clone(), policy, CancellationToken::new())
        .await
        .unwrap();
    let monitor = supervisor.monitor();
    assert!(monitor.current().is_ready());
    let addresses = factory.control.lock().unwrap().address;
    for address in addresses.into_iter().flatten() {
        assert!(TcpListener::bind(address).await.is_err());
    }
    supervisor.shutdown().await.unwrap();
    assert!(!monitor.current().is_ready());
    for address in addresses.into_iter().flatten() {
        assert!(TcpListener::bind(address).await.is_ok());
    }
    assert_eq!(factory.control.lock().unwrap().live, [0, 0]);
}

#[tokio::test(start_paused = true)]
async fn initial_second_service_failure_rolls_back_without_retrying() {
    let (_publisher, policy) = policy();
    let factory = Arc::new(Factory::default());
    factory.control.lock().unwrap().fail_next[1] = 1;
    assert!(
        Supervisor::start(factory.clone(), policy, CancellationToken::new())
            .await
            .is_err()
    );
    let address = {
        let control = factory.control.lock().unwrap();
        assert_eq!(control.attempts, [1, 1]);
        assert_eq!(control.live, [0, 0]);
        control.address[0].unwrap()
    };
    assert!(TcpListener::bind(address).await.is_ok());
}

#[tokio::test(start_paused = true)]
async fn retirement_finishes_before_backoff_and_rebinding() {
    let (_publisher, policy) = policy();
    let factory = Arc::new(Factory::default());
    let supervisor = Supervisor::start(factory.clone(), policy, CancellationToken::new())
        .await
        .unwrap();
    let monitor = supervisor.monitor();
    let gate = Arc::new(Notify::new());
    factory.control.lock().unwrap().gate[0] = Some(gate.clone());
    factory.fail(ServiceKind::Dns);
    spin(|| factory.control.lock().unwrap().stops[0] == 1).await;
    assert!(!monitor.current().is_ready());
    tokio::time::advance(Duration::from_secs(90)).await;
    assert_eq!(factory.attempts(ServiceKind::Dns), 1);
    factory.control.lock().unwrap().gate[0] = None;
    gate.notify_one();
    spin(|| matches!(monitor.current().dns.phase, ProxyPhase::Backoff { .. })).await;
    tokio::time::advance(Duration::from_millis(999)).await;
    assert_eq!(factory.attempts(ServiceKind::Dns), 1);
    tokio::time::advance(Duration::from_millis(1)).await;
    spin(|| factory.attempts(ServiceKind::Dns) == 2 && monitor.current().is_ready()).await;
    assert_eq!(factory.attempts(ServiceKind::Http), 1);
    supervisor.shutdown().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn repeated_failures_cap_backoff_and_healthy_uptime_resets_it() {
    let (_publisher, policy) = policy();
    let factory = Arc::new(Factory::default());
    let supervisor = Supervisor::start(factory.clone(), policy, CancellationToken::new())
        .await
        .unwrap();
    let monitor = supervisor.monitor();
    for expected in [1, 2, 4, 8, 16, 30, 30] {
        factory.fail(ServiceKind::Http);
        spin(|| matches!(monitor.current().http.phase, ProxyPhase::Backoff { .. })).await;
        let ProxyPhase::Backoff { delay, .. } = monitor.current().http.phase else {
            panic!()
        };
        assert_eq!(delay, Duration::from_secs(expected));
        tokio::time::advance(delay).await;
        spin(|| monitor.current().is_ready()).await;
    }
    tokio::time::advance(Duration::from_secs(60)).await;
    factory.fail(ServiceKind::Http);
    spin(|| matches!(monitor.current().http.phase, ProxyPhase::Backoff { .. })).await;
    let ProxyPhase::Backoff { delay, .. } = monitor.current().http.phase else {
        panic!()
    };
    assert_eq!(delay, Duration::from_secs(1));
    supervisor.shutdown().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn failed_rebinding_remains_unready_and_cancellation_interrupts_backoff() {
    let (_publisher, policy) = policy();
    let factory = Arc::new(Factory::default());
    let supervisor = Supervisor::start(factory.clone(), policy, CancellationToken::new())
        .await
        .unwrap();
    let monitor = supervisor.monitor();
    factory.control.lock().unwrap().fail_next[0] = 2;
    factory.fail(ServiceKind::Dns);
    spin(|| matches!(monitor.current().dns.phase, ProxyPhase::Backoff { .. })).await;
    tokio::time::advance(Duration::from_secs(1)).await;
    spin(|| factory.attempts(ServiceKind::Dns) == 2).await;
    assert!(!monitor.current().is_ready());
    supervisor.shutdown().await.unwrap();
    tokio::time::advance(Duration::from_secs(100)).await;
    assert_eq!(factory.attempts(ServiceKind::Dns), 2);
    assert_eq!(factory.control.lock().unwrap().live, [0, 0]);
}

#[tokio::test(start_paused = true)]
async fn policy_owner_loss_withdraws_readiness_and_stops_both_proxies() {
    let (publisher, policy) = policy();
    let factory = Arc::new(Factory::default());
    let supervisor = Supervisor::start(factory.clone(), policy, CancellationToken::new())
        .await
        .unwrap();
    let monitor = supervisor.monitor();
    drop(publisher);
    assert!(!monitor.current().is_ready());
    assert!(supervisor.wait().await.is_err());
    assert_eq!(factory.control.lock().unwrap().live, [0, 0]);
}

struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Self {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("nullgate-runtime-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn config(scratch: &Scratch, upstream: SocketAddr) -> nullgate_core::AppConfig {
    use nullgate_core::*;
    AppConfig {
        schema_version: 1,
        data_dir: scratch.0.clone(),
        dns: DnsConfig {
            udp_listen: "127.0.0.1:0".parse().unwrap(),
            tcp_listen: "127.0.0.1:0".parse().unwrap(),
            upstreams: vec![upstream],
            attempt_timeout_ms: 2000,
            total_timeout_ms: 5000,
        },
        http: HttpConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
        },
        web: WebConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            tls: None,
        },
        limits: ResourceLimits::default(),
        auth: AuthMode::Local,
    }
}
async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("local lifecycle operation timed out")
}
async fn read_head(stream: &mut tokio::net::TcpStream) -> String {
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await.unwrap());
    }
    String::from_utf8(bytes).unwrap()
}

#[tokio::test]
async fn real_application_binds_and_policy_activation_closes_tunnels_before_save_ack() {
    use nullgate_core::{Mutation, PolicyManagement, SourceKind};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpStream, UdpSocket};
    let scratch = Scratch::new();
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let app = nullgate_orchestrator::Application::start(
        config(&scratch, upstream.local_addr().unwrap()),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let status = app.monitor().current();
    assert!(status.is_ready());
    let ProxyPhase::Ready(http) = status.http.phase else {
        panic!()
    };
    let address = http.listeners[0].address;
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = format!("localhost:{}", origin.local_addr().unwrap().port());
    let origin_job = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let (mut read, mut write) = stream.split();
        tokio::io::copy(&mut read, &mut write).await.unwrap();
    });
    let mut tunnel = TcpStream::connect(address).await.unwrap();
    tunnel
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    assert!(
        bounded(read_head(&mut tunnel))
            .await
            .starts_with("HTTP/1.1 200")
    );
    tunnel.write_all(b"still end-to-end").await.unwrap();
    let mut echo = [0; 16];
    bounded(tunnel.read_exact(&mut echo)).await.unwrap();
    assert_eq!(&echo, b"still end-to-end");
    let writer = app.policy();
    writer
        .save(
            0,
            Mutation::CreateList {
                name: "runtime".into(),
            },
        )
        .await
        .unwrap();
    let result = writer
        .save(
            1,
            Mutation::AddSource {
                list_id: 1,
                kind: SourceKind::Manual,
            },
        )
        .await
        .unwrap();
    let source = result.snapshot.repository().lists[0].sources[0].id;
    bounded(writer.save(
        2,
        Mutation::Import {
            source_id: source,
            text: "localhost\nblocked.invalid".into(),
            at: 1,
        },
    ))
    .await
    .unwrap();
    assert!(bounded(tunnel.read_u8()).await.is_err());
    bounded(origin_job).await.unwrap();
    // Blocked DNS must use the injected live policy, without querying the upstream.
    let ProxyPhase::Ready(dns) = status.dns.phase else {
        panic!()
    };
    let dns_udp = dns
        .listeners
        .iter()
        .find(|listener| listener.transport == ServiceTransport::Udp)
        .unwrap()
        .address;
    let mut query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    query.extend_from_slice(b"\x07blocked\x07invalid\x00\x00\x01\x00\x01");
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(&query, dns_udp).await.unwrap();
    let mut answer = [0; 512];
    let size = bounded(client.recv(&mut answer)).await.unwrap();
    assert!(size >= 12);
    assert_eq!(answer[3] & 15, 3);
    // One forwarded query is still waiting upstream when shutdown begins.
    let mut pending = query;
    pending[12] = 7;
    pending[13..20].copy_from_slice(b"allowed");
    client.send_to(&pending, dns_udp).await.unwrap();
    let mut received = [0; 512];
    bounded(upstream.recv(&mut received)).await.unwrap();
    bounded(app.shutdown()).await.unwrap();
    assert!(writer.subscribe().current().is_err());
    assert!(UdpSocket::bind(dns_udp).await.is_ok());
    for listener in dns.listeners {
        if listener.transport == ServiceTransport::Tcp {
            assert!(TcpListener::bind(listener.address).await.is_ok());
        }
    }
    assert!(TcpListener::bind(address).await.is_ok());
}

#[tokio::test]
async fn real_http_bind_failure_releases_initial_dns_and_storage_owner() {
    let scratch = Scratch::new();
    let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut cfg = config(&scratch, upstream.local_addr().unwrap());
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    cfg.http.listen = occupied.local_addr().unwrap();
    let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dns = reserved.local_addr().unwrap();
    drop(reserved);
    cfg.dns.tcp_listen = dns;
    cfg.dns.udp_listen = dns;
    assert!(
        nullgate_orchestrator::Application::start(cfg, CancellationToken::new())
            .await
            .is_err()
    );
    assert!(TcpListener::bind(dns).await.is_ok());
    assert!(tokio::net::UdpSocket::bind(dns).await.is_ok());
}

struct SlowSecond {
    inner: Arc<Factory>,
    entered: Arc<Notify>,
}
impl ProxyFactory for SlowSecond {
    fn start(
        &self,
        kind: ServiceKind,
        cancel: CancellationToken,
    ) -> PolicyFuture<'_, Result<Box<dyn ManagedProxy>, ServiceFailure>> {
        Box::pin(async move {
            if kind == ServiceKind::Http {
                self.entered.notify_one();
                std::future::pending::<()>().await;
            }
            self.inner.start(kind, cancel).await
        })
    }
}
#[tokio::test(start_paused = true)]
async fn cancellation_during_initial_start_rolls_back_the_already_bound_peer() {
    let (_publisher, policy) = policy();
    let inner = Arc::new(Factory::default());
    let entered = Arc::new(Notify::new());
    let factory = Arc::new(SlowSecond {
        inner: inner.clone(),
        entered: entered.clone(),
    });
    let token = CancellationToken::new();
    let cancel = token.clone();
    let start = tokio::spawn(async move { Supervisor::start(factory, policy, cancel).await });
    entered.notified().await;
    token.cancel();
    assert!(start.await.unwrap().is_err());
    assert_eq!(inner.control.lock().unwrap().live, [0, 0]);
}

#[tokio::test(start_paused = true)]
async fn transient_policy_unavailability_withdraws_readiness_without_restarting_proxies() {
    use nullgate_core::UnavailableReason;
    let (mut publisher, policy) = policy();
    let snapshot = policy.current().unwrap();
    let factory = Arc::new(Factory::default());
    let supervisor = Supervisor::start(factory.clone(), policy, CancellationToken::new())
        .await
        .unwrap();
    let monitor = supervisor.monitor();
    publisher.unavailable(1, UnavailableReason::Activating);
    assert!(!monitor.current().is_ready());
    spin(|| monitor.current().policy_unavailable.is_some()).await;
    publisher.publish(snapshot);
    spin(|| monitor.current().is_ready()).await;
    assert_eq!(factory.control.lock().unwrap().attempts, [1, 1]);
    supervisor.shutdown().await.unwrap();
}
