//! UDP/TCP DNS listeners, local filtering and supervised cancellable request tasks.
use crate::upstream;
use hickory_proto::{
    op::{Edns, Header, Message, MessageType, OpCode, ResponseCode},
    rr::{Name, RecordType},
    serialize::binary::{BinDecodable, BinDecoder},
};
use nullgate_core::{
    BoundListener, DnsConfig, FailureCode, FailureStage, PolicySubscription, RuleSet,
    ServiceFailure, ServiceKind, ServiceMonitor, ServiceReadiness, ServiceStatus, ServiceTransport,
    normalize_host, service_status_channel,
};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

/// Bounds for admitted work; runtime wiring can map AppConfig's connection limit here.
#[derive(Clone, Debug)]
pub struct DnsOptions {
    pub max_requests: usize,
    pub max_tcp_connections: usize,
    pub tcp_idle_timeout: Duration,
}
impl Default for DnsOptions {
    fn default() -> Self {
        Self {
            max_requests: 1024,
            max_tcp_connections: 1024,
            tcp_idle_timeout: Duration::from_secs(30),
        }
    }
}
/// A bound DNS service. Start returns only after both sockets are ready; drop requests cancellation.
#[derive(Debug)]
pub struct DnsService {
    udp_address: SocketAddr,
    tcp_address: SocketAddr,
    monitor: ServiceMonitor,
    cancel: CancellationToken,
    worker: Option<JoinHandle<Result<(), ServiceFailure>>>,
}
impl DnsService {
    pub async fn start(
        config: DnsConfig,
        policy: PolicySubscription,
        options: DnsOptions,
        cancel: CancellationToken,
    ) -> Result<Self, ServiceFailure> {
        validate(&config, &options)?;
        if cancel.is_cancelled() {
            return Err(failure(
                FailureStage::Configure,
                None,
                FailureCode::Cancelled,
                None,
            ));
        }
        let udp = UdpSocket::bind(config.udp_listen).await.map_err(|e| {
            failure(
                FailureStage::Bind,
                Some(ServiceTransport::Udp),
                FailureCode::BindFailed,
                Some(e.kind()),
            )
        })?;
        let tcp = TcpListener::bind(config.tcp_listen).await.map_err(|e| {
            failure(
                FailureStage::Bind,
                Some(ServiceTransport::Tcp),
                FailureCode::BindFailed,
                Some(e.kind()),
            )
        })?;
        let udp_address = udp.local_addr().map_err(|e| {
            failure(
                FailureStage::Bind,
                Some(ServiceTransport::Udp),
                FailureCode::BindFailed,
                Some(e.kind()),
            )
        })?;
        let tcp_address = tcp.local_addr().map_err(|e| {
            failure(
                FailureStage::Bind,
                Some(ServiceTransport::Tcp),
                FailureCode::BindFailed,
                Some(e.kind()),
            )
        })?;
        let (status, monitor) = service_status_channel(ServiceKind::Dns);
        status.send_replace(ServiceStatus::Ready(ServiceReadiness {
            service: ServiceKind::Dns,
            listeners: vec![
                BoundListener {
                    transport: ServiceTransport::Udp,
                    address: udp_address,
                },
                BoundListener {
                    transport: ServiceTransport::Tcp,
                    address: tcp_address,
                },
            ],
        }));
        let cancel = cancel.child_token();
        let token = cancel.clone();
        let worker = tokio::spawn(async move {
            let result = serve(Arc::new(udp), tcp, Arc::new(config), policy, options, token).await;
            status.send_replace(match result {
                Ok(()) => ServiceStatus::Stopped,
                Err(error) => ServiceStatus::Failed(error),
            });
            result
        });
        Ok(Self {
            udp_address,
            tcp_address,
            monitor,
            cancel,
            worker: Some(worker),
        })
    }
    pub fn udp_addr(&self) -> SocketAddr {
        self.udp_address
    }
    pub fn tcp_addr(&self) -> SocketAddr {
        self.tcp_address
    }
    pub fn monitor(&self) -> ServiceMonitor {
        self.monitor.clone()
    }
    pub fn cancel(&self) {
        self.cancel.cancel();
    }
    /// Cancel admitted work, join all request tasks and release listeners before returning.
    pub async fn shutdown(mut self) -> Result<(), ServiceFailure> {
        self.cancel();
        match self.worker.take() {
            Some(worker) => worker.await.map_err(|error| {
                failure(
                    FailureStage::Run,
                    None,
                    if error.is_panic() {
                        FailureCode::WorkerPanicked
                    } else {
                        FailureCode::WorkerLost
                    },
                    None,
                )
            })?,
            None => Ok(()),
        }
    }
}
impl Drop for DnsService {
    fn drop(&mut self) {
        self.cancel();
    }
}
fn failure(
    stage: FailureStage,
    transport: Option<ServiceTransport>,
    code: FailureCode,
    io_kind: Option<io::ErrorKind>,
) -> ServiceFailure {
    ServiceFailure {
        service: ServiceKind::Dns,
        stage,
        transport,
        code,
        io_kind,
    }
}
fn validate(config: &DnsConfig, options: &DnsOptions) -> Result<(), ServiceFailure> {
    if config.upstreams.is_empty()
        || config.attempt_timeout_ms == 0
        || config.attempt_timeout_ms > config.total_timeout_ms
        || config.total_timeout_ms > 60_000
        || config.upstreams.iter().any(|address| {
            address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast()
        })
        || options.max_requests == 0
        || options.max_requests > 65_535
        || options.max_tcp_connections == 0
        || options.max_tcp_connections > 65_535
        || options.tcp_idle_timeout.is_zero()
        || options.tcp_idle_timeout > Duration::from_secs(300)
    {
        return Err(failure(
            FailureStage::Configure,
            None,
            FailureCode::InvalidConfig,
            None,
        ));
    }
    Ok(())
}
async fn serve(
    udp: Arc<UdpSocket>,
    tcp: TcpListener,
    config: Arc<DnsConfig>,
    policy: PolicySubscription,
    options: DnsOptions,
    cancel: CancellationToken,
) -> Result<(), ServiceFailure> {
    let requests = Arc::new(Semaphore::new(options.max_requests));
    let connections = Arc::new(Semaphore::new(options.max_tcp_connections));
    let mut tasks = JoinSet::new();
    let mut buffer = vec![0; 65535];
    let result = loop {
        match next_incoming(&udp, &tcp, &mut tasks, &mut buffer, &cancel).await {
            Incoming::Cancelled => break Ok(()),
            Incoming::Completed(Ok(())) => {}
            Incoming::Completed(Err(error)) => {
                let code = if error.is_panic() {
                    FailureCode::WorkerPanicked
                } else {
                    FailureCode::WorkerLost
                };
                break Err(failure(FailureStage::Run, None, code, None));
            }
            Incoming::Datagram(received) => {
                let (size, peer) = match received {
                    Ok(received) => received,
                    Err(error) => {
                        break Err(failure(
                            FailureStage::Run,
                            Some(ServiceTransport::Udp),
                            FailureCode::ListenerIo,
                            Some(error.kind()),
                        ));
                    }
                };
                let Ok(permit) = requests.clone().try_acquire_owned() else {
                    continue;
                };
                let bytes = buffer[..size].to_vec();
                let udp = udp.clone();
                let policy = policy.clone();
                let config = config.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Some(response) =
                        answer(&bytes, &config, &policy, ServiceTransport::Udp).await
                    {
                        let _ = udp.send_to(&response, peer).await;
                    }
                });
            }
            Incoming::Connection(accepted) => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
                        ) =>
                    {
                        continue;
                    }
                    Err(error) => {
                        break Err(failure(
                            FailureStage::Run,
                            Some(ServiceTransport::Tcp),
                            FailureCode::ListenerIo,
                            Some(error.kind()),
                        ));
                    }
                };
                let Ok(permit) = connections.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let requests = requests.clone();
                let config = config.clone();
                let policy = policy.clone();
                let idle = options.tcp_idle_timeout;
                tasks.spawn(async move {
                    let _permit = permit;
                    let _ = tcp_client(stream, config, policy, requests, idle).await;
                });
            }
        }
    };
    tasks.shutdown().await;
    result
}
enum Incoming {
    Cancelled,
    Completed(Result<(), tokio::task::JoinError>),
    Datagram(io::Result<(usize, SocketAddr)>),
    Connection(io::Result<(TcpStream, SocketAddr)>),
}

async fn next_incoming(
    udp: &UdpSocket,
    tcp: &TcpListener,
    tasks: &mut JoinSet<()>,
    buffer: &mut [u8],
    cancel: &CancellationToken,
) -> Incoming {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Incoming::Cancelled,
        // Reap completed children before admitting more work, keeping retained results bounded.
        // Children never create new listener tasks, so this drain cannot starve listeners.
        Some(completed) = tasks.join_next(), if !tasks.is_empty() => Incoming::Completed(completed),
        incoming = async {
            // Listener readiness is fair: a readable UDP socket must not starve TCP retries.
            tokio::select! {
                received = udp.recv_from(buffer) => Incoming::Datagram(received),
                accepted = tcp.accept() => Incoming::Connection(accepted),
            }
        } => incoming,
    }
}

async fn tcp_client(
    mut stream: TcpStream,
    config: Arc<DnsConfig>,
    policy: PolicySubscription,
    requests: Arc<Semaphore>,
    idle: Duration,
) -> io::Result<()> {
    loop {
        let bytes = tokio::time::timeout(idle, async {
            let size = stream.read_u16().await?;
            if size == 0 {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            let mut bytes = vec![0; size as usize];
            stream.read_exact(&mut bytes).await?;
            Ok::<_, io::Error>(bytes)
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        let _permit = requests
            .acquire()
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::Interrupted))?;
        let Some(response) = answer(&bytes, &config, &policy, ServiceTransport::Tcp).await else {
            return Ok(());
        };
        tokio::time::timeout(idle, async {
            stream.write_u16(response.len() as u16).await?;
            stream.write_all(&response).await
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    }
}

fn blocked_name(rules: &RuleSet, name: &Name) -> bool {
    let labels: Vec<_> = name.iter().collect();
    for start in 0..labels.len() {
        let suffix = &labels[start..];
        if suffix.iter().any(|label| {
            !label
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        }) {
            continue;
        }
        let text = suffix
            .iter()
            .map(|label| std::str::from_utf8(label).expect("ASCII labels"))
            .collect::<Vec<_>>()
            .join(".");
        if let Ok(host) = normalize_host(&text)
            && ((start == 0 && rules.blocks_domain(&host))
                || (start > 0 && rules.blocks_subdomains_of(&host)))
        {
            return true;
        }
    }
    false
}
fn local_response(request: &Message, code: ResponseCode) -> Message {
    let mut response = Message::error_msg(request.metadata.id, request.metadata.op_code, code);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.checking_disabled = request.metadata.checking_disabled;
    response.metadata.recursion_available = true;
    response.queries = request.queries.clone();
    if let Some(edns) = &request.edns {
        let mut local = Edns::new();
        local
            .set_max_payload(edns.max_payload().clamp(512, 1232))
            .set_dnssec_ok(edns.flags().dnssec_ok);
        response.edns = Some(local);
    }
    response
}
fn encode_local(request: &Message, code: ResponseCode) -> Option<Vec<u8>> {
    local_response(request, code).to_vec().ok()
}
async fn answer(
    bytes: &[u8],
    config: &DnsConfig,
    policy: &PolicySubscription,
    transport: ServiceTransport,
) -> Option<Vec<u8>> {
    if bytes.len() < 12 || bytes[2] & 0x80 != 0 {
        return None;
    }
    let request = match upstream::decode(bytes) {
        Ok(message) => message,
        Err(()) => {
            let header = Header::read(&mut BinDecoder::new(bytes)).ok()?;
            let mut request = Message::new(
                header.metadata.id,
                MessageType::Query,
                header.metadata.op_code,
            );
            request.metadata.recursion_desired = header.metadata.recursion_desired;
            request.metadata.checking_disabled = header.metadata.checking_disabled;
            return encode_local(
                &request,
                if header.metadata.op_code == OpCode::Query {
                    ResponseCode::FormErr
                } else {
                    ResponseCode::NotImp
                },
            );
        }
    };
    if request.metadata.op_code != OpCode::Query {
        return encode_local(&request, ResponseCode::NotImp);
    }
    if bytes[3] & 0x40 != 0
        || request.queries.len() != 1
        || !request.answers.is_empty()
        || !request.authorities.is_empty()
        || request.metadata.truncation
        || request.metadata.response_code != ResponseCode::NoError
    {
        return encode_local(&request, ResponseCode::FormErr);
    }
    if request.signature.is_some()
        || request
            .additionals
            .iter()
            .any(|record| matches!(record.record_type(), RecordType::TSIG | RecordType::SIG))
        || matches!(
            request.queries[0].query_type(),
            RecordType::AXFR | RecordType::IXFR
        )
    {
        return encode_local(&request, ResponseCode::NotImp);
    }
    if request
        .edns
        .as_ref()
        .is_some_and(|edns| edns.version() != 0)
    {
        return encode_local(&request, ResponseCode::BADVERS);
    }
    let snapshot = match policy.current() {
        Ok(snapshot) => snapshot,
        Err(_) => return encode_local(&request, ResponseCode::ServFail),
    };
    if blocked_name(snapshot.rules(), request.queries[0].name()) {
        return encode_local(&request, ResponseCode::NXDomain);
    }
    let Some(response) = upstream::forward(bytes, &request, config, transport).await else {
        return encode_local(&request, ResponseCode::ServFail);
    };
    let maximum = request
        .edns
        .as_ref()
        .map_or(512, |edns| edns.max_payload().clamp(512, 1232)) as usize;
    if transport == ServiceTransport::Udp && response.len() > maximum {
        let mut truncated = local_response(&request, ResponseCode::NoError);
        truncated.metadata.truncation = true;
        return truncated.to_vec().ok();
    }
    Some(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tcp_accept_progresses_while_udp_stays_continuously_readable() {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _client = TcpStream::connect(tcp.local_addr().unwrap()).await.unwrap();
        let producer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut tasks = JoinSet::new();
        let mut buffer = [0; 512];
        let cancel = CancellationToken::new();
        // Refill before every poll: UDP is never exhausted as an escape from starvation.
        for _ in 0..128 {
            producer.send_to(&[1], udp.local_addr().unwrap()).unwrap();
            udp.readable().await.unwrap();
            tokio::task::yield_now().await;
            match next_incoming(&udp, &tcp, &mut tasks, &mut buffer, &cancel).await {
                Incoming::Connection(Ok(_)) => return,
                Incoming::Datagram(Ok(_)) => {}
                _ => panic!("unexpected listener event"),
            }
        }
        panic!("TCP was starved by continuously readable UDP");
    }
}
