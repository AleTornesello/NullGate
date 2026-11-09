//! Cancellable HTTP/1 listener over injected immutable policy subscriptions.
use crate::{
    forward::{self, ForwardError, ProxyBody},
    ingress::{GuardedIo, Heads, Ingress},
    policy::{Decision, ValidatedTarget, evaluate},
};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Body, Incoming},
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use nullgate_core::{
    BoundListener, FailureCode, FailureStage, HttpConfig, HttpScheme, PolicySubscription,
    ServiceFailure, ServiceKind, ServiceMonitor, ServiceReadiness, ServiceStatus, ServiceTransport,
    service_status_channel,
};
use std::{
    collections::VecDeque,
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::Semaphore,
    task::{JoinHandle, JoinSet},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
#[derive(Clone, Debug)]
pub struct HttpOptions {
    pub max_connections: usize,
    pub max_requests: usize,
    pub connect_timeout: Duration,
    pub upstream_header_timeout: Duration,
    pub request_header_timeout: Duration,
}
impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            max_requests: 1024,
            connect_timeout: Duration::from_secs(10),
            upstream_header_timeout: Duration::from_secs(30),
            request_header_timeout: Duration::from_secs(30),
        }
    }
}
#[derive(Debug)]
pub struct HttpService {
    address: SocketAddr,
    monitor: ServiceMonitor,
    cancel: CancellationToken,
    worker: Option<JoinHandle<Result<(), ServiceFailure>>>,
}
impl HttpService {
    pub async fn start(
        config: HttpConfig,
        policy: PolicySubscription,
        options: HttpOptions,
        cancel: CancellationToken,
    ) -> Result<Self, ServiceFailure> {
        if options.max_connections == 0
            || options.max_connections > 65535
            || options.max_requests == 0
            || options.max_requests > 65535
            || [
                options.connect_timeout,
                options.upstream_header_timeout,
                options.request_header_timeout,
            ]
            .iter()
            .any(|time| time.is_zero() || *time > Duration::from_secs(86400))
        {
            return Err(failure(
                FailureStage::Configure,
                FailureCode::InvalidConfig,
                None,
            ));
        }
        if cancel.is_cancelled() {
            return Err(failure(
                FailureStage::Configure,
                FailureCode::Cancelled,
                None,
            ));
        }
        let listener = TcpListener::bind(config.listen).await.map_err(|error| {
            failure(
                FailureStage::Bind,
                FailureCode::BindFailed,
                Some(error.kind()),
            )
        })?;
        let address = listener.local_addr().map_err(|error| {
            failure(
                FailureStage::Bind,
                FailureCode::BindFailed,
                Some(error.kind()),
            )
        })?;
        let (status, monitor) = service_status_channel(ServiceKind::Http);
        status.send_replace(ServiceStatus::Ready(ServiceReadiness {
            service: ServiceKind::Http,
            listeners: vec![BoundListener {
                transport: ServiceTransport::Tcp,
                address,
            }],
        }));
        let cancel = cancel.child_token();
        let token = cancel.clone();
        let tracker = TaskTracker::new();
        let state = Arc::new(State {
            policy,
            requests: Arc::new(Semaphore::new(options.max_requests)),
            options,
            tracker: tracker.clone(),
        });
        let worker = tokio::spawn(async move {
            let result = serve(listener, state, token).await;
            tracker.close();
            tracker.wait().await;
            status.send_replace(match result {
                Ok(()) => ServiceStatus::Stopped,
                Err(error) => ServiceStatus::Failed(error),
            });
            result
        });
        Ok(Self {
            address,
            monitor,
            cancel,
            worker: Some(worker),
        })
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }
    pub fn monitor(&self) -> ServiceMonitor {
        self.monitor.clone()
    }
    pub fn cancel(&self) {
        self.cancel.cancel();
    }
    pub async fn shutdown(mut self) -> Result<(), ServiceFailure> {
        self.cancel();
        match self.worker.take() {
            Some(worker) => worker.await.map_err(|error| {
                failure(
                    FailureStage::Run,
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
impl Drop for HttpService {
    fn drop(&mut self) {
        self.cancel();
    }
}
fn failure(
    stage: FailureStage,
    code: FailureCode,
    io_kind: Option<std::io::ErrorKind>,
) -> ServiceFailure {
    ServiceFailure {
        service: ServiceKind::Http,
        stage,
        code,
        transport: Some(ServiceTransport::Tcp),
        io_kind,
    }
}
struct State {
    policy: PolicySubscription,
    requests: Arc<Semaphore>,
    options: HttpOptions,
    tracker: TaskTracker,
}
async fn serve(
    listener: TcpListener,
    state: Arc<State>,
    cancel: CancellationToken,
) -> Result<(), ServiceFailure> {
    let connections = Arc::new(Semaphore::new(state.options.max_connections));
    let mut clients = JoinSet::new();
    let result = loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break Ok(()),
            Some(completed) = clients.join_next(), if !clients.is_empty() => {
                if let Err(error) = completed {
                    let code = if error.is_panic() { FailureCode::WorkerPanicked } else { FailureCode::WorkerLost };
                    break Err(failure(FailureStage::Run, code, None));
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(value) => value,
                    Err(error) if matches!(error.kind(), std::io::ErrorKind::Interrupted | std::io::ErrorKind::ConnectionAborted) => continue,
                    Err(error) => break Err(failure(FailureStage::Run, FailureCode::ListenerIo, Some(error.kind()))),
                };
                let Ok(permit) = connections.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let state = state.clone();
                clients.spawn(async move {
                    let _permit = permit;
                    let heads = Arc::new(Mutex::new(VecDeque::new()));
                    let io = GuardedIo::new(stream, heads.clone());
                    let deadline = state.options.request_header_timeout;
                    let service = service_fn(move |request| handle(request, state.clone(), heads.clone()));
                    let mut builder = hyper::server::conn::http1::Builder::new();
                    builder.timer(TokioTimer::new()).header_read_timeout(deadline)
                        .max_headers(100).max_buf_size(32768);
                    // Malformed peer traffic ends this connection, not the listener.
                    let _ = builder.serve_connection(TokioIo::new(io), service).await;
                });
            }
        }
    };
    clients.shutdown().await;
    result
}
fn local(status: StatusCode, close: bool) -> Response<ProxyBody> {
    let mut response = Response::new(ProxyBody::empty());
    *response.status_mut() = status;
    response.headers_mut().insert(
        hyper::header::CONTENT_LENGTH,
        hyper::header::HeaderValue::from_static("0"),
    );
    if close {
        response.headers_mut().insert(
            hyper::header::CONNECTION,
            hyper::header::HeaderValue::from_static("close"),
        );
    }
    response
}
async fn handle(
    request: Request<Incoming>,
    state: Arc<State>,
    heads: Heads,
) -> Result<Response<ProxyBody>, Infallible> {
    let ingress = heads.lock().unwrap().pop_front();
    let raw = match ingress {
        Some(Ingress::Accepted(raw)) => raw,
        Some(Ingress::Rejected(status)) => return Ok(local(status, true)),
        None => return Ok(local(StatusCode::BAD_REQUEST, true)),
    };
    let close = !request.body().is_end_stream();
    if request.method() == Method::CONNECT || request.headers().contains_key(hyper::header::UPGRADE)
    {
        return Ok(local(StatusCode::NOT_IMPLEMENTED, true));
    }
    if forward::via_loop(request.headers()) {
        return Ok(local(StatusCode::LOOP_DETECTED, true));
    }
    let target = match ValidatedTarget::parse(
        &raw,
        request.headers(),
        request.version(),
        HttpScheme::Http,
    ) {
        Ok(target) => target,
        Err(error) => return Ok(local(error.status(), true)),
    };
    let snapshot = match state.policy.current() {
        Ok(snapshot) => snapshot,
        Err(_) => return Ok(local(StatusCode::SERVICE_UNAVAILABLE, close)),
    };
    if evaluate(&snapshot, target.normalized()) == Decision::Blocked {
        return Ok(local(StatusCode::FORBIDDEN, close));
    }
    let Ok(permit) = state.requests.clone().try_acquire_owned() else {
        return Ok(local(StatusCode::SERVICE_UNAVAILABLE, close));
    };
    let response =
        match forward::forward(request, &target, &state.options, &state.tracker, permit).await {
            Ok(response) => response,
            Err(ForwardError::InvalidRequest) => local(StatusCode::BAD_REQUEST, true),
            Err(ForwardError::Gateway) => local(StatusCode::BAD_GATEWAY, true),
            Err(ForwardError::Timeout) => local(StatusCode::GATEWAY_TIMEOUT, true),
        };
    Ok(response)
}
