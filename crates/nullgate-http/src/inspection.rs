//! HTTPS HTTP/1 inspection with per-request policy and CONNECT authority binding.
use crate::{
    ca::CaProvider,
    forward::{self, ForwardError, ProxyBody},
    ingress::{GuardedIo, Heads, Ingress},
    policy::{Decision, ValidatedTarget, evaluate},
    server::{HttpOptions, local},
    tls::TlsConfigError,
};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Body, Incoming},
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use nullgate_core::{HttpScheme, NormalizedAuthority, PolicySubscription};
use std::{
    collections::VecDeque,
    convert::Infallible,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Semaphore,
};
use tokio_util::task::TaskTracker;
/// Trusted constructor accepts roots, never an arbitrary verifier or insecure TLS setting.
pub struct Inspection {
    pub(crate) ca: Arc<CaProvider>,
    pub(crate) upstream: Arc<rustls::ClientConfig>,
    pub(crate) signing: Arc<Semaphore>,
}
impl Inspection {
    pub fn new(
        ca: Arc<CaProvider>,
        roots: rustls::RootCertStore,
    ) -> Result<Arc<Self>, TlsConfigError> {
        Ok(Arc::new(Self {
            ca,
            upstream: crate::tls::client_config(roots)?,
            signing: Arc::new(Semaphore::new(4)),
        }))
    }
    pub fn with_system_roots(ca: Arc<CaProvider>) -> Result<Arc<Self>, TlsConfigError> {
        Self::new(ca, crate::tls::system_roots()?)
    }
}
pub(crate) struct Context {
    pub target: NormalizedAuthority,
    pub policy: PolicySubscription,
    pub options: HttpOptions,
    pub requests: Arc<Semaphore>,
    pub inspection: Arc<Inspection>,
    pub tracker: TaskTracker,
}
pub(crate) async fn serve<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    io: S,
    context: Context,
) {
    let io = match tokio::time::timeout(
        context.options.connect_timeout,
        crate::tls::accept(
            io,
            context.target.host(),
            &context.inspection,
            &context.tracker,
        ),
    )
    .await
    {
        Ok(Ok(io)) => io,
        _ => return,
    };
    let heads: Heads = Arc::new(Mutex::new(VecDeque::new()));
    let io = GuardedIo::new(io, heads.clone());
    let deadline = context.options.request_header_timeout;
    let context = Arc::new(context);
    let service = service_fn(move |request| handle(request, context.clone(), heads.clone()));
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(deadline)
        .max_headers(100)
        .max_buf_size(32768);
    let _ = builder.serve_connection(TokioIo::new(io), service).await;
}
async fn handle(
    request: Request<Incoming>,
    context: Arc<Context>,
    heads: Heads,
) -> Result<Response<ProxyBody>, Infallible> {
    let raw = match heads.lock().unwrap().pop_front() {
        Some(Ingress::Accepted(raw)) => raw,
        Some(Ingress::Rejected(status)) => return Ok(local(status, true)),
        None => return Ok(local(StatusCode::BAD_REQUEST, true)),
    };
    if request.version() != hyper::Version::HTTP_11 {
        return Ok(local(StatusCode::HTTP_VERSION_NOT_SUPPORTED, true));
    }
    if request.method() == Method::CONNECT || request.headers().contains_key(hyper::header::UPGRADE)
    {
        return Ok(local(StatusCode::NOT_IMPLEMENTED, true));
    }
    if forward::via_loop(request.headers()) {
        return Ok(local(StatusCode::LOOP_DETECTED, true));
    }
    let close = !request.body().is_end_stream();
    let target = match ValidatedTarget::parse(
        &raw,
        request.headers(),
        request.version(),
        HttpScheme::Https,
    ) {
        Ok(target) => target,
        Err(error) => return Ok(local(error.status(), true)),
    };
    if target.normalized().host() != context.target.host()
        || target.normalized().port() != context.target.port()
    {
        return Ok(local(StatusCode::MISDIRECTED_REQUEST, true));
    }
    let snapshot = match context.policy.current() {
        Ok(snapshot) => snapshot,
        Err(_) => return Ok(local(StatusCode::SERVICE_UNAVAILABLE, close)),
    };
    if evaluate(&snapshot, target.normalized()) == Decision::Blocked {
        context.options.metrics.decision(
            nullgate_core::metrics::Traffic::Https,
            nullgate_core::metrics::DecisionKind::Blocked,
        );
        return Ok(local(StatusCode::FORBIDDEN, close));
    }
    context.options.metrics.decision(
        nullgate_core::metrics::Traffic::Https,
        nullgate_core::metrics::DecisionKind::Allowed,
    );
    let Ok(permit) = context.requests.clone().try_acquire_owned() else {
        return Ok(local(StatusCode::SERVICE_UNAVAILABLE, close));
    };
    Ok(
        match forward::forward_https(
            request,
            &target,
            &context.options,
            &context.tracker,
            permit,
            context.inspection.upstream.clone(),
        )
        .await
        {
            Ok(response) => response,
            Err(ForwardError::InvalidRequest) => local(StatusCode::BAD_REQUEST, true),
            Err(ForwardError::Gateway) => local(StatusCode::BAD_GATEWAY, true),
            Err(ForwardError::Timeout) => local(StatusCode::GATEWAY_TIMEOUT, true),
        },
    )
}
