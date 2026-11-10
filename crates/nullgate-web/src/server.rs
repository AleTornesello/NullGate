//! Cancellable, bound-before-ready administration listener over trusted HTTP/TLS transport.
use crate::{AuthService, WebSecurity, WebState, management_routes};
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{
        StatusCode,
        header::{CONNECTION, HeaderValue},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use hyper::body::{Body as HttpBody, Bytes, Frame, SizeHint};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use nullgate_core::{
    BoundListener, FailureCode, FailureStage, PolicyManagement, ServiceFailure, ServiceKind,
    ServiceMonitor, ServiceReadiness, ServiceStatus, ServiceTransport, WebConfig,
    service_status_channel,
};
use std::{
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore},
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;
pub struct WebService {
    address: SocketAddr,
    monitor: ServiceMonitor,
    cancel: CancellationToken,
    worker: Option<JoinHandle<Result<(), ServiceFailure>>>,
}
fn failure(
    stage: FailureStage,
    code: FailureCode,
    io_kind: Option<std::io::ErrorKind>,
) -> ServiceFailure {
    ServiceFailure {
        service: ServiceKind::Web,
        stage,
        code,
        transport: Some(ServiceTransport::Tcp),
        io_kind,
    }
}
impl WebService {
    pub async fn start(
        config: WebConfig,
        auth: AuthService,
        management: Arc<dyn PolicyManagement>,
        limit: usize,
        cancel: CancellationToken,
    ) -> Result<Self, ServiceFailure> {
        if limit == 0
            || limit > 65535
            || config.tls_terminated_by_proxy
                && (!config.listen.ip().is_loopback()
                    || config.tls.is_some()
                    || config.public_origin.is_none())
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
        let tls = if let Some(files) = config.tls.clone() {
            Some(
                tokio::task::spawn_blocking(move || {
                    let mut cert = std::io::BufReader::new(std::io::Cursor::new(read_pem(
                        &files.certificate_file,
                        false,
                    )?));
                    let certificates = rustls_pemfile::certs(&mut cert)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| ())?;
                    let mut key = std::io::BufReader::new(std::io::Cursor::new(read_pem(
                        &files.private_key_file,
                        true,
                    )?));
                    let key = rustls_pemfile::private_key(&mut key)
                        .map_err(|_| ())?
                        .ok_or(())?;
                    let mut server = rustls::ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(certificates, key)
                        .map_err(|_| ())?;
                    server.alpn_protocols = vec![b"http/1.1".to_vec()];
                    Ok::<_, ()>(tokio_rustls::TlsAcceptor::from(Arc::new(server)))
                })
                .await
                .map_err(|_| failure(FailureStage::Configure, FailureCode::InvalidConfig, None))?
                .map_err(|_| failure(FailureStage::Configure, FailureCode::InvalidConfig, None))?,
            )
        } else {
            None
        };
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
        let secure = tls.is_some() || config.tls_terminated_by_proxy;
        let origin = match config.public_origin {
            Some(origin) => origin,
            None => {
                if address.ip().is_unspecified() {
                    return Err(failure(
                        FailureStage::Configure,
                        FailureCode::InvalidConfig,
                        None,
                    ));
                }
                format!("{}://{address}", if secure { "https" } else { "http" })
            }
        };
        let security = if config.tls_terminated_by_proxy {
            WebSecurity::loopback_tls_proxy(address, &origin)
        } else if tls.is_some() {
            WebSecurity::direct_https(address, &origin)
        } else {
            WebSecurity::loopback_http(address, &origin)
        }
        .map_err(|_| failure(FailureStage::Configure, FailureCode::InvalidConfig, None))?;
        let state = WebState::new(auth, security, management);
        let router = crate::router(state, management_routes()).layer(
            middleware::from_fn_with_state(Arc::new(Semaphore::new(limit.min(16))), admission),
        );
        let (status, monitor) = service_status_channel(ServiceKind::Web);
        status.send_replace(ServiceStatus::Ready(ServiceReadiness {
            service: ServiceKind::Web,
            listeners: vec![BoundListener {
                transport: ServiceTransport::Tcp,
                address,
            }],
        }));
        let cancel = cancel.child_token();
        let token = cancel.clone();
        let worker = tokio::spawn(async move {
            let result = serve(listener, tls, router, limit, token).await;
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
        self.worker
            .take()
            .unwrap()
            .await
            .map_err(|_| failure(FailureStage::Run, FailureCode::WorkerLost, None))?
    }
}
impl Drop for WebService {
    fn drop(&mut self) {
        self.cancel();
    }
}
async fn serve(
    listener: TcpListener,
    tls: Option<tokio_rustls::TlsAcceptor>,
    router: Router,
    limit: usize,
    cancel: CancellationToken,
) -> Result<(), ServiceFailure> {
    let permits = Arc::new(Semaphore::new(limit));
    let mut clients = JoinSet::new();
    let result = loop {
        tokio::select! {
        biased;
        _=cancel.cancelled()=>break Ok(()),
        Some(done)=clients.join_next(),if !clients.is_empty()=>{if done.is_err(){break Err(failure(FailureStage::Run,FailureCode::WorkerPanicked,None));}},
        accepted=listener.accept()=>{let(stream,_)=match accepted{Ok(stream)=>stream,Err(error)if matches!(error.kind(),std::io::ErrorKind::Interrupted|std::io::ErrorKind::ConnectionAborted)=>continue,Err(error)=>break Err(failure(FailureStage::Run,FailureCode::ListenerIo,Some(error.kind())))};let Ok(permit)=permits.clone().try_acquire_owned()else{drop(stream);continue;};let tls=tls.clone();let router=router.clone();clients.spawn(async move{let _permit=permit;match tls{Some(tls)=>{if let Ok(Ok(stream))=tokio::time::timeout(Duration::from_secs(10),tls.accept(stream)).await{connection(stream,router).await;}},None=>connection(stream,router).await}});}
        }
    };
    clients.shutdown().await;
    result
}
async fn connection<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(
    stream: T,
    router: Router,
) {
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(30))
        .max_headers(100)
        .max_buf_size(32768);
    let _ = builder
        .serve_connection(TokioIo::new(stream), TowerToHyperService::new(router))
        .await;
}
fn unavailable(status: StatusCode, message: &'static str) -> Response {
    let mut response = (status, message).into_response();
    response
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
    response
}
async fn admission(State(gate): State<Arc<Semaphore>>, request: Request, next: Next) -> Response {
    let Ok(permit) = gate.try_acquire_owned() else {
        return unavailable(
            StatusCode::SERVICE_UNAVAILABLE,
            "Administration busy; retry after reading current state",
        );
    };
    match tokio::time::timeout(Duration::from_secs(30), next.run(request)).await {
        Ok(response) => response.map(|body| {
            Body::new(AdmittedBody {
                body,
                permit: Some(permit),
            })
        }),
        Err(_) => unavailable(
            StatusCode::GATEWAY_TIMEOUT,
            "Request timed out; outcome may be unknown. Reload current state before retrying.",
        ),
    }
}
struct AdmittedBody {
    body: Body,
    permit: Option<OwnedSemaphorePermit>,
}
impl HttpBody for AdmittedBody {
    type Data = Bytes;
    type Error = axum::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        let frame = Pin::new(&mut self.body).poll_frame(cx);
        if matches!(frame, Poll::Ready(None) | Poll::Ready(Some(Err(_)))) {
            self.permit.take();
        }
        frame
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

// Configured TLS material is bounded and never reflected in diagnostics.
fn read_pem(path: &std::path::Path, private: bool) -> Result<Vec<u8>, ()> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if private && metadata.permissions().mode() & 0o077 != 0 {
            return Err(());
        }
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > 1024 * 1024 {
        return Err(());
    }
    Ok(bytes)
}
