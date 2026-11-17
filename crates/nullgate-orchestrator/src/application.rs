//! Composition root: storage, activation and supervised DNS/HTTP/web services.
use crate::{
    ManagedProxy, PolicyCoordinator, PolicyHandle, PolicyOptions, ProxyFactory, RuntimeError,
    RuntimeMonitor, Supervisor,
};
use nullgate_core::PolicyManagement;
use nullgate_core::{
    AppConfig, FailureCode, FailureStage, PolicyFuture, PolicySubscription, ServiceFailure,
    ServiceKind, ServiceMonitor,
};
use nullgate_dns::{DnsOptions, DnsService};
use nullgate_http::{HttpOptions, HttpService, TunnelControl};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
pub struct Application {
    supervisor: Option<Supervisor>,
    coordinator: Option<PolicyCoordinator>,
    policy: PolicyHandle,
}
impl Application {
    /// Config must come from AppConfig's validated parsing/loading boundary.
    pub async fn start(config: AppConfig, cancel: CancellationToken) -> Result<Self, RuntimeError> {
        let metrics = nullgate_core::metrics::Metrics::default();
        let metrics_source = Arc::new(crate::metrics::RuntimeMetrics::new(metrics.clone()));
        let tunnels = TunnelControl::default();
        let coordinator = PolicyCoordinator::open(
            config.database_path(),
            PolicyOptions {
                metrics: metrics.clone(),
                queue_capacity: config.limits.storage_queue_capacity as usize,
                activators: vec![Arc::new(tunnels.clone())],
                ..PolicyOptions::default()
            },
        )
        .await
        .map_err(RuntimeError::Policy)?;
        let policy = coordinator.handle();
        let authentication = async {
            let oidc = if config.auth == nullgate_core::AuthMode::Oidc {
                Some(
                    nullgate_web::oidc::OidcService::open(
                        config
                            .oidc
                            .clone()
                            .ok_or(nullgate_web::AuthError::Invalid)?,
                    )
                    .await?,
                )
            } else {
                None
            };
            let auth = if let Some(provider) = &oidc {
                nullgate_web::AuthService::open_external(
                    config.database_path(),
                    provider.context().to_owned(),
                )
                .await?
            } else {
                nullgate_web::AuthService::open(config.database_path(), config.auth).await?
            };
            Ok::<_, nullgate_web::AuthError>((auth, oidc))
        }
        .await;
        let (auth, oidc) = match authentication {
            Ok(auth) => auth,
            Err(_) => {
                let _ = coordinator.shutdown().await;
                return Err(RuntimeError::InitialService(ServiceFailure {
                    service: ServiceKind::Web,
                    stage: FailureStage::Configure,
                    transport: None,
                    code: FailureCode::InvalidConfig,
                    io_kind: None,
                }));
            }
        };
        let data_dir = config.data_dir.clone();
        let ca = match tokio::task::spawn_blocking(move || {
            nullgate_http::ca::CaProvider::open(&data_dir).map(Arc::new)
        })
        .await
        {
            Ok(Ok(ca)) => ca,
            result => {
                let _ = coordinator.shutdown().await;
                return Err(RuntimeError::InspectionCa(match result {
                    Ok(Err(error)) => error,
                    _ => nullgate_http::ca::CaError::Crypto,
                }));
            }
        };
        let public_ca = ca.public_certificate();
        let inspection = match tokio::task::spawn_blocking(move || {
            nullgate_http::inspection::Inspection::with_system_roots(ca)
        })
        .await
        {
            Ok(Ok(inspection)) => inspection,
            result => {
                let _ = coordinator.shutdown().await;
                return Err(RuntimeError::InspectionTls(match result {
                    Ok(Err(error)) => error,
                    _ => nullgate_http::tls::TlsConfigError::InvalidTrustRoots,
                }));
            }
        };
        let factory = Arc::new(Services {
            metrics,
            metrics_source: metrics_source.clone(),
            inspection,
            config,
            public_ca,
            auth,
            oidc,
            management: Arc::new(policy.clone()),
            remote: Arc::new(crate::imports::RemoteService::new(
                Arc::new(policy.clone()),
                crate::imports::RemoteFetcher::new(
                    Arc::new(crate::imports::PublicFetchPolicy),
                    crate::imports::FetchOptions::default(),
                )
                .expect("valid default fetch bounds"),
            )),
            policy: policy.subscribe(),
            tunnels,
        });
        let supervisor = match Supervisor::start_with_web(factory, policy.subscribe(), cancel).await
        {
            Ok(supervisor) => supervisor,
            Err(error) => {
                let _ = coordinator.shutdown().await;
                return Err(error);
            }
        };
        metrics_source.attach(supervisor.monitor());
        Ok(Self {
            supervisor: Some(supervisor),
            coordinator: Some(coordinator),
            policy,
        })
    }
    pub fn monitor(&self) -> RuntimeMonitor {
        self.supervisor
            .as_ref()
            .expect("running application")
            .monitor()
    }
    pub fn policy(&self) -> PolicyHandle {
        self.policy.clone()
    }
    pub fn cancel(&self) {
        if let Some(supervisor) = &self.supervisor {
            supervisor.cancel();
        }
    }
    pub async fn wait(mut self) -> Result<(), RuntimeError> {
        let service_result = self
            .supervisor
            .take()
            .expect("running application")
            .wait()
            .await;
        let policy_result = self
            .coordinator
            .take()
            .expect("running policy")
            .shutdown()
            .await
            .map_err(RuntimeError::Policy);
        service_result.and(policy_result)
    }
    pub async fn shutdown(self) -> Result<(), RuntimeError> {
        self.cancel();
        self.wait().await
    }
}
impl Drop for Application {
    fn drop(&mut self) {
        self.cancel();
    }
}
struct Services {
    metrics: nullgate_core::metrics::Metrics,
    metrics_source: Arc<crate::metrics::RuntimeMetrics>,
    config: AppConfig,
    auth: nullgate_web::AuthService,
    oidc: Option<Arc<nullgate_web::oidc::OidcService>>,
    public_ca: Arc<dyn nullgate_core::PublicCaCertificate>,
    inspection: Arc<nullgate_http::inspection::Inspection>,
    management: Arc<dyn PolicyManagement>,
    remote: Arc<dyn nullgate_core::RemoteManagement>,
    policy: PolicySubscription,
    tunnels: TunnelControl,
}
struct Dns(DnsService);
impl ManagedProxy for Dns {
    fn monitor(&self) -> ServiceMonitor {
        self.0.monitor()
    }
    fn shutdown(self: Box<Self>) -> PolicyFuture<'static, Result<(), ServiceFailure>> {
        Box::pin(async move { self.0.shutdown().await })
    }
}
struct Http(HttpService);
impl ManagedProxy for Http {
    fn monitor(&self) -> ServiceMonitor {
        self.0.monitor()
    }
    fn shutdown(self: Box<Self>) -> PolicyFuture<'static, Result<(), ServiceFailure>> {
        Box::pin(async move { self.0.shutdown().await })
    }
}
struct Web(nullgate_web::WebService);
impl ManagedProxy for Web {
    fn monitor(&self) -> ServiceMonitor {
        self.0.monitor()
    }
    fn shutdown(self: Box<Self>) -> PolicyFuture<'static, Result<(), ServiceFailure>> {
        Box::pin(async move { self.0.shutdown().await })
    }
}
impl ProxyFactory for Services {
    fn start(
        &self,
        kind: ServiceKind,
        cancel: CancellationToken,
    ) -> PolicyFuture<'_, Result<Box<dyn ManagedProxy>, ServiceFailure>> {
        Box::pin(async move {
            let limit = self.config.limits.max_connections as usize;
            match kind {
                ServiceKind::Dns => Ok(Box::new(Dns(DnsService::start(
                    self.config.dns.clone(),
                    self.policy.clone(),
                    DnsOptions {
                        metrics: self.metrics.clone(),
                        max_requests: limit,
                        max_tcp_connections: limit,
                        ..DnsOptions::default()
                    },
                    cancel,
                )
                .await?)) as Box<dyn ManagedProxy>),
                ServiceKind::Http => Ok(Box::new(Http(
                    HttpService::start_with_inspection(
                        self.config.http.clone(),
                        self.policy.clone(),
                        HttpOptions {
                            metrics: self.metrics.clone(),
                            max_connections: limit,
                            max_requests: limit,
                            ..HttpOptions::default()
                        },
                        cancel,
                        self.tunnels.clone(),
                        self.inspection.clone(),
                    )
                    .await?,
                )) as Box<dyn ManagedProxy>),
                ServiceKind::Web => Ok(Box::new(Web(
                    nullgate_web::WebService::start_with_capabilities(
                        self.config.web.clone(),
                        self.auth.clone(),
                        self.management.clone(),
                        nullgate_web::WebCapabilities {
                            metrics: Some(self.metrics_source.clone()),
                            remote: Some(self.remote.clone()),
                            public_ca: Some(self.public_ca.clone()),
                            https_inspection: true,
                            oidc: self.oidc.clone(),
                        },
                        limit,
                        cancel,
                    )
                    .await?,
                )) as Box<dyn ManagedProxy>),
            }
        })
    }
}
