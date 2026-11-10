//! Composition root: storage, activation and supervised DNS/HTTP, without web startup.
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
        let tunnels = TunnelControl::default();
        let coordinator = PolicyCoordinator::open(
            config.database_path(),
            PolicyOptions {
                queue_capacity: config.limits.storage_queue_capacity as usize,
                activators: vec![Arc::new(tunnels.clone())],
                ..PolicyOptions::default()
            },
        )
        .await
        .map_err(RuntimeError::Policy)?;
        let policy = coordinator.handle();
        let factory = Arc::new(Services {
            config,
            policy: policy.subscribe(),
            tunnels,
        });
        let supervisor = match Supervisor::start(factory, policy.subscribe(), cancel).await {
            Ok(supervisor) => supervisor,
            Err(error) => {
                let _ = coordinator.shutdown().await;
                return Err(error);
            }
        };
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
    config: AppConfig,
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
                        max_requests: limit,
                        max_tcp_connections: limit,
                        ..DnsOptions::default()
                    },
                    cancel,
                )
                .await?)) as Box<dyn ManagedProxy>),
                ServiceKind::Http => Ok(Box::new(Http(
                    HttpService::start_with_tunnel_control(
                        self.config.http.clone(),
                        self.policy.clone(),
                        HttpOptions {
                            max_connections: limit,
                            max_requests: limit,
                            ..HttpOptions::default()
                        },
                        cancel,
                        self.tunnels.clone(),
                    )
                    .await?,
                )) as Box<dyn ManagedProxy>),
                ServiceKind::Web => Err(ServiceFailure {
                    service: kind,
                    stage: FailureStage::Configure,
                    transport: None,
                    code: FailureCode::InvalidConfig,
                    io_kind: None,
                }),
            }
        })
    }
}
