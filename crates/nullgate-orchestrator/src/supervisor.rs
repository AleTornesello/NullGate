//! Bound-service supervision and safe aggregate health.
use nullgate_core::{
    PolicyError, PolicyFuture, PolicySubscription, ServiceFailure, ServiceKind, ServiceMonitor,
    ServiceReadiness, UnavailableReason,
};
use std::{fmt, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
/// Shutdown must cancel and join all work, releasing listeners before returning even on failure.
pub trait ManagedProxy: Send {
    fn monitor(&self) -> ServiceMonitor;
    fn shutdown(self: Box<Self>) -> PolicyFuture<'static, Result<(), ServiceFailure>>;
}
/// Startup is cancellation-safe; success must carry readiness after binding, never a promise to bind.
pub trait ProxyFactory: Send + Sync {
    fn start(
        &self,
        kind: ServiceKind,
        cancel: CancellationToken,
    ) -> PolicyFuture<'_, Result<Box<dyn ManagedProxy>, ServiceFailure>>;
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProxyPhase {
    Starting,
    Ready(ServiceReadiness),
    Backoff { attempt: u32, delay: Duration },
    Stopped,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyHealth {
    pub phase: ProxyPhase,
    pub restarts: u64,
    pub last_failure: Option<ServiceFailure>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimePhase {
    Running,
    Stopping,
    Stopped,
    Failed,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeStatus {
    pub phase: RuntimePhase,
    pub dns: ProxyHealth,
    pub http: ProxyHealth,
    pub web: Option<ProxyHealth>,
    pub policy_revision: u64,
    pub policy_unavailable: Option<UnavailableReason>,
}
impl RuntimeStatus {
    pub fn is_ready(&self) -> bool {
        self.phase == RuntimePhase::Running
            && self.policy_unavailable.is_none()
            && matches!(self.dns.phase, ProxyPhase::Ready(_))
            && matches!(self.http.phase, ProxyPhase::Ready(_))
            && self
                .web
                .as_ref()
                .is_none_or(|web| matches!(web.phase, ProxyPhase::Ready(_)))
    }
}
#[derive(Clone, Debug)]
pub struct RuntimeMonitor {
    receiver: tokio::sync::watch::Receiver<RuntimeStatus>,
    policy: PolicySubscription,
}
impl RuntimeMonitor {
    pub fn current(&self) -> RuntimeStatus {
        let mut state = self.receiver.borrow().clone();
        match self.policy.current() {
            Ok(policy) => {
                state.policy_revision = policy.revision();
                state.policy_unavailable = None;
            }
            Err(error) => {
                state.policy_revision = error.revision;
                state.policy_unavailable = Some(error.reason);
            }
        }
        if self.receiver.has_changed().is_err()
            && matches!(state.phase, RuntimePhase::Running | RuntimePhase::Stopping)
        {
            state.phase = RuntimePhase::Failed;
        }
        state
    }
    pub async fn changed(&mut self) -> RuntimeStatus {
        let _ = self.receiver.changed().await;
        self.current()
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    InspectionCa(nullgate_http::ca::CaError),
    InitialService(ServiceFailure),
    InvalidReadiness(ServiceKind),
    Policy(PolicyError),
    PolicyUnavailable,
    WorkerLost,
    Cancelled,
}
impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InspectionCa(error) => write!(f, "Initial startup failed: {error}"),
            Self::InitialService(error) => write!(f, "Initial startup failed: {error}"),
            Self::InvalidReadiness(kind) => write!(f, "{kind:?} reported invalid readiness"),
            Self::Policy(error) => write!(f, "Policy owner failed: {error}"),
            Self::PolicyUnavailable => f.write_str("Policy owner unavailable"),
            Self::WorkerLost => f.write_str("Supervisor worker failed"),
            Self::Cancelled => f.write_str("Startup cancelled"),
        }
    }
}
impl std::error::Error for RuntimeError {}
pub struct Supervisor {
    monitor: RuntimeMonitor,
    cancel: CancellationToken,
    worker: Option<tokio::task::JoinHandle<Result<(), RuntimeError>>>,
}
impl Supervisor {
    pub async fn start(
        factory: Arc<dyn ProxyFactory>,
        policy: PolicySubscription,
        cancel: CancellationToken,
    ) -> Result<Self, RuntimeError> {
        Self::start_services(factory, policy, cancel, false).await
    }
    pub async fn start_with_web(
        factory: Arc<dyn ProxyFactory>,
        policy: PolicySubscription,
        cancel: CancellationToken,
    ) -> Result<Self, RuntimeError> {
        Self::start_services(factory, policy, cancel, true).await
    }
    async fn start_services(
        factory: Arc<dyn ProxyFactory>,
        policy: PolicySubscription,
        cancel: CancellationToken,
        with_web: bool,
    ) -> Result<Self, RuntimeError> {
        let cancel = cancel.child_token();
        if cancel.is_cancelled() {
            return Err(RuntimeError::Cancelled);
        }
        let dns = start_one(&factory, ServiceKind::Dns, &cancel).await?;
        let http = match start_one(&factory, ServiceKind::Http, &cancel).await {
            Ok(service) => service,
            Err(error) => {
                let _ = dns.shutdown().await;
                return Err(error);
            }
        };
        let web = if with_web {
            match start_one(&factory, ServiceKind::Web, &cancel).await {
                Ok(web) => Some(web),
                Err(error) => {
                    let _ = http.shutdown().await;
                    let _ = dns.shutdown().await;
                    return Err(error);
                }
            }
        } else {
            None
        };
        let web_readiness = web
            .as_ref()
            .map(|web| ready(&**web, ServiceKind::Web))
            .transpose();
        let readiness = ready(&*dns, ServiceKind::Dns)
            .and_then(|dns| ready(&*http, ServiceKind::Http).map(|http| (dns, http)));
        let initial = policy.current();
        if readiness.is_err() || web_readiness.is_err() || initial.is_err() || cancel.is_cancelled()
        {
            if let Some(web) = web {
                let _ = web.shutdown().await;
            }
            let _ = http.shutdown().await;
            let _ = dns.shutdown().await;
            return Err(readiness.err().or(web_readiness.err()).unwrap_or(
                if cancel.is_cancelled() {
                    RuntimeError::Cancelled
                } else {
                    RuntimeError::PolicyUnavailable
                },
            ));
        }
        let (dns_ready, http_ready) = readiness.unwrap();
        let revision = initial.unwrap().revision();
        let initial = RuntimeStatus {
            phase: RuntimePhase::Running,
            dns: ProxyHealth {
                phase: ProxyPhase::Ready(dns_ready),
                restarts: 0,
                last_failure: None,
            },
            http: ProxyHealth {
                phase: ProxyPhase::Ready(http_ready),
                restarts: 0,
                last_failure: None,
            },
            web: web_readiness.unwrap().map(|ready| ProxyHealth {
                phase: ProxyPhase::Ready(ready),
                restarts: 0,
                last_failure: None,
            }),
            policy_revision: revision,
            policy_unavailable: None,
        };
        let (sender, receiver) = tokio::sync::watch::channel(initial);
        let monitor = RuntimeMonitor {
            receiver,
            policy: policy.clone(),
        };
        let token = cancel.clone();
        let worker = tokio::spawn(async move {
            let _cancel_on_exit = token.clone().drop_guard();
            let mut children = tokio::task::JoinSet::new();
            children.spawn(supervise(
                ServiceKind::Dns,
                dns,
                factory.clone(),
                sender.clone(),
                token.clone(),
            ));
            children.spawn(supervise(
                ServiceKind::Http,
                http,
                factory.clone(),
                sender.clone(),
                token.clone(),
            ));
            if let Some(web) = web {
                children.spawn(supervise(
                    ServiceKind::Web,
                    web,
                    factory,
                    sender.clone(),
                    token.clone(),
                ));
            }
            let mut policy = policy;
            let mut result = loop {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => break Ok(()),
                    _ = children.join_next() => break Err(RuntimeError::WorkerLost),
                    changed = policy.changed() => {
                        let stopped = matches!(changed, Err(error) if error.reason == UnavailableReason::Stopped);
                        sender.send_modify(|state| match changed {
                            Ok(ref snapshot) => {
                                state.policy_revision = snapshot.revision();
                                state.policy_unavailable = None;
                            }
                            Err(error) => {
                                state.policy_revision = error.revision;
                                state.policy_unavailable = Some(error.reason);
                            }
                        });
                        if stopped { break Err(RuntimeError::PolicyUnavailable); }
                    }
                }
            };
            sender.send_modify(|state| state.phase = RuntimePhase::Stopping);
            token.cancel();
            while let Some(completed) = children.join_next().await {
                if completed.is_err() {
                    result = Err(RuntimeError::WorkerLost);
                }
            }
            sender.send_modify(|state| {
                state.phase = if result.is_ok() {
                    RuntimePhase::Stopped
                } else {
                    RuntimePhase::Failed
                }
            });
            result
        });
        Ok(Self {
            monitor,
            cancel,
            worker: Some(worker),
        })
    }
    pub fn monitor(&self) -> RuntimeMonitor {
        self.monitor.clone()
    }
    pub fn cancel(&self) {
        self.cancel.cancel();
    }
    pub async fn wait(mut self) -> Result<(), RuntimeError> {
        self.worker
            .take()
            .unwrap()
            .await
            .map_err(|_| RuntimeError::WorkerLost)?
    }
    pub async fn shutdown(self) -> Result<(), RuntimeError> {
        self.cancel();
        self.wait().await
    }
}
impl Drop for Supervisor {
    fn drop(&mut self) {
        self.cancel();
    }
}

async fn start_one(
    factory: &Arc<dyn ProxyFactory>,
    kind: ServiceKind,
    cancel: &CancellationToken,
) -> Result<Box<dyn ManagedProxy>, RuntimeError> {
    let instance = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err(RuntimeError::Cancelled),
        result = factory.start(kind, cancel.child_token()) => result.map_err(RuntimeError::InitialService)?,
    };
    if let Err(error) = ready(&*instance, kind) {
        let _ = instance.shutdown().await;
        return Err(error);
    }
    Ok(instance)
}
fn ready(instance: &dyn ManagedProxy, kind: ServiceKind) -> Result<ServiceReadiness, RuntimeError> {
    match instance.monitor().current() {
        nullgate_core::ServiceStatus::Ready(ready)
            if ready.service == kind
                && !ready.listeners.is_empty()
                && ready
                    .listeners
                    .iter()
                    .all(|listener| listener.address.port() != 0) =>
        {
            Ok(ready)
        }
        nullgate_core::ServiceStatus::Failed(error) => Err(RuntimeError::InitialService(error)),
        _ => Err(RuntimeError::InvalidReadiness(kind)),
    }
}
fn update(
    sender: &tokio::sync::watch::Sender<RuntimeStatus>,
    kind: ServiceKind,
    change: impl FnOnce(&mut ProxyHealth),
) {
    sender.send_modify(|state| {
        change(match kind {
            ServiceKind::Dns => &mut state.dns,
            ServiceKind::Http => &mut state.http,
            ServiceKind::Web => state.web.as_mut().expect("web supervision enabled"),
        })
    });
}
fn unexpected_stop(kind: ServiceKind) -> ServiceFailure {
    ServiceFailure {
        service: kind,
        stage: nullgate_core::FailureStage::Run,
        transport: None,
        code: nullgate_core::FailureCode::WorkerLost,
        io_kind: None,
    }
}
async fn supervise(
    kind: ServiceKind,
    first: Box<dyn ManagedProxy>,
    factory: Arc<dyn ProxyFactory>,
    sender: tokio::sync::watch::Sender<RuntimeStatus>,
    cancel: CancellationToken,
) {
    let mut instance = Some(first);
    let mut since = tokio::time::Instant::now();
    let mut streak = 0u32;
    let mut failed_start = None;
    loop {
        let failure = if let Some(service) = instance.take() {
            let mut monitor = service.monitor();
            let failure = loop {
                let status = monitor.current();
                match status {
                    nullgate_core::ServiceStatus::Failed(error) => break error,
                    nullgate_core::ServiceStatus::Stopped => break unexpected_stop(kind),
                    _ => {}
                }
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {
                        let _ = service.shutdown().await;
                        update(&sender, kind, |health| health.phase = ProxyPhase::Stopped);
                        return;
                    }
                    _ = monitor.changed() => {},
                }
            };
            if since.elapsed() >= Duration::from_secs(60) {
                streak = 0;
            }
            update(&sender, kind, |health| {
                health.phase = ProxyPhase::Starting;
                health.last_failure = Some(failure);
            });
            // Never replace an instance until it has relinquished listeners and work.
            let _ = service.shutdown().await;
            failure
        } else {
            failed_start.take().expect("retry follows a failed start")
        };
        if cancel.is_cancelled() {
            break;
        }
        streak = streak.saturating_add(1);
        let delay = Duration::from_secs((1u64 << streak.saturating_sub(1).min(5)).min(30));
        update(&sender, kind, |health| {
            health.phase = ProxyPhase::Backoff {
                attempt: streak,
                delay,
            };
            health.last_failure = Some(failure);
        });
        tracing::warn!(service=?kind,code=?failure.code,stage=?failure.stage,delay_ms=delay.as_millis() as u64,"proxy restart scheduled");
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(delay) => {},
        }
        update(&sender, kind, |health| {
            health.phase = ProxyPhase::Starting;
            health.restarts = health.restarts.saturating_add(1);
        });
        let started = tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            result = factory.start(kind, cancel.child_token()) => result,
        };
        match started {
            Ok(service) => match ready(&*service, kind) {
                Ok(readiness) => {
                    since = tokio::time::Instant::now();
                    update(&sender, kind, |health| {
                        health.phase = ProxyPhase::Ready(readiness)
                    });
                    instance = Some(service);
                }
                Err(_) => {
                    let _ = service.shutdown().await;
                    let mut failure = unexpected_stop(kind);
                    failure.code = nullgate_core::FailureCode::InvalidConfig;
                    failed_start = Some(failure);
                }
            },
            Err(error) => failed_start = Some(error),
        }
    }
    update(&sender, kind, |health| health.phase = ProxyPhase::Stopped);
}
