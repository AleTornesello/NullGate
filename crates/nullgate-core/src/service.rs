//! Shared service lifecycle reporting without dependencies on individual services.
use std::{fmt, net::SocketAddr};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceKind {
    Dns,
    Http,
    Web,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceTransport {
    Udp,
    Tcp,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundListener {
    pub transport: ServiceTransport,
    pub address: SocketAddr,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceReadiness {
    pub service: ServiceKind,
    pub listeners: Vec<BoundListener>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureStage {
    Configure,
    Bind,
    Run,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureCode {
    InvalidConfig,
    BindFailed,
    ListenerIo,
    WorkerPanicked,
    WorkerLost,
    Cancelled,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceFailure {
    pub service: ServiceKind,
    pub stage: FailureStage,
    pub transport: Option<ServiceTransport>,
    pub code: FailureCode,
    pub io_kind: Option<std::io::ErrorKind>,
}
impl fmt::Display for ServiceFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} service {:?} failure ({:?})",
            self.service, self.stage, self.code
        )
    }
}
impl std::error::Error for ServiceFailure {}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceStatus {
    Starting,
    Ready(ServiceReadiness),
    Failed(ServiceFailure),
    Stopped,
}
#[derive(Clone, Debug)]
/// Read-only lifecycle state. Unexpected channel loss cannot leave readiness falsely active.
pub struct ServiceMonitor {
    service: ServiceKind,
    receiver: tokio::sync::watch::Receiver<ServiceStatus>,
}
impl ServiceMonitor {
    pub fn current(&self) -> ServiceStatus {
        let status = self.receiver.borrow().clone();
        if self.receiver.has_changed().is_err()
            && matches!(status, ServiceStatus::Starting | ServiceStatus::Ready(_))
        {
            ServiceStatus::Failed(ServiceFailure {
                service: self.service,
                stage: FailureStage::Run,
                transport: None,
                code: FailureCode::WorkerLost,
                io_kind: None,
            })
        } else {
            status
        }
    }
    /// Wait for a change; Failed/Stopped are terminal, so callers must stop their monitor loop.
    pub async fn changed(&mut self) -> ServiceStatus {
        let _ = self.receiver.changed().await;
        self.current()
    }
}

/// Service implementations retain the sender; orchestration receives only the monitor.
pub fn service_status_channel(
    service: ServiceKind,
) -> (tokio::sync::watch::Sender<ServiceStatus>, ServiceMonitor) {
    let (sender, receiver) = tokio::sync::watch::channel(ServiceStatus::Starting);
    (sender, ServiceMonitor { service, receiver })
}
