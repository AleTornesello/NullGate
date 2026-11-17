//! Read-only adaptation of live supervisor health into core metrics, without a web dependency.
use crate::{ProxyHealth, ProxyPhase, RuntimeMonitor, RuntimePhase};
use nullgate_core::metrics::{
    HealthMetrics, MetricPhase, Metrics, MetricsSnapshot, MetricsSource, ServiceMetrics,
};
use std::sync::RwLock;
pub struct RuntimeMetrics {
    counters: Metrics,
    monitor: RwLock<Option<RuntimeMonitor>>,
}
impl RuntimeMetrics {
    pub fn new(counters: Metrics) -> Self {
        Self {
            counters,
            monitor: RwLock::new(None),
        }
    }
    /// Attach only after startup has bound and verified all listeners. Until then health is unknown.
    pub fn attach(&self, monitor: RuntimeMonitor) {
        *self
            .monitor
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(monitor);
    }
}
fn service(health: &ProxyHealth, runtime: RuntimePhase) -> ServiceMetrics {
    let phase = match runtime {
        RuntimePhase::Stopping => MetricPhase::Stopping,
        RuntimePhase::Stopped => MetricPhase::Stopped,
        RuntimePhase::Failed => MetricPhase::Failed,
        RuntimePhase::Running => match health.phase {
            ProxyPhase::Starting => MetricPhase::Starting,
            ProxyPhase::Ready(_) => MetricPhase::Ready,
            ProxyPhase::Backoff { .. } => MetricPhase::Backoff,
            ProxyPhase::Stopped => MetricPhase::Stopped,
        },
    };
    ServiceMetrics {
        phase,
        restarts: health.restarts,
    }
}
impl MetricsSource for RuntimeMetrics {
    fn snapshot(&self) -> MetricsSnapshot {
        let mut snapshot = self.counters.snapshot();
        if let Some(monitor) = self
            .monitor
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            let status = monitor.current();
            snapshot.health = Some(HealthMetrics {
                dns: service(&status.dns, status.phase),
                http: service(&status.http, status.phase),
                web: status.web.as_ref().map(|web| service(web, status.phase)),
                policy_available: status.policy_unavailable.is_none(),
                ready: status.is_ready(),
            });
        }
        snapshot
    }
}
