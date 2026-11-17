//! Fixed-cardinality process-lifetime aggregates. No labels, request text or history are retained.
use crate::ServiceKind;
use serde::Serialize;
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Clone, Copy, Debug)]
pub enum Traffic {
    Dns,
    Http,
    Https,
    Connect,
}
#[derive(Clone, Copy, Debug)]
pub enum DecisionKind {
    Allowed,
    Blocked,
}
#[derive(Clone, Copy, Debug)]
pub enum ImportResult {
    Succeeded,
    Partial,
    Rejected,
    Failed,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Decisions {
    pub allowed: u64,
    pub blocked: u64,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Imports {
    pub succeeded: u64,
    pub partial: u64,
    pub rejected: u64,
    pub failed: u64,
    pub accepted_lines: u64,
    pub malformed_lines: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricPhase {
    Starting,
    Ready,
    Backoff,
    Stopping,
    Stopped,
    Failed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ServiceMetrics {
    pub phase: MetricPhase,
    pub restarts: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct HealthMetrics {
    pub dns: ServiceMetrics,
    pub http: ServiceMetrics,
    pub web: Option<ServiceMetrics>,
    pub policy_available: bool,
    pub ready: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct MetricsSnapshot {
    pub uptime_seconds: u64,
    pub dns: Decisions,
    pub http: Decisions,
    pub https: Decisions,
    pub connect: Decisions,
    pub active_dns_connections: u64,
    pub active_http_connections: u64,
    pub imports: Imports,
    /// None means health is unavailable, never that a service is healthy with no traffic.
    pub health: Option<HealthMetrics>,
}
pub trait MetricsSource: Send + Sync {
    fn snapshot(&self) -> MetricsSnapshot;
}
#[derive(Debug, Default)]
struct Counters {
    dns: Decisions,
    http: Decisions,
    https: Decisions,
    connect: Decisions,
    active_dns_connections: u64,
    active_http_connections: u64,
    imports: Imports,
}
#[derive(Debug)]
struct Collector {
    started: Instant,
    counters: Mutex<Counters>,
}
/// Clones share one collector across supervised service generations.
#[derive(Clone, Debug)]
pub struct Metrics(Arc<Collector>);
impl Default for Metrics {
    fn default() -> Self {
        Self(Arc::new(Collector {
            started: Instant::now(),
            counters: Mutex::default(),
        }))
    }
}
impl Metrics {
    fn counters(&self) -> std::sync::MutexGuard<'_, Counters> {
        self.0
            .counters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    pub fn decision(&self, traffic: Traffic, decision: DecisionKind) {
        let mut counters = self.counters();
        let totals = match traffic {
            Traffic::Dns => &mut counters.dns,
            Traffic::Http => &mut counters.http,
            Traffic::Https => &mut counters.https,
            Traffic::Connect => &mut counters.connect,
        };
        let total = match decision {
            DecisionKind::Allowed => &mut totals.allowed,
            DecisionKind::Blocked => &mut totals.blocked,
        };
        *total = total.saturating_add(1);
    }
    pub fn import(&self, outcome: ImportResult, accepted: usize, malformed: usize) {
        let mut counters = self.counters();
        let imports = &mut counters.imports;
        let total = match outcome {
            ImportResult::Succeeded => &mut imports.succeeded,
            ImportResult::Partial => &mut imports.partial,
            ImportResult::Rejected => &mut imports.rejected,
            ImportResult::Failed => &mut imports.failed,
        };
        *total = total.saturating_add(1);
        imports.accepted_lines = imports.accepted_lines.saturating_add(accepted as u64);
        imports.malformed_lines = imports.malformed_lines.saturating_add(malformed as u64);
    }
    /// Tracks admitted client TCP sockets, including idle and upgraded connections, until drop.
    pub fn connection(&self, service: ServiceKind) -> ConnectionGuard {
        let mut counters = self.counters();
        match service {
            ServiceKind::Dns => {
                counters.active_dns_connections = counters.active_dns_connections.saturating_add(1)
            }
            ServiceKind::Http => {
                counters.active_http_connections =
                    counters.active_http_connections.saturating_add(1)
            }
            ServiceKind::Web => {}
        }
        ConnectionGuard {
            metrics: self.clone(),
            service,
        }
    }
}
#[derive(Debug)]
pub struct ConnectionGuard {
    metrics: Metrics,
    service: ServiceKind,
}
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut counters = self.metrics.counters();
        match self.service {
            ServiceKind::Dns => {
                counters.active_dns_connections = counters.active_dns_connections.saturating_sub(1)
            }
            ServiceKind::Http => {
                counters.active_http_connections =
                    counters.active_http_connections.saturating_sub(1)
            }
            ServiceKind::Web => {}
        }
    }
}
impl MetricsSource for Metrics {
    fn snapshot(&self) -> MetricsSnapshot {
        let counters = self.counters();
        MetricsSnapshot {
            uptime_seconds: self.0.started.elapsed().as_secs(),
            dns: counters.dns,
            http: counters.http,
            https: counters.https,
            connect: counters.connect,
            active_dns_connections: counters.active_dns_connections,
            active_http_connections: counters.active_http_connections,
            imports: counters.imports,
            health: None,
        }
    }
}
