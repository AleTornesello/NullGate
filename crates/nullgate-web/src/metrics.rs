//! Read-only aggregate telemetry. Authorization is applied by the management router.
use crate::{WebState, views};
use axum::{
    Extension, Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use maud::{Markup, html};
use nullgate_core::{
    Identity, Role,
    metrics::{Decisions, MetricPhase, MetricsSnapshot, ServiceMetrics},
};

pub async fn read(State(state): State<WebState>) -> Response {
    match state.metrics.as_ref() {
        Some(source) => Json(source.snapshot()).into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"code":"metrics_unavailable"})),
        )
            .into_response(),
    }
}

fn phase(phase: MetricPhase) -> &'static str {
    match phase {
        MetricPhase::Starting => "Starting",
        MetricPhase::Ready => "Ready",
        MetricPhase::Backoff => "Backoff",
        MetricPhase::Stopping => "Stopping",
        MetricPhase::Stopped => "Stopped",
        MetricPhase::Failed => "Failed",
    }
}
fn service(name: &str, metrics: Option<ServiceMetrics>) -> Markup {
    html! {tr {th scope="row" {(name)}
        @if let Some(metrics)=metrics {
            td {span class=(if metrics.phase==MetricPhase::Ready {"health ready"}else{"health unavailable"}) {(phase(metrics.phase))}}
            td {(metrics.restarts)}
        } @else {td {span.health.unavailable {"Unavailable"}} td {"—"}}
    }}
}
fn decisions(name: &str, key: &str, values: Decisions) -> Markup {
    html! {section.card.metric-card {h3 {(name)} dl {
        div {dt {"Allowed"} dd data-metric=(format!("{key}-allowed")) {(values.allowed)}}
        div {dt {"Blocked"} dd data-metric=(format!("{key}-blocked")) {(values.blocked)}}
    }}}
}
fn totals(metrics: &MetricsSnapshot) -> Markup {
    html! {
        @if let Some(health)=metrics.health {
            div class=(if health.ready {"notice health-ready"}else{"notice health-warning"}) {
                strong {(if health.ready {"All services ready"}else{"Services unavailable or recovering"})}
                " · " (if health.policy_available {"Policy available"}else{"Policy unavailable"})
            }
            section.card.service-health {h2 {"Service health"}
                table {thead {tr {th {"Service"} th {"State"} th {"Restarts"}}} tbody {
                    (service("DNS",Some(health.dns))) (service("HTTP / HTTPS proxy",Some(health.http))) (service("Web",health.web))
                }}
            }
        } @else {div.notice.health-warning {strong {"Service health unavailable"} " · Counters alone do not establish readiness."}}
        div.metrics-grid {
            (decisions("DNS requests","dns",metrics.dns))
            (decisions("HTTP requests","http",metrics.http))
            (decisions("Inspected HTTPS","https",metrics.https))
            (decisions("CONNECT admissions","connect",metrics.connect))
        }
        p.small {"Allowed and blocked are policy decisions, independent of upstream success. Encrypted requests inside passthrough tunnels are not counted; their CONNECT admissions are shown separately."}
        div.metrics-grid {
            section.card.metric-card {h2 {"Active connections"} dl {
                div {dt {"DNS client TCP"} dd data-metric="dns-active" {(metrics.active_dns_connections)}}
                div {dt {"HTTP / CONNECT client TCP"} dd data-metric="http-active" {(metrics.active_http_connections)}}
            } p.small {"Includes idle keep-alive and upgraded connections. UDP datagrams and upstream sockets are excluded."}}
            section.card.metric-card {h2 {"Import outcomes"} dl {
                div {dt {"Succeeded"} dd data-metric="imports-succeeded" {(metrics.imports.succeeded)}}
                div {dt {"Partially valid"} dd data-metric="imports-partial" {(metrics.imports.partial)}}
                div {dt {"Rejected"} dd data-metric="imports-rejected" {(metrics.imports.rejected)}}
                div {dt {"Failed"} dd data-metric="imports-failed" {(metrics.imports.failed)}}
                div {dt {"Accepted rule lines"} dd {(metrics.imports.accepted_lines)}}
                div {dt {"Malformed lines reported"} dd {(metrics.imports.malformed_lines)}}
            } p.small {"Completed import commands in this runtime; existing stored reports are not replayed."}}
        }
        footer {"Uptime: " (metrics.uptime_seconds) " seconds. Reset on process restart. Counts survive proxy restarts. No request history is retained. Updated on page load."}
    }
}
pub async fn dashboard(
    State(state): State<WebState>,
    Extension(identity): Extension<Identity>,
) -> Response {
    let snapshot = state.metrics.as_ref().map(|source| source.snapshot());
    let status = if snapshot.is_some() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let page = views::shell(
        "Traffic dashboard",
        "metrics",
        html! {
            header.topbar {
                a.brand href="/" {"N" span {"NullGate"}}
                nav {span.active {"Dashboard"} a href="/" {"Blocklists"}}
                div.account {
                    span.role {(if identity.role==Role::Administrator {"Administrator"}else{"Viewer · read only"})}
                    span {(identity.username.as_deref().unwrap_or("Authentication disabled"))}
                    form data-kind="logout" method="post" action="/api/v1/auth/logout" {button.quiet type="submit" {"Sign out"}}
                }
            }
            main.metrics-page {
                div.page-heading {div {p.eyebrow {"PROCESS-LIFETIME AGGREGATES"} h1 {"Traffic dashboard"} p.muted {"One view across your shared filtering services."}} a.button.secondary href="/dashboard" {"Refresh metrics"}}
                div id="feedback" role="status" aria-live="polite" {}
                @if let Some(metrics)=snapshot {(totals(&metrics))}
                @else {section.card {h2 {"Metrics unavailable"} p {"The runtime metrics source is not connected. Zero traffic cannot be inferred."}}}
            }
        },
    );
    (status, page).into_response()
}
