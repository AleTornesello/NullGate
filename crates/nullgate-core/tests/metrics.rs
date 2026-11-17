use nullgate_core::ServiceKind;
use nullgate_core::metrics::{DecisionKind, Metrics, MetricsSource, Traffic};

#[test]
fn aggregate_decisions_and_connection_guards_are_shared_and_reset_with_new_collector() {
    let metrics = Metrics::default();
    let shared = metrics.clone();
    metrics.decision(Traffic::Dns, DecisionKind::Allowed);
    shared.decision(Traffic::Dns, DecisionKind::Blocked);
    metrics.decision(Traffic::Http, DecisionKind::Allowed);
    metrics.decision(Traffic::Https, DecisionKind::Blocked);
    metrics.decision(Traffic::Connect, DecisionKind::Allowed);
    let guard = metrics.connection(ServiceKind::Http);
    let dns = metrics.connection(ServiceKind::Dns);
    let snapshot = shared.snapshot();
    assert_eq!(snapshot.dns.allowed, 1);
    assert_eq!(snapshot.dns.blocked, 1);
    assert_eq!(snapshot.http.allowed, 1);
    assert_eq!(snapshot.https.blocked, 1);
    assert_eq!(snapshot.connect.allowed, 1);
    assert_eq!(snapshot.active_http_connections, 1);
    assert_eq!(snapshot.active_dns_connections, 1);
    assert!(snapshot.health.is_none());
    drop(guard);
    drop(dns);
    assert_eq!(shared.snapshot().active_http_connections, 0);
    assert_eq!(shared.snapshot().active_dns_connections, 0);
    assert_eq!(Metrics::default().snapshot().dns.allowed, 0);
}

#[test]
fn concurrent_updates_never_lose_decisions_and_unwinding_releases_connections() {
    let metrics = Metrics::default();
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let m = metrics.clone();
            scope.spawn(move || {
                for _ in 0..1000 {
                    m.decision(Traffic::Http, DecisionKind::Allowed);
                }
            });
        }
    });
    assert_eq!(metrics.snapshot().http.allowed, 4000);
    let _ = std::panic::catch_unwind(|| {
        let _guard = metrics.connection(ServiceKind::Http);
        panic!("fixture task failure");
    });
    assert_eq!(metrics.snapshot().active_http_connections, 0);
}

#[test]
fn import_outcomes_keep_only_fixed_aggregate_counts() {
    use nullgate_core::metrics::ImportResult;
    let metrics = Metrics::default();
    metrics.import(ImportResult::Succeeded, 2, 0);
    metrics.import(ImportResult::Partial, 1, 3);
    metrics.import(ImportResult::Rejected, 0, 4);
    metrics.import(ImportResult::Failed, 0, 0);
    let imports = metrics.snapshot().imports;
    assert_eq!(
        (
            imports.succeeded,
            imports.partial,
            imports.rejected,
            imports.failed
        ),
        (1, 1, 1, 1)
    );
    assert_eq!((imports.accepted_lines, imports.malformed_lines), (3, 7));
}
