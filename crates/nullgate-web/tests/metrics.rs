use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use nullgate_core::metrics::{
    DecisionKind, HealthMetrics, MetricPhase, Metrics, MetricsSnapshot, MetricsSource,
    ServiceMetrics, Traffic,
};
use nullgate_core::{
    AuthMode, Mutation, PolicyError, PolicyFuture, PolicyManagement, PolicySaveResult,
    PolicySnapshot, PolicySubscription, RepositorySnapshot, Role, policy_channel,
};
use nullgate_web::{AuthService, WebSecurity, WebState, management_routes, router};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::Arc};
use tower::ServiceExt;
struct Manager {
    reader: PolicySubscription,
    _publisher: nullgate_core::PolicyPublisher,
}
impl PolicyManagement for Manager {
    fn subscribe(&self) -> PolicySubscription {
        self.reader.clone()
    }
    fn save(&self, _: u64, _: Mutation) -> PolicyFuture<'_, Result<PolicySaveResult, PolicyError>> {
        Box::pin(async { Err(PolicyError::Stopped) })
    }
}
struct Source {
    metrics: Metrics,
}
impl MetricsSource for Source {
    fn snapshot(&self) -> MetricsSnapshot {
        let mut snapshot = self.metrics.snapshot();
        snapshot.health = Some(HealthMetrics {
            dns: ServiceMetrics {
                phase: MetricPhase::Ready,
                restarts: 0,
            },
            http: ServiceMetrics {
                phase: MetricPhase::Backoff,
                restarts: 2,
            },
            web: None,
            policy_available: false,
            ready: false,
        });
        snapshot
    }
}
struct Fixture {
    path: PathBuf,
    app: Router,
    admin: Option<String>,
    viewer: Option<String>,
}
impl Fixture {
    async fn new(mode: AuthMode, source: Option<Arc<dyn MetricsSource>>) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "nullgate-metrics-web-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let auth = AuthService::open(path.join("state.sqlite3"), mode)
            .await
            .unwrap();
        let (admin, viewer) = if mode == AuthMode::Local {
            auth.provision_admin("admin", "test-password-with-length")
                .await
                .unwrap();
            let mut repo = nullgate_core::AuthRepository::open(path.join("state.sqlite3")).unwrap();
            let admin = repo.user("admin").unwrap().unwrap();
            repo.insert_user(
                "viewer",
                &admin.password_hash,
                Role::Viewer,
                nullgate_core::AccountCreation::NoAuthentication,
            )
            .unwrap();
            let viewer = repo.user("viewer").unwrap().unwrap();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let tokens = ["a".repeat(64), "b".repeat(64)];
            for (user, token) in [(&admin, &tokens[0]), (&viewer, &tokens[1])] {
                repo.create_session(
                    user,
                    &Sha256::digest(token.as_bytes()).into(),
                    None,
                    now,
                    now + 3600,
                )
                .unwrap();
            }
            (Some(tokens[0].clone()), Some(tokens[1].clone()))
        } else {
            (None, None)
        };
        let (publisher, reader) = policy_channel(
            PolicySnapshot::from_repository(RepositorySnapshot {
                revision: 0,
                lists: vec![],
            })
            .unwrap(),
        );
        let mut state = WebState::new(
            auth,
            WebSecurity::loopback_http("127.0.0.1:8081".parse().unwrap(), "http://127.0.0.1:8081")
                .unwrap(),
            Arc::new(Manager {
                reader,
                _publisher: publisher,
            }),
        );
        if let Some(source) = source {
            state = state.with_metrics(source);
        }
        Self {
            path,
            app: router(state, management_routes()),
            admin,
            viewer,
        }
    }
    async fn get(&self, method: &str, path: &str, token: Option<&str>) -> (StatusCode, String) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "127.0.0.1:8081");
        if let Some(token) = token {
            request = request.header("cookie", format!("nullgate_session={token}"));
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        (
            response.status(),
            String::from_utf8(
                response
                    .into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes()
                    .to_vec(),
            )
            .unwrap(),
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
#[tokio::test]
async fn both_roles_read_metrics_but_anonymous_and_viewer_mutations_are_denied() {
    let metrics = Metrics::default();
    metrics.decision(Traffic::Dns, DecisionKind::Blocked);
    let f = Fixture::new(AuthMode::Local, Some(Arc::new(Source { metrics }))).await;
    assert_eq!(
        f.get("GET", "/api/v1/metrics", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    for token in [f.admin.as_deref(), f.viewer.as_deref()] {
        let (status, body) = f.get("GET", "/api/v1/metrics", token).await;
        assert_eq!(status, StatusCode::OK);
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["dns"]["blocked"], 1);
        assert_eq!(value["health"]["http"]["phase"], "backoff");
        assert_eq!(value["health"]["http"]["restarts"], 2);
        assert_eq!(value["health"]["ready"], false);
        let (status, html) = f.get("GET", "/dashboard", token).await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains("Traffic dashboard"));
        assert!(html.contains("Backoff"));
        assert!(html.contains("Policy unavailable"));
        assert!(html.contains("Reset on process restart"));
        assert!(html.contains("Inspected HTTPS"));
    }
    assert_eq!(
        f.get("POST", "/api/v1/metrics", f.viewer.as_deref())
            .await
            .0,
        StatusCode::FORBIDDEN
    );
}
#[tokio::test]
async fn unavailable_collection_is_distinct_from_ready_with_zero_traffic() {
    let f = Fixture::new(AuthMode::None, None).await;
    let (status, error) = f.get("GET", "/api/v1/metrics", None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(error.contains("metrics_unavailable"));
    let (status, body) = f.get("GET", "/dashboard", None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("Metrics unavailable"));
    let f = Fixture::new(AuthMode::None, Some(Arc::new(Metrics::default()))).await;
    let (_, body) = f.get("GET", "/api/v1/metrics", None).await;
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(value["health"].is_null());
    assert_eq!(value["dns"]["allowed"], 0);
    let (_, body) = f.get("GET", "/dashboard", None).await;
    assert!(body.contains("Service health unavailable"));
    assert!(!body.contains("All services ready"));
}
