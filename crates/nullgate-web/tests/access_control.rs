use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::get,
};
use http_body_util::BodyExt;
use nullgate_core::{
    AuthMode, Mutation, PolicyError, PolicyFuture, PolicyManagement, PolicySaveResult,
    PolicySnapshot, PolicySubscription, RepositorySnapshot, Role, policy_channel,
};
use nullgate_web::{AuthService, Clock, WebSecurity, WebState, router};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
};
use tower::ServiceExt;
struct Time(AtomicI64);
impl Clock for Time {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}
struct Management {
    _publisher: nullgate_core::PolicyPublisher,
    reader: PolicySubscription,
}
impl PolicyManagement for Management {
    fn subscribe(&self) -> PolicySubscription {
        self.reader.clone()
    }
    fn save(&self, _: u64, _: Mutation) -> PolicyFuture<'_, Result<PolicySaveResult, PolicyError>> {
        Box::pin(async { Err(PolicyError::Stopped) })
    }
}
struct Fixture {
    path: PathBuf,
    auth: AuthService,
    app: Router,
    time: Arc<Time>,
    https: bool,
}
impl Fixture {
    async fn new(mode: AuthMode, https: bool) -> Self {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("nullgate-auth-{}-{stamp}", std::process::id()));
        let time = Arc::new(Time(AtomicI64::new(1000)));
        let auth = AuthService::open_with_clock(path.join("state.sqlite3"), mode, time.clone())
            .await
            .unwrap();
        let (publisher, reader) = policy_channel(
            PolicySnapshot::from_repository(RepositorySnapshot {
                revision: 0,
                lists: vec![],
            })
            .unwrap(),
        );
        let security = if https {
            WebSecurity::direct_https(
                "0.0.0.0:8443".parse().unwrap(),
                "https://admin.example:8443",
            )
            .unwrap()
        } else {
            WebSecurity::loopback_http("127.0.0.1:8081".parse().unwrap(), "http://127.0.0.1:8081")
                .unwrap()
        };
        let state = WebState::new(
            auth.clone(),
            security,
            Arc::new(Management {
                _publisher: publisher,
                reader,
            }),
        );
        let routes = Router::new().route(
            "/api/v1/manage",
            get(|| async { "read" }).post(|| async { "write" }),
        );
        let app = router(state, routes);
        Self {
            path,
            auth,
            app,
            time,
            https,
        }
    }
    async fn call(
        &self,
        method: &str,
        path: &str,
        cookies: &str,
        csrf: &str,
        body: &str,
    ) -> (StatusCode, Vec<String>, String) {
        let origin = if self.app_origin_https() {
            "https://admin.example:8443"
        } else {
            "http://127.0.0.1:8081"
        };
        let host = origin.split("://").nth(1).unwrap();
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", host)
            .header("origin", origin)
            .header(header::CONTENT_TYPE, "application/json");
        if !cookies.is_empty() {
            request = request.header(header::COOKIE, cookies);
        }
        if !csrf.is_empty() {
            request = request.header("x-csrf-token", csrf);
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(body.to_owned())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, cookies, String::from_utf8(body.to_vec()).unwrap())
    }
    fn app_origin_https(&self) -> bool {
        self.https
    }
    async fn bootstrap(&self) -> (String, String) {
        let (status, cookies, body) = self.call("GET", "/api/v1/auth/csrf", "", "", "").await;
        assert_eq!(status, StatusCode::OK);
        let csrf = body.split('"').nth(3).unwrap().to_string();
        (cookies[0].split(';').next().unwrap().to_string(), csrf)
    }
    async fn login(&self, user: &str, password: &str) -> (String, String) {
        let (cookie, csrf) = self.bootstrap().await;
        let (status, cookies, body) = self
            .call(
                "POST",
                "/api/v1/auth/login",
                &cookie,
                &csrf,
                &format!(r#"{{"username":"{user}","password":"{password}"}}"#),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let cookie = cookies
            .iter()
            .find(|v| v.contains("session=") && !v.contains("Max-Age=0"))
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let csrf = body.split('"').nth(3).unwrap().to_string();
        (cookie, csrf)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
const PASSWORD: &str = "correct secret phrase";
#[tokio::test]
async fn provisioned_passwords_login_rotate_expire_and_logout_durably() {
    let f = Fixture::new(AuthMode::Local, false).await;
    f.auth.provision_admin("admin", PASSWORD).await.unwrap();
    assert!(f.auth.provision_admin("second", PASSWORD).await.is_err());
    let (cookie, csrf) = f.login("ADMIN", PASSWORD).await;
    assert_eq!(
        f.call("GET", "/api/v1/manage", &cookie, "", "").await.0,
        StatusCode::OK
    );
    let (status, cookies, _) = f
        .call(
            "POST",
            "/api/v1/auth/login",
            &cookie,
            &csrf,
            &format!(r#"{{"username":"admin","password":"{PASSWORD}"}}"#),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        f.call("GET", "/api/v1/manage", &cookie, "", "").await.0,
        StatusCode::UNAUTHORIZED
    );
    let new_cookie = cookies
        .iter()
        .find(|v| v.contains("session=") && !v.contains("Max-Age=0"))
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let (_, _, body) = f.call("GET", "/api/v1/auth/csrf", new_cookie, "", "").await;
    let csrf = body.split('"').nth(3).unwrap();
    assert_eq!(
        f.call("POST", "/api/v1/auth/logout", new_cookie, csrf, "")
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call("GET", "/api/v1/manage", new_cookie, "", "").await.0,
        StatusCode::UNAUTHORIZED
    );
    let (cookie, _) = f.login("admin", PASSWORD).await;
    f.time.0.store(1000 + 28800, Ordering::SeqCst);
    assert_eq!(
        f.call("GET", "/api/v1/manage", &cookie, "", "").await.0,
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn invalid_credentials_and_unauthenticated_direct_requests_are_denied() {
    let f = Fixture::new(AuthMode::Local, false).await;
    f.auth.provision_admin("admin", PASSWORD).await.unwrap();
    assert_eq!(
        f.call("GET", "/api/v1/manage", "", "", "").await.0,
        StatusCode::UNAUTHORIZED
    );
    for user in ["admin", "unknown"] {
        let (cookie, csrf) = f.bootstrap().await;
        assert_eq!(
            f.call(
                "POST",
                "/api/v1/auth/login",
                &cookie,
                &csrf,
                &format!(r#"{{"username":"{user}","password":"wrong password"}}"#)
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        f.call("GET", "/api/v1/manage", "nullgate_session=garbage", "", "")
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn viewers_cannot_write_via_direct_requests_and_csrf_is_required() {
    let f = Fixture::new(AuthMode::Local, false).await;
    f.auth.provision_admin("admin", PASSWORD).await.unwrap();
    let (admin, csrf) = f.login("admin", PASSWORD).await;
    let raw = admin.split('=').nth(1).unwrap();
    f.auth
        .create_user(Some(raw), "viewer", PASSWORD, Role::Viewer)
        .await
        .unwrap();
    let (viewer, token) = f.login("viewer", PASSWORD).await;
    assert_eq!(
        f.call("GET", "/api/v1/manage", &viewer, "", "").await.0,
        StatusCode::OK
    );
    assert_eq!(
        f.call("POST", "/api/v1/manage", &viewer, &token, "")
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.call("POST", "/api/v1/manage", &admin, "", "").await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.call("POST", "/api/v1/manage", &admin, &csrf, "").await.0,
        StatusCode::OK
    );
}
#[tokio::test]
async fn explicit_no_auth_is_administrator_but_keeps_csrf_protection() {
    let f = Fixture::new(AuthMode::None, false).await;
    assert_eq!(
        f.call("GET", "/api/v1/manage", "", "", "").await.0,
        StatusCode::OK
    );
    assert_eq!(
        f.call("POST", "/api/v1/manage", "", "", "").await.0,
        StatusCode::FORBIDDEN
    );
    let (cookie, csrf) = f.bootstrap().await;
    assert_eq!(
        f.call("POST", "/api/v1/manage", &cookie, &csrf, "").await.0,
        StatusCode::OK
    );
}
#[test]
fn transport_rejects_public_cleartext_and_requires_explicit_trusted_origin() {
    assert!(
        WebSecurity::loopback_http("0.0.0.0:8081".parse().unwrap(), "http://admin.example")
            .is_err()
    );
    assert!(
        WebSecurity::direct_https("0.0.0.0:8443".parse().unwrap(), "http://admin.example").is_err()
    );
}
#[tokio::test]
async fn origins_cookie_flags_and_forwarded_headers_cannot_bypass_csrf() {
    let f = Fixture::new(AuthMode::None, false).await;
    let (cookie, csrf) = f.bootstrap().await;
    let response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/manage")
                .header("host", "127.0.0.1:8081")
                .header("origin", "https://attacker.invalid")
                .header("x-csrf-token", &csrf)
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/csrf")
                .header("host", "attacker.invalid")
                .header("x-forwarded-host", "127.0.0.1:8081")
                .header("x-forwarded-proto", "https")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let (_, cookies, _) = f.call("GET", "/api/v1/auth/csrf", "", "", "").await;
    assert!(cookies[0].contains("HttpOnly"));
    assert!(cookies[0].contains("SameSite=Lax"));
    assert!(!cookies[0].contains("Secure"));
    let f = Fixture::new(AuthMode::None, true).await;
    let (_, cookies, _) = f.call("GET", "/api/v1/auth/csrf", "", "", "").await;
    assert!(cookies[0].starts_with("__Host-"));
    assert!(cookies[0].contains("Secure"));
    assert!(!cookies[0].contains("Domain="));
}
#[tokio::test]
async fn hashes_are_salted_sessions_persist_hashed_and_roles_are_rechecked() {
    let f = Fixture::new(AuthMode::Local, false).await;
    f.auth.provision_admin("admin", PASSWORD).await.unwrap();
    let (cookie, csrf) = f.login("admin", PASSWORD).await;
    let raw = cookie.split('=').nth(1).unwrap();

    f.auth
        .create_user(Some(raw), "other", PASSWORD, Role::Viewer)
        .await
        .unwrap();
    let db = rusqlite::Connection::open(f.path.join("state.sqlite3")).unwrap();
    let hashes = db
        .prepare("SELECT password_hash FROM auth_users ORDER BY username")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(hashes.len(), 2);
    assert_ne!(hashes[0], hashes[1]);
    assert!(
        hashes
            .iter()
            .all(|hash| hash.starts_with("$argon2id$v=19$m=65536,t=3,p=1$"))
    );
    let hash: Vec<u8> = db
        .query_row("SELECT token_hash FROM auth_sessions", [], |row| row.get(0))
        .unwrap();
    assert_eq!(hash.len(), 32);
    assert_ne!(hash, raw.as_bytes());
    let reopened = AuthService::open_with_clock(
        f.path.join("state.sqlite3"),
        AuthMode::Local,
        f.time.clone(),
    )
    .await
    .unwrap();
    assert!(reopened.identity(Some(raw)).await.is_ok());
    db.execute(
        "UPDATE auth_users SET role='viewer' WHERE username='admin'",
        [],
    )
    .unwrap();
    assert_eq!(
        f.call("POST", "/api/v1/manage", &cookie, &csrf, "").await.0,
        StatusCode::FORBIDDEN
    );
    db.execute("UPDATE auth_users SET enabled=0 WHERE username='admin'", [])
        .unwrap();
    assert_eq!(
        f.call("GET", "/api/v1/manage", &cookie, "", "").await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn login_csrf_and_failed_session_writes_preserve_existing_session() {
    let f = Fixture::new(AuthMode::Local, false).await;
    f.auth.provision_admin("admin", PASSWORD).await.unwrap();
    let (cookie, csrf) = f.bootstrap().await;
    let body = format!(r#"{{"username":"admin","password":"{PASSWORD}"}}"#);
    assert_eq!(
        f.call("POST", "/api/v1/auth/login", &cookie, "", &body)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("host", "127.0.0.1:8081")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let (cookie, csrf) = f.login("admin", PASSWORD).await;
    let db = rusqlite::Connection::open(f.path.join("state.sqlite3")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_session BEFORE INSERT ON auth_sessions BEGIN SELECT RAISE(ABORT,'forced failure'); END;").unwrap();
    assert_eq!(
        f.call("POST", "/api/v1/auth/login", &cookie, &csrf, &body)
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        f.call("GET", "/api/v1/manage", &cookie, "", "").await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn simultaneous_first_run_provisioning_creates_only_one_administrator() {
    let f = Fixture::new(AuthMode::Local, false).await;
    let second = AuthService::open_with_clock(
        f.path.join("state.sqlite3"),
        AuthMode::Local,
        f.time.clone(),
    )
    .await
    .unwrap();
    let (one, two) = tokio::join!(
        f.auth.provision_admin("one", PASSWORD),
        second.provision_admin("two", PASSWORD)
    );
    assert_ne!(one.is_ok(), two.is_ok());
    let db = rusqlite::Connection::open(f.path.join("state.sqlite3")).unwrap();
    let count: i64 = db
        .query_row(
            "SELECT count(*) FROM auth_users WHERE role='administrator'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
    let revision: i64 = db
        .query_row("SELECT revision FROM state", [], |row| row.get(0))
        .unwrap();
    assert_eq!(revision, 0);
}

#[tokio::test]
async fn account_creation_rejects_cached_identity_after_logout() {
    let f = Fixture::new(AuthMode::Local, false).await;
    f.auth.provision_admin("admin", PASSWORD).await.unwrap();
    let (cookie, csrf) = f.login("admin", PASSWORD).await;
    assert_eq!(
        f.call("POST", "/api/v1/auth/logout", &cookie, &csrf, "")
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert!(
        f.auth
            .create_user(cookie.split('=').nth(1), "stale", PASSWORD, Role::Viewer)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn custom_management_fallback_is_protected_too() {
    let f = Fixture::new(AuthMode::Local, false).await;
    let (publisher, reader) = policy_channel(
        PolicySnapshot::from_repository(RepositorySnapshot {
            revision: 0,
            lists: vec![],
        })
        .unwrap(),
    );
    let state = WebState::new(
        f.auth.clone(),
        WebSecurity::loopback_http("127.0.0.1:8081".parse().unwrap(), "http://127.0.0.1:8081")
            .unwrap(),
        Arc::new(Management {
            _publisher: publisher,
            reader,
        }),
    );
    let app = router(
        state,
        Router::new()
            .route("/known", get(|| async { "known" }))
            .fallback(|| async { "sensitive fallback" }),
    );
    let response = app
        .oneshot(
            Request::builder()
                .uri("/unknown")
                .header("host", "127.0.0.1:8081")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
