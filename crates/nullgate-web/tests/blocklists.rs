use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use nullgate_core::{
    AuthMode, BlocklistRepository, Mutation, PolicyError, PolicyFuture, PolicyManagement,
    PolicySaveResult, PolicySnapshot, PolicySubscription, Role, SqliteRepository, policy_channel,
};
use nullgate_web::{AuthService, WebSecurity, WebState, management_routes, router};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tower::ServiceExt;
struct Management {
    repo: Mutex<SqliteRepository>,
    publisher: Mutex<nullgate_core::PolicyPublisher>,
    reader: PolicySubscription,
}
impl PolicyManagement for Management {
    fn subscribe(&self) -> PolicySubscription {
        self.reader.clone()
    }
    fn save(
        &self,
        revision: u64,
        mutation: Mutation,
    ) -> PolicyFuture<'_, Result<PolicySaveResult, PolicyError>> {
        Box::pin(async move {
            let commit = self
                .repo
                .lock()
                .unwrap()
                .apply(revision, mutation)
                .map_err(PolicyError::Storage)?;
            let (snapshot, report) = PolicySnapshot::from_commit(commit);
            let snapshot = Arc::new(snapshot);
            self.publisher.lock().unwrap().publish(snapshot.clone());
            Ok(PolicySaveResult {
                snapshot,
                import_report: report,
            })
        })
    }
}
struct Fixture {
    path: PathBuf,
    app: Router,
    manager: Arc<Management>,
    auth: AuthService,
}
impl Fixture {
    async fn new(mode: AuthMode) -> Self {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "nullgate-blocklist-api-{}-{stamp}",
            std::process::id()
        ));
        let mut repo = SqliteRepository::open(path.join("state.sqlite3")).unwrap();
        let (publisher, reader) =
            policy_channel(PolicySnapshot::from_repository(repo.snapshot().unwrap()).unwrap());
        let manager = Arc::new(Management {
            repo: Mutex::new(repo),
            publisher: Mutex::new(publisher),
            reader,
        });
        let auth = AuthService::open(path.join("state.sqlite3"), mode)
            .await
            .unwrap();
        let state = WebState::new(
            auth.clone(),
            WebSecurity::loopback_http("127.0.0.1:8081".parse().unwrap(), "http://127.0.0.1:8081")
                .unwrap(),
            manager.clone(),
        );
        let app = router(state, management_routes());
        Self {
            path,
            app,
            manager,
            auth,
        }
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Body,
        content_type: &str,
        cookie: &str,
        proof: &str,
    ) -> (StatusCode, Vec<String>, String) {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "127.0.0.1:8081")
            .header("origin", "http://127.0.0.1:8081")
            .header(header::CONTENT_TYPE, content_type);
        if !cookie.is_empty() {
            req = req.header(header::COOKIE, cookie);
        }
        if !proof.is_empty() {
            req = req.header("x-csrf-token", proof);
        }
        let response = self
            .app
            .clone()
            .oneshot(req.body(body).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
            .collect();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, cookies, String::from_utf8(bytes.to_vec()).unwrap())
    }
    async fn csrf(&self, cookie: &str) -> (String, String) {
        let (status, cookies, text) = self
            .request(
                "GET",
                "/api/v1/auth/csrf",
                Body::empty(),
                "application/json",
                cookie,
                "",
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let proof: serde_json::Value = serde_json::from_str(&text).unwrap();
        (
            if cookie.is_empty() {
                cookies[0].clone()
            } else {
                cookie.into()
            },
            proof["csrf"].as_str().unwrap().into(),
        )
    }
    async fn json(
        &self,
        method: &str,
        path: &str,
        value: serde_json::Value,
        cookie: &str,
        proof: &str,
    ) -> (StatusCode, serde_json::Value) {
        let (status, _, body) = self
            .request(
                method,
                path,
                Body::from(value.to_string()),
                "application/json",
                cookie,
                proof,
            )
            .await;
        (
            status,
            serde_json::from_str(&body).unwrap_or(serde_json::Value::String(body)),
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
#[tokio::test]
async fn mixed_imports_report_lines_atomically_persist_and_require_revision() {
    let f = Fixture::new(AuthMode::None).await;
    let (cookie, proof) = f.csrf("").await;
    let (status, created) = f
        .json(
            "POST",
            "/api/v1/lists",
            serde_json::json!({"expected_revision":0,"name":"Mixed"}),
            &cookie,
            &proof,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let list_id = f.manager.reader.current().unwrap().repository().lists[0].id;
    let(status,report)=f.json("POST",&format!("/api/v1/lists/{list_id}/rules"),serde_json::json!({"expected_revision":1,"text":"blocked.invalid\nhttp://news.invalid/ads\nnot a rule\n*.tracking.invalid"}),&cookie,&proof).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    assert_eq!(report["revision"], 2);
    assert_eq!(report["import"]["accepted"], 3);
    assert_eq!(report["import"]["malformed"][0]["line"], 3);
    let snapshot = f.manager.reader.current().unwrap();
    assert_eq!(snapshot.repository().lists[0].sources.len(), 1);
    assert_eq!(snapshot.repository().lists[0].sources[0].entries.len(), 3);
    assert!(
        snapshot
            .rules()
            .blocks_domain(&nullgate_core::normalize_host("blocked.invalid").unwrap())
    );
    assert!(
        !snapshot
            .rules()
            .blocks_domain(&nullgate_core::normalize_host("news.invalid").unwrap())
    );
    assert!(
        snapshot.rules().blocks_url(
            &nullgate_core::normalize_url("http://news.invalid/ads?ignored=yes").unwrap()
        )
    );
    let mut reopened = SqliteRepository::open(f.path.join("state.sqlite3")).unwrap();
    assert_eq!(reopened.snapshot().unwrap().revision, 2);
    let (status, error) = f
        .json(
            "PATCH",
            &format!("/api/v1/lists/{list_id}"),
            serde_json::json!({"expected_revision":1,"name":"stale"}),
            &cookie,
            &proof,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{error}");
    assert_eq!(f.manager.reader.current().unwrap().revision(), 2);
}
#[tokio::test]
async fn file_import_bounds_utf8_source_replacement_and_deletion() {
    let f = Fixture::new(AuthMode::None).await;
    let (cookie, proof) = f.csrf("").await;
    assert_eq!(
        f.json(
            "POST",
            "/api/v1/lists",
            serde_json::json!({"expected_revision":0,"name":"Files"}),
            &cookie,
            &proof
        )
        .await
        .0,
        StatusCode::OK
    );
    let list_id = f.manager.reader.current().unwrap().repository().lists[0].id;
    let (status, _, body) = f
        .request(
            "POST",
            &format!("/api/v1/lists/{list_id}/imports?expected_revision=1&filename=sample.txt"),
            Body::from("good.invalid\nhttps://site.invalid/ads\nwrong rule"),
            "text/plain",
            &cookie,
            &proof,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let source = f.manager.reader.current().unwrap().repository().lists[0].sources[0].id;
    assert_eq!(f.manager.reader.current().unwrap().revision(), 2);
    let (status, _, _) = f
        .request(
            "POST",
            &format!("/api/v1/lists/{list_id}/imports?expected_revision=2&filename=bad.txt"),
            Body::from(vec![255]),
            "text/plain",
            &cookie,
            &proof,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(f.manager.reader.current().unwrap().revision(), 2);
    let (status, _, _) = f
        .request(
            "POST",
            &format!("/api/v1/lists/{list_id}/imports?expected_revision=2&filename=large.txt"),
            Body::from(vec![b'a'; nullgate_core::MAX_IMPORT_BYTES + 1]),
            "text/plain",
            &cookie,
            &proof,
        )
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(f.manager.reader.current().unwrap().revision(), 2);
    let (status, _) = f
        .json(
            "PUT",
            &format!("/api/v1/sources/{source}/entries"),
            serde_json::json!({"expected_revision":2,"text":"all invalid input"}),
            &cookie,
            &proof,
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(f.manager.reader.current().unwrap().revision(), 2);
    assert_eq!(
        f.json(
            "PUT",
            &format!("/api/v1/sources/{source}/entries"),
            serde_json::json!({"expected_revision":2,"text":"replacement.invalid\nwrong entry"}),
            &cookie,
            &proof
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        f.manager.reader.current().unwrap().repository().lists[0].sources[0]
            .entries
            .len(),
        1
    );
    assert_eq!(
        f.json(
            "DELETE",
            &format!("/api/v1/lists/{list_id}"),
            serde_json::json!({"expected_revision":3}),
            &cookie,
            &proof
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(
        f.manager
            .reader
            .current()
            .unwrap()
            .repository()
            .lists
            .is_empty()
    );
}
#[tokio::test]
async fn html_escapes_names_and_rules_and_all_api_writes_are_authorized() {
    let f = Fixture::new(AuthMode::None).await;
    let (cookie, proof) = f.csrf("").await;
    assert_eq!(
        f.json(
            "POST",
            "/api/v1/lists",
            serde_json::json!({"expected_revision":0,"name":"<img src=x onerror=alert(1)>"}),
            &cookie,
            &proof
        )
        .await
        .0,
        StatusCode::OK
    );
    let (status, _, html) = f
        .request("GET", "/", Body::empty(), "text/html", "", "")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("&lt;img"));
    assert!(!html.contains("<img src=x"));
    let f = Fixture::new(AuthMode::Local).await;
    assert_eq!(
        f.json(
            "POST",
            "/api/v1/lists",
            serde_json::json!({"expected_revision":0,"name":"no"}),
            "",
            ""
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    f.auth
        .provision_admin("admin", "safe testing password")
        .await
        .unwrap();
    let (cookie, proof) = f.csrf("").await;
    let (status, cookies, _) = f
        .request(
            "POST",
            "/api/v1/auth/login",
            Body::from(r#"{"username":"admin","password":"safe testing password"}"#),
            "application/json",
            &cookie,
            &proof,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let session = cookies.iter().find(|c| c.contains("session=")).unwrap();
    f.auth
        .create_user(
            session.split('=').nth(1),
            "viewer",
            "safe testing password",
            Role::Viewer,
        )
        .await
        .unwrap();
    let (cookie, proof) = f.csrf("").await;
    let (status, cookies, _) = f
        .request(
            "POST",
            "/api/v1/auth/login",
            Body::from(r#"{"username":"viewer","password":"safe testing password"}"#),
            "application/json",
            &cookie,
            &proof,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let session = cookies.iter().find(|c| c.contains("session=")).unwrap();
    let (_, csrf) = f.csrf(session).await;
    for path in ["/api/v1/lists/1/remote", "/api/v1/sources/1/refresh"] {
        assert_eq!(
            f.json(
                "POST",
                path,
                serde_json::json!({"expected_revision":0,"url":"http://127.0.0.1/internal"}),
                session,
                &csrf
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
    }

    assert_eq!(
        f.json("GET", "/api/v1/lists", serde_json::json!({}), session, "")
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        f.json(
            "POST",
            "/api/v1/lists",
            serde_json::json!({"expected_revision":0,"name":"denied"}),
            session,
            &csrf
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn bound_web_listener_reports_ready_and_cancellation_releases_clients() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let f = Fixture::new(AuthMode::None).await;
    let config = nullgate_core::WebConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        tls: None,
        public_origin: None,
        tls_terminated_by_proxy: false,
    };
    let service = nullgate_web::WebService::start(
        config,
        f.auth.clone(),
        f.manager.clone(),
        8,
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap();
    assert!(matches!(
        service.monitor().current(),
        nullgate_core::ServiceStatus::Ready(_)
    ));
    let address = service.local_addr();
    let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
    client
        .write_all(
            format!("GET /api/v1/lists HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let mut idle = tokio::net::TcpStream::connect(address).await.unwrap();
    service.shutdown().await.unwrap();
    assert!(idle.read_u8().await.is_err());
    assert!(tokio::net::TcpListener::bind(address).await.is_ok());
}

#[tokio::test]
async fn dedicated_tls_validates_configuration_and_sets_secure_cookies() {
    use rustls::pki_types::{IpAddr, ServerName};
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let f = Fixture::new(AuthMode::None).await;
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let certificate = f.path.join("certificate.pem");
    let key = f.path.join("private.pem");
    std::fs::write(&certificate, cert.cert.pem()).unwrap();
    std::fs::write(&key, cert.signing_key.serialize_pem()).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = nullgate_core::WebConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        tls: Some(nullgate_core::TlsFiles {
            certificate_file: certificate,
            private_key_file: key,
        }),
        public_origin: None,
        tls_terminated_by_proxy: false,
    };
    let service = nullgate_web::WebService::start(
        config,
        f.auth.clone(),
        f.manager.clone(),
        8,
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap();
    let address = service.local_addr();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(client))
        .connect(
            ServerName::IpAddress(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST.into())),
            stream,
        )
        .await
        .unwrap();
    tls.write_all(
        format!("GET /api/v1/auth/csrf HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let mut response = String::new();
    match tls.read_to_string(&mut response).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(error) => panic!("{error}"),
    };
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains("__Host-nullgate_csrf="));
    assert!(response.contains("Secure"));
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn unsafe_tls_key_permissions_fail_before_readiness() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new(AuthMode::None).await;
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let certificate = f.path.join("certificate.pem");
    let key = f.path.join("private.pem");
    std::fs::write(&certificate, cert.cert.pem()).unwrap();
    std::fs::write(&key, cert.signing_key.serialize_pem()).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let config = nullgate_core::WebConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        tls: Some(nullgate_core::TlsFiles {
            certificate_file: certificate,
            private_key_file: key,
        }),
        public_origin: None,
        tls_terminated_by_proxy: false,
    };
    assert!(
        nullgate_web::WebService::start(
            config,
            f.auth.clone(),
            f.manager.clone(),
            8,
            tokio_util::sync::CancellationToken::new()
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn native_login_submission_keeps_credentials_out_of_urls() {
    let html = nullgate_web::views::login().await.0;
    let form = html
        .split("<form")
        .nth(1)
        .unwrap()
        .split('>')
        .next()
        .unwrap();
    assert!(
        form.contains("method=\"post\""),
        "native login must POST even without JavaScript"
    );
    assert!(form.contains("action=\"/api/v1/auth/login\""));
}

#[tokio::test]
async fn malformed_envelopes_have_stable_bad_request_outcomes() {
    let f = Fixture::new(AuthMode::None).await;
    let (cookie, proof) = f.csrf("").await;
    for body in [
        serde_json::json!({"name":"missing revision"}),
        serde_json::json!({"expected_revision":"bad","name":"wrong type"}),
        serde_json::json!({"expected_revision":0,"name":"unknown field","extra":true}),
    ] {
        let (status, error) = f.json("POST", "/api/v1/lists", body, &cookie, &proof).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
        assert_eq!(error["code"], "invalid_request");
    }
    assert_eq!(f.manager.reader.current().unwrap().revision(), 0);
}

struct Rejected {
    reader: PolicySubscription,
    error: PolicyError,
}
impl PolicyManagement for Rejected {
    fn subscribe(&self) -> PolicySubscription {
        self.reader.clone()
    }
    fn save(&self, _: u64, _: Mutation) -> PolicyFuture<'_, Result<PolicySaveResult, PolicyError>> {
        let error = self.error.clone();
        Box::pin(async move { Err(error) })
    }
}
#[tokio::test]
async fn capacity_and_activation_failure_are_distinct_api_outcomes() {
    let f = Fixture::new(AuthMode::None).await;
    let (cookie, proof) = f.csrf("").await;
    for (error, status, code) in [
        (
            PolicyError::Storage(nullgate_core::StorageError::Capacity),
            StatusCode::UNPROCESSABLE_ENTITY,
            "capacity",
        ),
        (
            PolicyError::CommittedNotActive { revision: 1 },
            StatusCode::SERVICE_UNAVAILABLE,
            "committed_not_active",
        ),
        (
            PolicyError::OutcomeUnknown,
            StatusCode::SERVICE_UNAVAILABLE,
            "outcome_unknown",
        ),
    ] {
        let state = WebState::new(
            f.auth.clone(),
            WebSecurity::loopback_http("127.0.0.1:8081".parse().unwrap(), "http://127.0.0.1:8081")
                .unwrap(),
            Arc::new(Rejected {
                reader: f.manager.reader.clone(),
                error,
            }),
        );
        let app = router(state, management_routes());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/lists")
                    .header("host", "127.0.0.1:8081")
                    .header("origin", "http://127.0.0.1:8081")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", &proof)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"expected_revision":0,"name":"rejected"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["code"], code);
    }
    assert!(
        f.manager
            .reader
            .current()
            .unwrap()
            .repository()
            .lists
            .is_empty()
    );
}

struct RemoteStub {
    manager: Arc<Management>,
    calls: std::sync::atomic::AtomicUsize,
}
impl nullgate_core::RemoteManagement for RemoteStub {
    fn import_url(
        &self,
        revision: u64,
        list_id: i64,
        url: String,
    ) -> PolicyFuture<'_, Result<nullgate_core::RemoteResult, nullgate_core::RemoteError>> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async move {
            let saved = self
                .manager
                .save(
                    revision,
                    Mutation::RemoteSourceAttempt {
                        list_id,
                        url,
                        text: Some("remote.invalid\nbad rule".into()),
                        at: 1,
                    },
                )
                .await?;
            Ok(nullgate_core::RemoteResult {
                saved,
                outcome: nullgate_core::RemoteOutcome::Applied,
            })
        })
    }
    fn refresh(
        &self,
        revision: u64,
        source_id: i64,
    ) -> PolicyFuture<'_, Result<nullgate_core::RemoteResult, nullgate_core::RemoteError>> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async move {
            let saved = self
                .manager
                .save(revision, Mutation::RecordFetchFailure { source_id, at: 2 })
                .await?;
            Ok(nullgate_core::RemoteResult {
                saved,
                outcome: nullgate_core::RemoteOutcome::FetchFailed(
                    nullgate_core::FetchFailure::Network,
                ),
            })
        })
    }
}
#[tokio::test]
async fn remote_routes_require_csrf_and_report_recorded_failure_revision() {
    let mut f = Fixture::new(AuthMode::None).await;
    let stub = Arc::new(RemoteStub {
        manager: f.manager.clone(),
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let state = WebState::new(
        f.auth.clone(),
        WebSecurity::loopback_http("127.0.0.1:8081".parse().unwrap(), "http://127.0.0.1:8081")
            .unwrap(),
        f.manager.clone(),
    )
    .with_remote(stub.clone());
    f.app = router(state, management_routes());
    f.manager
        .save(
            0,
            Mutation::CreateList {
                name: "Remote".into(),
            },
        )
        .await
        .unwrap();
    let id = f.manager.reader.current().unwrap().repository().lists[0].id;
    let path = format!("/api/v1/lists/{id}/remote");
    let body = serde_json::json!({"expected_revision":1,"url":"https://rules.invalid/list?token=%3Cscript%3E"});
    assert_eq!(
        f.json("POST", &path, body.clone(), "", "").await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(stub.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    let (cookie, proof) = f.csrf("").await;
    let (status, saved) = f.json("POST", &path, body, &cookie, &proof).await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(saved["revision"], 2);
    assert_eq!(saved["import"]["malformed"][0]["line"], 2);
    let source = f.manager.reader.current().unwrap().repository().lists[0].sources[0].id;
    let (status, error) = f
        .json(
            "POST",
            &format!("/api/v1/sources/{source}/refresh"),
            serde_json::json!({"expected_revision":2}),
            &cookie,
            &proof,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(error["revision"], 3);
    assert_eq!(error["code"], "download_failed");
    assert_eq!(
        f.manager
            .reader
            .current()
            .unwrap()
            .repository()
            .source(source)
            .unwrap()
            .entries
            .len(),
        1
    );
    let (status, _, html) = f
        .request("GET", "/", Body::empty(), "text/html", &cookie, "")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("Refresh remote source"));
    assert!(!html.contains("<script>"));
}
