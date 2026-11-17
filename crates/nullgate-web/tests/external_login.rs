//! Local signed OIDC provider fixtures. No public provider, shared credentials or trust changes.
use axum::{
    Json, Router,
    body::Body,
    extract::{Form, State},
    http::{HeaderMap, Request, StatusCode, header},
    routing::{get, post},
};
use http_body_util::BodyExt;
use nullgate_core::{
    BlocklistRepository, Mutation, OidcConfig, PolicyError, PolicyFuture, PolicyManagement,
    PolicySaveResult, PolicySnapshot, PolicySubscription, SqliteRepository, policy_channel,
};
use nullgate_web::{
    AuthService, Clock, WebSecurity, WebState, management_routes, oidc::OidcService, router,
};
use openidconnect::{
    AccessToken, AdditionalClaims, Audience, ClientId, EndUserUsername, IdToken, IdTokenClaims,
    IssuerUrl, JsonWebKeyId, Nonce, PkceCodeChallenge, PkceCodeVerifier, PrivateSigningKey,
    StandardClaims, SubjectIdentifier,
    core::{
        CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
        CoreRsaPrivateSigningKey,
    },
};
use rsa::{
    pkcs1::{EncodeRsaPrivateKey, LineEnding},
    pkcs8::DecodePrivateKey,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, AtomicU64, Ordering},
    },
};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Extra {
    #[serde(flatten)]
    values: serde_json::Map<String, Value>,
}
impl AdditionalClaims for Extra {}
type Token =
    IdToken<Extra, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm>;
#[derive(Clone, Copy, Debug, PartialEq)]
enum Fault {
    None,
    Issuer,
    Audience,
    Nonce,
    Expired,
    Future,
    Signature,
    Azp,
    AccessHash,
    Provider,
    Redirect,
    Malformed,
    Oversized,
}
#[derive(Clone)]
struct Code {
    nonce: String,
    challenge: String,
}
struct ProviderState {
    issuer: String,
    key: CoreRsaPrivateSigningKey,
    codes: Mutex<HashMap<String, Code>>,
    fault: Mutex<Fault>,
    roles: Mutex<Vec<String>>,
    clock: Arc<TestClock>,
}
struct Provider {
    state: Arc<ProviderState>,
    cancel: CancellationToken,
    job: tokio::task::JoinHandle<()>,
}
#[derive(Default)]
struct TestClock(AtomicI64);
impl Clock for TestClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}
impl Provider {
    async fn new(clock: Arc<TestClock>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}/realms/test", listener.local_addr().unwrap());
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
        let key = rsa::RsaPrivateKey::from_pkcs8_der(&key.serialize_der())
            .unwrap()
            .to_pkcs1_pem(LineEnding::LF)
            .unwrap();
        let key =
            CoreRsaPrivateSigningKey::from_pem(&key, Some(JsonWebKeyId::new("fixture".into())))
                .unwrap();
        let state = Arc::new(ProviderState {
            issuer,
            key,
            codes: Mutex::new(HashMap::new()),
            fault: Mutex::new(Fault::None),
            roles: Mutex::new(vec!["viewer".into()]),
            clock,
        });
        async fn metadata(State(state): State<Arc<ProviderState>>) -> axum::response::Response {
            use axum::response::IntoResponse;
            let fault = *state.fault.lock().unwrap();
            if fault == Fault::Provider {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            if fault == Fault::Redirect {
                return (
                    StatusCode::FOUND,
                    [(header::LOCATION, "http://127.0.0.1:1/internal")],
                )
                    .into_response();
            }
            Json(json!({"issuer":state.issuer,"authorization_endpoint":format!("{}/authorize",state.issuer),"token_endpoint":format!("{}/token",state.issuer),"jwks_uri":format!("{}/certs",state.issuer),"end_session_endpoint":format!("{}/logout",state.issuer),"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],"code_challenge_methods_supported":["S256"]})).into_response()
        }
        async fn keys(State(state): State<Arc<ProviderState>>) -> Json<Value> {
            Json(json!({"keys":[state.key.as_verification_key()]}))
        }
        async fn token(
            State(state): State<Arc<ProviderState>>,
            Form(form): Form<HashMap<String, String>>,
        ) -> (StatusCode, Json<Value>) {
            let Some(code) = form
                .get("code")
                .and_then(|code| state.codes.lock().unwrap().get(code).cloned())
            else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error":"invalid_grant"})),
                );
            };
            let challenge = form.get("code_verifier").map(|value| {
                PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(value.clone()))
            });
            if form.get("grant_type").map(String::as_str) != Some("authorization_code")
                || form.get("client_id").map(String::as_str) != Some("nullgate")
                || form.get("redirect_uri").map(String::as_str)
                    != Some("http://127.0.0.1:8081/api/v1/auth/oidc/callback")
                || challenge.as_ref().map(|value| value.as_str()) != Some(code.challenge.as_str())
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error":"invalid_grant"})),
                );
            }
            let fault = *state.fault.lock().unwrap();
            if fault == Fault::Provider {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error":"provider unavailable"})),
                );
            }
            if fault == Fault::Malformed {
                return (
                    StatusCode::OK,
                    Json(
                        json!({"id_token":"not a signed token","access_token":"fixture-access","token_type":"Bearer"}),
                    ),
                );
            }
            if fault == Fault::Oversized {
                return (
                    StatusCode::OK,
                    Json(
                        json!({"id_token":"x".repeat(270000),"access_token":"fixture-access","token_type":"Bearer"}),
                    ),
                );
            }
            let now = state.clock.now();
            let issuer = if fault == Fault::Issuer {
                "https://wrong.invalid"
            } else {
                &state.issuer
            };
            let audience = if fault == Fault::Audience {
                "wrong-client"
            } else {
                "nullgate"
            };
            let expires = if fault == Fault::Expired {
                now - 1
            } else {
                now + 120
            };
            let issued = if fault == Fault::Future {
                now + 3600
            } else {
                now
            };
            let roles = state.roles.lock().unwrap().clone();
            let mut values = serde_json::Map::new();
            values.insert("realm_access".into(), json!({"roles":roles}));
            let mut claims = IdTokenClaims::new(
                IssuerUrl::new(issuer.into()).unwrap(),
                vec![Audience::new(audience.into())],
                chrono::DateTime::from_timestamp(expires, 0).unwrap(),
                chrono::DateTime::from_timestamp(issued, 0).unwrap(),
                StandardClaims::new(SubjectIdentifier::new("subject-1".into()))
                    .set_preferred_username(Some(EndUserUsername::new("Provider <Alice>".into()))),
                Extra { values },
            )
            .set_nonce(Some(Nonce::new(if fault == Fault::Nonce {
                "wrong-nonce".into()
            } else {
                code.nonce
            })));
            if fault == Fault::Azp {
                claims = claims.set_authorized_party(Some(ClientId::new("wrong-client".into())));
            }
            let access = AccessToken::new("fixture-access".into());
            let mut token = Token::new(
                claims,
                &state.key,
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                Some(&access),
                None,
            )
            .unwrap()
            .to_string();
            if fault == Fault::Signature {
                let position = token.rfind('.').unwrap() + 1;
                token.replace_range(
                    position..position + 1,
                    if &token[position..position + 1] == "A" {
                        "B"
                    } else {
                        "A"
                    },
                );
            }
            (
                StatusCode::OK,
                Json(
                    json!({"access_token":if fault==Fault::AccessHash{"substituted-access"}else{"fixture-access"},"token_type":"Bearer","id_token":token}),
                ),
            )
        }
        let app = Router::new()
            .route(
                "/realms/test/.well-known/openid-configuration",
                get(metadata),
            )
            .route("/realms/test/certs", get(keys))
            .route("/realms/test/token", post(token))
            .with_state(state.clone());
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let job = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(stop.cancelled_owned())
                .await
                .unwrap();
        });
        Self { state, cancel, job }
    }
    fn config(&self) -> OidcConfig {
        OidcConfig {
            issuer: self.state.issuer.clone(),
            client_id: "nullgate".into(),
            redirect_uri: "http://127.0.0.1:8081/api/v1/auth/oidc/callback".into(),
            client_secret_file: None,
            role_claim: "/realm_access/roles".into(),
            administrator_values: vec!["admin".into()],
            viewer_values: vec!["viewer".into()],
        }
    }
    fn authorize(&self, url: &str) -> (String, String) {
        static CODE: AtomicU64 = AtomicU64::new(0);
        let url = reqwest::Url::parse(url).unwrap();
        let values = url.query_pairs().into_owned().collect::<HashMap<_, _>>();
        assert_eq!(values["response_type"], "code");
        assert_eq!(values["code_challenge_method"], "S256");
        assert_eq!(values["client_id"], "nullgate");
        assert!(values["scope"].split(' ').any(|scope| scope == "openid"));
        let code = format!("fixture-code-{}", CODE.fetch_add(1, Ordering::Relaxed));
        self.state.codes.lock().unwrap().insert(
            code.clone(),
            Code {
                nonce: values["nonce"].clone(),
                challenge: values["code_challenge"].clone(),
            },
        );
        (values["state"].clone(), code)
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.job.abort();
    }
}
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
struct Fixture {
    path: PathBuf,
    app: Router,
    provider: Provider,
    clock: Arc<TestClock>,
}
impl Fixture {
    async fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "nullgate-oidc-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let clock = Arc::new(TestClock(AtomicI64::new(1_800_000_000)));
        let provider = Provider::new(clock.clone()).await;
        let service = OidcService::open_with_clock(provider.config(), clock.clone())
            .await
            .unwrap();
        let auth = AuthService::open_external_with_clock(
            path.join("state.sqlite3"),
            service.context().to_owned(),
            clock.clone(),
        )
        .await
        .unwrap();
        let mut repo = SqliteRepository::open(path.join("state.sqlite3")).unwrap();
        let (publisher, reader) =
            policy_channel(PolicySnapshot::from_repository(repo.snapshot().unwrap()).unwrap());
        let state = WebState::new(
            auth.clone(),
            WebSecurity::loopback_http("127.0.0.1:8081".parse().unwrap(), "http://127.0.0.1:8081")
                .unwrap(),
            Arc::new(Manager {
                reader,
                _publisher: publisher,
            }),
        )
        .with_oidc(service);
        let app = router(state, management_routes());
        Self {
            path,
            app,
            provider,
            clock,
        }
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        cookie: &str,
        proof: &str,
        body: Value,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "127.0.0.1:8081")
            .header("origin", "http://127.0.0.1:8081")
            .header("content-type", "application/json");
        if !cookie.is_empty() {
            request = request.header("cookie", cookie);
        }
        if !proof.is_empty() {
            request = request.header("x-csrf-token", proof);
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        (status, headers, bytes)
    }
    async fn csrf(&self, cookie: &str) -> (String, String) {
        let (status, headers, body) = self
            .request("GET", "/api/v1/auth/csrf", cookie, "", Value::Null)
            .await;
        assert_eq!(status, StatusCode::OK);
        let proof: Value = serde_json::from_slice(&body).unwrap();
        (
            if cookie.is_empty() {
                cookie_named(&headers, "nullgate_csrf")
            } else {
                cookie.into()
            },
            proof["csrf"].as_str().unwrap().into(),
        )
    }
    async fn start(&self) -> (String, String, String) {
        let (cookie, proof) = self.csrf("").await;
        let (status, headers, body) = self
            .request(
                "POST",
                "/api/v1/auth/oidc/start",
                &cookie,
                &proof,
                json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        let url: Value = serde_json::from_slice(&body).unwrap();
        let (state, code) = self
            .provider
            .authorize(url["authorization_url"].as_str().unwrap());
        (cookie_named(&headers, "nullgate_oidc"), state, code)
    }
    async fn callback(
        &self,
        cookie: &str,
        state: &str,
        code: &str,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        self.request(
            "GET",
            &format!("/api/v1/auth/oidc/callback?state={state}&code={code}"),
            cookie,
            "",
            Value::Null,
        )
        .await
    }
}
fn cookie_named(headers: &HeaderMap, name: &str) -> String {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|value| value.split(';').next().unwrap())
        .find(|value| value.starts_with(&format!("{name}=")))
        .unwrap()
        .into()
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
#[tokio::test]
async fn mapped_viewer_admin_and_unmapped_claims_enforce_existing_roles() {
    let f = Fixture::new().await;
    let (cookie, state, code) = f.start().await;
    let (status, headers, _) = f.callback(&cookie, &state, &code).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let viewer = cookie_named(&headers, "nullgate_session");
    let (status, _, body) = f
        .request("GET", "/api/v1/auth/me", &viewer, "", Value::Null)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["role"],
        "viewer"
    );
    let (_, _, html) = f.request("GET", "/", &viewer, "", Value::Null).await;
    let html = String::from_utf8(html).unwrap();
    assert!(html.contains("Provider &lt;Alice&gt;"));
    assert!(!html.contains("Provider <Alice>"));
    let (_, proof) = f.csrf(&viewer).await;
    assert_eq!(
        f.request(
            "POST",
            "/api/v1/lists",
            &viewer,
            &proof,
            json!({"expected_revision":0,"name":"denied"})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    *f.provider.state.roles.lock().unwrap() = vec!["admin".into(), "viewer".into()];
    let (cookie, state, code) = f.start().await;
    let (status, headers, _) = f.callback(&cookie, &state, &code).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let admin = cookie_named(&headers, "nullgate_session");
    assert_eq!(
        f.request("GET", "/api/v1/auth/me", &viewer, "", Value::Null)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (_, _, body) = f
        .request("GET", "/api/v1/auth/me", &admin, "", Value::Null)
        .await;
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["role"],
        "administrator"
    );
    *f.provider.state.roles.lock().unwrap() = vec!["unmapped".into()];
    let (cookie, state, code) = f.start().await;
    assert_eq!(
        f.callback(&cookie, &state, &code).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.request("GET", "/api/v1/auth/me", &admin, "", Value::Null)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn invalid_state_browser_replay_and_expired_flow_never_issue_sessions() {
    let f = Fixture::new().await;
    assert_eq!(
        f.request("POST", "/api/v1/auth/oidc/start", "", "", json!({}))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (cookie, state, code) = f.start().await;
    assert_eq!(
        f.callback(&format!("nullgate_oidc={}", "b".repeat(64)), &state, &code)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.callback("", &state, &code).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.callback(&cookie, &"a".repeat(64), &code).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.callback(&cookie, &state, &code).await.0,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        f.callback(&cookie, &state, &code).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (cookie, state, code) = f.start().await;
    f.clock.0.fetch_add(601, Ordering::SeqCst);
    assert_eq!(
        f.callback(&cookie, &state, &code).await.0,
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn invalid_signed_claims_signatures_and_token_responses_fail_closed() {
    let f = Fixture::new().await;
    for fault in [
        Fault::Issuer,
        Fault::Audience,
        Fault::Nonce,
        Fault::Expired,
        Fault::Future,
        Fault::Signature,
        Fault::Azp,
        Fault::AccessHash,
        Fault::Malformed,
        Fault::Oversized,
    ] {
        let (cookie, state, code) = f.start().await;
        *f.provider.state.fault.lock().unwrap() = fault;
        let (status, headers, body) = f.callback(&cookie, &state, &code).await;
        assert!(
            !status.is_success() && !status.is_redirection(),
            "{fault:?}: {status}"
        );
        assert!(
            !headers
                .get_all(header::SET_COOKIE)
                .iter()
                .any(|value| value.to_str().unwrap().starts_with("nullgate_session="))
        );
        assert!(!String::from_utf8_lossy(&body).contains("fixture-access"));
        *f.provider.state.fault.lock().unwrap() = Fault::None;
    }
}
#[tokio::test]
async fn sessions_expire_at_id_token_expiry_and_logout_revokes_before_provider_redirect() {
    let f = Fixture::new().await;
    let (cookie, state, code) = f.start().await;
    let (_, headers, _) = f.callback(&cookie, &state, &code).await;
    let cookie = cookie_named(&headers, "nullgate_session");
    let (_, proof) = f.csrf(&cookie).await;
    let (status, headers, body) = f
        .request("POST", "/api/v1/auth/logout", &cookie, &proof, json!({}))
        .await;
    assert_eq!(status, StatusCode::OK);
    let result: Value = serde_json::from_slice(&body).unwrap();
    let url = reqwest::Url::parse(result["redirect"].as_str().unwrap()).unwrap();
    assert!(url.path().ends_with("/logout"));
    let query = url.query_pairs().into_owned().collect::<HashMap<_, _>>();
    assert_eq!(query["client_id"], "nullgate");
    assert_eq!(
        query["post_logout_redirect_uri"],
        "http://127.0.0.1:8081/login"
    );
    assert!(!query.contains_key("id_token_hint"));
    assert!(
        headers
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|value| value.to_str().unwrap().contains("Max-Age=0"))
    );
    assert_eq!(
        f.request("GET", "/api/v1/auth/me", &cookie, "", Value::Null)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (cookie, state, code) = f.start().await;
    let (_, headers, _) = f.callback(&cookie, &state, &code).await;
    let cookie = cookie_named(&headers, "nullgate_session");
    f.clock.0.fetch_add(120, Ordering::SeqCst);
    assert_eq!(
        f.request("GET", "/api/v1/auth/me", &cookie, "", Value::Null)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn provider_errors_and_redirects_do_not_enable_password_login() {
    let f = Fixture::new().await;
    for fault in [Fault::Provider, Fault::Redirect] {
        *f.provider.state.fault.lock().unwrap() = fault;
        let (cookie, proof) = f.csrf("").await;
        assert_eq!(
            f.request(
                "POST",
                "/api/v1/auth/oidc/start",
                &cookie,
                &proof,
                json!({})
            )
            .await
            .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            f.request(
                "POST",
                "/api/v1/auth/login",
                &cookie,
                &proof,
                json!({"username":"admin","password":"not a real provider credential"})
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    let (status, _, body) = f.request("GET", "/login", "", "", Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("Continue with identity provider"));
    assert!(!String::from_utf8_lossy(&body).contains("type=\"password\""));
}
#[tokio::test]
async fn secret_files_are_bounded_service_owned_and_not_part_of_configuration_debug() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new().await;
    let secret = f.path.join("client-secret");
    std::fs::write(&secret, "isolated-test-client-secret").unwrap();
    let mut config = f.provider.config();
    config.client_secret_file = Some(secret.clone());
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(OidcService::open(config.clone()).await.is_err());
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(OidcService::open(config.clone()).await.is_ok());
    assert!(!format!("{config:?}").contains("isolated-test-client-secret"));
    std::fs::write(secret, vec![b'x'; 4097]).unwrap();
    assert!(OidcService::open(config).await.is_err());
}

#[tokio::test]
async fn provider_cancelled_callbacks_consume_the_bound_authorization_attempt() {
    let f = Fixture::new().await;
    let (cookie, state, code) = f.start().await;
    let (status, _, _) = f
        .request(
            "GET",
            &format!("/api/v1/auth/oidc/callback?state={state}&error=access_denied"),
            &cookie,
            "",
            Value::Null,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        f.callback(&cookie, &state, &code).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn logout_also_invalidates_pending_login_from_that_browser() {
    let f = Fixture::new().await;
    let (binding, state, code) = f.start().await;
    let (_, headers, _) = f.callback(&binding, &state, &code).await;
    let session = cookie_named(&headers, "nullgate_session");
    let (_, proof) = f.csrf(&session).await;
    let (status, headers, body) = f
        .request(
            "POST",
            "/api/v1/auth/oidc/start",
            &session,
            &proof,
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let url: Value = serde_json::from_slice(&body).unwrap();
    let (state, code) = f
        .provider
        .authorize(url["authorization_url"].as_str().unwrap());
    let binding = cookie_named(&headers, "nullgate_oidc");
    assert_eq!(
        f.request(
            "POST",
            "/api/v1/auth/logout",
            &format!("{session}; {binding}"),
            &proof,
            json!({})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        f.callback(&binding, &state, &code).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn cross_site_provider_navigation_reaches_only_oidc_return_pages() {
    let f = Fixture::new().await;
    let (binding, state, code) = f.start().await;
    for (path, cookie, expected) in [
        (
            format!("/api/v1/auth/oidc/callback?state={state}&code={code}"),
            binding.as_str(),
            StatusCode::SEE_OTHER,
        ),
        ("/login".into(), "", StatusCode::OK),
        ("/".into(), "", StatusCode::SEE_OTHER),
        ("/api/v1/auth/me".into(), "", StatusCode::FORBIDDEN),
        (
            "/api/v1/auth/oidc/callback?state=invalid&code=invalid".into(),
            "",
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let response = f
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("host", "127.0.0.1:8081")
                    .header("sec-fetch-site", "cross-site")
                    .header("sec-fetch-mode", "navigate")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    let response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oidc/start")
                .header("host", "127.0.0.1:8081")
                .header("sec-fetch-site", "cross-site")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
