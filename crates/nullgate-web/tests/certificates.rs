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
use nullgate_http::ca::CaProvider;
use nullgate_web::{AuthService, WebSecurity, WebState, management_routes, router};
use std::{path::PathBuf, sync::Arc};
use tower::ServiceExt;
struct Fixture {
    path: PathBuf,
    app: Router,
    auth: AuthService,
    pem: Arc<[u8]>,
    private: Vec<u8>,
}
impl Fixture {
    async fn new(mode: AuthMode) -> Self {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("nullgate-ca-web-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        let ca = CaProvider::open(&path).unwrap();
        let public = ca.public_certificate();
        let pem = public.certificate_pem();
        let private = std::fs::read(path.join("inspection-ca/material.bin")).unwrap();
        let auth = AuthService::open(path.join("state.sqlite3"), mode)
            .await
            .unwrap();
        let mut repo = SqliteRepository::open(path.join("state.sqlite3")).unwrap();
        let (_publisher, reader) =
            policy_channel(PolicySnapshot::from_repository(repo.snapshot().unwrap()).unwrap());
        // The public capability remains usable after the signer is dropped.
        struct Manager {
            _publisher: nullgate_core::PolicyPublisher,
            reader: PolicySubscription,
        }
        impl PolicyManagement for Manager {
            fn subscribe(&self) -> PolicySubscription {
                self.reader.clone()
            }
            fn save(
                &self,
                _: u64,
                _: Mutation,
            ) -> PolicyFuture<'_, Result<PolicySaveResult, PolicyError>> {
                Box::pin(async { Err(PolicyError::Stopped) })
            }
        }
        let state = WebState::new(
            auth.clone(),
            WebSecurity::loopback_http("127.0.0.1:8081".parse().unwrap(), "http://127.0.0.1:8081")
                .unwrap(),
            Arc::new(Manager { _publisher, reader }),
        )
        .with_public_ca(public);
        let app = router(state, management_routes());
        Self {
            path,
            app,
            auth,
            pem,
            private,
        }
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        cookie: &str,
        proof: &str,
        body: Body,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
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
            .oneshot(request.body(body).unwrap())
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
    async fn login(&self, user: &str) -> String {
        let (status, headers, bytes) = self
            .request("GET", "/api/v1/auth/csrf", "", "", Body::empty())
            .await;
        assert_eq!(status, StatusCode::OK);
        let cookie = headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let proof: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let body = serde_json::json!({"username":user,"password":"unique test password for CA"})
            .to_string();
        let (status, headers, _) = self
            .request(
                "POST",
                "/api/v1/auth/login",
                cookie,
                proof["csrf"].as_str().unwrap(),
                Body::from(body),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        headers
            .get_all(header::SET_COOKIE)
            .iter()
            .find_map(|header| {
                let pair = header.to_str().unwrap().split(';').next().unwrap();
                pair.contains("session=").then(|| pair.to_owned())
            })
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
#[tokio::test]
async fn downloads_are_public_certificate_only_and_admin_only() {
    let f = Fixture::new(AuthMode::Local).await;
    assert_eq!(
        f.request("GET", "/api/v1/certificates/ca", "", "", Body::empty())
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    f.auth
        .provision_admin("admin", "unique test password for CA")
        .await
        .unwrap();
    let admin = f.login("admin").await;
    f.auth
        .create_user(
            admin.split_once('=').map(|(_, value)| value),
            "viewer",
            "unique test password for CA",
            Role::Viewer,
        )
        .await
        .unwrap();
    let viewer = f.login("viewer").await;
    for method in ["GET", "HEAD"] {
        assert_eq!(
            f.request(
                method,
                "/api/v1/certificates/ca",
                &viewer,
                "",
                Body::empty()
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
    }
    let (status, headers, bytes) = f
        .request("GET", "/api/v1/certificates/ca", &admin, "", Body::empty())
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/x-pem-file");
    assert!(
        headers[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .contains("attachment; filename=\"nullgate-inspection-ca.pem\"")
    );
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(bytes, f.pem.as_ref());
    assert!(!String::from_utf8_lossy(&bytes).contains("PRIVATE KEY"));
    let cert_len = u32::from_be_bytes(f.private[8..12].try_into().unwrap()) as usize;
    let key = &f.private[16 + cert_len..];
    assert!(!bytes.windows(key.len()).any(|window| window == key));
    let (_, _, viewer_html) = f.request("GET", "/", &viewer, "", Body::empty()).await;
    assert!(!String::from_utf8_lossy(&viewer_html).contains("Download public CA"));
    let (_, _, admin_html) = f.request("GET", "/", &admin, "", Body::empty()).await;
    assert!(String::from_utf8_lossy(&admin_html).contains("Download public CA"));
}
#[tokio::test]
async fn explicit_no_auth_allows_public_download_without_private_operations() {
    let f = Fixture::new(AuthMode::None).await;
    let (status, _, body) = f
        .request("GET", "/api/v1/certificates/ca", "", "", Body::empty())
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, f.pem.as_ref());
    assert_eq!(
        std::fs::read(f.path.join("inspection-ca/material.bin")).unwrap(),
        f.private
    );
}
