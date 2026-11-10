//! Browser authentication/middleware; listener/UI wiring belongs to Task10.
pub mod auth;
pub mod authorization;
pub mod session;
pub use auth::{AuthError, AuthService, Clock, SystemClock};
pub use authorization::WebSecurity;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{
        HeaderMap, Method, StatusCode,
        header::{self, HeaderValue},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use nullgate_core::{Identity, PolicyManagement, Role};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
#[derive(Clone)]
pub struct WebState {
    pub auth: AuthService,
    pub security: WebSecurity,
    pub management: Arc<dyn PolicyManagement>,
    pub remote: Option<Arc<dyn nullgate_core::RemoteManagement>>,
}
impl WebState {
    pub fn new(
        auth: AuthService,
        security: WebSecurity,
        management: Arc<dyn PolicyManagement>,
    ) -> Self {
        Self {
            auth,
            security,
            management,
            remote: None,
        }
    }
}
impl WebState {
    pub fn with_remote(mut self, remote: Arc<dyn nullgate_core::RemoteManagement>) -> Self {
        self.remote = Some(remote);
        self
    }
}
impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Invalid => StatusCode::BAD_REQUEST,
            Self::Conflict => StatusCode::CONFLICT,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        };
        (status, self.to_string()).into_response()
    }
}
fn cookie(headers: &HeaderMap, name: &str) -> Result<Option<String>, AuthError> {
    let mut found = None;
    let mut size = 0;
    for value in headers.get_all(header::COOKIE) {
        size += value.as_bytes().len();
        if size > 8192 {
            return Err(AuthError::Invalid);
        }
        let text = value.to_str().map_err(|_| AuthError::Invalid)?;
        for pair in text.split(';') {
            let Some((key, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if key == name {
                if found.is_some() {
                    return Err(AuthError::Invalid);
                }
                found = Some(value.to_string());
            }
        }
    }
    Ok(found)
}
fn set_cookie(response: &mut Response, value: String) {
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&value).expect("cookie contains only fixed fields and hex token"),
    );
}
fn mutating(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}
fn csrf(
    headers: &HeaderMap,
    state: &WebState,
    token: Option<&str>,
    authenticated: bool,
) -> Result<(), AuthError> {
    if !state.security.origin_ok(headers) {
        return Err(AuthError::Forbidden);
    }
    let mut proofs = headers.get_all("x-csrf-token").iter();
    let proof = proofs
        .next()
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::Forbidden)?;
    if proofs.next().is_some() {
        return Err(AuthError::Forbidden);
    }
    let expected = if authenticated {
        session::csrf(token.ok_or(AuthError::Forbidden)?)
    } else {
        cookie(headers, state.security.bootstrap_name())?.ok_or(AuthError::Forbidden)?
    };
    if !session::equal(proof, &expected) {
        return Err(AuthError::Forbidden);
    }
    Ok(())
}
async fn boundary(State(state): State<WebState>, request: Request, next: Next) -> Response {
    if !state.security.host_ok(request.headers()) {
        return AuthError::Invalid.into_response();
    }
    if request
        .headers()
        .get("sec-fetch-site")
        .is_some_and(|v| v == "cross-site")
    {
        return AuthError::Forbidden.into_response();
    }
    if request.headers().contains_key(header::ORIGIN)
        && !state.security.origin_ok(request.headers())
    {
        return AuthError::Forbidden.into_response();
    }
    let mut response = next.run(request).await;
    response.headers_mut().insert(header::CONTENT_SECURITY_POLICY,HeaderValue::from_static("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
async fn authorize(State(state): State<WebState>, mut request: Request, next: Next) -> Response {
    let token = match cookie(request.headers(), state.security.session_name()) {
        Ok(token) => token,
        Err(error) => return error.into_response(),
    };
    let identity = match state.auth.identity(token.as_deref()).await {
        Ok(identity) => identity,
        Err(AuthError::Unauthorized)
            if request.method() == Method::GET && request.uri().path() == "/" =>
        {
            return axum::response::Redirect::to("/login").into_response();
        }
        Err(error) => return error.into_response(),
    };
    if mutating(request.method()) {
        if identity.role != Role::Administrator {
            return AuthError::Forbidden.into_response();
        }
        if let Err(error) = csrf(
            request.headers(),
            &state,
            token.as_deref(),
            !state.auth.no_auth(),
        ) {
            return error.into_response();
        }
    }
    request.extensions_mut().insert(identity);
    next.run(request).await
}
/// All management routes passed here are protected, including crafted direct requests.
pub fn router(state: WebState, management: Router<WebState>) -> Router {
    let management = management.layer(middleware::from_fn_with_state(state.clone(), authorize));
    let auth = Router::new()
        .route("/api/v1/auth/csrf", get(csrf_route))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/me", get(me))
        .layer(DefaultBodyLimit::max(8192));
    auth.route("/login", get(views::login))
        .route(
            "/app.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../assets/app.js"),
                )
            }),
        )
        .route(
            "/app.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../assets/app.css"),
                )
            }),
        )
        .merge(management)
        .layer(middleware::from_fn_with_state(state.clone(), boundary))
        .with_state(state)
}
#[derive(Serialize)]
struct Proof {
    csrf: String,
}
async fn csrf_route(
    State(state): State<WebState>,
    headers: HeaderMap,
) -> Result<Response, AuthError> {
    let token = cookie(&headers, state.security.session_name())?;
    if !state.auth.no_auth() {
        match state.auth.identity(token.as_deref()).await {
            Ok(_) => {
                return Ok(Json(Proof {
                    csrf: session::csrf(token.as_deref().unwrap()),
                })
                .into_response());
            }
            Err(AuthError::Unauthorized) => {}
            Err(error) => return Err(error),
        }
    }
    let token = session::random()?;
    let mut response = Json(Proof {
        csrf: token.clone(),
    })
    .into_response();
    set_cookie(
        &mut response,
        session::cookie(
            state.security.bootstrap_name(),
            &token,
            state.security.secure,
            600,
        ),
    );
    Ok(response)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Credentials {
    username: String,
    password: String,
}
async fn login(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(credentials): Json<Credentials>,
) -> Result<Response, AuthError> {
    let old = cookie(&headers, state.security.session_name())?;
    let authenticated = match state.auth.identity(old.as_deref()).await {
        Ok(_) => !state.auth.no_auth(),
        Err(AuthError::Unauthorized) => false,
        Err(error) => return Err(error),
    };
    csrf(&headers, &state, old.as_deref(), authenticated)?;
    let grant = state
        .auth
        .login(credentials.username, credentials.password, old)
        .await?;
    let mut response = Json(Proof { csrf: grant.csrf }).into_response();
    set_cookie(
        &mut response,
        session::cookie(
            state.security.session_name(),
            &grant.token,
            state.security.secure,
            28800,
        ),
    );
    set_cookie(
        &mut response,
        session::cookie(
            state.security.bootstrap_name(),
            "",
            state.security.secure,
            0,
        ),
    );
    Ok(response)
}
async fn logout(State(state): State<WebState>, headers: HeaderMap) -> Result<Response, AuthError> {
    let token = cookie(&headers, state.security.session_name())?;
    state.auth.identity(token.as_deref()).await?;
    csrf(&headers, &state, token.as_deref(), !state.auth.no_auth())?;
    state.auth.logout(token).await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    set_cookie(
        &mut response,
        session::cookie(state.security.session_name(), "", state.security.secure, 0),
    );
    set_cookie(
        &mut response,
        session::cookie(
            state.security.bootstrap_name(),
            "",
            state.security.secure,
            0,
        ),
    );
    Ok(response)
}
async fn me(
    State(state): State<WebState>,
    headers: HeaderMap,
) -> Result<Json<Identity>, AuthError> {
    let token = cookie(&headers, state.security.session_name())?;
    Ok(Json(state.auth.identity(token.as_deref()).await?))
}

pub mod blocklists;
pub mod routes;
pub mod views;
pub use routes::management_routes;
pub mod server;
pub use server::WebService;

pub mod imports;
