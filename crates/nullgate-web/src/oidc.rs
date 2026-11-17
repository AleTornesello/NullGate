//! OIDC code/S256 login with one-shot browser binding and verified, explicitly mapped claims.
mod secret;
mod transport;
use crate::{AuthError, Clock, SystemClock, session};
use nullgate_core::{OidcConfig, Role};
use openidconnect::TokenResponse;
use openidconnect::{
    AccessTokenHash, AdditionalClaims, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    IdToken, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    core::{
        CoreAuthenticationFlow, CoreClient, CoreGenderClaim, CoreJsonWebKeySet,
        CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreProviderMetadata,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use transport::Transport;
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Claims {
    #[serde(flatten)]
    values: serde_json::Map<String, serde_json::Value>,
}
impl AdditionalClaims for Claims {}
type Token =
    IdToken<Claims, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm>;
struct Pending {
    browser: String,
    nonce: Nonce,
    verifier: PkceCodeVerifier,
    expires: i64,
}
struct Provider {
    metadata: CoreProviderMetadata,
    logout: reqwest::Url,
}
pub struct VerifiedIdentity {
    pub(crate) issuer: String,
    pub(crate) subject: String,
    pub(crate) display: String,
    pub(crate) role: Option<Role>,
    pub(crate) expires: i64,
    pub(crate) context: String,
}
pub struct Begun {
    pub authorization_url: String,
    pub(crate) browser: String,
}
pub struct OidcService {
    config: OidcConfig,
    transport: Transport,
    secret: Option<ClientSecret>,
    pending: Mutex<HashMap<[u8; 32], Pending>>,
    gate: Arc<tokio::sync::Semaphore>,
    clock: Arc<dyn Clock>,
    context: String,
    logout: Mutex<Option<reqwest::Url>>,
}
impl OidcService {
    pub async fn open(config: OidcConfig) -> Result<Arc<Self>, AuthError> {
        Self::open_with_clock(config, Arc::new(SystemClock)).await
    }
    pub async fn open_with_clock(
        config: OidcConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Self>, AuthError> {
        let issuer = reqwest::Url::parse(&config.issuer).map_err(|_| AuthError::Invalid)?;
        let redirect = reqwest::Url::parse(&config.redirect_uri).map_err(|_| AuthError::Invalid)?;
        let web = nullgate_core::WebConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            public_origin: Some(redirect.origin().ascii_serialization()),
            tls_terminated_by_proxy: false,
            tls: None,
        };
        config.validate(&web).map_err(|_| AuthError::Invalid)?;
        let file = config.client_secret_file.clone();
        let secret =
            tokio::task::spawn_blocking(move || file.map(|path| secret::read(&path)).transpose())
                .await
                .map_err(|_| AuthError::Unavailable)??
                .map(ClientSecret::new);
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(10));
        if issuer.scheme() == "http"
            && issuer
                .host_str()
                .is_some_and(|host| host.trim_end_matches('.').eq_ignore_ascii_case("localhost"))
        {
            let port = issuer.port_or_known_default().ok_or(AuthError::Invalid)?;
            builder = builder.resolve_to_addrs(
                issuer.host_str().ok_or(AuthError::Invalid)?,
                &[
                    std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                    std::net::SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), port),
                ],
            );
        }
        let client = builder.build().map_err(|_| AuthError::Unavailable)?;
        let context = Sha256::digest(serde_json::to_vec(&config).map_err(|_| AuthError::Invalid)?)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Ok(Arc::new(Self {
            config,
            transport: Transport { client, issuer },
            secret,
            pending: Mutex::new(HashMap::new()),
            gate: Arc::new(tokio::sync::Semaphore::new(4)),
            clock,
            context,
            logout: Mutex::new(None),
        }))
    }
    pub(crate) fn cancel_browser(&self, browser: &str) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.retain(|_, entry| !session::equal(&entry.browser, browser));
        }
    }
    pub fn context(&self) -> &str {
        &self.context
    }
    pub(crate) fn now(&self) -> Result<i64, AuthError> {
        let now = self.clock.now();
        if chrono::DateTime::from_timestamp(now, 0).is_none() || now < 0 {
            Err(AuthError::Unavailable)
        } else {
            Ok(now)
        }
    }
    async fn provider(&self) -> Result<Provider, AuthError> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.transport.issuer.as_str().trim_end_matches('/')
        );
        let bytes = self.transport.get(&url).await?;
        let raw: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| AuthError::Unavailable)?;
        let metadata: CoreProviderMetadata =
            serde_json::from_slice(&bytes).map_err(|_| AuthError::Unavailable)?;
        if metadata.issuer().as_str() != self.config.issuer {
            return Err(AuthError::Unavailable);
        }
        for endpoint in [
            metadata.authorization_endpoint().as_str(),
            metadata
                .token_endpoint()
                .ok_or(AuthError::Unavailable)?
                .as_str(),
            metadata.jwks_uri().as_str(),
        ] {
            self.transport
                .check(&reqwest::Url::parse(endpoint).map_err(|_| AuthError::Unavailable)?)?;
        }
        if raw
            .get("code_challenge_methods_supported")
            .is_some_and(|value| {
                !value
                    .as_array()
                    .is_some_and(|values| values.iter().any(|value| value == "S256"))
            })
        {
            return Err(AuthError::Unavailable);
        }
        let logout = reqwest::Url::parse(
            raw.get("end_session_endpoint")
                .and_then(|value| value.as_str())
                .ok_or(AuthError::Unavailable)?,
        )
        .map_err(|_| AuthError::Unavailable)?;
        self.transport.check(&logout)?;
        if logout.query().is_some() {
            return Err(AuthError::Unavailable);
        }
        let keys: CoreJsonWebKeySet =
            serde_json::from_slice(&self.transport.get(metadata.jwks_uri().as_str()).await?)
                .map_err(|_| AuthError::Unavailable)?;
        *self.logout.lock().map_err(|_| AuthError::Unavailable)? = Some(logout.clone());
        Ok(Provider {
            metadata: metadata.set_jwks(keys),
            logout,
        })
    }
    pub async fn begin(&self) -> Result<Begun, AuthError> {
        let _slot = self
            .gate
            .clone()
            .try_acquire_owned()
            .map_err(|_| AuthError::Unavailable)?;
        tokio::time::timeout(Duration::from_secs(20), async {
            let provider = self.provider().await?;
            let client = CoreClient::from_provider_metadata(
                provider.metadata,
                ClientId::new(self.config.client_id.clone()),
                self.secret.clone(),
            )
            .set_redirect_uri(
                RedirectUrl::new(self.config.redirect_uri.clone())
                    .map_err(|_| AuthError::Invalid)?,
            );
            let state = session::random()?;
            let browser = session::random()?;
            let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
            let state_for_url = state.clone();
            let (url, _, nonce) = client
                .authorize_url(
                    CoreAuthenticationFlow::AuthorizationCode,
                    move || CsrfToken::new(state_for_url.clone()),
                    Nonce::new_random,
                )
                .set_pkce_challenge(challenge)
                .url();
            let now = self.now()?;
            let mut pending = self.pending.lock().map_err(|_| AuthError::Unavailable)?;
            pending.retain(|_, entry| entry.expires > now);
            if pending.len() >= 1024 {
                return Err(AuthError::Unavailable);
            }
            pending.insert(
                session::digest(&state),
                Pending {
                    browser: browser.clone(),
                    nonce,
                    verifier,
                    expires: now.checked_add(600).ok_or(AuthError::Unavailable)?,
                },
            );
            Ok(Begun {
                authorization_url: url.to_string(),
                browser,
            })
        })
        .await
        .map_err(|_| AuthError::Unavailable)?
    }
    fn take_pending(&self, state: &str, browser: &str) -> Result<Pending, AuthError> {
        if !session::valid(state) || !session::valid(browser) {
            return Err(AuthError::Unauthorized);
        }
        let mut pending = self.pending.lock().map_err(|_| AuthError::Unavailable)?;
        let key = session::digest(state);
        let entry = pending.get(&key).ok_or(AuthError::Unauthorized)?;
        if entry.expires <= self.now()? {
            pending.remove(&key);
            return Err(AuthError::Unauthorized);
        }
        if !session::equal(&entry.browser, browser) {
            return Err(AuthError::Unauthorized);
        }
        pending.remove(&key).ok_or(AuthError::Unauthorized)
    }
    fn cancel(&self, state: &str, browser: &str) -> Result<(), AuthError> {
        let _ = self.take_pending(state, browser)?;
        Ok(())
    }
    pub async fn complete(
        &self,
        state: &str,
        browser: &str,
        code: &str,
        response_issuer: Option<&str>,
    ) -> Result<VerifiedIdentity, AuthError> {
        let transaction = self.take_pending(state, browser)?;
        if code.is_empty()
            || code.len() > 4096
            || response_issuer.is_some_and(|issuer| issuer != self.config.issuer)
        {
            return Err(AuthError::Unauthorized);
        }
        let slot = self
            .gate
            .clone()
            .try_acquire_owned()
            .map_err(|_| AuthError::Unavailable)?;
        tokio::time::timeout(Duration::from_secs(20), async {
            let provider = self.provider().await?;
            let client = CoreClient::from_provider_metadata(
                provider.metadata,
                ClientId::new(self.config.client_id.clone()),
                self.secret.clone(),
            )
            .set_redirect_uri(
                RedirectUrl::new(self.config.redirect_uri.clone())
                    .map_err(|_| AuthError::Invalid)?,
            );
            let tokens = client
                .exchange_code(AuthorizationCode::new(code.to_owned()))
                .map_err(|_| AuthError::Unavailable)?
                .set_pkce_verifier(transaction.verifier)
                .request_async(&self.transport)
                .await
                .map_err(|error| match error {
                    openidconnect::RequestTokenError::Request(error) => error,
                    _ => AuthError::Unauthorized,
                })?;
            let raw = tokens
                .id_token()
                .ok_or(AuthError::Unauthorized)?
                .to_string();
            if raw.len() > 32768 {
                return Err(AuthError::Unauthorized);
            }
            let token: Token = raw.parse().map_err(|_| AuthError::Unauthorized)?;
            let config = self.config.clone();
            let context = self.context.clone();
            let now = self.now()?;
            tokio::task::spawn_blocking(move || {
                let _slot = slot;
                let verifier = client
                    .id_token_verifier()
                    .set_allowed_algs(vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256])
                    .set_other_audience_verifier_fn(|_| true)
                    .set_time_fn(move || {
                        chrono::DateTime::from_timestamp(now, 0)
                            .unwrap_or(chrono::DateTime::UNIX_EPOCH)
                    })
                    .set_issue_time_verifier_fn(move |issued| {
                        if issued.timestamp() >= 0 && issued.timestamp() <= now + 60 {
                            Ok(())
                        } else {
                            Err("Invalid issue time".into())
                        }
                    });
                let claims = token
                    .claims(&verifier, &transaction.nonce)
                    .map_err(|_| AuthError::Unauthorized)?;
                if claims
                    .authorized_party()
                    .is_some_and(|party| party.as_str() != config.client_id)
                    || (claims.audiences().len() > 1 && claims.authorized_party().is_none())
                {
                    return Err(AuthError::Unauthorized);
                }
                if let Some(expected) = claims.access_token_hash() {
                    let actual = AccessTokenHash::from_token(
                        tokens.access_token(),
                        token.signing_alg().map_err(|_| AuthError::Unauthorized)?,
                        token
                            .signing_key(&verifier)
                            .map_err(|_| AuthError::Unauthorized)?,
                    )
                    .map_err(|_| AuthError::Unauthorized)?;
                    if &actual != expected {
                        return Err(AuthError::Unauthorized);
                    }
                }
                let value = serde_json::to_value(claims).map_err(|_| AuthError::Unauthorized)?;
                if value
                    .get("nbf")
                    .is_some_and(|nbf| nbf.as_i64().is_none_or(|not_before| not_before > now))
                {
                    return Err(AuthError::Unauthorized);
                }
                let role = map_role(&value, &config)?;
                let subject = claims.subject().as_str().to_owned();
                let display = claims
                    .preferred_username()
                    .map(|name| name.as_str())
                    .unwrap_or(&subject)
                    .to_owned();
                if subject.is_empty()
                    || subject.len() > 255
                    || display.is_empty()
                    || display.len() > 256
                    || subject.chars().chain(display.chars()).any(char::is_control)
                {
                    return Err(AuthError::Unauthorized);
                }
                Ok(VerifiedIdentity {
                    issuer: claims.issuer().as_str().to_owned(),
                    subject,
                    display,
                    role,
                    expires: claims.expiration().timestamp(),
                    context,
                })
            })
            .await
            .map_err(|_| AuthError::Unavailable)?
        })
        .await
        .map_err(|_| AuthError::Unavailable)?
    }
    pub(crate) async fn logout_redirect(&self) -> Option<String> {
        let cached = self.logout.lock().ok()?.clone();
        let endpoint = if let Some(endpoint) = cached {
            endpoint
        } else {
            let _slot = self.gate.clone().try_acquire_owned().ok()?;
            tokio::time::timeout(Duration::from_secs(20), self.provider())
                .await
                .ok()?
                .ok()?
                .logout
        };
        let mut redirect = reqwest::Url::parse(&self.config.redirect_uri).ok()?;
        redirect.set_path("/login");
        redirect.set_query(None);
        let mut endpoint = endpoint;
        endpoint
            .query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair("post_logout_redirect_uri", redirect.as_str());
        Some(endpoint.to_string())
    }
}
fn map_role(claims: &serde_json::Value, config: &OidcConfig) -> Result<Option<Role>, AuthError> {
    let Some(value) = claims.pointer(&config.role_claim) else {
        return Ok(None);
    };
    let values = if let Some(value) = value.as_str() {
        vec![value]
    } else if let Some(values) = value.as_array() {
        values
            .iter()
            .map(|value| value.as_str().ok_or(AuthError::Unauthorized))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        return Err(AuthError::Unauthorized);
    };
    if values.iter().any(|value| {
        config
            .administrator_values
            .iter()
            .any(|allowed| allowed == value)
    }) {
        Ok(Some(Role::Administrator))
    } else if values
        .iter()
        .any(|value| config.viewer_values.iter().any(|allowed| allowed == value))
    {
        Ok(Some(Role::Viewer))
    } else {
        Ok(None)
    }
}

use crate::WebState;
use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
pub async fn login_page(State(state): State<WebState>) -> axum::response::Html<String> {
    if state.auth.is_external() {
        crate::views::external_login().await
    } else {
        crate::views::login().await
    }
}
pub async fn start_handler(
    State(state): State<WebState>,
    headers: HeaderMap,
) -> Result<Response, AuthError> {
    if !state.auth.is_external() {
        return Err(AuthError::Invalid);
    }
    let old = crate::cookie(&headers, state.security.session_name())?;
    let authenticated = match state.auth.identity(old.as_deref()).await {
        Ok(_) => true,
        Err(AuthError::Unauthorized) => false,
        Err(error) => return Err(error),
    };
    crate::csrf(&headers, &state, old.as_deref(), authenticated)?;
    let provider = state.oidc.as_ref().ok_or(AuthError::Unavailable)?;
    let begun = provider.begin().await?;
    let mut response = axum::Json(serde_json::json!({"authorization_url":begun.authorization_url}))
        .into_response();
    crate::set_cookie(
        &mut response,
        session::cookie(
            state.security.oidc_name(),
            &begun.browser,
            state.security.secure,
            600,
        ),
    );
    Ok(response)
}
#[derive(Deserialize)]
pub struct Callback {
    state: Option<String>,
    code: Option<String>,
    error: Option<String>,
    iss: Option<String>,
}
pub async fn callback_handler(
    State(state): State<WebState>,
    headers: HeaderMap,
    query: Result<Query<Callback>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let result = async {
        if !state.auth.is_external() {
            return Err(AuthError::Invalid);
        }
        let Query(input) = query.map_err(|_| AuthError::Invalid)?;
        let browser =
            crate::cookie(&headers, state.security.oidc_name())?.ok_or(AuthError::Unauthorized)?;
        let provider = state.oidc.as_ref().ok_or(AuthError::Unavailable)?;
        if input.error.is_some() || input.code.is_none() {
            provider.cancel(
                input.state.as_deref().ok_or(AuthError::Unauthorized)?,
                &browser,
            )?;
            return Err(AuthError::Unauthorized);
        }
        let identity = provider
            .complete(
                input.state.as_deref().ok_or(AuthError::Unauthorized)?,
                &browser,
                input.code.as_deref().ok_or(AuthError::Unauthorized)?,
                input.iss.as_deref(),
            )
            .await?;
        let old = crate::cookie(&headers, state.security.session_name())?;
        state.auth.external_login(identity, old).await
    }
    .await;
    let mut response = match result {
        Ok(grant) => {
            let mut response = Redirect::to("/").into_response();
            crate::set_cookie(
                &mut response,
                session::cookie(
                    state.security.session_name(),
                    &grant.token,
                    state.security.secure,
                    grant.max_age,
                ),
            );
            crate::set_cookie(
                &mut response,
                session::cookie(
                    state.security.bootstrap_name(),
                    "",
                    state.security.secure,
                    0,
                ),
            );
            response
        }
        Err(error) => {
            let forbidden = error == AuthError::Forbidden;
            let mut response = error.into_response();
            if forbidden {
                crate::set_cookie(
                    &mut response,
                    session::cookie(state.security.session_name(), "", state.security.secure, 0),
                );
            }
            response
        }
    };
    crate::set_cookie(
        &mut response,
        session::cookie(state.security.oidc_name(), "", state.security.secure, 0),
    );
    response
}
