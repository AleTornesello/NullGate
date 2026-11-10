//! Server-side identities and trusted transport/origin policy.
use crate::auth::AuthError;
use axum::http::{HeaderMap, Uri};
use nullgate_core::{NormalizedAuthority, NormalizedHost, normalize_authority};
use std::net::SocketAddr;
#[derive(Clone)]
pub struct WebSecurity {
    pub(crate) secure: bool,
    authority: NormalizedAuthority,
}
impl WebSecurity {
    pub fn loopback_http(listen: SocketAddr, origin: &str) -> Result<Self, AuthError> {
        let policy = Self::parse(origin, false)?;
        if !listen.ip().is_loopback()
            || !match policy.authority.host() {
                NormalizedHost::Ipv4(ip) => ip.is_loopback(),
                NormalizedHost::Ipv6(ip) => ip.is_loopback(),
                NormalizedHost::Dns(name) => name.as_str() == "localhost",
            }
        {
            return Err(AuthError::Invalid);
        }
        Ok(policy)
    }
    /// The caller must serve this router through TLS, not a cleartext listener.
    pub fn direct_https(_listen: SocketAddr, origin: &str) -> Result<Self, AuthError> {
        Self::parse(origin, true)
    }
    /// Trust is explicit; arbitrary forwarding headers are never consulted.
    pub fn loopback_tls_proxy(listen: SocketAddr, origin: &str) -> Result<Self, AuthError> {
        if !listen.ip().is_loopback() {
            return Err(AuthError::Invalid);
        }
        Self::parse(origin, true)
    }
    fn parse(origin: &str, secure: bool) -> Result<Self, AuthError> {
        if origin.contains(['#', '?', '@']) {
            return Err(AuthError::Invalid);
        }
        let uri: Uri = origin.parse().map_err(|_| AuthError::Invalid)?;
        if uri.scheme_str() != Some(if secure { "https" } else { "http" })
            || uri
                .path_and_query()
                .is_some_and(|part| part.as_str() != "/")
        {
            return Err(AuthError::Invalid);
        }
        let authority = normalize_authority(
            uri.authority().ok_or(AuthError::Invalid)?.as_str(),
            Some(if secure { 443 } else { 80 }),
        )
        .map_err(|_| AuthError::Invalid)?;
        Ok(Self { secure, authority })
    }
    pub(crate) fn session_name(&self) -> &'static str {
        if self.secure {
            "__Host-nullgate_session"
        } else {
            "nullgate_session"
        }
    }
    pub(crate) fn bootstrap_name(&self) -> &'static str {
        if self.secure {
            "__Host-nullgate_csrf"
        } else {
            "nullgate_csrf"
        }
    }
    pub(crate) fn host_ok(&self, headers: &HeaderMap) -> bool {
        let mut hosts = headers.get_all(axum::http::header::HOST).iter();
        let host = hosts.next();
        if hosts.next().is_some() {
            return false;
        }
        host.and_then(|host| host.to_str().ok())
            .and_then(|host| {
                normalize_authority(host, Some(if self.secure { 443 } else { 80 })).ok()
            })
            .is_some_and(|authority| authority == self.authority)
    }
    pub(crate) fn origin_ok(&self, headers: &HeaderMap) -> bool {
        let mut origins = headers.get_all(axum::http::header::ORIGIN).iter();
        let origin = origins.next();
        if origins.next().is_some() {
            return false;
        }
        origin
            .and_then(|value| value.to_str().ok())
            .is_some_and(|origin| {
                Self::parse(origin, self.secure)
                    .is_ok_and(|other| other.authority == self.authority)
            })
    }
}
