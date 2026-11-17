//! Public OIDC configuration only. Secret file contents are never parsed here.
use crate::{ConfigError, HttpScheme, NormalizedHost, WebConfig, normalize_url};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub client_secret_file: Option<PathBuf>,
    pub role_claim: String,
    #[serde(default)]
    pub administrator_values: Vec<String>,
    #[serde(default)]
    pub viewer_values: Vec<String>,
}
impl OidcConfig {
    pub fn validate(&self, web: &WebConfig) -> Result<(), ConfigError> {
        let invalid = || {
            ConfigError::field(
                "oidc",
                "Use an explicit issuer/client/callback and disjoint trusted role mappings",
            )
        };
        let issuer = normalize_url(&self.issuer).map_err(|_| invalid())?;
        let local = match issuer.host() {
            NormalizedHost::Ipv4(ip) => ip.is_loopback(),
            NormalizedHost::Ipv6(ip) => ip.is_loopback(),
            NormalizedHost::Dns(name) => name.as_str() == "localhost",
        };
        if self.issuer.contains(['?', '#', '@'])
            || (issuer.scheme() != HttpScheme::Https && !local)
            || self.client_id.is_empty()
            || self.client_id.len() > 256
            || self.client_id.chars().any(char::is_control)
        {
            return Err(invalid());
        }
        let redirect = normalize_url(&self.redirect_uri).map_err(|_| invalid())?;
        let origin = normalize_url(web.public_origin.as_ref().ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
        if self.redirect_uri.contains(['?', '#', '@'])
            || !self.redirect_uri.ends_with("/api/v1/auth/oidc/callback")
            || redirect.path() != "/api/v1/auth/oidc/callback"
            || redirect.scheme() != origin.scheme()
            || redirect.host() != origin.host()
            || redirect.port() != origin.port()
        {
            return Err(invalid());
        }
        if !self.role_claim.starts_with('/')
            || self.role_claim.len() < 2
            || self.role_claim.len() > 512
            || self.role_claim.chars().any(char::is_control)
        {
            return Err(invalid());
        }
        let bytes = self.role_claim.as_bytes();
        for index in 0..bytes.len() {
            if bytes[index] == b'~'
                && !bytes
                    .get(index + 1)
                    .is_some_and(|c| *c == b'0' || *c == b'1')
            {
                return Err(invalid());
            }
        }
        let all = self
            .administrator_values
            .iter()
            .chain(&self.viewer_values)
            .collect::<Vec<_>>();
        if all.is_empty()
            || all.len() > 128
            || all.iter().any(|value| {
                value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
            })
            || all.iter().collect::<std::collections::HashSet<_>>().len() != all.len()
        {
            return Err(invalid());
        }
        if self
            .client_secret_file
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(invalid());
        }
        Ok(())
    }
}
