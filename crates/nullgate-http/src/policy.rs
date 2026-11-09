//! Pure validation and policy evaluation, reusable by future inspected HTTPS forwarding.
use hyper::{HeaderMap, StatusCode, Uri, Version};
use nullgate_core::{
    HttpScheme, NormalizedUrl, PolicySnapshot, UrlError, normalize_authority, normalize_url,
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetError {
    BadRequest,
    TooLong,
    Unsupported,
}
impl TargetError {
    pub fn status(self) -> StatusCode {
        match self {
            Self::BadRequest => StatusCode::BAD_REQUEST,
            Self::TooLong => StatusCode::URI_TOO_LONG,
            Self::Unsupported => StatusCode::NOT_IMPLEMENTED,
        }
    }
}
#[derive(Clone, Debug)]
pub struct ValidatedTarget {
    normalized: NormalizedUrl,
    origin: Uri,
    authority: String,
}
impl ValidatedTarget {
    /// `scheme` comes from the trusted transport context, never from an arbitrary Host header.
    pub fn parse(
        raw: &str,
        headers: &HeaderMap,
        version: Version,
        scheme: HttpScheme,
    ) -> Result<Self, TargetError> {
        if raw.len() > 8192 {
            return Err(TargetError::TooLong);
        }
        let host_values = headers
            .get_all(hyper::header::HOST)
            .iter()
            .collect::<Vec<_>>();
        if host_values.len() > 1 {
            return Err(TargetError::BadRequest);
        }
        let host = host_values
            .first()
            .map(|value| value.to_str().map_err(|_| TargetError::BadRequest))
            .transpose()?;
        if version == Version::HTTP_11 && host.is_none() {
            return Err(TargetError::BadRequest);
        }
        let scheme_name = match scheme {
            HttpScheme::Http => "http",
            HttpScheme::Https => "https",
        };
        let full = if raw.starts_with('/') {
            format!(
                "{scheme_name}://{}{raw}",
                host.ok_or(TargetError::BadRequest)?
            )
        } else if raw.contains("://") {
            raw.into()
        } else {
            return Err(TargetError::BadRequest);
        };
        let normalized = normalize_url(&full).map_err(|error| {
            if error == UrlError::TooLong {
                TargetError::TooLong
            } else {
                TargetError::BadRequest
            }
        })?;
        if normalized.scheme() != scheme {
            return Err(TargetError::Unsupported);
        }
        if let Some(host) = host {
            let authority = normalize_authority(
                host,
                Some(match scheme {
                    HttpScheme::Http => 80,
                    HttpScheme::Https => 443,
                }),
            )
            .map_err(|_| TargetError::BadRequest)?;
            if authority.host() != normalized.host() || authority.port() != normalized.port() {
                return Err(TargetError::BadRequest);
            }
        }
        let parsed: Uri = full.parse().map_err(|_| TargetError::BadRequest)?;
        let path = parsed.path_and_query().map_or("/", |path| path.as_str());
        let origin = path.parse().map_err(|_| TargetError::BadRequest)?;
        let authority = format!("{}:{}", normalized.host(), normalized.port());
        Ok(Self {
            normalized,
            origin,
            authority,
        })
    }
    pub fn normalized(&self) -> &NormalizedUrl {
        &self.normalized
    }
    pub fn origin_uri(&self) -> &Uri {
        &self.origin
    }
    pub fn authority(&self) -> &str {
        &self.authority
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Allowed,
    Blocked,
}
pub fn evaluate(snapshot: &PolicySnapshot, target: &NormalizedUrl) -> Decision {
    if snapshot.rules().blocks_url(target) {
        Decision::Blocked
    } else {
        Decision::Allowed
    }
}
