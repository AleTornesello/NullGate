//! Injected remote-import capability; transport implementation belongs to orchestration.
use crate::{PolicyError, PolicyFuture, PolicySaveResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FetchFailure {
    DestinationDenied,
    Network,
    Timeout,
    HttpStatus,
    TooLarge,
    InvalidUtf8,
    Encoding,
    RedirectLimit,
    InvalidRedirect,
    Downgrade,
}
impl FetchFailure {
    pub fn code(self) -> &'static str {
        match self {
            Self::DestinationDenied => "destination_denied",
            Self::Network => "download_failed",
            Self::Timeout => "download_timeout",
            Self::HttpStatus => "remote_status",
            Self::TooLarge => "remote_too_large",
            Self::InvalidUtf8 => "remote_invalid_utf8",
            Self::Encoding => "remote_encoding",
            Self::RedirectLimit => "redirect_limit",
            Self::InvalidRedirect => "invalid_redirect",
            Self::Downgrade => "https_downgrade",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteOutcome {
    Applied,
    NoValidRules,
    FetchFailed(FetchFailure),
}
#[derive(Debug)]
pub struct RemoteResult {
    pub saved: PolicySaveResult,
    pub outcome: RemoteOutcome,
}
#[derive(Debug)]
pub enum RemoteError {
    Policy(PolicyError),
    InvalidUrl,
    InvalidSource,
    Busy,
    InvalidOptions,
}
impl From<PolicyError> for RemoteError {
    fn from(value: PolicyError) -> Self {
        Self::Policy(value)
    }
}
impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Policy(_) => "Remote save failed",
            Self::InvalidUrl => "Invalid remote URL",
            Self::InvalidSource => "Invalid remote source",
            Self::Busy => "Remote fetch capacity reached",
            Self::InvalidOptions => "Invalid fetch options",
        })
    }
}
impl std::error::Error for RemoteError {}
/// Call only after Administrator and browser CSRF checks. No fetches occur implicitly.
pub trait RemoteManagement: Send + Sync {
    fn import_url(
        &self,
        expected_revision: u64,
        list_id: i64,
        url: String,
    ) -> PolicyFuture<'_, Result<RemoteResult, RemoteError>>;
    fn refresh(
        &self,
        expected_revision: u64,
        source_id: i64,
    ) -> PolicyFuture<'_, Result<RemoteResult, RemoteError>>;
}
