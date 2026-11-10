//! Explicit Administrator remote operations, protected by the outer auth/CSRF middleware.
use crate::{
    WebState,
    blocklists::{ApiError, ApiJson, Report, Saved},
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use nullgate_core::{RemoteError, RemoteOutcome, RemoteResult};
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Import {
    expected_revision: u64,
    url: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Refresh {
    expected_revision: u64,
}
impl From<RemoteError> for ApiError {
    fn from(error: RemoteError) -> Self {
        match error {
            RemoteError::Policy(error) => error.into(),
            RemoteError::Busy => Self {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "fetch_busy",
                ..Self::invalid("Remote fetch capacity reached; request was not accepted")
            },
            _ => Self::invalid("Invalid remote URL or source"),
        }
    }
}
fn result(result: RemoteResult) -> Result<Json<Saved>, ApiError> {
    match result.outcome {
        RemoteOutcome::Applied => Ok(Json(result.saved.into())),
        outcome => Err(ApiError {
            status: if outcome == RemoteOutcome::NoValidRules {
                StatusCode::UNPROCESSABLE_ENTITY
            } else {
                StatusCode::BAD_GATEWAY
            },
            code: match outcome {
                RemoteOutcome::FetchFailed(failure) => failure.code(),
                _ => "no_valid_rules",
            },
            message: "Attempt recorded; previous usable rules retained. Reload before retrying."
                .into(),
            revision: Some(result.saved.snapshot.revision()),
            diagnostics: result.saved.import_report.map(Report::from).map(Box::new),
        }),
    }
}
pub async fn import(
    State(state): State<WebState>,
    Path(id): Path<i64>,
    ApiJson(input): ApiJson<Import>,
) -> Result<Json<Saved>, ApiError> {
    let remote = state
        .remote
        .ok_or_else(|| ApiError::invalid("Remote imports are unavailable"))?;
    result(
        remote
            .import_url(input.expected_revision, id, input.url)
            .await?,
    )
}
pub async fn refresh(
    State(state): State<WebState>,
    Path(id): Path<i64>,
    ApiJson(input): ApiJson<Refresh>,
) -> Result<Json<Saved>, ApiError> {
    let remote = state
        .remote
        .ok_or_else(|| ApiError::invalid("Remote imports are unavailable"))?;
    result(remote.refresh(input.expected_revision, id).await?)
}
