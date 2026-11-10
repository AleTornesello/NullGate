//! Revision-checked management handlers over the injected core interface only.
use crate::WebState;
use axum::{
    Json,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use nullgate_core::{
    ImportReport, MAX_IMPORT_BYTES, Mutation, PolicyError, PolicySaveResult, PolicySnapshot, Rule,
    SourceKind, StorageError,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
/// Normalize malformed management JSON without echoing submitted values.
pub struct ApiJson<T>(pub T);
impl<S, T> axum::extract::FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned + Send,
{
    type Rejection = ApiError;
    async fn from_request(
        request: axum::extract::Request,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|error| {
                let status = error.status();
                let mut mapped = ApiError::invalid(
                    "Invalid JSON request; provide the required fields and types",
                );
                if status == StatusCode::PAYLOAD_TOO_LARGE {
                    mapped.status = status;
                    mapped.code = "too_large";
                    mapped.message = "Request body exceeds the limit".into();
                } else if status == StatusCode::UNSUPPORTED_MEDIA_TYPE {
                    mapped.status = status;
                    mapped.message = "Expected application/json".into();
                }
                mapped
            })
    }
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    #[serde(default)]
    pub offset: usize,
    pub limit: Option<usize>,
}
impl Page {
    fn limit(&self) -> usize {
        self.limit.unwrap_or(50).clamp(1, 100)
    }
}
#[derive(Serialize)]
pub struct Diagnostic {
    pub line: usize,
    pub code: &'static str,
    pub message: &'static str,
}
#[derive(Serialize)]
pub struct Report {
    pub accepted: usize,
    pub duplicates: usize,
    pub ignored: usize,
    pub malformed_total: usize,
    pub diagnostics_truncated: bool,
    pub malformed: Vec<Diagnostic>,
}
impl From<ImportReport> for Report {
    fn from(report: ImportReport) -> Self {
        let total = report.malformed.len();
        Self {
            accepted: report.accepted.len(),
            duplicates: report.duplicates.len(),
            ignored: report.ignored_lines,
            malformed_total: total,
            diagnostics_truncated: total > 1000,
            malformed: report
                .malformed
                .into_iter()
                .take(1000)
                .map(|d| Diagnostic {
                    line: d.line,
                    code: d.code,
                    message: d.message,
                })
                .collect(),
        }
    }
}
#[derive(Serialize)]
pub struct Saved {
    pub revision: u64,
    #[serde(rename = "import")]
    pub report: Option<Report>,
}
impl From<PolicySaveResult> for Saved {
    fn from(saved: PolicySaveResult) -> Self {
        Self {
            revision: saved.snapshot.revision(),
            report: saved.import_report.map(Report::from),
        }
    }
}
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub revision: Option<u64>,
    pub diagnostics: Option<Box<Report>>,
}
impl ApiError {
    pub fn invalid(message: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            message: message.into(),
            revision: None,
            diagnostics: None,
        }
    }
    fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: "List or source not found".into(),
            revision: None,
            diagnostics: None,
        }
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct Error {
            code: &'static str,
            message: String,
            revision: Option<u64>,
            diagnostics: Option<Box<Report>>,
        }
        (
            self.status,
            Json(Error {
                code: self.code,
                message: self.message,
                revision: self.revision,
                diagnostics: self.diagnostics,
            }),
        )
            .into_response()
    }
}
impl From<PolicyError> for ApiError {
    fn from(error: PolicyError) -> Self {
        let (status, code, revision) = match &error {
            PolicyError::Storage(StorageError::Conflict { actual, .. }) => {
                (StatusCode::CONFLICT, "revision_conflict", Some(*actual))
            }
            PolicyError::Storage(StorageError::NotFound) => {
                (StatusCode::NOT_FOUND, "not_found", None)
            }
            PolicyError::Storage(StorageError::ImportTooLarge) => {
                (StatusCode::PAYLOAD_TOO_LARGE, "too_large", None)
            }
            PolicyError::Storage(StorageError::Capacity) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "capacity", None)
            }
            PolicyError::Storage(StorageError::NoValidRules) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "no_valid_rules", None)
            }
            PolicyError::Storage(
                StorageError::InvalidName
                | StorageError::InvalidSource
                | StorageError::InvalidUtf8
                | StorageError::InvalidTimestamp,
            ) => (StatusCode::BAD_REQUEST, "invalid_request", None),
            PolicyError::Storage(StorageError::DuplicateName) => {
                (StatusCode::CONFLICT, "duplicate_name", None)
            }
            PolicyError::CommittedNotActive { revision } => (
                StatusCode::SERVICE_UNAVAILABLE,
                "committed_not_active",
                Some(*revision),
            ),
            PolicyError::Unavailable { revision } => (
                StatusCode::SERVICE_UNAVAILABLE,
                "policy_unavailable",
                Some(*revision),
            ),
            PolicyError::OutcomeUnknown => {
                (StatusCode::SERVICE_UNAVAILABLE, "outcome_unknown", None)
            }
            _ => (StatusCode::SERVICE_UNAVAILABLE, "unavailable", None),
        };
        Self {
            status,
            code,
            message: error.to_string(),
            revision,
            diagnostics: None,
        }
    }
}
pub(crate) fn snapshot(state: &WebState) -> Result<Arc<PolicySnapshot>, ApiError> {
    state.management.subscribe().current().map_err(|fault| {
        PolicyError::Unavailable {
            revision: fault.revision,
        }
        .into()
    })
}
fn now() -> Result<i64, ApiError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|time| time.as_secs().min(i64::MAX as u64) as i64)
        .map_err(|_| ApiError::invalid("Clock unavailable"))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Named {
    expected_revision: u64,
    name: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revision {
    expected_revision: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Text {
    expected_revision: u64,
    text: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Remove {
    expected_revision: u64,
    rule: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct File {
    expected_revision: u64,
    filename: String,
}
async fn save(
    state: &WebState,
    revision: u64,
    mutation: Mutation,
) -> Result<Json<Saved>, ApiError> {
    Ok(Json(
        state
            .management
            .save(revision, mutation)
            .await
            .map(Saved::from)?,
    ))
}
#[derive(Serialize)]
struct ListSummary {
    id: i64,
    name: String,
    sources: usize,
    rules: usize,
}
pub async fn lists(
    State(state): State<WebState>,
    Query(page): Query<Page>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let snapshot = snapshot(&state)?;
    let repo = snapshot.repository();
    let lists = repo
        .lists
        .iter()
        .skip(page.offset)
        .take(page.limit())
        .map(|list| ListSummary {
            id: list.id,
            name: list.name.clone(),
            sources: list.sources.len(),
            rules: list.sources.iter().map(|s| s.entries.len()).sum(),
        })
        .collect::<Vec<_>>();
    Ok(Json(
        serde_json::json!({"revision":snapshot.revision(),"total":repo.lists.len(),"lists":lists}),
    ))
}
pub async fn list(
    State(state): State<WebState>,
    Path(id): Path<i64>,
    Query(page): Query<Page>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let snapshot = snapshot(&state)?;
    let list = snapshot
        .repository()
        .lists
        .iter()
        .find(|list| list.id == id)
        .ok_or_else(ApiError::not_found)?;
    let sources=list.sources.iter().skip(page.offset).take(page.limit()).map(|source|serde_json::json!({"id":source.id,"kind":source.kind,"entries":source.entries.len(),"last_report":source.last_report})).collect::<Vec<_>>();
    Ok(Json(
        serde_json::json!({"revision":snapshot.revision(),"id":list.id,"name":list.name,"total_sources":list.sources.len(),"sources":sources}),
    ))
}
pub async fn entries(
    State(state): State<WebState>,
    Path(id): Path<i64>,
    Query(page): Query<Page>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let snapshot = snapshot(&state)?;
    let source = snapshot
        .repository()
        .source(id)
        .ok_or_else(ApiError::not_found)?;
    let entries = source
        .entries
        .iter()
        .skip(page.offset)
        .take(page.limit())
        .map(|entry| entry.input())
        .collect::<Vec<_>>();
    Ok(Json(
        serde_json::json!({"revision":snapshot.revision(),"total":source.entries.len(),"entries":entries}),
    ))
}
pub async fn create(
    State(state): State<WebState>,
    ApiJson(input): ApiJson<Named>,
) -> Result<Json<Saved>, ApiError> {
    save(
        &state,
        input.expected_revision,
        Mutation::CreateList { name: input.name },
    )
    .await
}
pub async fn rename(
    State(state): State<WebState>,
    Path(id): Path<i64>,
    ApiJson(input): ApiJson<Named>,
) -> Result<Json<Saved>, ApiError> {
    save(
        &state,
        input.expected_revision,
        Mutation::RenameList {
            list_id: id,
            name: input.name,
        },
    )
    .await
}
pub async fn delete(
    State(state): State<WebState>,
    Path(id): Path<i64>,
    ApiJson(input): ApiJson<Revision>,
) -> Result<Json<Saved>, ApiError> {
    save(
        &state,
        input.expected_revision,
        Mutation::DeleteList { list_id: id },
    )
    .await
}
pub async fn manual(
    State(state): State<WebState>,
    Path(id): Path<i64>,
    ApiJson(input): ApiJson<Text>,
) -> Result<Json<Saved>, ApiError> {
    save(
        &state,
        input.expected_revision,
        Mutation::ImportList {
            list_id: id,
            kind: SourceKind::Manual,
            text: input.text,
            at: now()?,
        },
    )
    .await
}
pub async fn file(
    State(state): State<WebState>,
    Path(id): Path<i64>,
    Query(input): Query<File>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Saved>, ApiError> {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !content_type
        .split(';')
        .next()
        .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("text/plain"))
    {
        return Err(ApiError {
            status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ..ApiError::invalid("Expected plain UTF-8 text")
        });
    }
    if body.len() > MAX_IMPORT_BYTES {
        return Err(PolicyError::Storage(StorageError::ImportTooLarge).into());
    }
    let text = std::str::from_utf8(&body)
        .map_err(|_| ApiError::invalid("Import must be UTF-8"))?
        .to_string();
    save(
        &state,
        input.expected_revision,
        Mutation::ImportList {
            list_id: id,
            kind: SourceKind::File {
                filename: input.filename,
            },
            text,
            at: now()?,
        },
    )
    .await
}
fn editable(state: &WebState, id: i64) -> Result<(), ApiError> {
    let snapshot = snapshot(state)?;
    let source = snapshot
        .repository()
        .source(id)
        .ok_or_else(ApiError::not_found)?;
    if matches!(source.kind, SourceKind::Remote { .. }) {
        return Err(ApiError::invalid("Remote-source editing is not available"));
    }
    Ok(())
}
pub async fn replace(
    State(state): State<WebState>,
    Path(id): Path<i64>,
    ApiJson(input): ApiJson<Text>,
) -> Result<Json<Saved>, ApiError> {
    editable(&state, id)?;
    if input.text.len() > MAX_IMPORT_BYTES {
        return Err(PolicyError::Storage(StorageError::ImportTooLarge).into());
    }
    let text = input.text;
    match state
        .management
        .save(
            input.expected_revision,
            Mutation::ReplaceEntries {
                source_id: id,
                text: text.clone(),
                at: now()?,
            },
        )
        .await
    {
        Ok(saved) => Ok(Json(saved.into())),
        Err(error) => {
            let is_invalid = matches!(error, PolicyError::Storage(StorageError::NoValidRules));
            let mut error = ApiError::from(error);
            if is_invalid {
                error.diagnostics = tokio::task::spawn_blocking(move || {
                    Report::from(nullgate_core::parse_blocklist(&text))
                })
                .await
                .ok()
                .map(Box::new);
            }
            Err(error)
        }
    }
}
pub async fn remove(
    State(state): State<WebState>,
    Path(id): Path<i64>,
    ApiJson(input): ApiJson<Remove>,
) -> Result<Json<Saved>, ApiError> {
    editable(&state, id)?;
    let rule = Rule::parse(&input.rule).map_err(|error| ApiError::invalid(error.message()))?;
    save(
        &state,
        input.expected_revision,
        Mutation::RemoveRule {
            source_id: id,
            rule,
        },
    )
    .await
}
pub async fn delete_source(
    State(state): State<WebState>,
    Path(id): Path<i64>,
    ApiJson(input): ApiJson<Revision>,
) -> Result<Json<Saved>, ApiError> {
    editable(&state, id)?;
    save(
        &state,
        input.expected_revision,
        Mutation::DeleteSource { source_id: id },
    )
    .await
}
