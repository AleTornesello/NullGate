//! Public-certificate download, with an explicit read-role check and no signer/key access.
use crate::{AuthError, WebState};
use axum::{
    Extension,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use nullgate_core::{Identity, Role};
pub async fn download(
    State(state): State<WebState>,
    Extension(identity): Extension<Identity>,
) -> Response {
    if identity.role != Role::Administrator {
        return AuthError::Forbidden.into_response();
    }
    let Some(public) = state.public_ca else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Public inspection CA is unavailable",
        )
            .into_response();
    };
    (
        [
            (header::CONTENT_TYPE, "application/x-pem-file"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"nullgate-inspection-ca.pem\"",
            ),
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        public.certificate_pem().to_vec(),
    )
        .into_response()
}
