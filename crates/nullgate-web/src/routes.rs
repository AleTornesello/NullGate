//! Management route registration; the outer authentication router protects every route/fallback.
use crate::{WebState, blocklists as api, views};
use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};
pub fn management_routes() -> Router<WebState> {
    let small = Router::new()
        .route("/api/v1/lists", get(api::lists).post(api::create))
        .route(
            "/api/v1/lists/{id}",
            get(api::list).patch(api::rename).delete(api::delete),
        )
        .route(
            "/api/v1/sources/{id}",
            axum::routing::delete(api::delete_source),
        )
        .layer(DefaultBodyLimit::max(8192));
    let text = Router::new()
        .route("/api/v1/lists/{id}/rules", post(api::manual))
        .route(
            "/api/v1/sources/{id}/entries",
            get(api::entries).put(api::replace),
        )
        .layer(DefaultBodyLimit::max(
            nullgate_core::MAX_IMPORT_BYTES + 8192,
        ));
    let files = Router::new()
        .route("/api/v1/lists/{id}/imports", post(api::file))
        .layer(DefaultBodyLimit::max(nullgate_core::MAX_IMPORT_BYTES));
    let remove = Router::new()
        .route("/api/v1/sources/{id}/remove", post(api::remove))
        .layer(DefaultBodyLimit::max(
            nullgate_core::MAX_RULE_LINE_BYTES * 6 + 8192,
        ));
    small
        .merge(text)
        .merge(files)
        .merge(remove)
        .route("/", get(views::index))
}
