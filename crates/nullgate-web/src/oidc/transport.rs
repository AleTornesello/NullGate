//! Bounded same-origin provider HTTP; no redirects, proxy, cookies or dynamic destinations.
use crate::AuthError;
use openidconnect::{AsyncHttpClient, HttpRequest, HttpResponse};
use std::{future::Future, pin::Pin};
#[derive(Clone)]
pub(super) struct Transport {
    pub client: reqwest::Client,
    pub issuer: reqwest::Url,
}
impl Transport {
    pub fn check(&self, url: &reqwest::Url) -> Result<(), AuthError> {
        if url.origin() != self.issuer.origin()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || !matches!(url.scheme(), "http" | "https")
        {
            return Err(AuthError::Unavailable);
        }
        Ok(())
    }
    pub async fn get(&self, url: &str) -> Result<Vec<u8>, AuthError> {
        let request = openidconnect::http::Request::builder()
            .uri(url)
            .body(vec![])
            .map_err(|_| AuthError::Unavailable)?;
        Ok(self.call(request).await?.into_body())
    }
}
impl<'c> AsyncHttpClient<'c> for Transport {
    type Error = AuthError;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, AuthError>> + Send + 'c>>;
    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            let (mut parts, body) = request.into_parts();
            if let Some(value) = parts
                .headers
                .get_mut(openidconnect::http::header::AUTHORIZATION)
            {
                value.set_sensitive(true);
            }
            let url =
                reqwest::Url::parse(&parts.uri.to_string()).map_err(|_| AuthError::Unavailable)?;
            self.check(&url)?;
            let mut response = self
                .client
                .request(parts.method, url)
                .headers(parts.headers)
                .header("accept-encoding", "identity")
                .body(body)
                .send()
                .await
                .map_err(|_| AuthError::Unavailable)?;
            if response.status() != reqwest::StatusCode::OK
                || response
                    .headers()
                    .get("content-encoding")
                    .is_some_and(|value| value != "identity")
                || response.content_length().is_some_and(|size| size > 262144)
            {
                return Err(AuthError::Unavailable);
            }
            let mut bytes = vec![];
            while let Some(chunk) = response.chunk().await.map_err(|_| AuthError::Unavailable)? {
                if chunk.len() > 262144 - bytes.len() {
                    return Err(AuthError::Unavailable);
                }
                bytes.extend_from_slice(&chunk);
            }
            let mut result = openidconnect::http::Response::builder().status(response.status());
            *result.headers_mut().ok_or(AuthError::Unavailable)? = response.headers().clone();
            result.body(bytes).map_err(|_| AuthError::Unavailable)
        })
    }
}
