//! Streaming HTTP/1 forwarding. Policy decisions are made before calling this module.
use crate::{policy::ValidatedTarget, server::HttpOptions};
use hyper::{
    HeaderMap, Request, Response, StatusCode,
    body::{Body, Bytes, Frame, Incoming, SizeHint},
    header::{HOST, HeaderName, HeaderValue, VIA},
};
use hyper_util::rt::TokioIo;
use nullgate_core::NormalizedHost;
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{net::TcpStream, sync::OwnedSemaphorePermit, task::JoinHandle};
use tokio_util::task::TaskTracker;
const HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
];
#[derive(Clone, Copy, Debug)]
pub struct RelayError;
impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HTTP body relay failed")
    }
}
impl std::error::Error for RelayError {}
struct Driver(JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
/// An empty or frame-streaming body. Driver/admission ownership follows response consumption.
pub struct ProxyBody {
    incoming: Option<Incoming>,
    nominated: Vec<HeaderName>,
    driver: Option<Driver>,
    permit: Option<OwnedSemaphorePermit>,
}
impl ProxyBody {
    pub fn empty() -> Self {
        Self {
            incoming: None,
            nominated: Vec::new(),
            driver: None,
            permit: None,
        }
    }
    fn relay(incoming: Incoming, nominated: Vec<HeaderName>) -> Self {
        Self {
            incoming: Some(incoming),
            nominated,
            driver: None,
            permit: None,
        }
    }
    fn finish(&mut self) {
        self.driver.take();
        self.permit.take();
    }
}
impl Body for ProxyBody {
    type Data = Bytes;
    type Error = RelayError;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, RelayError>>> {
        let this = self.get_mut();
        let Some(incoming) = &mut this.incoming else {
            return Poll::Ready(None);
        };
        match Pin::new(incoming).poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                this.finish();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(_))) => {
                this.finish();
                Poll::Ready(Some(Err(RelayError)))
            }
            Poll::Ready(Some(Ok(frame))) => {
                if frame.is_trailers() {
                    let mut headers = frame.into_trailers().expect("trailer frame");
                    if strip_hop_headers(&mut headers).is_err() {
                        this.finish();
                        return Poll::Ready(Some(Err(RelayError)));
                    }
                    for name in &this.nominated {
                        headers.remove(name);
                    }
                    let forbidden = headers
                        .keys()
                        .filter(|name| !safe_trailer(name))
                        .cloned()
                        .collect::<Vec<_>>();
                    for name in forbidden {
                        headers.remove(name);
                    }
                    Poll::Ready(Some(Ok(Frame::trailers(headers))))
                } else {
                    Poll::Ready(Some(Ok(frame)))
                }
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.incoming.as_ref().is_none_or(Body::is_end_stream)
    }
    fn size_hint(&self) -> SizeHint {
        self.incoming
            .as_ref()
            .map_or_else(|| SizeHint::with_exact(0), Body::size_hint)
    }
}
/// Remove both fixed hop fields and all comma-separated Connection nominations.
pub fn strip_hop_headers(headers: &mut HeaderMap) -> Result<Vec<HeaderName>, RelayError> {
    let mut nominated = Vec::new();
    for value in headers.get_all(hyper::header::CONNECTION) {
        let text = value.to_str().map_err(|_| RelayError)?;
        for token in text
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
        {
            nominated.push(HeaderName::from_bytes(token.as_bytes()).map_err(|_| RelayError)?);
        }
    }
    for name in &nominated {
        headers.remove(name);
    }
    for name in HOP {
        headers.remove(*name);
    }
    Ok(nominated)
}
// Trailer is hop-by-hop; regenerate a declaration for safe end-to-end fields
// instead of forwarding its original value or silently dropping payload trailers.
fn prepare_headers(headers: &mut HeaderMap) -> Result<Vec<HeaderName>, RelayError> {
    let declarations = headers
        .get_all(hyper::header::TRAILER)
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let nominated = strip_hop_headers(headers)?;
    let mut allowed = Vec::new();
    if !nominated.contains(&hyper::header::TRAILER) {
        for declaration in declarations {
            for token in declaration
                .to_str()
                .map_err(|_| RelayError)?
                .split(',')
                .map(str::trim)
            {
                let name = HeaderName::from_bytes(token.as_bytes()).map_err(|_| RelayError)?;
                if safe_trailer(&name) && !nominated.contains(&name) && !allowed.contains(&name) {
                    allowed.push(name);
                }
            }
        }
    }
    if !allowed.is_empty() {
        let value = allowed
            .iter()
            .map(HeaderName::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        headers.insert(
            hyper::header::TRAILER,
            HeaderValue::from_str(&value).map_err(|_| RelayError)?,
        );
    }
    Ok(nominated)
}
fn safe_trailer(name: &HeaderName) -> bool {
    !HOP.contains(&name.as_str())
        && !matches!(
            name.as_str(),
            "host"
                | "content-length"
                | "authorization"
                | "cache-control"
                | "content-encoding"
                | "content-range"
                | "content-type"
                | "max-forwards"
                | "set-cookie"
        )
}
pub(crate) fn via_loop(headers: &HeaderMap) -> bool {
    headers.get_all(VIA).iter().any(|value| {
        value.to_str().ok().is_some_and(|text| {
            text.split(',').any(|entry| {
                entry
                    .split_whitespace()
                    .nth(1)
                    .is_some_and(|name| name.eq_ignore_ascii_case("nullgate"))
            })
        })
    })
}
#[derive(Clone, Copy, Debug)]
pub(crate) enum ForwardError {
    InvalidRequest,
    Gateway,
    Timeout,
}
pub(crate) async fn forward(
    request: Request<Incoming>,
    target: &ValidatedTarget,
    options: &HttpOptions,
    tracker: &TaskTracker,
    permit: OwnedSemaphorePermit,
) -> Result<Response<ProxyBody>, ForwardError> {
    let (mut parts, body) = request.into_parts();
    let nominated =
        prepare_headers(&mut parts.headers).map_err(|_| ForwardError::InvalidRequest)?;
    if body.is_end_stream() {
        parts.headers.remove(hyper::header::TRAILER);
    }
    // Advertise this hop's trailer support; never reuse the client's TE value.
    parts
        .headers
        .insert(hyper::header::TE, HeaderValue::from_static("trailers"));
    parts
        .headers
        .insert(hyper::header::CONNECTION, HeaderValue::from_static("te"));
    let connect = async {
        match target.normalized().host() {
            NormalizedHost::Dns(name) => {
                TcpStream::connect((name.as_str(), target.normalized().port())).await
            }
            NormalizedHost::Ipv4(ip) => {
                TcpStream::connect(SocketAddr::new(IpAddr::V4(*ip), target.normalized().port()))
                    .await
            }
            NormalizedHost::Ipv6(ip) => {
                TcpStream::connect(SocketAddr::new(IpAddr::V6(*ip), target.normalized().port()))
                    .await
            }
        }
    };
    let stream = tokio::time::timeout(options.connect_timeout, connect)
        .await
        .map_err(|_| ForwardError::Timeout)?
        .map_err(|_| ForwardError::Gateway)?;
    let (sender, connection) =
        hyper::client::conn::http1::handshake::<_, ProxyBody>(TokioIo::new(stream))
            .await
            .map_err(|_| ForwardError::Gateway)?;
    let driver = Driver(tracker.spawn(async move {
        let _ = connection.await;
    }));
    parts.uri = target.origin_uri().clone();
    parts.version = hyper::Version::HTTP_11;
    parts.headers.insert(
        HOST,
        HeaderValue::from_str(target.authority()).map_err(|_| ForwardError::Gateway)?,
    );
    parts
        .headers
        .append(VIA, HeaderValue::from_static("1.1 nullgate"));
    let request = Request::from_parts(parts, ProxyBody::relay(body, nominated));
    let mut sender = sender;
    let response = tokio::time::timeout(
        options.upstream_header_timeout,
        sender.send_request(request),
    )
    .await
    .map_err(|_| ForwardError::Timeout)?
    .map_err(|_| ForwardError::Gateway)?;
    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        return Err(ForwardError::Gateway);
    }
    let (mut parts, body) = response.into_parts();
    let nominated = prepare_headers(&mut parts.headers).map_err(|_| ForwardError::Gateway)?;
    parts
        .headers
        .append(VIA, HeaderValue::from_static("1.1 nullgate"));
    let mut body = ProxyBody::relay(body, nominated);
    body.driver = Some(driver);
    body.permit = Some(permit);
    Ok(Response::from_parts(parts, body))
}
