//! Verified upstream trust and strict client-hello binding. No verification bypass exists here.
use crate::{ca::CaProvider, inspection::Inspection};
use nullgate_core::{NormalizedHost, normalize_host};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::ServerName,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::task::TaskTracker;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsConfigError {
    NoTrustRoots,
    InvalidTrustRoots,
}
impl std::fmt::Display for TlsConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NoTrustRoots => "HTTPS inspection requires a nonempty upstream trust store",
            Self::InvalidTrustRoots => "HTTPS inspection upstream trust configuration is invalid",
        })
    }
}
impl std::error::Error for TlsConfigError {}
pub(crate) fn client_config(roots: RootCertStore) -> Result<Arc<ClientConfig>, TlsConfigError> {
    if roots.is_empty() {
        return Err(TlsConfigError::NoTrustRoots);
    }
    let mut config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| TlsConfigError::InvalidTrustRoots)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}
pub fn system_roots() -> Result<RootCertStore, TlsConfigError> {
    let loaded = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    for cert in loaded.certs {
        roots
            .add(cert)
            .map_err(|_| TlsConfigError::InvalidTrustRoots)?;
    }
    if roots.is_empty() {
        Err(TlsConfigError::NoTrustRoots)
    } else {
        Ok(roots)
    }
}
pub(crate) fn server_name(host: &NormalizedHost) -> Result<ServerName<'static>, TlsConfigError> {
    match host {
        NormalizedHost::Dns(name) => ServerName::try_from(name.as_str().to_owned())
            .map_err(|_| TlsConfigError::InvalidTrustRoots),
        NormalizedHost::Ipv4(ip) => Ok(ServerName::IpAddress((*ip).into())),
        NormalizedHost::Ipv6(ip) => Ok(ServerName::IpAddress((*ip).into())),
    }
}
#[derive(Debug)]
struct Certificate(Option<Arc<CertifiedKey>>);
impl ResolvesServerCert for Certificate {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.clone()
    }
}
fn config(key: Option<Arc<CertifiedKey>>) -> Result<Arc<ServerConfig>, ()> {
    let mut config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| ())?
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(Certificate(key)));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
pub(crate) async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
    io: S,
    host: &NormalizedHost,
    inspection: &Inspection,
    tracker: &TaskTracker,
) -> Result<tokio_rustls::server::TlsStream<S>, ()> {
    let hello = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io)
        .await
        .map_err(|_| ())?;
    let matches = match (host, hello.client_hello().server_name()) {
        (NormalizedHost::Dns(_), Some(name)) => {
            normalize_host(name).is_ok_and(|name| &name == host)
        }
        (NormalizedHost::Ipv4(_) | NormalizedHost::Ipv6(_), None) => true,
        _ => false,
    };
    if !matches {
        let _ = hello.into_stream(config(None)?).await;
        return Err(());
    }
    let permit = inspection
        .signing
        .clone()
        .try_acquire_owned()
        .map_err(|_| ())?;
    let ca: Arc<CaProvider> = inspection.ca.clone();
    let host = host.clone();
    let key = tracker
        .spawn_blocking(move || {
            let _permit = permit;
            ca.issue(&host)
        })
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
    hello.into_stream(config(Some(key))?).await.map_err(|_| ())
}
