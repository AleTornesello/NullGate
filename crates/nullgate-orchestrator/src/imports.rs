//! Explicit, bounded remote refreshes. Checked DNS answers are pinned for each redirect hop.
use nullgate_core::{
    FetchFailure, MAX_IMPORT_BYTES, Mutation, NormalizedHost, PolicyError, PolicyFuture,
    PolicyManagement, RemoteError, RemoteManagement, RemoteOutcome, RemoteResult, StorageError,
    normalize_url,
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;

#[derive(Clone, Copy)]
pub struct FetchOptions {
    pub timeout: Duration,
    pub max_bytes: usize,
    pub max_redirects: usize,
}
impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_bytes: MAX_IMPORT_BYTES,
            max_redirects: 3,
        }
    }
}
/// Trusted application capability. Production uses PublicFetchPolicy; local fixtures explicitly inject a restricted policy.
pub trait FetchPolicy: Send + Sync {
    fn resolve(
        &self,
        host: NormalizedHost,
        port: u16,
    ) -> PolicyFuture<'_, Result<Vec<SocketAddr>, FetchFailure>>;
    fn permits(&self, address: SocketAddr) -> bool;
    fn extra_roots(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }
}
pub struct PublicFetchPolicy;
impl FetchPolicy for PublicFetchPolicy {
    fn resolve(
        &self,
        host: NormalizedHost,
        port: u16,
    ) -> PolicyFuture<'_, Result<Vec<SocketAddr>, FetchFailure>> {
        Box::pin(async move {
            match host {
                NormalizedHost::Ipv4(ip) => Ok(vec![SocketAddr::new(ip.into(), port)]),
                NormalizedHost::Ipv6(ip) => Ok(vec![SocketAddr::new(ip.into(), port)]),
                NormalizedHost::Dns(name) => tokio::net::lookup_host((name.as_str(), port))
                    .await
                    .map(|addresses| addresses.collect())
                    .map_err(|_| FetchFailure::Network),
            }
        })
    }
    fn permits(&self, address: SocketAddr) -> bool {
        match address.ip() {
            IpAddr::V4(ip) => {
                let [a, b, c, _] = ip.octets();
                !(ip.is_private()
                    || ip.is_loopback()
                    || ip.is_link_local()
                    || a == 0
                    || a >= 224
                    || (a == 100 && (64..=127).contains(&b))
                    || (a == 192 && ((b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99)))
                    || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                    || (a == 203 && b == 0 && c == 113))
            }
            IpAddr::V6(ip) => {
                let s = ip.segments();
                (s[0] & 0xe000) == 0x2000
                    && !(s[0] == 0x2001 && (s[1] < 0x200 || s[1] == 0xdb8))
                    && s[0] != 0x2002
                    && !(s[0] == 0x3fff && s[1] < 0x1000)
            }
        }
    }
}
#[derive(Clone)]
pub struct RemoteFetcher {
    policy: Arc<dyn FetchPolicy>,
    options: FetchOptions,
    slots: Arc<Semaphore>,
}
impl RemoteFetcher {
    pub fn new(policy: Arc<dyn FetchPolicy>, options: FetchOptions) -> Result<Self, RemoteError> {
        let defaults = FetchOptions::default();
        if options.timeout.is_zero()
            || options.timeout > defaults.timeout
            || options.max_bytes == 0
            || options.max_bytes > defaults.max_bytes
            || options.max_redirects > defaults.max_redirects
        {
            return Err(RemoteError::InvalidOptions);
        }
        Ok(Self {
            policy,
            options,
            slots: Arc::new(Semaphore::new(4)),
        })
    }
    async fn fetch(&self, url: reqwest::Url) -> Result<Result<String, FetchFailure>, RemoteError> {
        let _slot = self.slots.try_acquire().map_err(|_| RemoteError::Busy)?;
        Ok(
            tokio::time::timeout(self.options.timeout, self.fetch_inner(url))
                .await
                .unwrap_or(Err(FetchFailure::Timeout)),
        )
    }
    async fn fetch_inner(&self, mut url: reqwest::Url) -> Result<String, FetchFailure> {
        for redirects in 0..=self.options.max_redirects {
            let normalized =
                normalize_url(url.as_str()).map_err(|_| FetchFailure::InvalidRedirect)?;
            let addresses = self
                .policy
                .resolve(normalized.host().clone(), normalized.port())
                .await?;
            if addresses.is_empty()
                || addresses.iter().any(|address| {
                    address.port() != normalized.port() || !self.policy.permits(*address)
                })
            {
                return Err(FetchFailure::DestinationDenied);
            }
            let roots = self
                .policy
                .extra_roots()
                .iter()
                .map(|der| reqwest::Certificate::from_der(der).map_err(|_| FetchFailure::Network))
                .collect::<Result<Vec<_>, _>>()?;
            let client = reqwest::Client::builder()
                .no_proxy()
                .no_gzip()
                .no_brotli()
                .no_deflate()
                .no_zstd()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .connect_timeout(self.options.timeout)
                .pool_max_idle_per_host(0)
                .resolve_to_addrs(
                    url.host_str().ok_or(FetchFailure::InvalidRedirect)?,
                    &addresses,
                )
                .tls_certs_merge(roots)
                .build()
                .map_err(|_| FetchFailure::Network)?;
            let mut response = client
                .get(url.clone())
                .header(reqwest::header::ACCEPT_ENCODING, "identity")
                .send()
                .await
                .map_err(|_| FetchFailure::Network)?;
            if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                if redirects == self.options.max_redirects {
                    return Err(FetchFailure::RedirectLimit);
                }
                let mut locations = response.headers().get_all(reqwest::header::LOCATION).iter();
                let location = locations
                    .next()
                    .ok_or(FetchFailure::InvalidRedirect)?
                    .to_str()
                    .map_err(|_| FetchFailure::InvalidRedirect)?;
                if locations.next().is_some() {
                    return Err(FetchFailure::InvalidRedirect);
                }
                let next = url
                    .join(location)
                    .map_err(|_| FetchFailure::InvalidRedirect)?;
                validate_url(next.as_str()).map_err(|_| FetchFailure::InvalidRedirect)?;
                if url.scheme() == "https" && next.scheme() == "http" {
                    return Err(FetchFailure::Downgrade);
                }
                url = next;
                continue;
            }
            if response.status() != reqwest::StatusCode::OK {
                return Err(FetchFailure::HttpStatus);
            }
            for encoding in response
                .headers()
                .get_all(reqwest::header::CONTENT_ENCODING)
            {
                if !encoding
                    .to_str()
                    .is_ok_and(|value| value.trim().eq_ignore_ascii_case("identity"))
                {
                    return Err(FetchFailure::Encoding);
                }
            }
            if response
                .content_length()
                .is_some_and(|size| size > self.options.max_bytes as u64)
            {
                return Err(FetchFailure::TooLarge);
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| FetchFailure::Network)? {
                if chunk.len() > self.options.max_bytes - bytes.len() {
                    return Err(FetchFailure::TooLarge);
                }
                bytes.extend_from_slice(&chunk);
            }
            return String::from_utf8(bytes).map_err(|_| FetchFailure::InvalidUtf8);
        }
        Err(FetchFailure::RedirectLimit)
    }
}
fn validate_url(raw: &str) -> Result<reqwest::Url, RemoteError> {
    normalize_url(raw).map_err(|_| RemoteError::InvalidUrl)?;
    let url = reqwest::Url::parse(raw).map_err(|_| RemoteError::InvalidUrl)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || !matches!(url.scheme(), "http" | "https")
    {
        return Err(RemoteError::InvalidUrl);
    }
    Ok(url)
}
pub struct RemoteService {
    management: Arc<dyn PolicyManagement>,
    fetcher: RemoteFetcher,
}
impl RemoteService {
    pub fn new(management: Arc<dyn PolicyManagement>, fetcher: RemoteFetcher) -> Self {
        Self {
            management,
            fetcher,
        }
    }
    fn snapshot(&self, revision: u64) -> Result<Arc<nullgate_core::PolicySnapshot>, RemoteError> {
        let snapshot = self.management.subscribe().current().map_err(|error| {
            RemoteError::Policy(PolicyError::Unavailable {
                revision: error.revision,
            })
        })?;
        if snapshot.revision() != revision {
            return Err(PolicyError::Storage(StorageError::Conflict {
                expected: revision,
                actual: snapshot.revision(),
            })
            .into());
        }
        Ok(snapshot)
    }
    async fn attempt(
        &self,
        revision: u64,
        list_id: i64,
        source_id: Option<i64>,
        url: reqwest::Url,
    ) -> Result<RemoteResult, RemoteError> {
        let fetched = self.fetcher.fetch(url.clone()).await?;
        let at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RemoteError::InvalidOptions)?
            .as_secs()
            .try_into()
            .map_err(|_| RemoteError::InvalidOptions)?;
        let (text, failure) = match fetched {
            Ok(text) => (Some(text), None),
            Err(error) => (None, Some(error)),
        };
        let mutation = match (source_id, text) {
            (Some(source_id), Some(text)) => Mutation::Import {
                source_id,
                text,
                at,
            },
            (Some(source_id), None) => Mutation::RecordFetchFailure { source_id, at },
            (None, text) => Mutation::RemoteSourceAttempt {
                list_id,
                url: url.to_string(),
                text,
                at,
            },
        };
        let saved = self.management.save(revision, mutation).await?;
        let outcome = if let Some(failure) = failure {
            RemoteOutcome::FetchFailed(failure)
        } else if saved
            .import_report
            .as_ref()
            .is_some_and(|report| report.accepted.is_empty())
        {
            RemoteOutcome::NoValidRules
        } else {
            RemoteOutcome::Applied
        };
        Ok(RemoteResult { saved, outcome })
    }
}
impl RemoteManagement for RemoteService {
    fn import_url(
        &self,
        revision: u64,
        list_id: i64,
        raw: String,
    ) -> PolicyFuture<'_, Result<RemoteResult, RemoteError>> {
        Box::pin(async move {
            let url = validate_url(&raw)?;
            if !self
                .snapshot(revision)?
                .repository()
                .lists
                .iter()
                .any(|list| list.id == list_id)
            {
                return Err(PolicyError::Storage(StorageError::NotFound).into());
            }
            self.attempt(revision, list_id, None, url).await
        })
    }
    fn refresh(
        &self,
        revision: u64,
        source_id: i64,
    ) -> PolicyFuture<'_, Result<RemoteResult, RemoteError>> {
        Box::pin(async move {
            let snapshot = self.snapshot(revision)?;
            let list = snapshot
                .repository()
                .lists
                .iter()
                .find(|list| list.sources.iter().any(|source| source.id == source_id))
                .ok_or(RemoteError::InvalidSource)?;
            let source = list
                .sources
                .iter()
                .find(|source| source.id == source_id)
                .ok_or(RemoteError::InvalidSource)?;
            let nullgate_core::SourceKind::Remote { url } = &source.kind else {
                return Err(RemoteError::InvalidSource);
            };
            self.attempt(revision, list.id, Some(source_id), validate_url(url)?)
                .await
        })
    }
}
