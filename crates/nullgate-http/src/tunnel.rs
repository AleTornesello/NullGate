//! Opaque CONNECT transport and revision-aware invalidation. No TLS is terminated here.
use crate::{forward::ProxyBody, server::HttpOptions};
use hyper::{
    Request, Response, StatusCode, Version,
    body::Incoming,
    header::{CONTENT_LENGTH, HOST, TRANSFER_ENCODING, UPGRADE},
    upgrade::Upgraded,
};
use hyper_util::rt::TokioIo;
use nullgate_core::{
    ActivationError, NormalizedAuthority, NormalizedHost, PolicyActivation, PolicyFuture,
    PolicySnapshot, PolicySubscription, UnavailableReason, normalize_authority,
};
use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};
use tokio::{
    net::TcpStream,
    sync::{Notify, OwnedSemaphorePermit},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

/// Current capabilities, independent of whether an HTTPS host has URL rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpCapabilities {
    pub https_connect_passthrough: bool,
    pub https_url_filtering: bool,
}
/// Cloneable control injected into the policy coordinator's activation participants.
/// The coordinator must stop admission with `Activating` before invoking activation.
/// Direct publications also invalidate observed revisions, but watch updates may coalesce.
#[derive(Clone, Default)]
pub struct TunnelControl {
    inner: Arc<Inner>,
}
#[derive(Default)]
struct Inner {
    registry: Mutex<Registry>,
    changed: Notify,
}
#[derive(Default)]
struct Registry {
    next: u64,
    entries: HashMap<u64, Entry>,
}
struct Entry {
    host: NormalizedHost,
    inspection: bool,
    cancel: CancellationToken,
    lease_finished: bool,
    http_closed: bool,
    http_cancel: CancellationToken,
}
impl fmt::Debug for TunnelControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelControl")
            .field("active_count", &self.active_count())
            .finish()
    }
}
// Completion has two owners before upgrade: Hyper and the pending session.
// The HTTP driver signals only after its IO future/service/permit have dropped.
#[derive(Clone, Default)]
pub(crate) struct ConnectionLifetime {
    pub cancel: CancellationToken,
    ownership: Arc<Mutex<ConnectionOwnership>>,
}
#[derive(Default)]
struct ConnectionOwnership {
    closed: bool,
    entry: Option<(TunnelControl, u64)>,
}
pub(crate) struct HttpDriverGuard(ConnectionLifetime);
impl Drop for HttpDriverGuard {
    fn drop(&mut self) {
        let entry = {
            let mut ownership = self.0.ownership.lock().unwrap();
            ownership.closed = true;
            ownership.entry.clone()
        };
        // Never acquire registry while retaining ownership's lock.
        if let Some((control, id)) = entry {
            control.finish_owner(id, true);
        }
    }
}
impl ConnectionLifetime {
    pub fn driver_guard(&self) -> HttpDriverGuard {
        HttpDriverGuard(self.clone())
    }
}
impl TunnelControl {
    fn finish_owner(&self, id: u64, http: bool) {
        let mut registry = self.inner.registry.lock().unwrap();
        if let Some(entry) = registry.entries.get_mut(&id) {
            if http {
                entry.http_closed = true;
            } else {
                entry.lease_finished = true;
            }
            if entry.http_closed && entry.lease_finished {
                registry.entries.remove(&id);
            }
        }
        drop(registry);
        self.inner.changed.notify_waiters();
    }

    /// Includes pending upstream connections as well as established tunnels.
    pub fn active_count(&self) -> usize {
        self.inner.registry.lock().unwrap().entries.len()
    }
    /// Wait for all tracked sessions to release sockets and admission permits.
    pub async fn wait_idle(&self) {
        self.wait_removed(None).await;
    }
    async fn wait_removed(&self, ids: Option<&[u64]>) {
        loop {
            let changed = self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let finished = {
                let registry = self.inner.registry.lock().unwrap();
                match ids {
                    Some(ids) => ids.iter().all(|id| !registry.entries.contains_key(id)),
                    None => registry.entries.is_empty(),
                }
            };
            if finished {
                return;
            }
            changed.await;
        }
    }
    fn register(
        &self,
        host: NormalizedHost,
        policy: &PolicySubscription,
        request: OwnedSemaphorePermit,
        connection: Arc<OwnedSemaphorePermit>,
        lifetime: ConnectionLifetime,
    ) -> Result<Lease, StatusCode> {
        let mut registry = self.inner.registry.lock().unwrap();
        let snapshot = policy
            .current()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if snapshot.rules().blocks_domain(&host) {
            return Err(StatusCode::FORBIDDEN);
        }
        let inspection = snapshot.rules().requires_inspection(&host);
        registry.next = registry
            .next
            .checked_add(1)
            .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
        let id = registry.next;
        let cancel = CancellationToken::new();
        let http_closed = {
            let mut ownership = lifetime.ownership.lock().unwrap();
            ownership.entry = Some((self.clone(), id));
            ownership.closed
        };
        registry.entries.insert(
            id,
            Entry {
                host: host.clone(),
                inspection,
                cancel: cancel.clone(),
                lease_finished: false,
                http_closed,
                http_cancel: lifetime.cancel.clone(),
            },
        );
        Ok(Lease {
            control: self.clone(),
            id,
            host,
            inspection,
            cancel,
            request: Some(request),
            connection: Some(connection),
            lifetime,
        })
    }
}
impl PolicyActivation for TunnelControl {
    fn activate(
        &self,
        _previous: Arc<PolicySnapshot>,
        candidate: Arc<PolicySnapshot>,
    ) -> PolicyFuture<'_, Result<(), ActivationError>> {
        Box::pin(async move {
            let ids = {
                let registry = self.inner.registry.lock().unwrap();
                registry
                    .entries
                    .iter()
                    .filter_map(|(id, entry)| {
                        if candidate.rules().blocks_domain(&entry.host)
                            || candidate.rules().requires_inspection(&entry.host)
                                != entry.inspection
                        {
                            entry.cancel.cancel();
                            entry.http_cancel.cancel();
                            Some(*id)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            };
            self.wait_removed(Some(&ids)).await;
            Ok(())
        })
    }
}
struct Lease {
    control: TunnelControl,
    id: u64,
    host: NormalizedHost,
    inspection: bool,
    cancel: CancellationToken,
    request: Option<OwnedSemaphorePermit>,
    connection: Option<Arc<OwnedSemaphorePermit>>,
    lifetime: ConnectionLifetime,
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.request.take();
        self.connection.take();
        self.control.finish_owner(self.id, false);
    }
}
impl Lease {
    async fn invalidated(&self, mut policy: PolicySubscription, shutdown: CancellationToken) {
        loop {
            match policy.current() {
                Ok(snapshot)
                    if snapshot.rules().blocks_domain(&self.host)
                        || snapshot.rules().requires_inspection(&self.host) != self.inspection =>
                {
                    break;
                }
                Err(error) if error.reason != UnavailableReason::Activating => break,
                _ => {}
            }
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => break,
                _ = self.cancel.cancelled() => break,
                _ = policy.changed() => {},
            }
        }
        self.lifetime.cancel.cancel();
    }
}
// Field drop order matters: close sockets before the lease acknowledges cleanup.
struct Session {
    upstream: TcpStream,
    client: Option<TokioIo<Upgraded>>,
    lease: Lease,
}

impl Session {
    async fn run(
        mut self,
        upgrade: hyper::upgrade::OnUpgrade,
        policy: PolicySubscription,
        shutdown: CancellationToken,
        timeout: std::time::Duration,
    ) {
        let invalidated = self.lease.invalidated(policy, shutdown);
        tokio::pin!(invalidated);
        let upgraded = tokio::select! {
            biased;
            _= &mut invalidated => return,
            result=tokio::time::timeout(timeout,upgrade) => match result { Ok(Ok(io)) => io, _ => return },
        };
        self.client = Some(TokioIo::new(upgraded));
        tokio::select! {
            biased;
            _= &mut invalidated => {},
            _=tokio::io::copy_bidirectional(self.client.as_mut().unwrap(), &mut self.upstream) => {},
        }
    }
}

fn validate(request: &Request<Incoming>, raw: &str) -> Result<NormalizedAuthority, StatusCode> {
    let target = normalize_authority(raw, None).map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut hosts = request.headers().get_all(HOST).iter();
    let host = hosts.next();
    if hosts.next().is_some() || (request.version() == Version::HTTP_11 && host.is_none()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if let Some(host) = host {
        let host = host.to_str().map_err(|_| StatusCode::BAD_REQUEST)?;
        if normalize_authority(host, None).map_err(|_| StatusCode::BAD_REQUEST)? != target {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    if request.headers().contains_key(TRANSFER_ENCODING)
        || request.headers().contains_key(UPGRADE)
        || request
            .headers()
            .get(CONTENT_LENGTH)
            .is_some_and(|value| value.as_bytes() != b"0")
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    // Validate Connection syntax even though CONNECT headers are never forwarded.
    let mut headers = request.headers().clone();
    crate::forward::strip_hop_headers(&mut headers).map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(target)
}
async fn connect(target: &NormalizedAuthority) -> std::io::Result<TcpStream> {
    match target.host() {
        NormalizedHost::Dns(name) => TcpStream::connect((name.as_str(), target.port())).await,
        NormalizedHost::Ipv4(ip) => {
            TcpStream::connect(SocketAddr::new(IpAddr::V4(*ip), target.port())).await
        }
        NormalizedHost::Ipv6(ip) => {
            TcpStream::connect(SocketAddr::new(IpAddr::V6(*ip), target.port())).await
        }
    }
}
/// Inputs owned by the existing HTTP listener; admission is shared with ordinary requests.
pub(crate) struct TunnelContext<'a> {
    pub control: &'a TunnelControl,
    pub policy: PolicySubscription,
    pub options: &'a HttpOptions,
    pub tracker: &'a TaskTracker,
    pub shutdown: CancellationToken,
    pub request: OwnedSemaphorePermit,
    pub connection: Arc<OwnedSemaphorePermit>,
    pub lifetime: ConnectionLifetime,
}
pub(crate) async fn handle(
    mut request: Request<Incoming>,
    raw: &str,
    context: TunnelContext<'_>,
) -> Response<ProxyBody> {
    let target = match validate(&request, raw) {
        Ok(target) => target,
        Err(status) => return crate::server::local(status, true),
    };
    let lease = match context.control.register(
        target.host().clone(),
        &context.policy,
        context.request,
        context.connection,
        context.lifetime,
    ) {
        Ok(lease) => lease,
        Err(status) => return crate::server::local(status, true),
    };
    let upstream = tokio::select! {
        biased;
        _ = lease.invalidated(context.policy.clone(), context.shutdown.clone()) => {
            return crate::server::local(StatusCode::SERVICE_UNAVAILABLE, true);
        }
        result = tokio::time::timeout(context.options.connect_timeout, connect(&target)) => {
            match result {
                Ok(Ok(stream)) => stream,
                Ok(Err(_)) => return crate::server::local(StatusCode::BAD_GATEWAY, true),
                Err(_) => return crate::server::local(StatusCode::GATEWAY_TIMEOUT, true),
            }
        }
    };
    let session = Session {
        upstream,
        client: None,
        lease,
    };
    let upgrade = hyper::upgrade::on(&mut request);
    let timeout = context.options.request_header_timeout;
    context
        .tracker
        .spawn(session.run(upgrade, context.policy, context.shutdown, timeout));
    let mut response = Response::new(ProxyBody::empty());
    response.headers_mut().insert(
        "nullgate-https-url-filtering",
        hyper::header::HeaderValue::from_static("unavailable"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use nullgate_core::{RepositorySnapshot, normalize_host, policy_channel};
    use tokio::sync::Semaphore;
    fn blocked_candidate() -> Arc<PolicySnapshot> {
        use nullgate_core::{BlocklistRepository, Mutation, SourceKind, SqliteRepository};
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "nullgate-connect-ownership-{}-{stamp}",
            std::process::id()
        ));
        let snapshot = {
            let mut repo = SqliteRepository::open(path.join("state.sqlite3")).unwrap();
            repo.apply(
                0,
                Mutation::CreateList {
                    name: "ownership".into(),
                },
            )
            .unwrap();
            let commit = repo
                .apply(
                    1,
                    Mutation::AddSource {
                        list_id: 1,
                        kind: SourceKind::Manual,
                    },
                )
                .unwrap();
            let id = commit.snapshot.lists[0].sources[0].id;
            let commit = repo
                .apply(
                    2,
                    Mutation::Import {
                        source_id: id,
                        text: "localhost".into(),
                        at: 0,
                    },
                )
                .unwrap();
            Arc::new(PolicySnapshot::from_commit(commit).0)
        };
        std::fs::remove_dir_all(path).unwrap();
        snapshot
    }
    #[tokio::test]
    async fn pending_session_cleanup_waits_for_http_driver_ownership() {
        let control = TunnelControl::default();
        let snapshot = PolicySnapshot::from_repository(RepositorySnapshot {
            revision: 0,
            lists: vec![],
        })
        .unwrap();
        let (_publisher, policy) = policy_channel(snapshot);
        let connections = Arc::new(Semaphore::new(1));
        let requests = Arc::new(Semaphore::new(1));
        let connection = Arc::new(connections.clone().acquire_owned().await.unwrap());
        // Hyper's pre-upgrade HTTP driver retains its own connection permit.
        let http_driver = connection.clone();
        let lifetime = ConnectionLifetime::default();
        let http_closed = lifetime.driver_guard();
        let lease = control
            .register(
                normalize_host("localhost").unwrap(),
                &policy,
                requests.clone().acquire_owned().await.unwrap(),
                connection,
                lifetime.clone(),
            )
            .unwrap();
        drop(lease);
        assert_eq!(requests.available_permits(), 1);
        assert_eq!(connections.available_permits(), 0);
        assert_eq!(
            control.active_count(),
            1,
            "pending HTTP owner must prevent cleanup acknowledgement"
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), control.wait_idle())
                .await
                .is_err()
        );
        // A failed/cancelled dial may have released the session while Hyper is
        // still writing its terminal error. Activation must stop that driver too.
        let candidate = blocked_candidate();
        let activation = control.activate(policy.current().unwrap(), candidate);
        tokio::pin!(activation);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut activation)
                .await
                .is_err()
        );
        assert!(
            lifetime.cancel.is_cancelled(),
            "activation must cancel the retained HTTP owner"
        );
        drop(http_driver);
        drop(http_closed);
        tokio::time::timeout(std::time::Duration::from_secs(1), activation)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), control.wait_idle())
            .await
            .unwrap();
        assert_eq!(connections.available_permits(), 1);
    }
}
