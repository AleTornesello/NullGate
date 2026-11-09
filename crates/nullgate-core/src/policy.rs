//! Immutable policy snapshots and read/write capabilities shared across crate boundaries.
//!
//! Subscribers cannot publish. Capture one [`PolicySnapshot`] per admitted request;
//! a retained snapshot represents work admitted before a later policy change.

use crate::{
    CompileError, ImportReport, Mutation, RepositorySnapshot, RuleSet, StorageCommit, StorageError,
};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::watch;

/// Object-safe async method return type, usable through injected trait objects.
pub type PolicyFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Complete immutable policy and administrative state at one durable revision.
#[derive(Debug)]
pub struct PolicySnapshot {
    repository: RepositorySnapshot,
    rules: RuleSet,
}
impl PolicySnapshot {
    /// Validate and compile a detached durable snapshot at startup/recovery.
    pub fn from_repository(repository: RepositorySnapshot) -> Result<Self, CompileError> {
        let rules = repository.compile()?;
        Ok(Self { repository, rules })
    }
    /// Consume a verified repository commit without a fallible post-commit read/compile.
    /// Repository implementations must return matching metadata/rules and increment revision once.
    pub fn from_commit(commit: StorageCommit) -> (Self, Option<ImportReport>) {
        (
            Self {
                repository: commit.snapshot,
                rules: commit.rules,
            },
            commit.import_report,
        )
    }
    pub fn revision(&self) -> u64 {
        self.repository.revision
    }
    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }
    pub fn repository(&self) -> &RepositorySnapshot {
        &self.repository
    }
}

/// Unavailable policies must not admit new proxy requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnavailableReason {
    Activating,
    CommittedNotActive,
    Stopped,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyUnavailable {
    pub revision: u64,
    pub reason: UnavailableReason,
}
impl fmt::Display for PolicyUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Policy unavailable at revision {} ({:?})",
            self.revision, self.reason
        )
    }
}
impl std::error::Error for PolicyUnavailable {}

#[derive(Clone, Debug)]
enum PublishedState {
    Active(Arc<PolicySnapshot>),
    Unavailable(PolicyUnavailable),
}
impl PublishedState {
    fn revision(&self) -> u64 {
        match self {
            Self::Active(snapshot) => snapshot.revision(),
            Self::Unavailable(fault) => fault.revision,
        }
    }
}

/// Read-only capability. Watch notifications may coalesce revisions; `current` is authoritative.
#[derive(Clone, Debug)]
pub struct PolicySubscription {
    receiver: watch::Receiver<PublishedState>,
}
impl PolicySubscription {
    /// Obtain one complete snapshot without waiting for storage or holding a channel lock.
    /// A closed publisher fails closed even if its last state was active.
    pub fn current(&self) -> Result<Arc<PolicySnapshot>, PolicyUnavailable> {
        let state = self.receiver.borrow().clone();
        if self.receiver.has_changed().is_err() {
            return Err(PolicyUnavailable {
                revision: state.revision(),
                reason: UnavailableReason::Stopped,
            });
        }
        match state {
            PublishedState::Active(snapshot) => Ok(snapshot),
            PublishedState::Unavailable(fault) => Err(fault),
        }
    }
    /// Wait for the latest changed state. Unavailability is a notification, not a snapshot.
    /// This operation is cancellation-safe; call again after recoverable unavailable states.
    pub async fn changed(&mut self) -> Result<Arc<PolicySnapshot>, PolicyUnavailable> {
        if self.receiver.changed().await.is_err() {
            return Err(PolicyUnavailable {
                revision: self.receiver.borrow().revision(),
                reason: UnavailableReason::Stopped,
            });
        }
        self.current()
    }
}

/// Exclusive publication capability for the composition root. Never inject this into services.
/// The owner must serialize writes and ensure revisions never move backwards.
#[derive(Debug)]
pub struct PolicyPublisher {
    sender: watch::Sender<PublishedState>,
}
impl PolicyPublisher {
    /// Replace the entire state even when no subscribers are currently attached.
    pub fn publish(&mut self, snapshot: Arc<PolicySnapshot>) {
        self.sender.send_replace(PublishedState::Active(snapshot));
    }
    pub fn unavailable(&mut self, revision: u64, reason: UnavailableReason) {
        self.sender
            .send_replace(PublishedState::Unavailable(PolicyUnavailable {
                revision,
                reason,
            }));
    }
    pub fn subscribe(&self) -> PolicySubscription {
        PolicySubscription {
            receiver: self.sender.subscribe(),
        }
    }
    pub fn revision(&self) -> u64 {
        self.sender.borrow().revision()
    }
}

/// Create separate publisher/subscriber capabilities around a verified initial policy.
pub fn policy_channel(initial: PolicySnapshot) -> (PolicyPublisher, PolicySubscription) {
    let (sender, receiver) = watch::channel(PublishedState::Active(Arc::new(initial)));
    (PolicyPublisher { sender }, PolicySubscription { receiver })
}

/// Save/control outcome. Accepted commands with lost replies may already be durable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyError {
    /// Validation or pre-commit storage rejection; the prior active policy is retained.
    Storage(StorageError),
    /// Queue was full; the request was not accepted.
    Busy,
    /// Queue was closed; the request was not accepted.
    Stopped,
    /// The accepted command lost its reply. Reload/recover before retrying.
    OutcomeUnknown,
    InvalidOptions,
    WorkerFailed,
    CommittedNotActive {
        revision: u64,
    },
    Unavailable {
        revision: u64,
    },
}
impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => error.fmt(f),
            Self::CommittedNotActive { revision } => write!(
                f,
                "Revision {revision} committed but is not active; recovery is required"
            ),
            Self::Unavailable { revision } => write!(
                f,
                "Policy unavailable at revision {revision}; no new edit accepted by storage"
            ),
            other => f.write_str(match other {
                Self::Busy => "Policy queue is full; request was not accepted",
                Self::Stopped => "Policy coordinator stopped; request was not accepted",
                Self::OutcomeUnknown => {
                    "Accepted request outcome is unknown; reload before retrying"
                }
                Self::InvalidOptions => "Invalid policy queue capacity or activation deadline",
                Self::WorkerFailed => {
                    "Policy worker failed; reload durable state before restarting"
                }
                _ => unreachable!(),
            }),
        }
    }
}
impl std::error::Error for PolicyError {}

/// Returned only after durable commit, required activation acknowledgements and publication.
#[derive(Debug)]
pub struct PolicySaveResult {
    pub snapshot: Arc<PolicySnapshot>,
    pub import_report: Option<ImportReport>,
}

/// Inject this into web/application handlers without a dependency on the orchestrator crate.
pub trait PolicyManagement: Send + Sync {
    fn subscribe(&self) -> PolicySubscription;
    fn save(
        &self,
        expected_revision: u64,
        mutation: Mutation,
    ) -> PolicyFuture<'_, Result<PolicySaveResult, PolicyError>>;
}

/// Safe activation error; details must not include browsing data, credentials or private keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivationError;
impl fmt::Display for ActivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Policy activation failed")
    }
}
impl std::error::Error for ActivationError {}

/// Future connection managers implement idempotent invalidation and acknowledge only on completion.
/// Recovery may repeat a partially completed activation. Futures must yield rather than block,
/// acknowledge completed work only, and never recursively call saves. Deadlines are cooperative.
pub trait PolicyActivation: Send + Sync {
    fn activate(
        &self,
        previous: Arc<PolicySnapshot>,
        candidate: Arc<PolicySnapshot>,
    ) -> PolicyFuture<'_, Result<(), ActivationError>>;
}
