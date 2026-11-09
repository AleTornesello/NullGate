//! One bounded blocking worker owns validation/persistence and publication order.

use nullgate_core::{
    BlocklistRepository, MAX_IMPORT_BYTES, MAX_RULE_LINE_BYTES, Mutation, PolicyActivation,
    PolicyError, PolicyFuture, PolicyManagement, PolicyPublisher, PolicySaveResult, PolicySnapshot,
    PolicySubscription, SqliteRepository, StorageError, UnavailableReason, policy_channel,
};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// Runtime integration supplies the configured queue bound. Activation deadline covers all hooks.
pub struct PolicyOptions {
    pub queue_capacity: usize,
    pub activation_timeout: Duration,
    pub activators: Vec<Arc<dyn PolicyActivation>>,
}
impl Default for PolicyOptions {
    fn default() -> Self {
        Self {
            queue_capacity: 32,
            activation_timeout: Duration::from_secs(5),
            activators: Vec::new(),
        }
    }
}

enum Command {
    Save {
        expected: u64,
        mutation: Mutation,
        reply: oneshot::Sender<Result<PolicySaveResult, PolicyError>>,
    },
    Recover {
        reply: oneshot::Sender<Result<Arc<PolicySnapshot>, PolicyError>>,
    },
    Stop {
        reply: oneshot::Sender<()>,
    },
}

/// Cloneable injected writer. It cannot access the repository or publication sender.
#[derive(Clone, Debug)]
pub struct PolicyHandle {
    sender: mpsc::Sender<Command>,
    reader: PolicySubscription,
}
impl PolicyManagement for PolicyHandle {
    fn subscribe(&self) -> PolicySubscription {
        self.reader.clone()
    }
    fn save(
        &self,
        expected_revision: u64,
        mutation: Mutation,
    ) -> PolicyFuture<'_, Result<PolicySaveResult, PolicyError>> {
        Box::pin(async move {
            check_request_size(&mutation)?;
            let (reply, response) = oneshot::channel();
            enqueue(
                &self.sender,
                Command::Save {
                    expected: expected_revision,
                    mutation,
                    reply,
                },
            )?;
            response.await.map_err(|_| PolicyError::OutcomeUnknown)?
        })
    }
}

fn enqueue(sender: &mpsc::Sender<Command>, command: Command) -> Result<(), PolicyError> {
    sender.try_send(command).map_err(|error| match error {
        mpsc::error::TrySendError::Full(_) => PolicyError::Busy,
        mpsc::error::TrySendError::Closed(_) => PolicyError::Stopped,
    })
}
fn check_request_size(mutation: &Mutation) -> Result<(), PolicyError> {
    let error = match mutation {
        Mutation::Import { text, .. } | Mutation::ReplaceEntries { text, .. }
            if text.len() > MAX_IMPORT_BYTES =>
        {
            Some(StorageError::ImportTooLarge)
        }
        Mutation::CreateList { name } | Mutation::RenameList { name, .. } if name.len() > 128 => {
            Some(StorageError::InvalidName)
        }
        Mutation::AddSource {
            kind: nullgate_core::SourceKind::File { filename },
            ..
        } if filename.len() > 128 => Some(StorageError::InvalidSource),
        Mutation::AddSource {
            kind: nullgate_core::SourceKind::Remote { url },
            ..
        } if url.len() > MAX_RULE_LINE_BYTES => Some(StorageError::InvalidSource),
        _ => None,
    };
    match error {
        Some(error) => Err(PolicyError::Storage(error)),
        None => Ok(()),
    }
}

/// Owns the writer task. Explicit shutdown drains preceding accepted commands and joins it.
/// Drop requests shutdown; accepted requests whose replies are lost must not be blindly retried.
#[derive(Debug)]
pub struct PolicyCoordinator {
    handle: PolicyHandle,
    worker: Option<JoinHandle<()>>,
    stopping: Arc<AtomicBool>,
}
impl PolicyCoordinator {
    /// Move an already-open repository into the blocking worker. Only this worker may mutate it.
    pub async fn start<R: BlocklistRepository + Send + 'static>(
        repository: R,
        options: PolicyOptions,
    ) -> Result<Self, PolicyError> {
        Self::start_factory(move || Ok(Box::new(repository)), options).await
    }
    /// Open, validate and compile SQLite state entirely on the blocking worker.
    pub async fn open(path: PathBuf, options: PolicyOptions) -> Result<Self, PolicyError> {
        Self::start_factory(
            move || {
                SqliteRepository::open(path)
                    .map(|repo| Box::new(repo) as Box<dyn BlocklistRepository + Send>)
            },
            options,
        )
        .await
    }
    async fn start_factory<F>(factory: F, options: PolicyOptions) -> Result<Self, PolicyError>
    where
        F: FnOnce() -> Result<Box<dyn BlocklistRepository + Send>, StorageError> + Send + 'static,
    {
        if options.queue_capacity == 0
            || options.queue_capacity > 65_535
            || options.activation_timeout.is_zero()
            || options.activation_timeout > Duration::from_secs(60)
        {
            return Err(PolicyError::InvalidOptions);
        }
        let (sender, mut requests) = mpsc::channel(options.queue_capacity);
        let (ready, initialized) = oneshot::channel();
        let stopping = Arc::new(AtomicBool::new(false));
        let stop = stopping.clone();
        let runtime = tokio::runtime::Handle::current();
        let worker = tokio::task::spawn_blocking(move || {
            let prepared = (|| {
                let mut repository = factory().map_err(PolicyError::Storage)?;
                let snapshot = repository.snapshot().map_err(PolicyError::Storage)?;
                let initial = PolicySnapshot::from_repository(snapshot)
                    .map_err(|_| PolicyError::Storage(StorageError::Corrupt))?;
                Ok::<_, PolicyError>((repository, initial))
            })();
            let (mut repository, initial) = match prepared {
                Ok(prepared) => prepared,
                Err(error) => {
                    let _ = ready.send(Err(error));
                    return;
                }
            };
            let (mut publisher, reader) = policy_channel(initial);
            let mut healthy = reader.current().expect("new policy channel is active");
            if ready.send(Ok(reader)).is_err() {
                return;
            }
            let mut failed_revision = None;
            while let Some(command) = requests.blocking_recv() {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                match command {
                    Command::Save {
                        expected,
                        mutation,
                        reply,
                    } => {
                        let result = if let Some(revision) = failed_revision {
                            Err(PolicyError::Unavailable { revision })
                        } else {
                            let applied =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    repository.apply(expected, mutation)
                                }));
                            let applied = match applied {
                                Ok(applied) => applied,
                                Err(_) => {
                                    // In a normal unwind the request's reply sender can drop
                                    // before the publisher. Fail closed before telling the
                                    // caller that a potentially committed outcome is unknown.
                                    publisher.unavailable(
                                        publisher.revision(),
                                        UnavailableReason::Stopped,
                                    );
                                    let _ = reply.send(Err(PolicyError::OutcomeUnknown));
                                    break;
                                }
                            };
                            match applied {
                                Err(error) => Err(PolicyError::Storage(error)),
                                Ok(commit) => {
                                    let (snapshot, import_report) =
                                        PolicySnapshot::from_commit(commit);
                                    let candidate = Arc::new(snapshot);
                                    let revision = candidate.revision();
                                    if healthy.revision().checked_add(1) != Some(revision) {
                                        publisher.unavailable(
                                            revision,
                                            UnavailableReason::CommittedNotActive,
                                        );
                                        failed_revision = Some(revision);
                                        Err(PolicyError::CommittedNotActive { revision })
                                    } else if activate(
                                        &runtime,
                                        &options,
                                        &mut publisher,
                                        &healthy,
                                        &candidate,
                                    )
                                    .is_err()
                                    {
                                        failed_revision = Some(revision);
                                        Err(PolicyError::CommittedNotActive { revision })
                                    } else {
                                        healthy = candidate.clone();
                                        Ok(PolicySaveResult {
                                            snapshot: candidate,
                                            import_report,
                                        })
                                    }
                                }
                            }
                        };
                        // Cancellation of the requester never skips activation/publication.
                        let _ = reply.send(result);
                    }
                    Command::Recover { reply } => {
                        let state =
                            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                repository.snapshot()
                            })) {
                                Ok(state) => state,
                                Err(_) => {
                                    publisher.unavailable(
                                        publisher.revision(),
                                        UnavailableReason::Stopped,
                                    );
                                    let _ = reply.send(Err(PolicyError::OutcomeUnknown));
                                    break;
                                }
                            };
                        let result = (|| {
                            let state = state.map_err(PolicyError::Storage)?;
                            if state.revision < publisher.revision() {
                                return Err(PolicyError::Storage(StorageError::Corrupt));
                            }
                            let candidate = Arc::new(
                                PolicySnapshot::from_repository(state)
                                    .map_err(|_| PolicyError::Storage(StorageError::Corrupt))?,
                            );
                            let revision = candidate.revision();
                            if failed_revision.is_none() && revision == healthy.revision() {
                                return Ok(healthy.clone());
                            }
                            if activate(&runtime, &options, &mut publisher, &healthy, &candidate)
                                .is_err()
                            {
                                failed_revision = Some(revision);
                                return Err(PolicyError::CommittedNotActive { revision });
                            }
                            failed_revision = None;
                            healthy = candidate.clone();
                            Ok(candidate)
                        })();
                        let _ = reply.send(result);
                    }
                    Command::Stop { reply } => {
                        publisher.unavailable(publisher.revision(), UnavailableReason::Stopped);
                        let _ = reply.send(());
                        break;
                    }
                }
            }
            publisher.unavailable(publisher.revision(), UnavailableReason::Stopped);
        });
        let reader = initialized.await.map_err(|_| PolicyError::WorkerFailed)??;
        Ok(Self {
            handle: PolicyHandle { sender, reader },
            worker: Some(worker),
            stopping,
        })
    }
    pub fn handle(&self) -> PolicyHandle {
        self.handle.clone()
    }
    pub fn reader(&self) -> PolicySubscription {
        self.handle.subscribe()
    }
    /// Reconcile durable state after an activation fault; repeats idempotent hooks before publication.
    pub async fn recover(&self) -> Result<Arc<PolicySnapshot>, PolicyError> {
        let (reply, response) = oneshot::channel();
        enqueue(&self.handle.sender, Command::Recover { reply })?;
        response.await.map_err(|_| PolicyError::OutcomeUnknown)?
    }
    /// Drain requests queued before this marker and stop new admissions.
    pub async fn shutdown(mut self) -> Result<(), PolicyError> {
        let (reply, response) = oneshot::channel();
        let sent = self.handle.sender.send(Command::Stop { reply }).await;
        let acknowledged = if sent.is_ok() {
            response.await.is_ok()
        } else {
            false
        };
        let joined = match self.worker.take() {
            Some(worker) => worker.await.is_ok(),
            None => true,
        };
        if !joined {
            Err(PolicyError::WorkerFailed)
        } else if !acknowledged {
            Err(PolicyError::Stopped)
        } else {
            Ok(())
        }
    }
}
impl Drop for PolicyCoordinator {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        let (reply, _) = oneshot::channel();
        let _ = self.handle.sender.try_send(Command::Stop { reply });
    }
}

fn activate(
    runtime: &tokio::runtime::Handle,
    options: &PolicyOptions,
    publisher: &mut PolicyPublisher,
    previous: &Arc<PolicySnapshot>,
    candidate: &Arc<PolicySnapshot>,
) -> Result<(), ()> {
    if !options.activators.is_empty() {
        publisher.unavailable(candidate.revision(), UnavailableReason::Activating);
        let acknowledged = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.block_on(async {
                tokio::time::timeout(options.activation_timeout, async {
                    for participant in &options.activators {
                        participant
                            .activate(previous.clone(), candidate.clone())
                            .await?;
                    }
                    Ok::<(), nullgate_core::ActivationError>(())
                })
                .await
            })
        }));
        if !matches!(acknowledged, Ok(Ok(Ok(())))) {
            publisher.unavailable(candidate.revision(), UnavailableReason::CommittedNotActive);
            return Err(());
        }
    }
    publisher.publish(candidate.clone());
    Ok(())
}
