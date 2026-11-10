use nullgate_core::{
    ActivationError, BlocklistRepository, Mutation, PolicyActivation, PolicyError, PolicyFuture,
    PolicyManagement, PolicySnapshot, RepositorySnapshot, SourceKind, SqliteRepository,
    StorageCommit, StorageError, UnavailableReason, normalize_host, normalize_url,
};
use nullgate_orchestrator::{PolicyCoordinator, PolicyOptions};
use std::future::Future;
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Duration;
use tokio::sync::{Notify, oneshot};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "nullgate-policy-{}-{stamp}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn db(&self) -> PathBuf {
        self.0.join("state.sqlite3")
    }
    fn seed(&self) -> (SqliteRepository, i64) {
        let mut repo = SqliteRepository::open(self.db()).unwrap();
        repo.apply(
            0,
            Mutation::CreateList {
                name: "Policy".into(),
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
        (repo, id)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn import(source_id: i64, text: &str) -> Mutation {
    Mutation::Import {
        source_id,
        text: text.into(),
        at: 1,
    }
}
fn domain(snapshot: &PolicySnapshot, host: &str) -> bool {
    snapshot
        .rules()
        .blocks_domain(&normalize_host(host).unwrap())
}
fn url(snapshot: &PolicySnapshot, target: &str) -> bool {
    snapshot.rules().blocks_url(&normalize_url(target).unwrap())
}
fn inspected(snapshot: &PolicySnapshot, host: &str) -> bool {
    snapshot
        .rules()
        .requires_inspection(&normalize_host(host).unwrap())
}
async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .expect("test operation timed out")
}

#[tokio::test]
async fn existing_subscribers_see_complete_published_policy_before_success() {
    let scratch = Scratch::new();
    let (repo, source) = scratch.seed();
    let coordinator = PolicyCoordinator::start(repo, PolicyOptions::default())
        .await
        .unwrap();
    let api: Arc<dyn PolicyManagement> = Arc::new(coordinator.handle());
    let mut dns = api.subscribe();
    let mut http = api.subscribe();
    let mut tls = api.subscribe();
    let old = dns.current().unwrap();
    assert_eq!(old.revision(), 2);
    let saved = api.save(2, import(source, "blocked.example\n*.tracking.example\nhttps://secure.example/ads\nhttp://plain.example/ads\nmalformed rule")).await.unwrap();
    assert_eq!(saved.snapshot.revision(), 3);
    assert_eq!(saved.import_report.as_ref().unwrap().malformed[0].line, 5);
    assert_eq!(saved.import_report.as_ref().unwrap().accepted.len(), 4);
    for reader in [&mut dns, &mut http, &mut tls] {
        let snapshot = reader.current().unwrap();
        assert_eq!(snapshot.revision(), 3);
        assert!(domain(&snapshot, "blocked.example"));
        assert!(domain(&snapshot, "a.b.tracking.example"));
        assert!(!domain(&snapshot, "secure.example"));
        assert!(url(&snapshot, "https://secure.example/ads?x=1"));
        assert!(!url(&snapshot, "https://secure.example/news"));
        assert!(inspected(&snapshot, "secure.example"));
        assert!(!inspected(&snapshot, "plain.example"));
        assert_eq!(bounded(reader.changed()).await.unwrap().revision(), 3);
    }
    assert!(!domain(&old, "blocked.example"));
    assert_eq!(old.revision(), 2);
    assert_eq!(api.subscribe().current().unwrap().revision(), 3);
    coordinator.shutdown().await.unwrap();
}

#[tokio::test]
async fn repeated_changes_never_expose_mixed_versions() {
    let scratch = Scratch::new();
    let (repo, source) = scratch.seed();
    let coordinator = PolicyCoordinator::start(repo, PolicyOptions::default())
        .await
        .unwrap();
    let mut reader = coordinator.reader();
    let writer = coordinator.handle();
    let observer = tokio::spawn(async move {
        let mut observed = 0;
        loop {
            let snapshot = bounded(reader.changed()).await.unwrap();
            let odd = snapshot.revision() % 2 == 1;
            assert_eq!(domain(&snapshot, "odd.example"), odd);
            assert_eq!(domain(&snapshot, "even.example"), !odd);
            assert_eq!(url(&snapshot, "https://selected.example/ads"), odd);
            assert_eq!(inspected(&snapshot, "selected.example"), odd);
            assert!(!domain(&snapshot, "selected.example"));
            observed += 1;
            if snapshot.revision() == 42 {
                break;
            }
        }
        observed
    });
    for revision in 2..42 {
        let text = if revision % 2 == 0 {
            "odd.example\nhttps://selected.example/ads"
        } else {
            "even.example\nhttp://selected.example/ads"
        };
        let saved = writer
            .save(
                revision,
                Mutation::ReplaceEntries {
                    source_id: source,
                    text: text.into(),
                    at: 1,
                },
            )
            .await
            .unwrap();
        assert_eq!(saved.snapshot.revision(), revision + 1);
    }
    assert!(bounded(observer).await.unwrap() > 0);
    coordinator.shutdown().await.unwrap();
}

#[tokio::test]
async fn failed_validation_and_mid_transaction_write_leave_active_arc_unchanged() {
    let scratch = Scratch::new();
    let (repo, source) = scratch.seed();
    let coordinator = PolicyCoordinator::start(repo, PolicyOptions::default())
        .await
        .unwrap();
    let writer = coordinator.handle();
    let reader = coordinator.reader();
    writer
        .save(2, import(source, "keep.example"))
        .await
        .unwrap();
    let before = reader.current().unwrap();
    let db = rusqlite::Connection::open(scratch.db()).unwrap();
    db.execute_batch("CREATE TRIGGER fail_entry BEFORE INSERT ON entries WHEN NEW.input = 'reject.example' BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    let error = writer
        .save(
            3,
            Mutation::ReplaceEntries {
                source_id: source,
                text: "first.example\nreject.example".into(),
                at: 2,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(error, PolicyError::Storage(_)));
    assert!(Arc::ptr_eq(&before, &reader.current().unwrap()));
    assert!(domain(&before, "keep.example"));
    assert!(!domain(&before, "first.example"));
    assert!(
        writer
            .save(3, Mutation::CreateList { name: "".into() })
            .await
            .is_err()
    );
    assert!(Arc::ptr_eq(&before, &reader.current().unwrap()));
    coordinator.shutdown().await.unwrap();
    let durable = SqliteRepository::open(scratch.db())
        .unwrap()
        .snapshot()
        .unwrap();
    assert_eq!(durable.revision, 3);
    assert_eq!(durable.source(source).unwrap().entries.len(), 1);
}

#[tokio::test]
async fn same_revision_concurrent_edits_have_one_winner_and_explicit_conflict() {
    let scratch = Scratch::new();
    let (repo, source) = scratch.seed();
    let coordinator = PolicyCoordinator::start(repo, PolicyOptions::default())
        .await
        .unwrap();
    let a = coordinator.handle();
    let b = coordinator.handle();
    let (one, two) = tokio::join!(
        a.save(2, import(source, "one.example")),
        b.save(2, import(source, "two.example"))
    );
    let (winner, loser) = if one.is_ok() {
        (one.unwrap(), two.unwrap_err())
    } else {
        (two.unwrap(), one.unwrap_err())
    };
    assert_eq!(winner.snapshot.revision(), 3);
    assert_eq!(
        loser,
        PolicyError::Storage(StorageError::Conflict {
            expected: 2,
            actual: 3
        })
    );
    assert_eq!(
        coordinator
            .reader()
            .current()
            .unwrap()
            .repository()
            .source(source)
            .unwrap()
            .entries
            .len(),
        1
    );
    coordinator.shutdown().await.unwrap();
}

struct GateRepo {
    inner: SqliteRepository,
    entered: Option<oneshot::Sender<()>>,
    release: std::sync::mpsc::Receiver<()>,
}
impl BlocklistRepository for GateRepo {
    fn snapshot(&mut self) -> Result<RepositorySnapshot, StorageError> {
        self.inner.snapshot()
    }
    fn apply(&mut self, revision: u64, mutation: Mutation) -> Result<StorageCommit, StorageError> {
        if let Some(signal) = self.entered.take() {
            let _ = signal.send(());
            self.release.recv_timeout(Duration::from_secs(10)).unwrap();
        }
        self.inner.apply(revision, mutation)
    }
}

#[tokio::test]
async fn bounded_queue_rejects_overload_and_readers_do_not_wait_for_storage() {
    let scratch = Scratch::new();
    let (repo, source) = scratch.seed();
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let coordinator = PolicyCoordinator::start(
        GateRepo {
            inner: repo,
            entered: Some(entered_tx),
            release: release_rx,
        },
        PolicyOptions {
            queue_capacity: 1,
            ..PolicyOptions::default()
        },
    )
    .await
    .unwrap();
    let first_client = coordinator.handle();
    let first =
        tokio::spawn(async move { first_client.save(2, import(source, "one.example")).await });
    bounded(entered_rx).await.unwrap();
    assert_eq!(coordinator.reader().current().unwrap().revision(), 2);
    let queued_client = coordinator.handle();
    let mut queued = Box::pin(queued_client.save(3, import(source, "two.example")));
    // Poll once to enqueue without waiting for the deliberately blocked writer.
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(queued.as_mut().poll(cx).is_pending()))
            .await
    );
    assert_eq!(
        coordinator
            .handle()
            .save(4, import(source, "three.example"))
            .await
            .unwrap_err(),
        PolicyError::Busy
    );
    release_tx.send(()).unwrap();
    bounded(first).await.unwrap().unwrap();
    bounded(queued).await.unwrap();
    let current = coordinator.reader().current().unwrap();
    assert!(domain(&current, "one.example"));
    assert!(domain(&current, "two.example"));
    assert!(!domain(&current, "three.example"));
    coordinator.shutdown().await.unwrap();
}

#[tokio::test]
async fn accepted_save_survives_caller_cancellation_and_is_published() {
    let scratch = Scratch::new();
    let (repo, source) = scratch.seed();
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let coordinator = PolicyCoordinator::start(
        GateRepo {
            inner: repo,
            entered: Some(entered_tx),
            release: release_rx,
        },
        PolicyOptions::default(),
    )
    .await
    .unwrap();
    let mut reader = coordinator.reader();
    let writer = coordinator.handle();
    let save =
        tokio::spawn(async move { writer.save(2, import(source, "committed.example")).await });
    bounded(entered_rx).await.unwrap();
    save.abort();
    let _ = save.await;
    release_tx.send(()).unwrap();
    let updated = bounded(reader.changed()).await.unwrap();
    assert_eq!(updated.revision(), 3);
    assert!(domain(&updated, "committed.example"));
    coordinator.shutdown().await.unwrap();
}

struct Activator {
    entered: Mutex<Option<oneshot::Sender<()>>>,
    release: Notify,
    gated: AtomicBool,
    fail: AtomicBool,
}
impl PolicyActivation for Activator {
    fn activate(
        &self,
        _previous: Arc<PolicySnapshot>,
        _candidate: Arc<PolicySnapshot>,
    ) -> PolicyFuture<'_, Result<(), ActivationError>> {
        Box::pin(async move {
            if let Some(sender) = self.entered.lock().unwrap().take() {
                let _ = sender.send(());
            }
            if self.gated.load(Ordering::SeqCst) {
                self.release.notified().await;
            }
            if self.fail.load(Ordering::SeqCst) {
                Err(ActivationError)
            } else {
                Ok(())
            }
        })
    }
}
fn activator(gated: bool, fail: bool) -> (Arc<Activator>, oneshot::Receiver<()>) {
    let (sender, receiver) = oneshot::channel();
    (
        Arc::new(Activator {
            entered: Mutex::new(Some(sender)),
            release: Notify::new(),
            gated: AtomicBool::new(gated),
            fail: AtomicBool::new(fail),
        }),
        receiver,
    )
}

#[tokio::test]
async fn success_waits_for_activation_acknowledgement_after_durable_commit() {
    let scratch = Scratch::new();
    let (repo, source) = scratch.seed();
    let (hook, entered) = activator(true, false);
    let coordinator = PolicyCoordinator::start(
        repo,
        PolicyOptions {
            activators: vec![hook.clone()],
            ..PolicyOptions::default()
        },
    )
    .await
    .unwrap();
    let writer = coordinator.handle();
    let save = tokio::spawn(async move { writer.save(2, import(source, "new.example")).await });
    bounded(entered).await.unwrap();
    assert!(!save.is_finished());
    let fault = coordinator.reader().current().unwrap_err();
    assert_eq!(fault.revision, 3);
    assert_eq!(fault.reason, UnavailableReason::Activating);
    assert_eq!(
        SqliteRepository::open_read_only(scratch.db())
            .unwrap()
            .snapshot()
            .unwrap()
            .revision,
        3
    );
    hook.release.notify_one();
    assert_eq!(bounded(save).await.unwrap().unwrap().snapshot.revision(), 3);
    assert!(domain(
        &coordinator.reader().current().unwrap(),
        "new.example"
    ));
    coordinator.shutdown().await.unwrap();
}

#[tokio::test]
async fn committed_activation_failure_fails_closed_and_recovers_durable_state() {
    let scratch = Scratch::new();
    let (repo, source) = scratch.seed();
    let (hook, _) = activator(false, true);
    let coordinator = PolicyCoordinator::start(
        repo,
        PolicyOptions {
            activators: vec![hook.clone()],
            ..PolicyOptions::default()
        },
    )
    .await
    .unwrap();
    let writer = coordinator.handle();
    assert_eq!(
        writer
            .save(2, import(source, "https://secure.example/ads"))
            .await
            .unwrap_err(),
        PolicyError::CommittedNotActive { revision: 3 }
    );
    let fault = coordinator.reader().current().unwrap_err();
    assert_eq!(fault.reason, UnavailableReason::CommittedNotActive);
    assert_eq!(fault.revision, 3);
    assert_eq!(
        writer
            .save(3, import(source, "blocked.example"))
            .await
            .unwrap_err(),
        PolicyError::Unavailable { revision: 3 }
    );
    hook.fail.store(false, Ordering::SeqCst);
    let restored = coordinator.recover().await.unwrap();
    assert_eq!(restored.revision(), 3);
    assert!(inspected(&restored, "secure.example"));
    assert!(!domain(&restored, "blocked.example"));
    assert!(
        writer
            .save(3, import(source, "after.example"))
            .await
            .is_ok()
    );
    coordinator.shutdown().await.unwrap();
}

#[tokio::test]
async fn activation_deadline_does_not_acknowledge_inactive_commit() {
    let scratch = Scratch::new();
    let (repo, source) = scratch.seed();
    let (hook, _) = activator(true, false);
    let coordinator = PolicyCoordinator::start(
        repo,
        PolicyOptions {
            activators: vec![hook],
            activation_timeout: Duration::from_millis(20),
            ..PolicyOptions::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        bounded(
            coordinator
                .handle()
                .save(2, import(source, "timeout.example"))
        )
        .await
        .unwrap_err(),
        PolicyError::CommittedNotActive { revision: 3 }
    );
    assert!(coordinator.reader().current().is_err());
    coordinator.shutdown().await.unwrap();
}

#[tokio::test]
async fn restart_restores_durable_policy_and_shutdown_stops_new_requests() {
    let scratch = Scratch::new();
    let (repo, source) = scratch.seed();
    let coordinator = PolicyCoordinator::start(repo, PolicyOptions::default())
        .await
        .unwrap();
    coordinator
        .handle()
        .save(
            2,
            import(source, "blocked.example\nhttps://secure.example/ads"),
        )
        .await
        .unwrap();
    let reader = coordinator.reader();
    let writer = coordinator.handle();
    coordinator.shutdown().await.unwrap();
    assert_eq!(
        reader.current().unwrap_err().reason,
        UnavailableReason::Stopped
    );
    assert_eq!(
        writer
            .save(3, import(source, "stopped.example"))
            .await
            .unwrap_err(),
        PolicyError::Stopped
    );
    let restarted = PolicyCoordinator::open(scratch.db(), PolicyOptions::default())
        .await
        .unwrap();
    let current = restarted.reader().current().unwrap();
    assert_eq!(current.revision(), 3);
    assert!(domain(&current, "blocked.example"));
    assert!(inspected(&current, "secure.example"));
    restarted.shutdown().await.unwrap();
}

struct PanicAfterCommit(SqliteRepository);
impl BlocklistRepository for PanicAfterCommit {
    fn snapshot(&mut self) -> Result<RepositorySnapshot, StorageError> {
        self.0.snapshot()
    }
    fn apply(&mut self, revision: u64, mutation: Mutation) -> Result<StorageCommit, StorageError> {
        let _committed = self.0.apply(revision, mutation)?;
        panic!("injected lost worker after commit")
    }
}
#[tokio::test]
async fn worker_crash_is_unknown_outcome_and_readers_fail_closed_until_restart() {
    let scratch = Scratch::new();
    let (repo, source) = scratch.seed();
    let coordinator = PolicyCoordinator::start(PanicAfterCommit(repo), PolicyOptions::default())
        .await
        .unwrap();
    assert_eq!(
        coordinator
            .handle()
            .save(2, import(source, "durable.example"))
            .await
            .unwrap_err(),
        PolicyError::OutcomeUnknown
    );
    assert_eq!(
        coordinator.reader().current().unwrap_err().reason,
        UnavailableReason::Stopped
    );
    assert!(coordinator.shutdown().await.is_err());
    let restarted = PolicyCoordinator::open(scratch.db(), PolicyOptions::default())
        .await
        .unwrap();
    assert!(domain(
        &restarted.reader().current().unwrap(),
        "durable.example"
    ));
    restarted.shutdown().await.unwrap();
}

#[tokio::test]
async fn invalid_options_and_oversized_requests_are_rejected_without_side_effects() {
    let scratch = Scratch::new();
    let (repo, source) = scratch.seed();
    assert!(matches!(
        PolicyCoordinator::start(
            repo,
            PolicyOptions {
                queue_capacity: 0,
                ..PolicyOptions::default()
            }
        )
        .await,
        Err(PolicyError::InvalidOptions)
    ));
    let coordinator = PolicyCoordinator::open(scratch.db(), PolicyOptions::default())
        .await
        .unwrap();
    let before = coordinator.reader().current().unwrap();
    assert_eq!(
        coordinator
            .handle()
            .save(
                2,
                import(source, &"#".repeat(nullgate_core::MAX_IMPORT_BYTES + 1))
            )
            .await
            .unwrap_err(),
        PolicyError::Storage(StorageError::ImportTooLarge)
    );
    assert!(Arc::ptr_eq(
        &before,
        &coordinator.reader().current().unwrap()
    ));
    coordinator.shutdown().await.unwrap();
}

#[tokio::test]
async fn publication_survives_zero_receivers_and_watch_coalesces_complete_snapshots() {
    let scratch = Scratch::new();
    let (mut repo, source) = scratch.seed();
    let initial = PolicySnapshot::from_repository(repo.snapshot().unwrap()).unwrap();
    let (mut publisher, reader) = nullgate_core::policy_channel(initial);
    drop(reader);
    let (next, _) = PolicySnapshot::from_commit(
        repo.apply(
            2,
            import(source, "domain.example\nhttps://selected.example/ads"),
        )
        .unwrap(),
    );
    publisher.publish(Arc::new(next));
    let mut late = publisher.subscribe();
    assert_eq!(late.current().unwrap().revision(), 3);
    let (next, _) = PolicySnapshot::from_commit(
        repo.apply(
            3,
            Mutation::ReplaceEntries {
                source_id: source,
                text: "replacement.example\nhttp://selected.example/ads".into(),
                at: 2,
            },
        )
        .unwrap(),
    );
    publisher.publish(Arc::new(next));
    let snapshot = bounded(late.changed()).await.unwrap();
    assert_eq!(snapshot.revision(), 4);
    assert!(domain(&snapshot, "replacement.example"));
    assert!(!domain(&snapshot, "domain.example"));
    assert!(!inspected(&snapshot, "selected.example"));
    drop(publisher);
    assert_eq!(
        late.current().unwrap_err().reason,
        UnavailableReason::Stopped
    );
}

#[tokio::test]
async fn readonly_and_busy_storage_rejections_do_not_change_publication() {
    let scratch = Scratch::new();
    let (repo, source) = scratch.seed();
    drop(repo);
    let read_only = SqliteRepository::open_read_only(scratch.db()).unwrap();
    let coordinator = PolicyCoordinator::start(read_only, PolicyOptions::default())
        .await
        .unwrap();
    let before = coordinator.reader().current().unwrap();
    assert_eq!(
        coordinator
            .handle()
            .save(2, import(source, "rejected.example"))
            .await
            .unwrap_err(),
        PolicyError::Storage(StorageError::ReadOnly)
    );
    assert!(Arc::ptr_eq(
        &before,
        &coordinator.reader().current().unwrap()
    ));
    coordinator.shutdown().await.unwrap();
    let coordinator = PolicyCoordinator::open(scratch.db(), PolicyOptions::default())
        .await
        .unwrap();
    let before = coordinator.reader().current().unwrap();
    let lock = rusqlite::Connection::open(scratch.db()).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(
        coordinator
            .handle()
            .save(2, import(source, "busy.example"))
            .await
            .unwrap_err(),
        PolicyError::Storage(StorageError::Busy)
    );
    assert!(Arc::ptr_eq(
        &before,
        &coordinator.reader().current().unwrap()
    ));
    lock.execute_batch("ROLLBACK").unwrap();
    coordinator.shutdown().await.unwrap();
}

struct PanickingActivation;
impl PolicyActivation for PanickingActivation {
    fn activate(
        &self,
        _previous: Arc<PolicySnapshot>,
        _candidate: Arc<PolicySnapshot>,
    ) -> PolicyFuture<'_, Result<(), ActivationError>> {
        Box::pin(async { panic!("injected activation panic") })
    }
}
#[tokio::test]
async fn activation_panic_reports_committed_revision_without_losing_the_worker() {
    let scratch = Scratch::new();
    let (repo, source) = scratch.seed();
    let coordinator = PolicyCoordinator::start(
        repo,
        PolicyOptions {
            activators: vec![Arc::new(PanickingActivation)],
            ..PolicyOptions::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        coordinator
            .handle()
            .save(2, import(source, "saved.example"))
            .await
            .unwrap_err(),
        PolicyError::CommittedNotActive { revision: 3 }
    );
    assert_eq!(
        coordinator.reader().current().unwrap_err().reason,
        UnavailableReason::CommittedNotActive
    );
    assert_eq!(
        coordinator.recover().await.unwrap_err(),
        PolicyError::CommittedNotActive { revision: 3 }
    );
    coordinator.shutdown().await.unwrap();
}

#[tokio::test]
async fn dropping_owner_stops_admissions_even_with_retained_handles() {
    let scratch = Scratch::new();
    let (repo, source) = scratch.seed();
    let coordinator = PolicyCoordinator::start(repo, PolicyOptions::default())
        .await
        .unwrap();
    let writer = coordinator.handle();
    let mut reader = coordinator.reader();
    drop(coordinator);
    assert_eq!(
        bounded(reader.changed()).await.unwrap_err().reason,
        UnavailableReason::Stopped
    );
    let error = bounded(writer.save(2, import(source, "must-not-save.example")))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        PolicyError::Stopped | PolicyError::OutcomeUnknown
    ));
    assert_eq!(
        SqliteRepository::open_read_only(scratch.db())
            .unwrap()
            .snapshot()
            .unwrap()
            .revision,
        2
    );
}

#[tokio::test]
async fn corrupt_startup_state_is_not_reported_ready() {
    let scratch = Scratch::new();
    std::fs::write(scratch.db(), b"not a sqlite database").unwrap();
    assert!(matches!(
        bounded(PolicyCoordinator::open(
            scratch.db(),
            PolicyOptions::default()
        ))
        .await,
        Err(PolicyError::Storage(StorageError::Corrupt))
    ));
}

struct RecoveryFaultRepo {
    inner: SqliteRepository,
    fault: Arc<std::sync::atomic::AtomicU8>,
}
impl BlocklistRepository for RecoveryFaultRepo {
    fn snapshot(&mut self) -> Result<RepositorySnapshot, StorageError> {
        match self.fault.load(Ordering::SeqCst) {
            1 => Err(StorageError::Database),
            2 => panic!("injected recovery read panic"),
            _ => self.inner.snapshot(),
        }
    }
    fn apply(&mut self, revision: u64, mutation: Mutation) -> Result<StorageCommit, StorageError> {
        self.inner.apply(revision, mutation)
    }
}
#[tokio::test]
async fn recovery_read_errors_stay_unavailable_and_read_panics_stop_before_reply() {
    let scratch = Scratch::new();
    let (repo, source) = scratch.seed();
    let (hook, _) = activator(false, true);
    let fault = Arc::new(std::sync::atomic::AtomicU8::new(0));
    let coordinator = PolicyCoordinator::start(
        RecoveryFaultRepo {
            inner: repo,
            fault: fault.clone(),
        },
        PolicyOptions {
            activators: vec![hook.clone()],
            ..PolicyOptions::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        coordinator
            .handle()
            .save(2, import(source, "saved.example"))
            .await
            .unwrap_err(),
        PolicyError::CommittedNotActive { revision: 3 }
    );
    fault.store(1, Ordering::SeqCst);
    assert_eq!(
        coordinator.recover().await.unwrap_err(),
        PolicyError::Storage(StorageError::Database)
    );
    assert_eq!(
        coordinator.reader().current().unwrap_err().reason,
        UnavailableReason::CommittedNotActive
    );
    fault.store(0, Ordering::SeqCst);
    hook.fail.store(false, Ordering::SeqCst);
    assert_eq!(coordinator.recover().await.unwrap().revision(), 3);
    fault.store(2, Ordering::SeqCst);
    assert_eq!(
        coordinator.recover().await.unwrap_err(),
        PolicyError::OutcomeUnknown
    );
    assert_eq!(
        coordinator.reader().current().unwrap_err().reason,
        UnavailableReason::Stopped
    );
    assert!(coordinator.shutdown().await.is_err());
}

#[tokio::test]
async fn shutdown_drains_an_active_write_and_an_already_queued_write_in_order() {
    let scratch = Scratch::new();
    let (repo, source) = scratch.seed();
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let coordinator = PolicyCoordinator::start(
        GateRepo {
            inner: repo,
            entered: Some(entered_tx),
            release: release_rx,
        },
        PolicyOptions {
            queue_capacity: 2,
            ..PolicyOptions::default()
        },
    )
    .await
    .unwrap();
    let writer = coordinator.handle();
    let first_client = writer.clone();
    let first =
        tokio::spawn(async move { first_client.save(2, import(source, "first.example")).await });
    bounded(entered_rx).await.unwrap();
    let mut queued = Box::pin(writer.save(3, import(source, "queued.example")));
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(queued.as_mut().poll(cx).is_pending()))
            .await
    );
    let mut shutdown = Box::pin(coordinator.shutdown());
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(shutdown.as_mut().poll(cx).is_pending()))
            .await
    );
    release_tx.send(()).unwrap();
    assert_eq!(
        bounded(first).await.unwrap().unwrap().snapshot.revision(),
        3
    );
    assert_eq!(bounded(queued).await.unwrap().snapshot.revision(), 4);
    bounded(shutdown).await.unwrap();
    let persisted = SqliteRepository::open(scratch.db())
        .unwrap()
        .snapshot()
        .unwrap();
    let snapshot = PolicySnapshot::from_repository(persisted).unwrap();
    assert_eq!(snapshot.revision(), 4);
    assert!(domain(&snapshot, "first.example"));
    assert!(domain(&snapshot, "queued.example"));
    assert_eq!(
        writer
            .save(4, import(source, "late.example"))
            .await
            .unwrap_err(),
        PolicyError::Stopped
    );
}
