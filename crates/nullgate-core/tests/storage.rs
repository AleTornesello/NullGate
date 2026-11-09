use nullgate_core::{
    AppConfig, AuthMode, BlocklistRepository, ImportOutcome, Mutation, RepositorySnapshot, Rule,
    SourceKind, SqliteRepository, StorageError, normalize_host, normalize_url,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "nullgate-storage-{}-{stamp}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn db(&self) -> PathBuf {
        self.0.join("state.sqlite3")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn apply(repo: &mut impl BlocklistRepository, mutation: Mutation) -> RepositorySnapshot {
    let revision = repo.snapshot().unwrap().revision;
    repo.apply(revision, mutation).unwrap().snapshot
}
fn list(repo: &mut impl BlocklistRepository, name: &str) -> i64 {
    let snapshot = apply(repo, Mutation::CreateList { name: name.into() });
    snapshot.lists.iter().find(|l| l.name == name).unwrap().id
}
fn source(repo: &mut impl BlocklistRepository, list_id: i64, kind: SourceKind) -> i64 {
    let snapshot = apply(repo, Mutation::AddSource { list_id, kind });
    snapshot
        .lists
        .iter()
        .find(|l| l.id == list_id)
        .unwrap()
        .sources
        .last()
        .unwrap()
        .id
}
fn import(
    repo: &mut impl BlocklistRepository,
    source_id: i64,
    text: &str,
    at: i64,
) -> RepositorySnapshot {
    apply(
        repo,
        Mutation::Import {
            source_id,
            text: text.into(),
            at,
        },
    )
}
fn sample() -> &'static str {
    include_str!("../../../config/nullgate.example.toml")
}

#[test]
fn named_mixed_lists_reports_and_settings_survive_restart() {
    let scratch = Scratch::new();
    let config_path = scratch.0.join("nullgate.toml");
    std::fs::write(&config_path, sample()).unwrap();
    let config = AppConfig::load(&config_path).unwrap();
    let mut repo = SqliteRepository::open(scratch.db()).unwrap();
    let id = list(&mut repo, "Mixed rules");
    let source_id = source(&mut repo, id, SourceKind::Manual);
    let revision = repo.snapshot().unwrap().revision;
    let commit = repo.apply(revision, Mutation::Import { source_id, text: "EXAMPLE.com.\nhttps://news.example/ads?x=ignored\nnot a rule\nexample.com\n# comment\n".into(), at: 123 }).unwrap();
    let report = commit.import_report.unwrap();
    assert_eq!(report.accepted.len(), 2);
    assert_eq!(report.malformed[0].line, 3);
    assert_eq!(report.duplicates.len(), 1);
    assert_eq!(report.ignored_lines, 1);
    assert!(
        commit
            .rules
            .blocks_domain(&normalize_host("example.com").unwrap())
    );
    assert!(
        !commit
            .rules
            .blocks_domain(&normalize_host("news.example").unwrap())
    );
    assert!(
        commit
            .rules
            .blocks_url(&normalize_url("https://news.example/ads").unwrap())
    );
    let before = commit.snapshot;
    drop(repo);
    let mut reopened = SqliteRepository::open(scratch.db()).unwrap();
    assert_eq!(reopened.snapshot().unwrap(), before);
    let stored = &before.lists[0].sources[0];
    let summary = stored.last_report.as_ref().unwrap();
    assert_eq!(
        (
            summary.accepted,
            summary.malformed,
            summary.duplicates,
            summary.added
        ),
        (2, 1, 1, 2)
    );
    assert_eq!(summary.diagnostics[0].line, 3);
    assert_eq!(
        (stored.last_attempt, stored.last_success),
        (Some(123), Some(123))
    );
    assert_eq!(AppConfig::load(&config_path).unwrap(), config);
    assert_eq!(
        config.database_path(),
        config.data_dir.join("nullgate.sqlite3")
    );
}

#[test]
fn source_replacement_preserves_manual_file_and_other_remote_memberships() {
    let scratch = Scratch::new();
    let mut repo = SqliteRepository::open(scratch.db()).unwrap();
    let id = list(&mut repo, "Sources");
    let manual = source(&mut repo, id, SourceKind::Manual);
    let file = source(
        &mut repo,
        id,
        SourceKind::File {
            filename: "local.txt".into(),
        },
    );
    let remote = source(
        &mut repo,
        id,
        SourceKind::Remote {
            url: "https://lists.example/list?version=1".into(),
        },
    );
    let other = source(
        &mut repo,
        id,
        SourceKind::Remote {
            url: "https://other.example/list".into(),
        },
    );
    import(&mut repo, manual, "shared.example\nmanual.example", 1);
    import(&mut repo, file, "file.example", 2);
    import(&mut repo, remote, "shared.example\nold.example", 3);
    import(&mut repo, other, "other.example", 4);
    let after = import(
        &mut repo,
        remote,
        "new.example\nmalformed rule\nnew.example",
        5,
    );
    let rules = after.compile().unwrap();
    for host in [
        "shared.example",
        "manual.example",
        "file.example",
        "new.example",
        "other.example",
    ] {
        assert!(
            rules.blocks_domain(&normalize_host(host).unwrap()),
            "{host}"
        );
    }
    assert!(!rules.blocks_domain(&normalize_host("old.example").unwrap()));
    let src = after.source(remote).unwrap();
    assert_eq!((src.last_attempt, src.last_success), (Some(5), Some(5)));
    assert_eq!(src.last_report.as_ref().unwrap().malformed, 1);
    let after = apply(&mut repo, Mutation::DeleteSource { source_id: remote });
    assert!(
        after
            .compile()
            .unwrap()
            .blocks_domain(&normalize_host("shared.example").unwrap())
    );
    assert!(
        !after
            .compile()
            .unwrap()
            .blocks_domain(&normalize_host("new.example").unwrap())
    );
}

#[test]
fn empty_invalid_and_failed_refreshes_keep_last_usable_source() {
    let scratch = Scratch::new();
    let mut repo = SqliteRepository::open(scratch.db()).unwrap();
    let id = list(&mut repo, "Remote");
    let src = source(
        &mut repo,
        id,
        SourceKind::Remote {
            url: "https://lists.example/rules".into(),
        },
    );
    import(&mut repo, src, "keep.example", 1);
    for (i, text) in ["", "# empty", "not valid"].into_iter().enumerate() {
        let after = import(&mut repo, src, text, i as i64 + 2);
        let stored = after.source(src).unwrap();
        assert_eq!(
            stored.last_report.as_ref().unwrap().outcome,
            ImportOutcome::NoValidRules
        );
        assert_eq!(stored.last_success, Some(1));
        assert_eq!(stored.entries.len(), 1);
    }
    let after = apply(
        &mut repo,
        Mutation::RecordFetchFailure {
            source_id: src,
            at: 10,
        },
    );
    assert_eq!(
        after
            .source(src)
            .unwrap()
            .last_report
            .as_ref()
            .unwrap()
            .outcome,
        ImportOutcome::FetchFailed
    );
    assert_eq!(after.source(src).unwrap().last_success, Some(1));
    assert!(
        after
            .compile()
            .unwrap()
            .blocks_domain(&normalize_host("keep.example").unwrap())
    );
    drop(repo);
    assert_eq!(
        SqliteRepository::open(scratch.db())
            .unwrap()
            .snapshot()
            .unwrap(),
        after
    );
}

#[test]
fn additive_imports_explicit_replacement_removal_clear_and_list_crud() {
    let scratch = Scratch::new();
    let mut repo = SqliteRepository::open(scratch.db()).unwrap();
    let id = list(&mut repo, "Original");
    let src = source(&mut repo, id, SourceKind::Manual);
    import(&mut repo, src, "one.example", 1);
    let after = import(&mut repo, src, "ONE.example.\ntwo.example", 2);
    assert_eq!(after.source(src).unwrap().entries.len(), 2);
    assert_eq!(
        after
            .source(src)
            .unwrap()
            .last_report
            .as_ref()
            .unwrap()
            .added,
        1
    );
    let after = import(&mut repo, src, "", 3);
    assert_eq!(after.source(src).unwrap().entries.len(), 2);
    let after = apply(
        &mut repo,
        Mutation::ReplaceEntries {
            source_id: src,
            text: "three.example".into(),
            at: 4,
        },
    );
    assert_eq!(after.source(src).unwrap().entries.len(), 1);
    let before = after.clone();
    assert_eq!(
        repo.apply(
            after.revision,
            Mutation::ReplaceEntries {
                source_id: src,
                text: "not valid".into(),
                at: 5
            }
        )
        .unwrap_err(),
        StorageError::NoValidRules
    );
    assert_eq!(repo.snapshot().unwrap(), before);
    let after = apply(
        &mut repo,
        Mutation::RemoveRule {
            source_id: src,
            rule: Rule::parse("three.example").unwrap(),
        },
    );
    assert!(after.source(src).unwrap().entries.is_empty());
    import(&mut repo, src, "four.example", 6);
    let after = apply(&mut repo, Mutation::ClearSource { source_id: src });
    assert!(after.source(src).unwrap().entries.is_empty());
    let after = apply(
        &mut repo,
        Mutation::RenameList {
            list_id: id,
            name: "Renamed".into(),
        },
    );
    assert_eq!(after.lists[0].name, "Renamed");
    let after = apply(&mut repo, Mutation::DeleteList { list_id: id });
    assert!(after.lists.is_empty());
    let next = list(&mut repo, "Next");
    assert!(next > src);
}

#[test]
fn stale_mutations_and_duplicate_names_leave_state_intact() {
    let scratch = Scratch::new();
    let mut repo = SqliteRepository::open(scratch.db()).unwrap();
    let before = repo.snapshot().unwrap();
    list(&mut repo, "Existing");
    let mut other = SqliteRepository::open(scratch.db()).unwrap();
    let after = other.snapshot().unwrap();
    assert!(matches!(
        other.apply(
            before.revision,
            Mutation::CreateList {
                name: "Stale".into()
            }
        ),
        Err(StorageError::Conflict { .. })
    ));
    for name in ["", " Existing", "bad\nname", "Existing"] {
        assert!(
            other
                .apply(after.revision, Mutation::CreateList { name: name.into() })
                .is_err()
        );
        assert_eq!(other.snapshot().unwrap(), after);
    }
    assert!(
        other
            .apply(after.revision, Mutation::DeleteList { list_id: 999 })
            .is_err()
    );
    assert_eq!(repo.snapshot().unwrap(), after);
}

#[test]
fn mid_write_abort_rolls_back_entries_report_and_revision() {
    let scratch = Scratch::new();
    let mut repo = SqliteRepository::open(scratch.db()).unwrap();
    let id = list(&mut repo, "Rollback");
    let src = source(&mut repo, id, SourceKind::Manual);
    let before = import(&mut repo, src, "keep.example", 1);
    let connection = rusqlite::Connection::open(scratch.db()).unwrap();
    connection.execute_batch("CREATE TRIGGER fail_entry BEFORE INSERT ON entries WHEN NEW.input = 'reject.example' BEGIN SELECT RAISE(ABORT, 'injected write failure'); END;").unwrap();
    assert!(
        repo.apply(
            before.revision,
            Mutation::ReplaceEntries {
                source_id: src,
                text: "first.example\nreject.example".into(),
                at: 2
            }
        )
        .is_err()
    );
    assert_eq!(repo.snapshot().unwrap(), before);
    drop(repo);
    assert_eq!(
        SqliteRepository::open(scratch.db())
            .unwrap()
            .snapshot()
            .unwrap(),
        before
    );
}

#[test]
fn readonly_and_busy_write_failures_preserve_existing_state() {
    let scratch = Scratch::new();
    let mut repo = SqliteRepository::open(scratch.db()).unwrap();
    list(&mut repo, "Existing");
    let before = repo.snapshot().unwrap();
    let mut read_only = SqliteRepository::open_read_only(scratch.db()).unwrap();
    assert_eq!(
        read_only
            .apply(
                before.revision,
                Mutation::CreateList {
                    name: "Forbidden".into()
                }
            )
            .unwrap_err(),
        StorageError::ReadOnly
    );
    let lock = rusqlite::Connection::open(scratch.db()).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(
        repo.apply(
            before.revision,
            Mutation::CreateList {
                name: "Busy".into()
            }
        )
        .unwrap_err(),
        StorageError::Busy
    );
    lock.execute_batch("ROLLBACK").unwrap();
    assert_eq!(repo.snapshot().unwrap(), before);
}

#[test]
fn invalid_source_and_oversized_or_non_utf8_imports_never_commit() {
    let scratch = Scratch::new();
    let mut repo = SqliteRepository::open(scratch.db()).unwrap();
    let id = list(&mut repo, "Validate");
    let src = source(&mut repo, id, SourceKind::Manual);
    let before = repo.snapshot().unwrap();
    for url in [
        "ftp://lists.example/a",
        "https://user:secret@lists.example/a",
        "https://lists.example/#fragment",
    ] {
        assert!(
            repo.apply(
                before.revision,
                Mutation::AddSource {
                    list_id: id,
                    kind: SourceKind::Remote { url: url.into() }
                }
            )
            .is_err()
        );
    }
    assert_eq!(
        repo.apply(
            before.revision,
            Mutation::Import {
                source_id: src,
                text: "#".repeat(nullgate_core::MAX_IMPORT_BYTES + 1),
                at: 1
            }
        )
        .unwrap_err(),
        StorageError::ImportTooLarge
    );
    assert_eq!(
        Mutation::import_bytes(src, &[0xff], 1).unwrap_err(),
        StorageError::InvalidUtf8
    );
    assert_eq!(
        repo.apply(
            before.revision,
            Mutation::Import {
                source_id: src,
                text: "valid.example".into(),
                at: -1
            }
        )
        .unwrap_err(),
        StorageError::InvalidTimestamp
    );
    assert_eq!(repo.snapshot().unwrap(), before);
}

#[test]
fn persisted_unicode_rules_and_safe_report_summaries_round_trip() {
    let scratch = Scratch::new();
    let mut repo = SqliteRepository::open(scratch.db()).unwrap();
    let id = list(&mut repo, "Unicode");
    let src = source(&mut repo, id, SourceKind::Manual);
    let unicode = format!("https://example.com/{}", "é".repeat(3000));
    let text = format!("{unicode}?token=discard\n{}", "not valid\n".repeat(1100));
    let after = import(&mut repo, src, &text, 1);
    let summary = after.source(src).unwrap().last_report.as_ref().unwrap();
    assert_eq!(summary.malformed, 1100);
    assert_eq!(summary.diagnostics.len(), 1000);
    let connection = rusqlite::Connection::open(scratch.db()).unwrap();
    let stored: String = connection
        .query_row("SELECT input FROM entries", [], |r| r.get(0))
        .unwrap();
    assert!(!stored.contains("token="));
    drop(repo);
    let after_restart = SqliteRepository::open(scratch.db())
        .unwrap()
        .snapshot()
        .unwrap();
    assert_eq!(after_restart, after);
    assert!(
        after_restart
            .compile()
            .unwrap()
            .blocks_url(&normalize_url(&unicode).unwrap())
    );
}

#[test]
fn unsupported_schema_and_corrupt_rules_are_rejected_without_reset() {
    let scratch = Scratch::new();
    let mut repo = SqliteRepository::open(scratch.db()).unwrap();
    let id = list(&mut repo, "Persist");
    let src = source(&mut repo, id, SourceKind::Manual);
    import(&mut repo, src, "keep.example", 1);
    drop(repo);
    let db = rusqlite::Connection::open(scratch.db()).unwrap();
    db.pragma_update(None, "user_version", 99).unwrap();
    assert!(matches!(
        SqliteRepository::open(scratch.db()),
        Err(StorageError::UnsupportedSchema(99))
    ));
    db.pragma_update(None, "user_version", 1).unwrap();
    db.execute("UPDATE entries SET input = 'malformed rule'", [])
        .unwrap();
    assert!(matches!(
        SqliteRepository::open(scratch.db()),
        Err(StorageError::Corrupt)
    ));
    assert_eq!(
        db.query_row("SELECT count(*) FROM lists", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn example_config_defaults_and_relative_paths_are_nonsecret() {
    let config =
        AppConfig::parse(sample(), Path::new("/tmp/nullgate/config/example.toml")).unwrap();
    assert_eq!(config.schema_version, 1);
    assert_eq!(config.auth, AuthMode::Local);
    assert_eq!(config.data_dir, Path::new("/tmp/nullgate/config/../data"));
    assert_eq!(
        (config.dns.attempt_timeout_ms, config.dns.total_timeout_ms),
        (2000, 5000)
    );
    assert!(!config.dns.upstreams.is_empty());
    assert!(config.dns.udp_listen.port() >= 1024);
    assert!(config.http.listen.port() >= 1024);
    assert!(config.web.listen.port() >= 1024);
    let no_auth = AppConfig::parse(
        &sample().replace("mode = \"local\"", "mode = \"none\""),
        Path::new("/tmp/config.toml"),
    )
    .unwrap();
    assert_eq!(no_auth.auth, AuthMode::None);
    let oidc = AppConfig::parse(
        &sample().replace("mode = \"local\"", "mode = \"oidc\""),
        Path::new("/tmp/config.toml"),
    )
    .unwrap();
    assert_eq!(oidc.auth, AuthMode::Oidc);
    let without_auth = sample().split("[auth]").next().unwrap();
    assert_eq!(
        AppConfig::parse(without_auth, Path::new("/tmp/config.toml"))
            .unwrap()
            .auth,
        AuthMode::Local
    );
}

#[test]
fn malformed_configuration_reports_keys_without_echoing_sensitive_values() {
    for (text, field) in [
        (
            sample().replace("schema_version = 1", "schema_version = 99"),
            "schema_version",
        ),
        (sample().replace("udp_listen =", "udp_litsen ="), "dns"),
        (
            sample().replace("127.0.0.1:5353", "secret-invalid-address"),
            "dns",
        ),
        (
            sample().replace(
                "upstreams = [\"1.1.1.1:53\", \"9.9.9.9:53\"]",
                "upstreams = []",
            ),
            "dns.upstreams",
        ),
        (
            sample().replace("mode = \"local\"", "mode = \"secret-invalid-mode\""),
            "auth",
        ),
        (sample().replace("../data", ""), "data_dir"),
        (
            format!("{}\npassword = \"private-value\"", sample()),
            "auth",
        ),
    ] {
        let error = AppConfig::parse(&text, Path::new("/tmp/nullgate.toml")).unwrap_err();
        assert!(error.key.starts_with(field), "{field}: {error:?}");
        let safe = format!("{error:?} {error}");
        assert!(!safe.contains("secret-invalid"));
        assert!(!safe.contains("private-value"));
    }
    let error = AppConfig::parse("schema_version = [secret", Path::new("/tmp/c.toml")).unwrap_err();
    assert!(error.line.is_some());
    assert!(!format!("{error}").contains("secret"));
    assert!(AppConfig::parse(&"#".repeat(65_537), Path::new("/tmp/c.toml")).is_err());
}

#[test]
fn invalid_listener_overlap_timeouts_and_public_cleartext_are_rejected() {
    for text in [
        sample().replace("127.0.0.1:8081", "127.0.0.1:8080"),
        sample().replace("127.0.0.1:8081", "0.0.0.0:8081"),
        sample().replace("1.1.1.1:53", "0.0.0.0:53"),
        sample().replace("1.1.1.1:53", "1.1.1.1:0"),
        sample().replace("total_timeout_ms = 5000", "total_timeout_ms = 0"),
        sample().replace("attempt_timeout_ms = 2000", "attempt_timeout_ms = 6000"),
    ] {
        assert!(
            AppConfig::parse(&text, Path::new("/tmp/c.toml")).is_err(),
            "{text}"
        );
    }
    let text = sample().replace("127.0.0.1:8081", "0.0.0.0:8081").replace(
        "[auth]",
        "[web.tls]\ncertificate_file = 'cert.pem'\nprivate_key_file = 'key.pem'\n\n[auth]",
    );
    let config = AppConfig::parse(&text, Path::new("/tmp/c.toml")).unwrap();
    assert_eq!(
        config.web.tls.unwrap().private_key_file,
        Path::new("/tmp/key.pem")
    );
}

#[test]
fn unknown_persisted_source_fields_are_rejected_as_corruption() {
    let scratch = Scratch::new();
    let mut repo = SqliteRepository::open(scratch.db()).unwrap();
    let id = list(&mut repo, "Strict provenance");
    source(&mut repo, id, SourceKind::Manual);
    drop(repo);
    let db = rusqlite::Connection::open(scratch.db()).unwrap();
    db.execute(
        "UPDATE sources SET kind = ?1",
        ["type = 'manual'\nunexpected = 'ignored'"],
    )
    .unwrap();
    assert!(matches!(
        SqliteRepository::open(scratch.db()),
        Err(StorageError::Corrupt)
    ));
}

#[test]
fn candidate_capacity_failure_preserves_previous_memberships_and_report() {
    let scratch = Scratch::new();
    let mut repo = SqliteRepository::open(scratch.db()).unwrap();
    let id = list(&mut repo, "Capacity");
    let src = source(&mut repo, id, SourceKind::Manual);
    let before = import(&mut repo, src, "keep.example", 1);
    let text = (0..nullgate_core::MAX_RULES)
        .map(|i| format!("d{i}.example\n"))
        .collect::<String>();
    assert_eq!(
        repo.apply(
            before.revision,
            Mutation::Import {
                source_id: src,
                text,
                at: 2
            }
        )
        .unwrap_err(),
        StorageError::Capacity
    );
    assert_eq!(repo.snapshot().unwrap(), before);
}

#[test]
fn missing_configuration_fields_name_the_exact_required_key_without_values() {
    let base = sample().replace("../data", "sensitive-data-value");
    let no_mode = base
        .lines()
        .filter(|line| !line.starts_with("mode = "))
        .collect::<Vec<_>>()
        .join("\n");
    let tls = base.replace(
        "[auth]",
        "[web.tls]\ncertificate_file = 'sensitive-certificate-value'\n\n[auth]",
    );
    for (text, key) in [
        (base.replace("schema_version = 1\n", ""), "schema_version"),
        (
            base.replace("udp_listen = \"127.0.0.1:5353\"\n", ""),
            "dns.udp_listen",
        ),
        (no_mode, "auth.mode"),
        (tls, "web.tls.private_key_file"),
    ] {
        let error = AppConfig::parse(&text, Path::new("/tmp/config.toml")).unwrap_err();
        assert_eq!(error.key, key);
        assert!(error.message.contains("Missing required"));
        assert!(error.line.is_some());
        let diagnostic = format!("{error} {error:?}");
        assert!(!diagnostic.contains("sensitive-data-value"));
        assert!(!diagnostic.contains("sensitive-certificate-value"));
    }
}
