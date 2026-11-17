use nullgate_core::{AuthRepository, ExternalLogin, Role};
fn path() -> std::path::PathBuf {
    let id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "nullgate-external-{}-{id}/state.sqlite3",
        std::process::id()
    ))
}
#[test]
fn external_sessions_are_context_bound_durable_expiring_and_revocable() {
    let path = path();
    let mut repo = AuthRepository::open(&path).unwrap();
    let login = ExternalLogin {
        issuer: "https://idp.invalid/realms/test".into(),
        subject: "subject-1".into(),
        display_name: "Alice".into(),
        role: Role::Viewer,
        context: "a".repeat(64),
    };
    repo.external_session(&login, &[1; 32], None, 100, 200)
        .unwrap();
    assert_eq!(
        repo.external_identity(&[1; 32], 101, &login.context)
            .unwrap()
            .unwrap()
            .role,
        Role::Viewer
    );
    assert!(
        repo.external_identity(&[1; 32], 101, &"b".repeat(64))
            .unwrap()
            .is_none()
    );
    assert!(repo.local_identity(&[1; 32], 101).unwrap().is_none());
    drop(repo);
    let mut repo = AuthRepository::open(&path).unwrap();
    assert!(
        repo.external_identity(&[1; 32], 200, &login.context)
            .unwrap()
            .is_none()
    );
    repo.revoke(&[1; 32]).unwrap();
    assert!(
        repo.external_identity(&[1; 32], 101, &login.context)
            .unwrap()
            .is_none()
    );
    drop(repo);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
#[test]
fn verified_role_change_revokes_prior_sessions_without_merging_local_identity() {
    let path = path();
    let mut repo = AuthRepository::open(&path).unwrap();
    let mut login = ExternalLogin {
        issuer: "https://idp.invalid".into(),
        subject: "subject-1".into(),
        display_name: "admin".into(),
        role: Role::Viewer,
        context: "a".repeat(64),
    };
    repo.external_session(&login, &[1; 32], None, 100, 200)
        .unwrap();
    login.role = Role::Administrator;
    repo.external_session(&login, &[2; 32], None, 110, 210)
        .unwrap();
    assert!(
        repo.external_identity(&[1; 32], 111, &login.context)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        repo.external_identity(&[2; 32], 111, &login.context)
            .unwrap()
            .unwrap()
            .role,
        Role::Administrator
    );
    repo.revoke_external(&login.issuer, &login.subject).unwrap();
    assert!(
        repo.external_identity(&[2; 32], 111, &login.context)
            .unwrap()
            .is_none()
    );
    drop(repo);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn disabled_external_accounts_remain_disabled_after_provider_relogin() {
    let path = path();
    let mut repo = AuthRepository::open(&path).unwrap();
    let login = ExternalLogin {
        issuer: "https://idp.invalid".into(),
        subject: "disabled-subject".into(),
        display_name: "Disabled".into(),
        role: Role::Viewer,
        context: "a".repeat(64),
    };
    repo.external_session(&login, &[1; 32], None, 100, 200)
        .unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute("UPDATE auth_users SET enabled=0", [])
        .unwrap();
    assert!(
        repo.external_identity(&[1; 32], 101, &login.context)
            .unwrap()
            .is_none()
    );
    assert!(
        repo.external_session(&login, &[2; 32], None, 110, 210)
            .is_err()
    );
    drop(connection);
    drop(repo);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn authentication_v1_migration_preserves_local_accounts_sessions_and_policy_revision() {
    let path = path();
    let mut repo = AuthRepository::open(&path).unwrap();
    let hash = "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$ZmFrZS1maXh0dXJl";
    repo.insert_user(
        "local-admin",
        hash,
        Role::Administrator,
        nullgate_core::AccountCreation::FirstAdministrator,
    )
    .unwrap();
    let user = repo.user("local-admin").unwrap().unwrap();
    repo.create_session(&user, &[9; 32], None, 100, 200)
        .unwrap();
    drop(repo);
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch(
        "DROP TABLE auth_external_sessions;DROP TABLE auth_external;UPDATE auth_meta SET version=1",
    )
    .unwrap();
    drop(db);
    let repo = AuthRepository::open(&path).unwrap();
    assert_eq!(
        repo.local_identity(&[9; 32], 101).unwrap().unwrap().role,
        Role::Administrator
    );
    drop(repo);
    let mut rules = nullgate_core::SqliteRepository::open(&path).unwrap();
    use nullgate_core::BlocklistRepository;
    assert_eq!(rules.snapshot().unwrap().revision, 0);
    drop(rules);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
