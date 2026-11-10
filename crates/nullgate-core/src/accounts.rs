//! Blocking authentication storage, separate from policy revisions and snapshots.
use crate::{SqliteRepository, StorageError};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::Serialize;
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Administrator,
    Viewer,
}
impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Administrator => "administrator",
            Self::Viewer => "viewer",
        }
    }
    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "administrator" => Ok(Self::Administrator),
            "viewer" => Ok(Self::Viewer),
            _ => Err(StorageError::Corrupt),
        }
    }
}
#[derive(Clone, Serialize)]
pub struct Identity {
    pub user_id: Option<i64>,
    pub username: Option<String>,
    pub role: Role,
}
pub struct Account {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub role: Role,
    pub enabled: bool,
}
/// Storage callers are trusted; browser-facing services must obtain a live proof.
pub enum AccountCreation<'a> {
    FirstAdministrator,
    Session { digest: &'a [u8; 32], now: i64 },
    NoAuthentication,
}
pub struct AuthRepository {
    repo: SqliteRepository,
}
impl AuthRepository {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, StorageError> {
        let mut repo = SqliteRepository::open(path)?;
        let tx = repo
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS auth_meta(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL);INSERT OR IGNORE INTO auth_meta VALUES(1,1);CREATE TABLE IF NOT EXISTS auth_users(id INTEGER PRIMARY KEY,username TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('administrator','viewer')),enabled INTEGER NOT NULL CHECK(enabled IN (0,1)));CREATE TABLE IF NOT EXISTS auth_sessions(token_hash BLOB PRIMARY KEY CHECK(length(token_hash)=32),user_id INTEGER NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,created INTEGER NOT NULL,expires INTEGER NOT NULL CHECK(expires>created));CREATE INDEX IF NOT EXISTS auth_expiry ON auth_sessions(expires);")?;
        let version: i64 = tx.query_row("SELECT version FROM auth_meta WHERE id=1", [], |row| {
            row.get(0)
        })?;
        if version != 1 {
            return Err(StorageError::Corrupt);
        }
        tx.commit()?;
        Ok(Self { repo })
    }
    pub fn user(&self, name: &str) -> Result<Option<Account>, StorageError> {
        let row = self
            .repo
            .connection
            .query_row(
                "SELECT id,username,password_hash,role,enabled FROM auth_users WHERE username=?",
                [name],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, bool>(4)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(id, username, password_hash, role, enabled)| {
            Ok(Account {
                id,
                username,
                password_hash,
                role: Role::parse(&role)?,
                enabled,
            })
        })
        .transpose()
    }
    /// A transaction serializes simultaneous first-run provision attempts.
    pub fn insert_user(
        &mut self,
        name: &str,
        hash: &str,
        role: Role,
        authorization: AccountCreation<'_>,
    ) -> Result<(), StorageError> {
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
            || hash.len() > 512
            || !hash.starts_with("$argon2id$v=19$m=65536,t=3,p=1$")
        {
            return Err(StorageError::InvalidSource);
        }
        let tx = self
            .repo
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 = tx.query_row("SELECT count(*) FROM auth_users", [], |row| row.get(0))?;
        let allowed=match authorization {
            AccountCreation::FirstAdministrator=>count==0&&role==Role::Administrator,
            AccountCreation::NoAuthentication=>count>0,
            AccountCreation::Session{digest,now}=>count>0&&now>=0&&tx.query_row("SELECT count(*) FROM auth_sessions s JOIN auth_users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>? AND u.enabled=1 AND u.role='administrator'",params![digest.as_slice(),now],|row|row.get::<_,i64>(0))?==1,
        };
        if !allowed {
            return Err(StorageError::InvalidSource);
        }
        tx.execute(
            "INSERT INTO auth_users(username,password_hash,role,enabled)VALUES(?,?,?,1)",
            params![name, hash, role.as_str()],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn create_session(
        &mut self,
        user: &Account,
        digest: &[u8; 32],
        old: Option<&[u8; 32]>,
        now: i64,
        expires: i64,
    ) -> Result<(), StorageError> {
        let tx = self
            .repo
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let valid: i64 = tx.query_row(
            "SELECT count(*) FROM auth_users WHERE id=? AND password_hash=? AND enabled=1",
            params![user.id, user.password_hash],
            |r| r.get(0),
        )?;
        if valid != 1 {
            return Err(StorageError::InvalidSource);
        }
        tx.execute("DELETE FROM auth_sessions WHERE expires<=?", [now])?;
        if let Some(old) = old {
            tx.execute(
                "DELETE FROM auth_sessions WHERE token_hash=?",
                [old.as_slice()],
            )?;
        }
        let count: i64 = tx.query_row("SELECT count(*) FROM auth_sessions", [], |r| r.get(0))?;
        if count >= 10000 {
            return Err(StorageError::Capacity);
        }
        tx.execute("DELETE FROM auth_sessions WHERE token_hash IN(SELECT token_hash FROM auth_sessions WHERE user_id=? ORDER BY created DESC,rowid DESC LIMIT -1 OFFSET 9)",[user.id])?;
        tx.execute(
            "INSERT INTO auth_sessions(token_hash,user_id,created,expires)VALUES(?,?,?,?)",
            params![digest.as_slice(), user.id, now, expires],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn identity(&self, digest: &[u8; 32], now: i64) -> Result<Option<Identity>, StorageError> {
        let row=self.repo.connection.query_row("SELECT u.id,u.username,u.role FROM auth_sessions s JOIN auth_users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>? AND u.enabled=1",params![digest.as_slice(),now],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?))).optional()?;
        row.map(|(id, name, role)| {
            Ok(Identity {
                user_id: Some(id),
                username: Some(name),
                role: Role::parse(&role)?,
            })
        })
        .transpose()
    }
    pub fn revoke(&mut self, digest: &[u8; 32]) -> Result<(), StorageError> {
        self.repo.connection.execute(
            "DELETE FROM auth_sessions WHERE token_hash=?",
            [digest.as_slice()],
        )?;
        Ok(())
    }
}
