//! Bounded blocking password/session operations; no secret-bearing Debug implementations.
use crate::session;
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use nullgate_core::{AccountCreation, AuthMode, AuthRepository, Identity, Role};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::sync::Semaphore;
pub trait Clock: Send + Sync {
    fn now(&self) -> i64;
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(-1, |duration| {
                duration.as_secs().min(i64::MAX as u64) as i64
            })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthError {
    Unauthorized,
    Forbidden,
    Invalid,
    Conflict,
    Unavailable,
}
impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unauthorized => "Authentication required",
            Self::Forbidden => "Access denied",
            Self::Invalid => "Invalid authentication input",
            Self::Conflict => "Account provisioning conflict",
            Self::Unavailable => "Authentication unavailable",
        })
    }
}
impl std::error::Error for AuthError {}
#[derive(Clone)]
pub struct AuthService {
    repo: Arc<Mutex<AuthRepository>>,
    db_gate: Arc<Semaphore>,
    hash_gate: Arc<Semaphore>,
    dummy: Arc<String>,
    clock: Arc<dyn Clock>,
    mode: AuthMode,
    external_context: Option<String>,
}
fn argon() -> Result<Argon2<'static>, AuthError> {
    Ok(Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(65536, 3, 1, Some(32)).map_err(|_| AuthError::Unavailable)?,
    ))
}
fn hash(password: &str) -> Result<String, AuthError> {
    argon()?
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|_| AuthError::Unavailable)
}
fn username(name: &str) -> Result<String, AuthError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(AuthError::Invalid);
    }
    Ok(name.to_ascii_lowercase())
}
fn password_valid(password: &str) -> Result<(), AuthError> {
    if !(12..=1024).contains(&password.len()) {
        return Err(AuthError::Invalid);
    }
    Ok(())
}
pub(crate) struct Grant {
    pub token: String,
    pub csrf: String,
    pub max_age: u64,
}
impl AuthService {
    pub async fn open(path: PathBuf, mode: AuthMode) -> Result<Self, AuthError> {
        Self::open_with_clock(path, mode, Arc::new(SystemClock)).await
    }
    pub async fn open_with_clock(
        path: PathBuf,
        mode: AuthMode,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, AuthError> {
        if mode == AuthMode::Oidc {
            return Err(AuthError::Unavailable);
        }
        Self::open_configured(path, mode, None, clock).await
    }
    pub async fn open_external(path: PathBuf, context: String) -> Result<Self, AuthError> {
        Self::open_external_with_clock(path, context, Arc::new(SystemClock)).await
    }
    pub async fn open_external_with_clock(
        path: PathBuf,
        context: String,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, AuthError> {
        if !session::valid(&context) {
            return Err(AuthError::Invalid);
        }
        Self::open_configured(path, AuthMode::Oidc, Some(context), clock).await
    }
    async fn open_configured(
        path: PathBuf,
        mode: AuthMode,
        external_context: Option<String>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, AuthError> {
        let (repo, dummy) = tokio::task::spawn_blocking(move || {
            Ok::<_, AuthError>((
                AuthRepository::open(path).map_err(|_| AuthError::Unavailable)?,
                hash("dummy-unusable-random-login")?,
            ))
        })
        .await
        .map_err(|_| AuthError::Unavailable)??;
        Ok(Self {
            repo: Arc::new(Mutex::new(repo)),
            db_gate: Arc::new(Semaphore::new(16)),
            hash_gate: Arc::new(Semaphore::new(2)),
            dummy: Arc::new(dummy),
            clock,
            mode,
            external_context,
        })
    }
    async fn work<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut AuthRepository) -> Result<T, AuthError> + Send + 'static,
    ) -> Result<T, AuthError> {
        let permit = self
            .db_gate
            .clone()
            .try_acquire_owned()
            .map_err(|_| AuthError::Unavailable)?;
        let repo = self.repo.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut repo = repo.lock().map_err(|_| AuthError::Unavailable)?;
            operation(&mut repo)
        })
        .await
        .map_err(|_| AuthError::Unavailable)?
    }
    async fn password_work<T: Send + 'static>(
        &self,
        operation: impl FnOnce() -> Result<T, AuthError> + Send + 'static,
    ) -> Result<T, AuthError> {
        let permit = self
            .hash_gate
            .clone()
            .try_acquire_owned()
            .map_err(|_| AuthError::Unavailable)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            operation()
        })
        .await
        .map_err(|_| AuthError::Unavailable)?
    }
    pub async fn provision_admin(&self, name: &str, password: &str) -> Result<(), AuthError> {
        if self.mode == AuthMode::Oidc {
            return Err(AuthError::Invalid);
        }
        let name = username(name)?;
        password_valid(password)?;
        let password = password.to_owned();
        let hash = self.password_work(move || hash(&password)).await?;
        self.work(move |repo| {
            repo.insert_user(
                &name,
                &hash,
                Role::Administrator,
                AccountCreation::FirstAdministrator,
            )
            .map_err(|_| AuthError::Conflict)
        })
        .await
    }
    /// Session proof is rechecked transactionally after hashing; cached identities are not authority.
    pub async fn create_user(
        &self,
        administrator_session: Option<&str>,
        name: &str,
        password: &str,
        role: Role,
    ) -> Result<(), AuthError> {
        if self.mode == AuthMode::Oidc {
            return Err(AuthError::Invalid);
        }
        let actor = self.identity(administrator_session).await?;
        if actor.role != Role::Administrator {
            return Err(AuthError::Forbidden);
        }
        let proof = administrator_session
            .filter(|token| session::valid(token))
            .map(session::digest);
        let no_auth = self.no_auth();
        let clock = self.clock.clone();
        let name = username(name)?;
        password_valid(password)?;
        let password = password.to_owned();
        let hash = self.password_work(move || hash(&password)).await?;
        self.work(move |repo| {
            let authorization = if no_auth {
                AccountCreation::NoAuthentication
            } else {
                AccountCreation::Session {
                    digest: proof.as_ref().ok_or(AuthError::Unauthorized)?,
                    now: clock.now(),
                }
            };
            repo.insert_user(&name, &hash, role, authorization)
                .map_err(|_| AuthError::Forbidden)
        })
        .await
    }
    pub async fn identity(&self, token: Option<&str>) -> Result<Identity, AuthError> {
        if self.mode == AuthMode::None {
            return Ok(Identity {
                user_id: None,
                username: None,
                role: Role::Administrator,
            });
        }
        let token = token
            .filter(|t| session::valid(t))
            .ok_or(AuthError::Unauthorized)?;
        let digest = session::digest(token);
        let now = self.clock.now();
        if now < 0 {
            return Err(AuthError::Unavailable);
        }
        let context = self.external_context.clone();
        self.work(move |repo| {
            let identity = if let Some(context) = context {
                repo.external_identity(&digest, now, &context)
            } else {
                repo.local_identity(&digest, now)
            };
            identity
                .map_err(|_| AuthError::Unavailable)?
                .ok_or(AuthError::Unauthorized)
        })
        .await
    }
    pub fn is_external(&self) -> bool {
        self.mode == AuthMode::Oidc
    }
    pub(crate) fn no_auth(&self) -> bool {
        self.mode == AuthMode::None
    }
    pub(crate) async fn login(
        &self,
        name: String,
        password: String,
        old: Option<String>,
    ) -> Result<Grant, AuthError> {
        if self.mode != AuthMode::Local {
            return Err(AuthError::Invalid);
        }
        if password.len() > 1024 {
            return Err(AuthError::Unauthorized);
        }
        let name = username(&name).ok();
        let user = self
            .work(move |repo| match name {
                Some(name) => repo.user(&name).map_err(|_| AuthError::Unavailable),
                None => Ok(None),
            })
            .await?;
        let dummy = self.dummy.clone();
        let user = self
            .password_work(move || {
                let encoded = user
                    .as_ref()
                    .map_or(dummy.as_str(), |user| user.password_hash.as_str());
                if !encoded.starts_with("$argon2id$v=19$m=65536,t=3,p=1$") || encoded.len() > 512 {
                    return Err(AuthError::Unavailable);
                }
                let parsed = PasswordHash::new(encoded).map_err(|_| AuthError::Unavailable)?;
                let verified = argon()?
                    .verify_password(password.as_bytes(), &parsed)
                    .is_ok();
                user.filter(|user| verified && user.enabled)
                    .ok_or(AuthError::Unauthorized)
            })
            .await?;
        let clock = self.clock.clone();
        self.work(move |repo| {
            let now = clock.now();
            let expires = now
                .checked_add(28800)
                .filter(|_| now >= 0)
                .ok_or(AuthError::Unavailable)?;
            let token = session::random()?;
            let digest = session::digest(&token);
            let old = old
                .filter(|token| session::valid(token))
                .map(|token| session::digest(&token));
            repo.create_session(&user, &digest, old.as_ref(), now, expires)
                .map_err(|_| AuthError::Unavailable)?;
            Ok(Grant {
                csrf: session::csrf(&token),
                max_age: 28800,
                token,
            })
        })
        .await
    }
    pub(crate) async fn external_login(
        &self,
        identity: crate::oidc::VerifiedIdentity,
        old: Option<String>,
    ) -> Result<Grant, AuthError> {
        if self.mode != AuthMode::Oidc || self.external_context.as_ref() != Some(&identity.context)
        {
            return Err(AuthError::Invalid);
        }
        let clock = self.clock.clone();
        self.work(move |repo| {
            let old = old
                .filter(|token| session::valid(token))
                .map(|token| session::digest(&token));
            let Some(role) = identity.role else {
                repo.revoke_external(&identity.issuer, &identity.subject)
                    .map_err(|_| AuthError::Unavailable)?;
                if let Some(old) = old {
                    repo.revoke(&old).map_err(|_| AuthError::Unavailable)?;
                }
                return Err(AuthError::Forbidden);
            };
            let now = clock.now();
            let expires = now
                .checked_add(28800)
                .ok_or(AuthError::Unavailable)?
                .min(identity.expires);
            if now < 0 || expires <= now {
                return Err(AuthError::Unauthorized);
            }
            let token = session::random()?;
            let login = nullgate_core::ExternalLogin {
                issuer: identity.issuer,
                subject: identity.subject,
                display_name: identity.display,
                role,
                context: identity.context,
            };
            repo.external_session(&login, &session::digest(&token), old.as_ref(), now, expires)
                .map_err(|error| {
                    if error == nullgate_core::StorageError::InvalidSource {
                        AuthError::Forbidden
                    } else {
                        AuthError::Unavailable
                    }
                })?;
            Ok(Grant {
                csrf: session::csrf(&token),
                token,
                max_age: (expires - now) as u64,
            })
        })
        .await
    }
    pub(crate) async fn logout(&self, token: Option<String>) -> Result<(), AuthError> {
        if self.no_auth() {
            return Ok(());
        }
        let token = token
            .filter(|token| session::valid(token))
            .ok_or(AuthError::Unauthorized)?;
        let digest = session::digest(&token);
        self.work(move |repo| repo.revoke(&digest).map_err(|_| AuthError::Unavailable))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn exhausted_password_admission_does_not_starve_established_sessions() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("nullgate-auth-admission-{stamp}"));
        let auth = AuthService::open(path.join("state.sqlite3"), AuthMode::Local)
            .await
            .unwrap();
        auth.provision_admin("admin", "safe testing password")
            .await
            .unwrap();
        let grant = auth
            .login("admin".into(), "safe testing password".into(), None)
            .await
            .unwrap();
        let one = auth.hash_gate.clone().acquire_owned().await.unwrap();
        let two = auth.hash_gate.clone().acquire_owned().await.unwrap();
        assert!(auth.identity(Some(&grant.token)).await.is_ok());
        drop((one, two));
        drop(auth);
        std::fs::remove_dir_all(path).unwrap();
    }
}
