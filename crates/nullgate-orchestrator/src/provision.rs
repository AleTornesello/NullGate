//! Local-only bootstrap command; no unauthenticated browser provisioning endpoint.
use nullgate_core::{AppConfig, AuthMode};
use nullgate_web::{AuthError, AuthService};
use std::{io::Read, path::PathBuf};
/// Read a protected password file without putting its contents in arguments or logs.
pub async fn provision_local_administrator(
    config: AppConfig,
    username: String,
    path: PathBuf,
) -> Result<(), AuthError> {
    if config.auth != AuthMode::Local {
        return Err(AuthError::Invalid);
    }
    let password = tokio::task::spawn_blocking(move || {
        let link = std::fs::symlink_metadata(&path).map_err(|_| AuthError::Invalid)?;
        if link.file_type().is_symlink() {
            return Err(AuthError::Invalid);
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(path).map_err(|_| AuthError::Invalid)?;
        let metadata = file.metadata().map_err(|_| AuthError::Invalid)?;
        if !metadata.is_file() {
            return Err(AuthError::Invalid);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(AuthError::Invalid);
            }
        }
        #[cfg(not(unix))]
        {
            return Err(AuthError::Invalid);
        }
        let mut bytes = Vec::new();
        file.take(1027)
            .read_to_end(&mut bytes)
            .map_err(|_| AuthError::Invalid)?;
        if bytes.len() > 1026 {
            return Err(AuthError::Invalid);
        }
        if bytes.ends_with(b"\n") {
            bytes.pop();
            if bytes.ends_with(b"\r") {
                bytes.pop();
            }
        }
        String::from_utf8(bytes).map_err(|_| AuthError::Invalid)
    })
    .await
    .map_err(|_| AuthError::Unavailable)??;
    AuthService::open(config.database_path(), AuthMode::Local)
        .await?
        .provision_admin(&username, &password)
        .await
}
