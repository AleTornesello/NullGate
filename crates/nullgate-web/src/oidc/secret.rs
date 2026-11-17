//! Read a service-owned secret through validated directory handles; never expose I/O details.
use crate::AuthError;
use rustix::{
    fs::{self, FileType, Mode, OFlags},
    process::geteuid,
};
use std::{
    io::Read,
    path::{Component, Path},
};
pub(super) fn read(path: &Path) -> Result<String, AuthError> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|_| AuthError::Unavailable)?
            .join(path)
    };
    let mut components = absolute.components().collect::<Vec<_>>();
    let Some(Component::Normal(name)) = components.pop() else {
        return Err(AuthError::Invalid);
    };
    let flags =
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    let root = fs::open("/", flags, Mode::empty()).map_err(|_| AuthError::Unavailable)?;
    let system = fs::fstat(&root).map_err(|_| AuthError::Unavailable)?.st_uid;
    let user = geteuid().as_raw();
    let mut stack = vec![root];
    for component in components {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                if stack.len() > 1 {
                    stack.pop();
                }
            }
            Component::Normal(part) => {
                let fd = fs::openat(
                    stack.last().ok_or(AuthError::Unavailable)?,
                    part,
                    flags,
                    Mode::empty(),
                )
                .map_err(|_| AuthError::Unavailable)?;
                let stat = fs::fstat(&fd).map_err(|_| AuthError::Unavailable)?;
                if (stat.st_uid != system && stat.st_uid != user)
                    || (stat.st_mode & 0o022 != 0 && stat.st_mode & 0o1000 == 0)
                {
                    return Err(AuthError::Unavailable);
                }
                stack.push(fd);
            }
            _ => return Err(AuthError::Invalid),
        }
    }
    let fd = fs::openat(
        stack.last().ok_or(AuthError::Unavailable)?,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| AuthError::Unavailable)?;
    let stat = fs::fstat(&fd).map_err(|_| AuthError::Unavailable)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != user
        || stat.st_mode & 0o077 != 0
        || stat.st_nlink != 1
        || stat.st_size <= 0
        || stat.st_size > 4096
    {
        return Err(AuthError::Unavailable);
    }
    let mut bytes = vec![];
    std::fs::File::from(fd)
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| AuthError::Unavailable)?;
    if bytes.len() > 4096 {
        return Err(AuthError::Unavailable);
    }
    let mut text = String::from_utf8(bytes).map_err(|_| AuthError::Unavailable)?;
    if text.ends_with('\n') {
        text.pop();
        if text.ends_with('\r') {
            text.pop();
        }
    }
    if text.is_empty() || text.chars().any(char::is_control) {
        return Err(AuthError::Unavailable);
    }
    Ok(text)
}
