//! Validated, pinned directory handles; paths are never re-resolved after validation.
use super::CaError;
use rustix::{
    fd::OwnedFd,
    fs::{self as os, FileType, Mode, OFlags, Stat},
    io::Errno,
    process::geteuid,
};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Component, Path},
};
const MAGIC: &[u8; 8] = b"NULLCA01";
const MAX: usize = 65536;
fn storage(error: Errno) -> CaError {
    match error {
        Errno::LOOP | Errno::NOTDIR => CaError::UnsafeStorage,
        _ => CaError::Storage,
    }
}
fn check_directory(
    stat: &Stat,
    system_owner: u32,
    private: bool,
    data: bool,
) -> Result<(), CaError> {
    let owner = geteuid().as_raw();
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || (stat.st_uid != owner && stat.st_uid != system_owner)
        || ((private || data) && stat.st_uid != owner)
    {
        return Err(CaError::UnsafeStorage);
    }
    let mode = stat.st_mode;
    if private {
        if mode & 0o077 != 0 {
            return Err(CaError::UnsafeStorage);
        }
    } else if mode & 0o022 != 0 && (data || mode & 0o1000 == 0) {
        return Err(CaError::UnsafeStorage);
    }
    Ok(())
}
fn data_directory(path: &Path) -> Result<OwnedFd, CaError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| CaError::Storage)?
            .join(path)
    };
    let flags =
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    let root = os::open("/", flags, Mode::empty()).map_err(storage)?;
    // The filesystem root's owner is the privileged system owner, including mapped containers.
    let system_owner = os::fstat(&root).map_err(storage)?.st_uid;
    check_directory(
        &os::fstat(&root).map_err(storage)?,
        system_owner,
        false,
        false,
    )?;
    let mut stack = vec![root];
    for component in absolute.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                let child = os::openat(
                    stack.last().ok_or(CaError::Storage)?,
                    name,
                    flags,
                    Mode::empty(),
                )
                .map_err(storage)?;
                check_directory(
                    &os::fstat(&child).map_err(storage)?,
                    system_owner,
                    false,
                    false,
                )?;
                stack.push(child);
            }
            Component::ParentDir => {
                if stack.len() > 1 {
                    stack.pop();
                }
            }
            _ => return Err(CaError::UnsafeStorage),
        }
    }
    let data = stack.pop().ok_or(CaError::Storage)?;
    check_directory(
        &os::fstat(&data).map_err(storage)?,
        system_owner,
        false,
        true,
    )?;
    Ok(data)
}
pub(super) struct Store {
    data: OwnedFd,
    directory: OwnedFd,
    fresh: bool,
}
impl Store {
    pub fn claim(data: &Path) -> Result<Self, CaError> {
        let data = data_directory(data)?;
        let fresh = match os::mkdirat(&data, "inspection-ca", Mode::from_raw_mode(0o700)) {
            Ok(()) => true,
            Err(Errno::EXIST) => false,
            Err(error) => return Err(storage(error)),
        };
        let directory = os::openat(
            &data,
            "inspection-ca",
            OFlags::RDONLY
                | OFlags::DIRECTORY
                | OFlags::CLOEXEC
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(storage)?;
        check_directory(
            &os::fstat(&directory).map_err(storage)?,
            geteuid().as_raw(),
            true,
            false,
        )?;
        Ok(Self {
            data,
            directory,
            fresh,
        })
    }
    pub fn fresh(&self) -> bool {
        self.fresh
    }
    pub fn read(&self) -> Result<(Vec<u8>, Vec<u8>), CaError> {
        let file = os::openat(
            &self.directory,
            "material.bin",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| {
            if error == Errno::NOENT {
                CaError::Incomplete
            } else {
                storage(error)
            }
        })?;
        let stat = os::fstat(&file).map_err(storage)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_size < 0
            || stat.st_size > MAX as i64
            || stat.st_mode & 0o077 != 0
            || stat.st_nlink != 1
            || stat.st_uid != geteuid().as_raw()
        {
            return Err(CaError::UnsafeStorage);
        }
        let mut bytes = Vec::new();
        File::from(file)
            .take(MAX as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| CaError::Storage)?;
        if bytes.len() < 16 || bytes.len() > MAX || &bytes[..8] != MAGIC {
            return Err(CaError::Corrupt);
        }
        let cert =
            u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| CaError::Corrupt)?) as usize;
        let key =
            u32::from_be_bytes(bytes[12..16].try_into().map_err(|_| CaError::Corrupt)?) as usize;
        if cert == 0
            || key == 0
            || cert > MAX - 16
            || key > MAX - 16 - cert
            || bytes.len() != 16 + cert + key
        {
            return Err(CaError::Corrupt);
        }
        Ok((bytes[16..16 + cert].to_vec(), bytes[16 + cert..].to_vec()))
    }
    pub fn write(&self, cert: &[u8], key: &[u8]) -> Result<(), CaError> {
        if !self.fresh || cert.len() + key.len() > MAX - 16 {
            return Err(CaError::Storage);
        }
        let fd = os::openat(
            &self.directory,
            "material.bin",
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK,
            Mode::from_raw_mode(0o600),
        )
        .map_err(storage)?;
        let mut file = File::from(fd);
        file.write_all(MAGIC)
            .and_then(|_| file.write_all(&(cert.len() as u32).to_be_bytes()))
            .and_then(|_| file.write_all(&(key.len() as u32).to_be_bytes()))
            .and_then(|_| file.write_all(cert))
            .and_then(|_| file.write_all(key))
            .and_then(|_| file.sync_all())
            .map_err(|_| CaError::Storage)?;
        os::fsync(&self.directory).map_err(storage)?;
        os::fsync(&self.data).map_err(storage)?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};
    fn scratch() -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "nullgate-ca-storage-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }
    #[test]
    #[cfg(unix)]
    fn directory_replacement_cannot_redirect_private_material() {
        use std::os::unix::fs::symlink;
        let data = scratch();
        let store = Store::claim(&data).unwrap();
        let target = data.join("target");
        fs::create_dir(&target).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        fs::rename(data.join("inspection-ca"), data.join("claimed")).unwrap();
        symlink(&target, data.join("inspection-ca")).unwrap();
        store.write(b"certificate", b"private-key").unwrap();
        assert!(
            !target.join("material.bin").exists(),
            "private material followed a replacement symlink"
        );
        assert!(data.join("claimed/material.bin").exists());
        assert_eq!(
            store.read().unwrap(),
            (b"certificate".to_vec(), b"private-key".to_vec())
        );
        fs::remove_dir_all(data).unwrap();
    }
    #[test]
    fn directory_ownership_must_be_trusted_and_private_state_must_be_service_owned() {
        let data = scratch();
        let fd = os::open(&data, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap();
        let mut stat = os::fstat(&fd).unwrap();
        let service = geteuid().as_raw();
        let system =
            os::fstat(os::open("/", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap())
                .unwrap()
                .st_uid;
        let mut foreign = service.wrapping_add(1);
        while foreign == service || foreign == system {
            foreign = foreign.wrapping_add(1);
        }
        stat.st_uid = foreign;
        assert!(matches!(
            check_directory(&stat, system, false, false),
            Err(CaError::UnsafeStorage)
        ));
        assert!(matches!(
            check_directory(&stat, system, true, false),
            Err(CaError::UnsafeStorage)
        ));
        stat.st_uid = service;
        stat.st_mode = (stat.st_mode & !0o777) | 0o700;
        check_directory(&stat, system, true, false).unwrap();
        fs::remove_dir_all(data).unwrap();
    }
    #[test]
    #[cfg(unix)]
    fn intermediate_symlinks_and_writable_ancestors_are_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let parent = scratch();
        let writable = parent.join("writable");
        fs::create_dir(&writable).unwrap();
        let data = writable.join("data");
        fs::create_dir(&data).unwrap();
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(Store::claim(&data), Err(CaError::UnsafeStorage)));
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o755)).unwrap();
        let alias = parent.join("alias");
        symlink(&writable, &alias).unwrap();
        assert!(matches!(
            Store::claim(&alias.join("data")),
            Err(CaError::UnsafeStorage)
        ));
        fs::remove_dir_all(parent).unwrap();
    }
}
