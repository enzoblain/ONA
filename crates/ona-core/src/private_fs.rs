//! Private files on every system the apps run on.
//!
//! On Unix a file is created with mode 600 and refused when its mode lets another account in. Windows has no such
//! mode: a file takes the access list (ACL) of its folder, and the apps keep their files in the user's profile. No
//! access list is set or checked there: the mode check has nothing to read and passes.

use std::fs::{File, Metadata, OpenOptions};
use std::path::Path;

pub(crate) trait OwnerOnly {
    /// Creates the file readable and writable by its owner only (Unix mode 600; see the module comment for Windows).
    fn owner_only(&mut self) -> &mut Self;
}

impl OwnerOnly for OpenOptions {
    fn owner_only(&mut self) -> &mut Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            self.mode(0o600);
        }
        self
    }
}

/// True when the Unix mode lets another account read or write the file. Always false on Windows.
pub(crate) fn open_to_others(meta: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o077 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        false
    }
}

/// Makes a folder private to its owner (Unix mode 700). Nothing to do on Windows.
pub(crate) fn private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Flushes a folder, so a rename in it reaches the disk. On Windows a folder opens only with
/// `FILE_FLAG_BACKUP_SEMANTICS`, and its buffers flush only with write access.
pub(crate) fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        OpenOptions::new().write(true).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(dir)?.sync_all()
    }
    #[cfg(not(windows))]
    File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Run on each system by the release workflow: on Windows, a folder must open and flush.
    #[test]
    fn a_folder_is_flushed_after_a_rename() {
        let dir = std::env::temp_dir().join(format!("ona-sync-dir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.tmp"), b"x").unwrap();
        std::fs::rename(dir.join("a.tmp"), dir.join("a")).unwrap();
        sync_dir(&dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
