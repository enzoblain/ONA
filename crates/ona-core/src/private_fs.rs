//! Private files on every system the apps run on.
//!
//! On Unix a file is created with mode 600 and refused when its mode lets another account in. Windows has no such
//! mode: a file takes the access list of its folder, and the apps keep their files in the user's profile, which other
//! standard accounts cannot open. There the mode check has nothing to read and passes.

#[cfg(unix)]
use std::fs::File;
use std::fs::{Metadata, OpenOptions};
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

/// Flushes a folder, so a rename in it reaches the disk. Unix only: Windows cannot open a folder as a file, so there
/// the rename is not flushed and a crash right after it may undo it.
pub(crate) fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}
