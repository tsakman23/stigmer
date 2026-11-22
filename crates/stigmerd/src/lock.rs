//! The data directory: private modes and the exclusive process lock.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use crate::Failure;

const LOCK_FILE: &str = "stigmer.lock";
const DB_FILE: &str = "stigmer.db";

/// A prepared data directory, exclusively locked by this process until dropped.
///
/// The lock is an advisory `flock` on `stigmer.lock`, released by the OS when the process
/// exits, so a crash never leaves a stale lock behind.
pub struct DataDir {
    path: PathBuf,
    _lock: File,
}

impl DataDir {
    /// Creates the directory if missing (0700 on unix), takes the lock and creates the
    /// database file (0600 on unix) so SQLite's `-wal` and `-shm` files inherit it.
    pub fn open(path: &Path) -> Result<Self, Failure> {
        create_dir(path)?;
        let lock = open_private(&path.join(LOCK_FILE)).map_err(|e| {
            Failure::Runtime(format!(
                "cannot create lock file in {}: {e}",
                path.display()
            ))
        })?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(Failure::Runtime(
                    "data directory is in use by another stigmerd process; stop it first".into(),
                ));
            }
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(Failure::Runtime(format!(
                    "cannot lock data dir {}: {e}",
                    path.display()
                )));
            }
        }
        let db = path.join(DB_FILE);
        open_private(&db).map_err(|e| {
            Failure::Runtime(format!("cannot create database {}: {e}", db.display()))
        })?;
        Ok(Self {
            path: path.to_owned(),
            _lock: lock,
        })
    }

    pub fn db_path(&self) -> PathBuf {
        self.path.join(DB_FILE)
    }
}

/// Opens `path` for writing, creating it private to the owner (0600) on unix. Existing
/// content and mode are kept.
fn open_private(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(false);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// Creates the data directory, private to the owner (0700) on unix. An existing
/// directory keeps its mode; a warning goes to stderr if others can access it.
fn create_dir(data_dir: &Path) -> Result<(), Failure> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(data_dir).map_err(|e| {
        Failure::Runtime(format!(
            "cannot create data dir {}: {e}",
            data_dir.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(data_dir)
            .map_err(|e| {
                Failure::Runtime(format!("cannot read data dir {}: {e}", data_dir.display()))
            })?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            eprintln!(
                "stigmerd: warning: data dir {} is accessible by group or others (mode {:o}); consider: chmod 700 {}",
                data_dir.display(),
                mode & 0o777,
                data_dir.display()
            );
        }
    }
    Ok(())
}
