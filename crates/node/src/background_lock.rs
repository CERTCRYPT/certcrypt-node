//! One process runs the background tasks of a node's state.
//!
//! Several node processes may share one journal and one outbox — for example
//! while an upgrade starts the new process before the old one stops, so the
//! node never stops answering. Any of them can serve requests: SQLite
//! serializes the writes, and the issuer proofs are bound to the request they
//! were made for (see [`crate::auth`]). The background tasks are different:
//! two outbox relays would deliver the same entries side by side, two domain
//! binders would sign competing statements, two retention sweeps would race
//! over the same rows. They run only in the process that holds an exclusive
//! lock on a file next to the journal. The others wait and take over when the
//! holder exits; the operating system releases the lock even if the holder
//! dies, so a crashed process never blocks its successor.

use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// How often a waiting process tries the lock again.
const RETRY_EVERY: Duration = Duration::from_secs(1);

/// Held for as long as this process runs the background tasks. Dropping it
/// (or the process ending) releases the lock.
#[derive(Debug)]
pub struct BackgroundLock {
    _file: File,
}

/// The lock file for a journal configured as `journal_cfg`, or `None` when the
/// journal is in memory: then no other process can share the state.
pub fn lock_path(journal_cfg: &str) -> Option<PathBuf> {
    match journal_cfg {
        "memory" | ":memory:" => None,
        path => Some(PathBuf::from(format!("{path}.background.lock"))),
    }
}

/// Takes the lock if no other process holds it.
pub fn try_acquire(path: &Path) -> std::io::Result<Option<BackgroundLock>> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(BackgroundLock { _file: file })),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(e)) => Err(e),
    }
}

/// Waits until this process holds the lock.
pub async fn acquire(path: PathBuf) -> std::io::Result<BackgroundLock> {
    let never = Arc::new(AtomicBool::new(false));
    Ok(acquire_unless(path, never)
        .await?
        .expect("never asked to stop"))
}

/// Waits until this process holds the lock, or until `stop` is set (the
/// process is shutting down before its turn came): then `None`.
pub async fn acquire_unless(
    path: PathBuf,
    stop: Arc<AtomicBool>,
) -> std::io::Result<Option<BackgroundLock>> {
    let mut announced = false;
    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(None);
        }
        if let Some(lock) = try_acquire(&path)? {
            if announced {
                tracing::info!(lock = %path.display(), "background tasks taken over from the previous process");
            }
            return Ok(Some(lock));
        }
        if !announced {
            tracing::info!(
                lock = %path.display(),
                "another node process on this state runs the background tasks; waiting for it to exit"
            );
            announced = true;
        }
        tokio::time::sleep(RETRY_EVERY).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_in_memory_journal_needs_no_lock() {
        assert!(lock_path("memory").is_none());
        assert!(lock_path(":memory:").is_none());
        assert_eq!(
            lock_path("/var/lib/node/node-journal.sqlite").unwrap(),
            PathBuf::from("/var/lib/node/node-journal.sqlite.background.lock")
        );
    }

    #[tokio::test]
    async fn one_holder_at_a_time_and_the_next_takes_over_on_release() {
        let path = std::env::temp_dir().join(format!(
            "node-background-lock-test-{}.lock",
            std::process::id()
        ));
        let first = try_acquire(&path).unwrap().expect("free lock");
        assert!(
            try_acquire(&path).unwrap().is_none(),
            "a second holder while the first runs"
        );
        let waiting = tokio::spawn(acquire(path.clone()));
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(!waiting.is_finished(), "took the lock while it was held");
        drop(first);
        let second = tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("never took over")
            .unwrap()
            .unwrap();
        drop(second);
        assert!(try_acquire(&path).unwrap().is_some());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn a_process_shutting_down_stops_waiting() {
        let path = std::env::temp_dir().join(format!(
            "node-background-lock-stop-{}.lock",
            std::process::id()
        ));
        let _held = try_acquire(&path).unwrap().expect("free lock");
        let stop = Arc::new(AtomicBool::new(false));
        let waiting = tokio::spawn(acquire_unless(path.clone(), stop.clone()));
        stop.store(true, Ordering::Relaxed);
        let got = tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("kept waiting after stop")
            .unwrap()
            .unwrap();
        assert!(got.is_none());
        let _ = std::fs::remove_file(&path);
    }
}
