//! Job-owned temporary outputs. Failed jobs never unlink a final destination by name.

#[cfg(not(target_arch = "wasm32"))]
use crate::io;
use crate::{Result, out};

/// Disk outputs remain private until encoding succeeds; sinks retain per-file delivery.
#[derive(Default)]
pub(crate) struct Pending {
    #[cfg(not(target_arch = "wasm32"))]
    files: std::sync::Mutex<Vec<Staged>>,
}

/// One owned staging file and the access mode observed before it received media.
#[cfg(not(target_arch = "wasm32"))]
struct Staged {
    temporary: tempfile::TempPath,
    path: String,
    #[cfg(unix)]
    mode: u32,
}

/// Existing Unix access bits, or no policy yet for a new destination. Other errors fail closed.
#[cfg(unix)]
fn destination_mode(path: &str) -> Result<Option<u32>> {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata.permissions().mode() & 0o777)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io(format!("cannot read output permissions for {path}: {e}"))),
    }
}

impl Pending {
    /// Create a unique staging file on the destination volume, without truncating the target.
    pub fn create<'a>(&self, sink: Option<&'a out::Sink>, path: &str) -> Result<out::Out<'a>> {
        if sink.is_some() {
            return out::create(sink, path);
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let dir = std::path::Path::new(path).parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(std::path::Path::new("."));
            std::fs::create_dir_all(dir).map_err(io)?;
            #[cfg(unix)]
            let mode = match destination_mode(path)? {
                Some(mode) => mode,
                None => {
                    use std::os::unix::fs::PermissionsExt;
                    // Observe the umask without changing process-global state. This separate,
                    // empty probe never receives media: even an already-open reader learns nothing.
                    let probe = tempfile::Builder::new()
                        .prefix(".effectcraft-permissions-")
                        .permissions(std::fs::Permissions::from_mode(0o666))
                        .tempfile_in(dir)
                        .map_err(io)?;
                    probe.as_file().metadata().map_err(io)?.permissions().mode() & 0o777
                }
            };
            // The default 0600 mode is applied atomically at creation, before any media is written.
            let (file, temporary) = tempfile::Builder::new().prefix(".effectcraft-export-").tempfile_in(dir).map_err(io)?.into_parts();
            self.files.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(Staged {
                temporary,
                path: path.to_owned(),
                #[cfg(unix)]
                mode,
            });
            Ok(out::Out::File(std::io::BufWriter::new(file)))
        }
        #[cfg(target_arch = "wasm32")]
        Err(crate::ExportError::Unsupported("web exports require an output sink".into()))
    }

    /// Atomically replace each destination after all encoding succeeds. Publication of a whole
    /// sequence is not atomic: if a later rename fails, already-published complete files stay.
    pub fn publish(&self) -> Result<()> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut files = self.files.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            while let Some(mut staged) = files.pop() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    // Also honor restrictions applied while encoding. Never widen the initial mode.
                    let permissions = destination_mode(&staged.path).and_then(|current| {
                        let mode = staged.mode & current.unwrap_or(staged.mode);
                        std::fs::set_permissions(&staged.temporary, std::fs::Permissions::from_mode(mode)).map_err(io)
                    });
                    if let Err(e) = permissions {
                        files.push(staged);
                        return Err(e);
                    }
                }
                if let Err(e) = staged.temporary.persist(&staged.path) {
                    let error = io(format!("cannot publish output {}: {}", staged.path, e.error));
                    staged.temporary = e.path;
                    files.push(staged);
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    /// Remove staging files only. Guards also clean up if an export future is dropped.
    pub fn discard(&self) -> Result<()> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let files = std::mem::take(&mut *self.files.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
            let mut failure = None;
            for staged in files {
                if let Err(e) = staged.temporary.close() {
                    failure.get_or_insert_with(|| io(format!("cannot remove temporary output for {}: {e}", staged.path)));
                }
            }
            if let Some(error) = failure {
                return Err(error);
            }
        }
        Ok(())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::io::Write;

    /// Replacing a restricted file keeps media private during encoding and after publication.
    #[cfg(unix)]
    #[test]
    fn restricted_replacements_keep_staging_and_published_media_private() {
        use std::os::unix::fs::PermissionsExt;
        for original in [0o600, 0o640, 0o400] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("private.mov");
            std::fs::write(&path, b"old").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(original)).unwrap();
            let pending = Pending::default();
            let mut output = pending.create(None, path.to_str().unwrap()).unwrap();
            output.write_all(b"private replacement").unwrap();
            output.flush().unwrap();
            let stage = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().path()).find(|p| p != &path).unwrap();
            assert_eq!(std::fs::metadata(stage).unwrap().permissions().mode() & 0o077, 0, "unfinished media must be owner-only");
            output.finish().unwrap();
            pending.publish().unwrap();
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, original);
            assert_eq!(std::fs::read(&path).unwrap(), b"private replacement");
        }
    }

    /// Permission changes during encoding can tighten publication but cannot widen its snapshot.
    #[cfg(unix)]
    #[test]
    fn publication_honors_restrictions_changed_during_encoding() {
        use std::os::unix::fs::PermissionsExt;
        for (initial, current, expected) in [(0o644, Some(0o600), 0o600), (0o600, Some(0o644), 0o600), (0o600, None, 0o600)] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("output.mov");
            std::fs::write(&path, b"old").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(initial)).unwrap();
            let pending = Pending::default();
            pending.create(None, path.to_str().unwrap()).unwrap().finish().unwrap();
            if let Some(mode) = current {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            } else {
                std::fs::remove_file(&path).unwrap();
            }
            pending.publish().unwrap();
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, expected);
        }
    }

    /// If current destination permissions cannot be read, fail without exposing staged media.
    #[cfg(unix)]
    #[test]
    fn unreadable_destination_policy_fails_closed() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.mov");
        let pending = Pending::default();
        let mut output = pending.create(None, path.to_str().unwrap()).unwrap();
        output.write_all(b"private").unwrap();
        output.finish().unwrap();
        symlink(&path, &path).unwrap(); // A loop yields an error other than NotFound.
        assert!(pending.publish().is_err());
        let stage = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().path()).find(|p| p != &path).unwrap();
        assert_eq!(std::fs::metadata(stage).unwrap().permissions().mode() & 0o077, 0);
        pending.discard().unwrap();
        assert!(std::fs::symlink_metadata(&path).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    /// Published exports use the same umask-filtered mode as an ordinary newly created file.
    #[cfg(unix)]
    #[test]
    fn publication_preserves_normal_creation_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let ordinary = dir.path().join("ordinary.mov");
        std::fs::File::create(&ordinary).unwrap();
        let path = dir.path().join("export.mov");
        let pending = Pending::default();
        pending.create(None, path.to_str().unwrap()).unwrap().finish().unwrap();
        pending.publish().unwrap();
        assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, std::fs::metadata(ordinary).unwrap().permissions().mode() & 0o777);
    }

    /// A failed replacement leaves old contents intact; a successful one publishes full bytes.
    #[test]
    fn destination_is_untouched_until_publication() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.mov");
        std::fs::write(&path, b"old movie").unwrap();
        for publish in [false, true] {
            let pending = Pending::default();
            let mut file = pending.create(None, path.to_str().unwrap()).unwrap();
            file.write_all(b"new complete movie").unwrap();
            assert_eq!(file.finish().unwrap(), 18);
            assert_eq!(std::fs::read(&path).unwrap(), b"old movie");
            if publish {
                pending.publish().unwrap();
            } else {
                pending.discard().unwrap();
            }
            assert_eq!(std::fs::read(&path).unwrap(), if publish { b"new complete movie".as_slice() } else { b"old movie" });
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }

    /// One job failing cannot delete another job's successful output at the same destination.
    #[test]
    fn independent_jobs_do_not_clean_each_others_output() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.mov");
        let a = Pending::default();
        let b = Pending::default();
        let mut first = a.create(None, path.to_str().unwrap()).unwrap();
        first.write_all(b"unfinished").unwrap();
        let mut second = b.create(None, path.to_str().unwrap()).unwrap();
        second.write_all(b"successful movie").unwrap();
        second.finish().unwrap();
        b.publish().unwrap();
        drop(first);
        a.discard().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"successful movie");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    /// Rename failure reports an error and cleanup leaves the conflicting destination intact.
    #[test]
    fn failed_publication_and_abandoned_jobs_clean_staging_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.mov");
        std::fs::create_dir(&path).unwrap();
        for publish in [false, true] {
            let pending = Pending::default();
            let mut file = pending.create(None, path.to_str().unwrap()).unwrap();
            file.write_all(b"complete").unwrap();
            file.finish().unwrap();
            if publish {
                assert!(pending.publish().is_err());
                pending.discard().unwrap();
            }
            drop(pending);
            assert!(path.is_dir());
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }
}
