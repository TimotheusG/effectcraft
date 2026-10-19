//! Job-owned temporary outputs. Failed jobs never unlink a final destination by name.

#[cfg(not(target_arch = "wasm32"))]
use crate::io;
use crate::{Result, out};

/// Disk outputs remain private until encoding succeeds; sinks retain per-file delivery.
#[derive(Default)]
pub(crate) struct Pending {
    #[cfg(not(target_arch = "wasm32"))]
    files: std::sync::Mutex<Vec<(tempfile::TempPath, String)>>,
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
            let (file, temporary) = tempfile::Builder::new().prefix(".effectcraft-export-").tempfile_in(dir).map_err(io)?.into_parts();
            self.files.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push((temporary, path.to_owned()));
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
            while let Some((temporary, path)) = files.pop() {
                if let Err(e) = temporary.persist(&path) {
                    let error = io(format!("cannot publish output {path}: {}", e.error));
                    files.push((e.path, path));
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
            for (temporary, path) in files {
                if let Err(e) = temporary.close() {
                    failure.get_or_insert_with(|| io(format!("cannot remove temporary output for {path}: {e}")));
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
