//! Job-owned staging: failed exports never clean up a final pathname.

use crate::{Result, out};

#[cfg(not(target_arch = "wasm32"))]
mod native;

#[derive(Default)]
pub(crate) struct Pending {
    #[cfg(not(target_arch = "wasm32"))]
    files: std::sync::Mutex<Vec<native::Staged>>,
}

impl Pending {
    /// Open a sink directly or register a unique, private native staging file for this job.
    pub fn create<'a>(&self, sink: Option<&'a out::Sink>, path: &str) -> Result<out::Out<'a>> {
        if sink.is_some() {
            return out::create(sink, path);
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut files = self.files.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let (staged, file) = native::Staged::create(path).map_err(crate::io)?;
            if files.iter().any(|other| other.path == staged.path) {
                return Err(crate::io(format!("duplicate export destination: {path}")));
            }
            files.push(staged);
            Ok(out::Out::File(std::io::BufWriter::new(file)))
        }
        #[cfg(target_arch = "wasm32")]
        Err(crate::ExportError::Unsupported("web exports require an output sink".into()))
    }

    /// Each rename publishes one complete file. A sequence is not an atomic transaction:
    /// previously published frames remain if a later publication fails.
    pub fn publish(&self) -> Result<()> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut files = self.files.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            // Validate all destinations before publishing any of them.
            for staged in files.iter() {
                staged.validate().map_err(crate::io)?;
            }
            while let Some(staged) = files.pop() {
                staged.publish().map_err(crate::io)?;
            }
        }
        Ok(())
    }

    /// Attempt cleanup of every pending file, returning the first cleanup failure.
    pub fn discard(&self) -> Result<()> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let files = std::mem::take(&mut *self.files.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
            let mut failure = None;
            for staged in files {
                if let Err(error) = staged.discard() {
                    failure.get_or_insert(error);
                }
            }
            if let Some(error) = failure {
                return Err(crate::io(error));
            }
        }
        Ok(())
    }
}
