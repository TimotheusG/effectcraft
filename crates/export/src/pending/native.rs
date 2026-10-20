use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
    time::SystemTime,
};

#[cfg(unix)]
#[path = "unix.rs"]
mod platform;

// Serialize validation and replacement across jobs in this process. External writers still
// require cooperation: portable filesystems do not provide compare-and-swap by file version.
static PUBLICATION: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[cfg(windows)]
#[path = "windows.rs"]
mod platform;

pub(super) struct Staged {
    temporary: tempfile::TempPath,
    directory: Option<tempfile::TempDir>,
    pub path: PathBuf,
    requested: PathBuf,
    original: Option<Version>,
    policy: platform::Policy,
    parent_policy: platform::Policy,
}

#[derive(PartialEq, Eq)]
struct Version {
    identity: (u64, u64),
    change_stamp: (i64, i64),
    len: u64,
    modified: SystemTime,
    policy: platform::Policy,
}

impl Version {
    /// Capture the writable destination's identity, content timestamp, and access policy.
    fn read(file: &File, path: &Path) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.is_file() || platform::links(file)? != 1 {
            return Err(io::Error::other(format!("export destination must be a regular file with one hard link: {}", path.display())));
        }
        Ok(Self {
            identity: platform::identity(file)?,
            change_stamp: platform::change_stamp(file)?,
            len: metadata.len(),
            modified: metadata.modified()?,
            policy: platform::Policy::read(path)?,
        })
    }
}

impl Staged {
    /// Check destination capabilities before creating private, job-owned media storage.
    pub fn create(path: &str) -> io::Result<(Self, File)> {
        let requested = std::path::absolute(path)?;
        let path = resolve(&requested, true)?;
        let parent = path.parent().ok_or_else(|| io::Error::other("output has no parent directory"))?;
        let parent_policy = platform::Policy::read(parent)?;
        match fs::metadata(&path) {
            Ok(metadata) if !metadata.is_file() => return Err(io::Error::other("export destination is not a regular file")),
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
        let original = match OpenOptions::new().write(true).open(&path) {
            Ok(file) => {
                let version = Version::read(&file, &path)?;
                Some(version)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        // The ordinary creation probe is always empty. No exported bytes ever enter an inode
        // that another account might have opened before access was restricted.
        let probe = platform::ordinary_file(parent)?;
        if original.is_none() {
            // Reject unsupported no-clobber publication before rendering. The probe contains
            // no media; the owned directory also cleans its link on an early return.
            let links = tempfile::Builder::new().prefix(".effectcraft-policy-").tempdir_in(parent)?;
            fs::hard_link(probe.path(), links.path().join("link"))
                .map_err(|error| io::Error::new(error.kind(), format!("export filesystem cannot publish new files with hard links: {error}")))?;
            links.close()?;
        }
        let policy = match &original {
            Some(version) => version.policy.clone(),
            None => platform::Policy::read(probe.path())?,
        };
        policy.apply(probe.path())?;
        let restored = platform::Policy::read(probe.path())?;
        if restored != policy {
            #[cfg(test)]
            eprintln!("policy restoration mismatch: expected {policy:?}; restored {restored:?}");
            return Err(io::Error::other("cannot preserve export destination access policy on this filesystem"));
        }
        probe.close()?;
        let (temporary, directory) = platform::private_file(parent)?;
        let (file, temporary) = temporary.into_parts();
        let staged = Self { temporary, directory, path, requested, original, policy, parent_policy };
        staged.validate()?;
        Ok((staged, file))
    }

    /// Reject changed links, destination versions, or parent access policy.
    pub fn validate(&self) -> io::Result<()> {
        if resolve(&self.requested, false)? != self.path {
            return Err(io::Error::other("export destination symlink changed while rendering"));
        }
        let parent = self.path.parent().ok_or_else(|| io::Error::other("output has no parent directory"))?;
        if platform::Policy::read(parent)? != self.parent_policy {
            return Err(io::Error::other("export directory access policy changed while rendering"));
        }
        match &self.original {
            Some(expected) => {
                let current = OpenOptions::new().write(true).open(&self.path)?;
                if Version::read(&current, &self.path)? != *expected {
                    return Err(io::Error::other(format!("export destination changed while rendering: {}", self.path.display())));
                }
            }
            None => match fs::symlink_metadata(&self.path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
                Ok(_) => return Err(io::Error::other(format!("export destination appeared while rendering: {}", self.path.display()))),
            },
        }
        Ok(())
    }

    /// Serialize final validation/publication and clean staging even when publication fails.
    pub fn publish(self) -> io::Result<()> {
        let result = {
            let _publication = PUBLICATION.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            self.publish_inner()
        };
        let cleanup = self.discard();
        match (result, cleanup) {
            (Err(error), Err(cleanup)) => Err(io::Error::new(error.kind(), format!("{error}; cleanup also failed: {cleanup}"))),
            (Err(error), _) | (_, Err(error)) => Err(error),
            _ => Ok(()),
        }
    }

    /// Restore access policy and publish one complete file without clobbering a new creator.
    fn publish_inner(&self) -> io::Result<()> {
        self.validate()?;
        self.policy.apply(&self.temporary)?;
        if platform::Policy::read(&self.temporary)? != self.policy {
            return Err(io::Error::other("staged export access policy could not be preserved"));
        }
        self.validate()?;
        if self.original.is_some() {
            fs::rename(&self.temporary, &self.path)?;
        } else {
            // Unlike a check followed by rename, this cannot overwrite a file that appeared
            // after validation. Both names refer to complete bytes until staging is removed.
            fs::hard_link(&self.temporary, &self.path)?;
        }
        Ok(())
    }

    /// Remove only owned staging paths; a successful rename already consumed the file path.
    pub fn discard(self) -> io::Result<()> {
        if let Err(error) = self.temporary.close()
            && error.kind() != io::ErrorKind::NotFound
        {
            return Err(io::Error::new(error.kind(), format!("cannot remove staging for {}: {error}", self.path.display())));
        }
        if let Some(directory) = self.directory {
            directory.close()?;
        }
        Ok(())
    }
}

/// Resolve leaf links explicitly, including dangling relative links. The OS resolves directory
/// links with its own loop checks; our leaf-link walk has a fixed bound.
fn resolve(requested: &Path, create_parents: bool) -> io::Result<PathBuf> {
    let mut path = requested.to_path_buf();
    for _ in 0..40 {
        let parent = path.parent().ok_or_else(|| io::Error::other("output has no parent directory"))?;
        if create_parents {
            fs::create_dir_all(parent)?;
        }
        let name = path.file_name().ok_or_else(|| io::Error::other("output has no filename"))?;
        path = parent.canonicalize()?.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                let target = fs::read_link(&path)?;
                path = if target.is_absolute() { target } else { path.parent().ok_or_else(|| io::Error::other("link has no parent"))?.join(target) };
            }
            Ok(_) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(path),
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::other("export destination has too many symbolic links"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Prepare completed test bytes and close the writer before publication assertions.
    fn stage(path: &Path, bytes: &[u8]) -> Staged {
        let (staged, mut file) = Staged::create(path.to_str().unwrap()).unwrap();
        file.write_all(bytes).unwrap();
        file.flush().unwrap();
        drop(file);
        staged
    }

    #[test]
    fn lifecycle_preserves_existing_bytes_until_publish_and_cleans_owned_files() {
        for existing in [false, true] {
            for action in ["drop", "discard", "publish"] {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("movie.mov");
                if existing {
                    fs::write(&path, b"old complete movie").unwrap();
                }
                let expected = if existing {
                    platform::Policy::read(&path).unwrap()
                } else {
                    let ordinary = dir.path().join("ordinary");
                    fs::write(&ordinary, b"").unwrap();
                    let policy = platform::Policy::read(&ordinary).unwrap();
                    fs::remove_file(ordinary).unwrap();
                    policy
                };
                let staged = stage(&path, b"new complete movie");
                assert_eq!(fs::read(&path).ok(), existing.then(|| b"old complete movie".to_vec()));
                match action {
                    "publish" => staged.publish().unwrap(),
                    "discard" => staged.discard().unwrap(),
                    _ => drop(staged),
                }
                if action == "publish" {
                    assert_eq!(fs::read(&path).unwrap(), b"new complete movie");
                    assert_eq!(platform::Policy::read(&path).unwrap(), expected);
                } else {
                    assert_eq!(fs::read(&path).ok(), existing.then(|| b"old complete movie".to_vec()));
                }
                assert_eq!(fs::read_dir(dir.path()).unwrap().count(), usize::from(existing || action == "publish"));
            }
        }
    }

    #[test]
    fn competing_jobs_and_external_writes_are_not_overwritten_or_deleted() {
        for existing in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("movie.mov");
            if existing {
                fs::write(&path, b"old").unwrap();
            }
            let first = stage(&path, b"first job");
            let second = stage(&path, b"second job");
            second.publish().unwrap();
            assert!(first.publish().is_err());
            assert_eq!(fs::read(&path).unwrap(), b"second job");
            let third = stage(&path, b"third job");
            fs::write(&path, b"external writer with different length").unwrap();
            assert!(third.publish().is_err());
            assert_eq!(fs::read(&path).unwrap(), b"external writer with different length");
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);

            let race = dir.path().join("race.mov");
            if existing {
                fs::write(&race, b"old").unwrap();
            }
            let a = stage(&race, b"a");
            let b = stage(&race, b"b");
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let barrier_b = barrier.clone();
            let successes = std::thread::scope(|scope| {
                let a = scope.spawn(move || {
                    barrier.wait();
                    a.publish().is_ok()
                });
                let b = scope.spawn(move || {
                    barrier_b.wait();
                    b.publish().is_ok()
                });
                usize::from(a.join().unwrap()) + usize::from(b.join().unwrap())
            });
            assert_eq!(successes, 1);
            assert!(matches!(fs::read(race).unwrap().as_slice(), b"a" | b"b"));
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
        }
    }

    #[test]
    fn publication_failure_leaves_destination_and_no_staging() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie.mov");
        let staged = stage(&path, b"complete movie");
        fs::create_dir(&path).unwrap();
        assert!(staged.publish().is_err());
        assert!(path.is_dir());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn hardlink_aliases_are_rejected_without_touching_either_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie.mov");
        let alias = dir.path().join("alias.mov");
        fs::write(&path, b"original").unwrap();
        fs::hard_link(&path, &alias).unwrap();
        assert!(Staged::create(path.to_str().unwrap()).is_err());
        assert_eq!(fs::read(path).unwrap(), b"original");
        assert_eq!(fs::read(alias).unwrap(), b"original");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn relative_and_dangling_links_preserve_links_and_retargeting_fails() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("movie.mov");
        let link = dir.path().join("link.mov");
        let chain = dir.path().join("chain.mov");
        symlink("movie.mov", &link).unwrap();
        symlink("link.mov", &chain).unwrap();
        stage(&chain, b"first").publish().unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"first");
        stage(&chain, b"second").publish().unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"second");
        assert_eq!(fs::read_link(&link).unwrap(), Path::new("movie.mov"));
        let staged = stage(&chain, b"stale");
        fs::remove_file(&link).unwrap();
        symlink("elsewhere.mov", &link).unwrap();
        assert!(staged.publish().is_err());
        assert!(!dir.path().join("elsewhere.mov").exists());
        fs::remove_file(&link).unwrap();
        symlink("chain.mov", &link).unwrap();
        assert!(Staged::create(chain.to_str().unwrap()).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"second");
    }

    #[cfg(unix)]
    #[test]
    fn unix_modes_group_and_policy_changes_are_preserved_or_rejected() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        for mode in [0o600, 0o640, 0o660] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("movie.mov");
            fs::write(&path, b"old").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            let before = fs::metadata(&path).unwrap();
            let staged = stage(&path, b"replacement");
            assert_eq!(fs::metadata(&staged.temporary).unwrap().permissions().mode() & 0o077, 0);
            staged.publish().unwrap();
            let after = fs::metadata(&path).unwrap();
            assert_eq!((after.uid(), after.gid(), after.mode()), (before.uid(), before.gid(), before.mode()));
            let staged = stage(&path, b"must not publish");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
            assert!(staged.publish().is_err());
            assert_eq!(fs::read(&path).unwrap(), b"replacement");
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_inherited_and_protected_acls_and_policy_changes() {
        use windows_permissions::{
            constants::{SeObjectType as O, SecurityInformation as S},
            wrappers as w,
        };
        for protected in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("movie.mov");
            fs::write(&path, b"old").unwrap();
            let owner = w::GetNamedSecurityInfo(path.as_os_str(), O::SE_FILE_OBJECT, S::Owner).unwrap();
            let sid = w::ConvertSidToStringSid(w::GetSecurityDescriptorOwner(&owner).unwrap().unwrap()).unwrap();
            let restricted = w::ConvertStringSecurityDescriptorToSecurityDescriptor(&format!("D:P(A;;FA;;;{})", sid.to_string_lossy())).unwrap();
            if protected {
                w::SetNamedSecurityInfo(
                    path.as_os_str(),
                    O::SE_FILE_OBJECT,
                    S::Dacl | S::ProtectedDacl,
                    None,
                    None,
                    w::GetSecurityDescriptorDacl(&restricted).unwrap(),
                    None,
                )
                .unwrap();
            }
            let expected = platform::Policy::read(&path).unwrap();
            let staged = stage(&path, b"replacement");
            let private = w::GetNamedSecurityInfo(staged.temporary.as_os_str(), O::SE_FILE_OBJECT, S::Dacl).unwrap();
            let private_text = w::ConvertSecurityDescriptorToStringSecurityDescriptor(&private, S::Dacl).unwrap();
            assert_eq!(private_text.to_string_lossy().replace("D:PAI", "D:P"), format!("D:P(A;;FA;;;{})", sid.to_string_lossy()));
            staged.publish().unwrap();
            assert_eq!(platform::Policy::read(&path).unwrap(), expected);
            let staged = stage(&path, b"must not publish");
            let original_permissions = fs::metadata(&path).unwrap().permissions();
            let mut permissions = original_permissions.clone();
            permissions.set_readonly(true);
            fs::set_permissions(&path, permissions).unwrap();
            assert!(staged.publish().is_err());
            assert_eq!(fs::read(&path).unwrap(), b"replacement");
            fs::set_permissions(&path, original_permissions).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_named_acl_and_setgid_parent_do_not_broaden_replacement() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("movie.mov");
        fs::write(&path, b"old").unwrap();
        // Linux POSIX ACL xattr format: version followed by tag, permissions, numeric ID.
        let mut acl = 2_u32.to_le_bytes().to_vec();
        for (tag, perms, id) in [(1_u16, 6_u16, u32::MAX), (2, 4, 12345), (4, 0, u32::MAX), (16, 4, u32::MAX), (32, 0, u32::MAX)] {
            acl.extend(tag.to_le_bytes());
            acl.extend(perms.to_le_bytes());
            acl.extend(id.to_le_bytes());
        }
        xattr::set(&path, "system.posix_acl_access", &acl).unwrap();
        let expected = platform::Policy::read(&path).unwrap();
        if fs::metadata(&path).unwrap().uid() == 0 {
            // The local Linux probe runs as root, allowing a genuine different-group case.
            std::os::unix::fs::chown(dir.path(), None, Some(54321)).unwrap();
        }
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o2770)).unwrap();
        let mut inherited_acl = acl.clone();
        inherited_acl[16..20].copy_from_slice(&23456_u32.to_le_bytes());
        xattr::set(dir.path(), "system.posix_acl_default", &inherited_acl).unwrap();
        stage(&path, b"replacement").publish().unwrap();
        assert_eq!(platform::Policy::read(&path).unwrap(), expected);
        assert_eq!(xattr::get(&path, "system.posix_acl_access").unwrap().unwrap(), acl);
        let staged = stage(&path, b"stale policy");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o2700)).unwrap();
        assert!(staged.publish().is_err());
        assert_eq!(fs::read(path).unwrap(), b"replacement");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_inherited_acl_is_absent_from_private_staging_and_restored_on_publish() {
        let dir = tempfile::tempdir().unwrap();
        let acl =
            [exacl::AclEntry::allow_group("everyone", exacl::Perm::READ | exacl::Perm::EXECUTE, exacl::Flag::FILE_INHERIT | exacl::Flag::DIRECTORY_INHERIT)];
        exacl::setfacl(&[dir.path()], &acl, None).unwrap();
        let path = dir.path().join("movie.mov");
        fs::write(&path, b"old").unwrap();
        let expected = platform::Policy::read(&path).unwrap();
        let staged = stage(&path, b"replacement");
        assert!(exacl::getfacl(&staged.temporary, None).unwrap().is_empty());
        staged.publish().unwrap();
        assert_eq!(platform::Policy::read(&path).unwrap(), expected);
        assert_eq!(fs::read(path).unwrap(), b"replacement");
    }
    /// More frames than a typical descriptor limit: snapshots retain metadata, not open files.
    #[test]
    fn replacement_sequence_keeps_file_handle_use_constant() {
        let dir = tempfile::tempdir().unwrap();
        let mut pending = Vec::new();
        for frame in 0..1536 {
            let path = dir.path().join(format!("frame_{frame}.png"));
            fs::write(&path, b"old").unwrap();
            pending.push(stage(&path, b"new"));
        }
        for staged in pending {
            let path = staged.path.clone();
            assert_eq!(fs::read(&path).unwrap(), b"old");
            staged.publish().unwrap();
            assert_eq!(fs::read(&path).unwrap(), b"new");
        }
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1536);
    }
}
