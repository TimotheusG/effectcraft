use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io,
    path::Path,
};
use windows_permissions::{
    constants::{SeObjectType as O, SecurityInformation as S},
    wrappers as w,
};

const OBJECT: O = O::SE_FILE_OBJECT;

#[derive(Clone, Debug, Eq)]
pub(super) struct Policy {
    descriptor: OsString,
    readonly: bool,
}

impl PartialEq for Policy {
    /// Compare access policy while tolerating Windows' duplicate-grant legacy conversion.
    fn eq(&self, other: &Self) -> bool {
        self.readonly == other.readonly
            && comparison_descriptor(&self.descriptor.to_string_lossy()) == comparison_descriptor(&other.descriptor.to_string_lossy())
    }
}

/// Canonicalize only simple, unprotected file allow ACLs whose inherited ACEs duplicate
/// explicit grants. SetNamedSecurityInfo adds these during legacy ACL conversion; AI
/// records conversion to the current inheritance model. All other descriptors remain
/// exact, including denies, new inherited rights, owner/group, protection, and SACLs.
fn comparison_descriptor(descriptor: &str) -> String {
    let Some((owner, acl)) = descriptor.split_once("D:") else { return descriptor.into() };
    let (acl, sacl) = match acl.split_once("S:") {
        Some((acl, sacl)) => (acl, Some(sacl)),
        None => (acl, None),
    };
    let acl = acl.strip_prefix("AI").unwrap_or(acl);
    let aces = acl.split_inclusive(')').collect::<Vec<_>>();
    if aces.is_empty()
        || !aces.iter().all(|ace| {
            let fields = ace.split(';').collect::<Vec<_>>();
            fields.len() == 6
                && fields.first() == Some(&"(A")
                && matches!(fields.get(1), Some(&"") | Some(&"ID"))
                && fields.get(3) == Some(&"")
                && fields.get(4) == Some(&"")
                && ace.ends_with(')')
                && ace.matches('(').count() == 1
        })
    {
        return descriptor.into();
    }
    for ace in &aces {
        if let Some(grant) = ace.strip_prefix("(A;ID;")
            && !aces.iter().any(|other| other.strip_prefix("(A;;") == Some(grant))
        {
            return descriptor.into();
        }
    }
    let mut result = format!("{owner}D:");
    for ace in aces.iter().filter(|ace| ace.starts_with("(A;;")) {
        result.push_str(ace);
    }
    if let Some(sacl) = sacl {
        result.push_str("S:");
        result.push_str(sacl);
    }
    result
}

impl Policy {
    /// Snapshot ownership, access controls, and permission state used for publication checks.
    pub fn read(path: &Path) -> io::Result<Self> {
        let descriptor = w::GetNamedSecurityInfo(path.as_os_str(), OBJECT, S::Owner | S::Group | S::Dacl | S::Label | S::Attribute | S::Scope)?;
        Ok(Self {
            descriptor: w::ConvertSecurityDescriptorToStringSecurityDescriptor(&descriptor, S::Owner | S::Group | S::Dacl | S::Sacl)?,
            readonly: path.metadata()?.permissions().readonly(),
        })
    }

    /// Restore the captured access policy; unsupported or unauthorized changes fail closed.
    pub fn apply(&self, path: &Path) -> io::Result<()> {
        let descriptor = w::ConvertStringSecurityDescriptorToSecurityDescriptor(&self.descriptor)?;
        // SDDL's D: flags precede the first ACE. Preserve inheritance instead of freezing
        // every inherited ACE as an explicit grant. Staging is a sibling of the final file.
        let text = self.descriptor.to_string_lossy();
        let protected = text.split("D:").nth(1).unwrap_or("").split('(').next().unwrap_or("").split("S:").next().unwrap_or("").contains('P');
        let sacl = w::GetSecurityDescriptorSacl(&descriptor)?;
        let mut flags = S::Owner | S::Group | S::Dacl | if protected { S::ProtectedDacl } else { S::UnprotectedDacl };
        if sacl.is_some() {
            flags |= S::Label | S::Attribute | S::Scope;
        }
        w::SetNamedSecurityInfo(
            path.as_os_str(),
            OBJECT,
            flags,
            w::GetSecurityDescriptorOwner(&descriptor)?,
            w::GetSecurityDescriptorGroup(&descriptor)?,
            w::GetSecurityDescriptorDacl(&descriptor)?,
            sacl,
        )?;
        let mut permissions = path.metadata()?.permissions();
        permissions.set_readonly(self.readonly);
        fs::set_permissions(path, permissions)
    }
}

/// Create an empty probe using the destination directory's ordinary creation policy.
pub(super) fn ordinary_file(parent: &Path) -> io::Result<tempfile::NamedTempFile> {
    tempfile::Builder::new().prefix(".effectcraft-policy-").tempfile_in(parent)
}

/// Create job-owned staging that is private before any media bytes are written.
pub(super) fn private_file(parent: &Path) -> io::Result<(tempfile::NamedTempFile, Option<tempfile::TempDir>)> {
    let file = tempfile::Builder::new().prefix(".effectcraft-export-").make_in(parent, |path| {
        let name = path.to_str().ok_or_else(|| io::Error::other("non-Unicode export staging path"))?;
        let mut acl = winsafe::ACL { AclRevision: 2, AclSize: std::mem::size_of::<winsafe::ACL>() as u16, ..Default::default() };
        let mut descriptor = winsafe::InitializeSecurityDescriptor().map_err(io::Error::other)?;
        descriptor.Control = winsafe::co::SE::DACL_PRESENT | winsafe::co::SE::DACL_PROTECTED;
        descriptor.Dacl = &mut acl;
        let mut attributes = winsafe::SECURITY_ATTRIBUTES::default();
        attributes.set_lpSecurityDescriptor(Some(&mut descriptor));
        // An empty protected DACL denies access at creation, including during the transition
        // to owner-only access. No broadly readable handle can predate the media writes.
        let (handle, _) = winsafe::HFILE::CreateFile(
            name,
            winsafe::co::GENERIC::READ | winsafe::co::GENERIC::WRITE,
            Some(winsafe::co::FILE_SHARE::READ | winsafe::co::FILE_SHARE::WRITE | winsafe::co::FILE_SHARE::DELETE),
            Some(&attributes),
            winsafe::co::DISPOSITION::CREATE_NEW,
            winsafe::co::FILE_ATTRIBUTE::NORMAL,
            None,
            None,
            None,
        )
        .map_err(|error| io::Error::from_raw_os_error(error.raw() as i32))?;
        let result = (|| {
            let owner_descriptor = w::GetNamedSecurityInfo(path.as_os_str(), OBJECT, S::Owner)?;
            let owner = w::GetSecurityDescriptorOwner(&owner_descriptor)?.ok_or_else(|| io::Error::other("staging has no owner"))?;
            let sid = w::ConvertSidToStringSid(owner)?;
            let private = w::ConvertStringSecurityDescriptorToSecurityDescriptor(&format!("D:P(A;;FA;;;{})", sid.to_string_lossy()))?;
            w::SetNamedSecurityInfo(path.as_os_str(), OBJECT, S::Dacl | S::ProtectedDacl, None, None, w::GetSecurityDescriptorDacl(&private)?, None)?;
            OpenOptions::new().read(true).write(true).open(path)
        })();
        drop(handle);
        if result.is_err() {
            let _ = fs::remove_file(path); // No media exists; retain the original setup error.
        }
        result
    })?;
    Ok((file, None))
}

/// Identify the open inode independently of its pathname.
pub(super) fn identity(file: &File) -> io::Result<(u64, u64)> {
    let info = winapi_util::file::information(file)?;
    Ok((info.volume_serial_number(), info.file_index()))
}

/// Count aliases so replacement cannot silently detach a hard-linked destination.
pub(super) fn links(file: &File) -> io::Result<u64> {
    Ok(winapi_util::file::information(file)?.number_of_links())
}

/// Capture creation time as an additional guard against reused file identities.
pub(super) fn change_stamp(file: &File) -> io::Result<(i64, i64)> {
    let stamp = winapi_util::file::information(file)?.creation_time().ok_or_else(|| io::Error::other("missing file creation time"))?;
    Ok((stamp as i64, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The runner's legacy ACL conversion is equivalent; additional rights or changed
    /// ownership, protection, denies, and security labels must still be rejected.
    #[test]
    fn legacy_conversion_accepts_only_duplicate_allow_grants() {
        let old = "O:BAG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)";
        let converted = "O:BAG:SYD:AI(A;;FA;;;SY)(A;;FA;;;BA)(A;ID;FA;;;SY)(A;ID;FA;;;BA)";
        assert_eq!(comparison_descriptor(old), comparison_descriptor(converted));
        for changed in [
            converted.replace("O:BA", "O:SY"),
            converted.replace("D:AI", "D:PAI"),
            format!("{converted}(A;ID;FA;;;WD)"),
            converted.replace("(A;ID;FA;;;BA)", "(A;ID;FR;;;BA)"),
            format!("{converted}S:(ML;;NW;;;LW)"),
        ] {
            assert_ne!(comparison_descriptor(old), comparison_descriptor(&changed), "{changed}");
        }
        assert_ne!(comparison_descriptor("O:BAG:SYD:(D;;FW;;;WD)(A;;FA;;;SY)"), comparison_descriptor("O:BAG:SYD:AI(D;;FW;;;WD)(A;;FA;;;SY)(A;ID;FA;;;SY)"));
    }
}
