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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Policy {
    descriptor: OsString,
    readonly: bool,
}

impl Policy {
    pub fn read(path: &Path) -> io::Result<Self> {
        let descriptor = w::GetNamedSecurityInfo(path.as_os_str(), OBJECT, S::Owner | S::Group | S::Dacl | S::Label | S::Attribute | S::Scope)?;
        Ok(Self {
            descriptor: w::ConvertSecurityDescriptorToStringSecurityDescriptor(&descriptor, S::Owner | S::Group | S::Dacl | S::Sacl)?,
            readonly: path.metadata()?.permissions().readonly(),
        })
    }

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

pub(super) fn ordinary_file(parent: &Path) -> io::Result<tempfile::NamedTempFile> {
    tempfile::Builder::new().prefix(".effectcraft-policy-").tempfile_in(parent)
}

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

pub(super) fn identity(file: &File) -> io::Result<(u64, u64)> {
    let info = winapi_util::file::information(file)?;
    Ok((info.volume_serial_number(), info.file_index()))
}

pub(super) fn links(file: &File) -> io::Result<u64> {
    Ok(winapi_util::file::information(file)?.number_of_links())
}

pub(super) fn change_stamp(file: &File) -> io::Result<(i64, i64)> {
    let stamp = winapi_util::file::information(file)?.creation_time().ok_or_else(|| io::Error::other("missing file creation time"))?;
    Ok((stamp as i64, 0))
}
