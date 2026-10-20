//! CI-only launcher for tests requiring Windows audit-policy privileges.
//! Enables a privilege already granted to this process; it cannot grant one to an
//! ordinary account. Children inherit it. The application never performs this step.

/// Run the complete Windows filesystem and export contract with audit access enabled.
#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use windows_permissions::{
        constants::{SeObjectType, SecurityInformation},
        wrappers,
    };
    use winsafe::{DisabPriv, HPROCESS, LUID_AND_ATTRIBUTES, TOKEN_PRIVILEGES, co};

    let token = HPROCESS::GetCurrentProcess().OpenProcessToken(co::TOKEN::ADJUST_PRIVILEGES | co::TOKEN::QUERY)?;
    let luid = winsafe::LookupPrivilegeValue(None, co::SE_PRIV::SECURITY_NAME)?;
    let privileges = TOKEN_PRIVILEGES::new(&[LUID_AND_ATTRIBUTES::new(luid, co::SE_PRIV_ATTR::ENABLED)])?;
    token.AdjustTokenPrivileges(DisabPriv::Privs(&privileges))?;
    // AdjustTokenPrivileges can succeed without assigning every requested privilege.
    // Prove full SACL access before claiming that privileged tests can run.
    let probe = tempfile::NamedTempFile::new()?;
    wrappers::GetNamedSecurityInfo(probe.path().as_os_str(), SeObjectType::SE_FILE_OBJECT, SecurityInformation::Sacl)?;
    probe.close()?;

    for selection in [vec!["--lib", "pending::native"], vec!["--test", "render_settings"]] {
        let status = std::process::Command::new(env!("CARGO"))
            .args(["test", "--locked", "--release", "-p", "effectcraft-export"])
            .args(selection)
            .args(["--", "--include-ignored"])
            .status()?;
        if !status.success() {
            return Err(std::io::Error::other("Windows audit export tests failed").into());
        }
    }
    Ok(())
}

/// Audit privileges are Windows-specific; other platforms use the ordinary test commands.
#[cfg(not(windows))]
fn main() {}
