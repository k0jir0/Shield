use std::ffi::{OsStr, c_void};
use std::fs::File;
use std::io::{Read, Write};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use uuid::Uuid;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::EventLog::*;
use windows_sys::Win32::System::IO::*;
use windows_sys::Win32::System::Pipes::*;
use windows_sys::Win32::System::Services::*;
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::UI::Shell::FOLDERID_ProgramFiles;

use crate::endpoint::{self, ChangeApproval, Plan, PolicyIdentity};
use crate::error::{Error, Result, invalid};
use crate::platform::{self, SecurityDescriptor, SystemLibrary, check, sid_string};
use crate::profile::{EndpointVerifier, Profile};
use crate::state::Store;
use crate::util::is_sha256 as digest_valid;
use crate::{files, util};

mod cleanup;
pub use cleanup::{inspect_cleanup, perform_cleanup};

const SYSTEM_SID: &str = "S-1-5-18";
const ADMIN_SID: &str = "S-1-5-32-544";
const CONFIG_BYTES: u64 = 80 * 1024;
const IMAGE_BYTES: u64 = 128 * 1024 * 1024;
const FRAME_BYTES: usize = 4096;
const QUERY_TIME: Duration = Duration::from_secs(10);
const CHANGE_TIME: Duration = Duration::from_secs(15);
const SERVICE_READ: u32 = SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL;
const FILE_READ_EXECUTE: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
const PIPE_CLIENT: u32 = FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE;
const SECURITY: u32 = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
const MARKERS: [&str; 4] = [
    "install.intent",
    "install.confirmed",
    "remove.intent",
    "remove.confirmed",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    schema: u32,
    profile: Profile,
    plan: Uuid,
    plan_sha256: String,
    policy: PolicyIdentity,
}

impl Binding {
    fn new(profile: &Profile, plan: &Plan) -> Result<Self> {
        if plan.profile_digest != profile.digest()? {
            return Err(Error::Denied(
                "verifier plan/profile binding differs".into(),
            ));
        }
        let binding = Self {
            schema: 1,
            profile: profile.clone(),
            plan: plan.id,
            plan_sha256: plan.digest()?,
            policy: plan.policy_identity(),
        };
        binding.validate(profile.id, plan.id)?;
        Ok(binding)
    }

    fn validate(&self, profile: Uuid, plan: Uuid) -> Result<()> {
        self.profile.validate()?;
        if self.schema != 1
            || self.profile.endpoint_verifier != EndpointVerifier::ProtectedService
            || self.profile.id != profile
            || matches!(self.profile.owner_sid.as_str(), SYSTEM_SID | ADMIN_SID)
            || self.plan != plan
            || plan.is_nil()
            || self.policy.policy_id != profile
            || !digest_valid(&self.plan_sha256)
            || !digest_valid(&self.policy.cip_sha256)
        {
            return Err(invalid("invalid protected endpoint verifier binding"));
        }
        Ok(())
    }

    fn digest(&self) -> Result<String> {
        let mut bytes = b"Shield/read-only-endpoint-verifier/v1\0".to_vec();
        bytes.extend(serde_json::to_vec(self)?);
        Ok(util::digest(&bytes))
    }

    fn image_command(&self, paths: &Paths) -> String {
        format!(
            "\"{}\" __verifier-service {} {} {}",
            paths.image().display(),
            self.profile.id,
            self.plan,
            self.profile.owner_sid
        )
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    nonce: Uuid,
    binding_sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
enum Response {
    Verified { nonce: Uuid, binding_sha256: String },
    Failed { nonce: Uuid, reason: String },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Acknowledgment {
    nonce: Uuid,
}

fn verify_request(request: &Request, expected: &str) -> Result<()> {
    if request.nonce.is_nil() || request.binding_sha256 != expected {
        return Err(Error::Denied("verifier request binding differs".into()));
    }
    Ok(())
}

fn verify_response(response: Response, nonce: Uuid, binding: &str) -> Result<()> {
    match response {
        Response::Verified {
            nonce: actual,
            binding_sha256,
        } if actual == nonce && binding_sha256 == binding => Ok(()),
        Response::Failed {
            nonce: actual,
            reason,
        } if actual == nonce => Err(Error::Denied(format!(
            "protected endpoint verifier refused: {}",
            util::literal(&reason)
        ))),
        _ => Err(Error::Denied(
            "verifier response is stale or differently bound".into(),
        )),
    }
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

fn win_error(operation: &'static str) -> Error {
    Error::Windows {
        operation,
        source: std::io::Error::last_os_error(),
    }
}

fn handle(raw: HANDLE, operation: &'static str) -> Result<OwnedHandle> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        Err(win_error(operation))
    } else {
        Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
    }
}

struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        if unsafe { CloseServiceHandle(self.0) } == 0 {
            eprintln!("Shield verifier: {}", win_error("CloseServiceHandle"));
        }
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

struct Paths {
    profile: PathBuf,
    plan: PathBuf,
}

fn program_files() -> Result<PathBuf> {
    // Shell/COM must not be loaded when this same executable starts as the LPAC worker.
    let shell = SystemLibrary::load("shell32.dll")?;
    let com = SystemLibrary::load("combase.dll")?;
    type KnownFolderPath = unsafe extern "system" fn(
        *const windows_sys::core::GUID,
        u32,
        HANDLE,
        *mut *mut u16,
    ) -> i32;
    type TaskMemFree = unsafe extern "system" fn(*const c_void);
    let get = unsafe {
        std::mem::transmute::<unsafe extern "system" fn() -> isize, KnownFolderPath>(
            shell.export(b"SHGetKnownFolderPath\0")?,
        )
    };
    let free = unsafe {
        std::mem::transmute::<unsafe extern "system" fn() -> isize, TaskMemFree>(
            com.export(b"CoTaskMemFree\0")?,
        )
    };
    let mut raw = null_mut();
    let status = unsafe { get(&FOLDERID_ProgramFiles, 0, null_mut(), &mut raw) };
    if status < 0 {
        return Err(Error::Unsupported(format!(
            "SHGetKnownFolderPath returned HRESULT {status:#x}"
        )));
    }
    let parsed = unsafe { native_string(raw) };
    unsafe { free(raw.cast()) };
    Ok(PathBuf::from(parsed?))
}

impl Paths {
    fn new(profile: Uuid, plan: Uuid) -> Result<Self> {
        if profile.is_nil() || plan.is_nil() {
            return Err(invalid("nil verifier profile/plan ID"));
        }
        let profile = program_files()?.join(format!("Shield.Verifier.{profile}"));
        files::validate_path(&profile)?;
        Ok(Self {
            plan: profile.join(plan.to_string()),
            profile,
        })
    }

    fn image(&self) -> PathBuf {
        self.plan.join("shield-verifier.exe")
    }

    fn config(&self) -> PathBuf {
        self.plan.join("binding.json")
    }
}

unsafe fn native_string(pointer: *const u16) -> Result<String> {
    if pointer.is_null() {
        return Err(invalid("missing native service string"));
    }
    unsafe {
        for length in 0..32768 {
            if *pointer.add(length) == 0 {
                return String::from_utf16(std::slice::from_raw_parts(pointer, length))
                    .map_err(|_| invalid("invalid native service string"));
            }
        }
    }
    Err(invalid("native service string exceeds its bound"))
}

fn service_name(profile: Uuid) -> String {
    format!("Shield.Verifier.{profile}")
}

fn pipe_name(profile: Uuid) -> Vec<u16> {
    wide(format!(r"\\.\pipe\Shield.Verifier.{profile}"))
}

fn descriptor(owner: &str, rights: u32, directory: bool) -> Result<SecurityDescriptor> {
    let inherit = if directory { "OICI" } else { "" };
    SecurityDescriptor::from_sddl(&format!(
        "O:BAG:BAD:P(A;{inherit};FA;;;SY)(A;{inherit};FA;;;BA)(A;{inherit};0x{rights:x};;;{owner})"
    ))
}

fn service_descriptor(owner: &str) -> Result<SecurityDescriptor> {
    SecurityDescriptor::from_sddl(&format!(
        "O:BAG:BAD:P(A;;0x{SERVICE_ALL_ACCESS:x};;;SY)(A;;0x{SERVICE_ALL_ACCESS:x};;;BA)(A;;0x{SERVICE_READ:x};;;{owner})"
    ))
}

fn query_descriptor(owner: &str, rights: u32) -> Result<SecurityDescriptor> {
    SecurityDescriptor::from_sddl(&format!(
        "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x{rights:x};;;{owner})"
    ))
}

fn verify_descriptor(raw: PSECURITY_DESCRIPTOR, owner: &str, rights: u32, all: u32) -> Result<()> {
    unsafe {
        if IsValidSecurityDescriptor(raw) == 0 {
            return Err(invalid("invalid verifier security descriptor"));
        }
        let mut actual_owner = null_mut();
        let mut defaulted = 0;
        check(
            GetSecurityDescriptorOwner(raw, &mut actual_owner, &mut defaulted),
            "GetSecurityDescriptorOwner verifier",
        )?;
        if !matches!(sid_string(actual_owner)?.as_str(), SYSTEM_SID | ADMIN_SID) {
            return Err(Error::Denied(
                "verifier object is not administrator/SYSTEM owned".into(),
            ));
        }
        let mut control = 0;
        let mut revision = 0;
        check(
            GetSecurityDescriptorControl(raw, &mut control, &mut revision),
            "GetSecurityDescriptorControl verifier",
        )?;
        let mut present = 0;
        let mut dacl = null_mut();
        check(
            GetSecurityDescriptorDacl(raw, &mut present, &mut dacl, &mut defaulted),
            "GetSecurityDescriptorDacl verifier",
        )?;
        if control & SE_DACL_PROTECTED == 0
            || present == 0
            || dacl.is_null()
            || IsValidAcl(dacl) == 0
            || (*dacl).AceCount != 3
        {
            return Err(Error::Denied(
                "verifier DACL is inherited, absent, or contains unexpected entries".into(),
            ));
        }
        let mut principals = Vec::new();
        for index in 0..3 {
            let mut ace = null_mut();
            check(GetAce(dacl, index, &mut ace), "GetAce verifier")?;
            let header = &*ace.cast::<ACE_HEADER>();
            if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
                || u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0
                || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
            {
                return Err(Error::Denied("unexpected verifier ACE".into()));
            }
            let ace = &*ace.cast::<ACCESS_ALLOWED_ACE>();
            let sid = sid_string(std::ptr::addr_of!(ace.SidStart).cast_mut().cast())?;
            let expected = match sid.as_str() {
                SYSTEM_SID | ADMIN_SID => all,
                value if value == owner => rights,
                _ => return Err(Error::Denied("unexpected verifier principal".into())),
            };
            if ace.Mask != expected || principals.contains(&sid) {
                return Err(Error::Denied(
                    "verifier permissions exceed or differ from the frozen role".into(),
                ));
            }
            principals.push(sid);
        }
    }
    Ok(())
}

fn verify_file_security(file: &File, owner: &str) -> Result<()> {
    let mut raw = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            SECURITY,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut raw,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(Error::Windows {
            operation: "GetSecurityInfo verifier file",
            source: std::io::Error::from_raw_os_error(status as i32),
        });
    }
    let _allocation = LocalAllocation(raw);
    verify_descriptor(raw, owner, FILE_READ_EXECUTE, FILE_ALL_ACCESS)
}

fn verify_directory(path: &Path, owner: &str) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    files::check_no_reparse(path)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    if !file.metadata()?.is_dir() {
        return Err(invalid("verifier directory is not a directory"));
    }
    verify_file_security(&file, owner)?;
    Ok(file)
}

fn create_directory(path: &Path, owner: &str) -> Result<()> {
    let security = descriptor(owner, FILE_READ_EXECUTE, true)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.as_ptr(),
        bInheritHandle: 0,
    };
    check(
        unsafe { CreateDirectoryW(wide(path).as_ptr(), &attributes) },
        "CreateDirectoryW protected verifier",
    )?;
    let _pin = verify_directory(path, owner)?;
    Ok(())
}

fn create_file(path: &Path, owner: &str) -> Result<File> {
    let security = descriptor(owner, FILE_READ_EXECUTE, false)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.as_ptr(),
        bInheritHandle: 0,
    };
    let raw = unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            GENERIC_WRITE | READ_CONTROL,
            FILE_SHARE_READ,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    let file = File::from(handle(raw, "CreateFileW protected verifier")?);
    verify_file_security(&file, owner)?;
    Ok(file)
}

fn write_new(path: &Path, owner: &str, bytes: &[u8]) -> Result<()> {
    let mut file = create_file(path, owner)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

struct ProtectedBinding {
    binding: Binding,
    paths: Paths,
    _pins: Vec<File>,
}

fn protected_pin(path: &Path, owner: &str, limit: u64) -> Result<(File, files::Fingerprint)> {
    use std::os::windows::fs::OpenOptionsExt;
    files::check_no_reparse(path)?;
    let validation = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    verify_file_security(&validation, owner)?;
    let result = files::pin(path, limit);
    drop(validation);
    result
}

fn read_binding(profile: Uuid, plan: Uuid, owner: &str) -> Result<ProtectedBinding> {
    let paths = Paths::new(profile, plan)?;
    let profile_pin = verify_directory(&paths.profile, owner)?;
    cleanup::ensure_not_retired(&paths, plan)?;
    let plan_pin = verify_directory(&paths.plan, owner)?;
    let (mut file, _) = protected_pin(&paths.config(), owner, CONFIG_BYTES)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let binding: Binding = serde_json::from_slice(&bytes)?;
    binding.validate(profile, plan)?;
    if binding.profile.owner_sid != owner {
        return Err(Error::Denied(
            "verifier manifest owner differs from its protected SCM binding".into(),
        ));
    }
    let mut pins = vec![profile_pin, plan_pin, file];
    let (image, fingerprint) = protected_pin(&paths.image(), owner, IMAGE_BYTES)?;
    if fingerprint.sha256 != binding.profile.binary_sha256 {
        return Err(Error::Denied("protected verifier image drifted".into()));
    }
    if binding.profile.publisher_cert_sha256.is_some() {
        binding.profile.verify_image(&paths.image())?;
    }
    pins.push(image);
    Ok(ProtectedBinding {
        binding,
        paths,
        _pins: pins,
    })
}

fn require_binding(protected: &ProtectedBinding, expected: &Binding) -> Result<()> {
    if protected.binding.digest()? != expected.digest()? {
        return Err(Error::Denied(
            "protected verifier does not bind this exact profile and endpoint plan".into(),
        ));
    }
    Ok(())
}

fn marker(protected: &ProtectedBinding, name: &str) -> Result<bool> {
    if !MARKERS.contains(&name) {
        return Err(invalid("unknown verifier lifecycle marker"));
    }
    let path = protected.paths.plan.join(name);
    if !path.try_exists()? {
        return Ok(false);
    }
    let (mut file, _) = protected_pin(&path, &protected.binding.profile.owner_sid, 64)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if bytes != protected.binding.digest()?.as_bytes() {
        return Err(Error::Denied(
            "protected verifier lifecycle marker binding differs".into(),
        ));
    }
    Ok(true)
}

fn mark(protected: &ProtectedBinding, name: &str) -> Result<()> {
    if !MARKERS.contains(&name) {
        return Err(invalid("unknown verifier lifecycle marker"));
    }
    write_new(
        &protected.paths.plan.join(name),
        &protected.binding.profile.owner_sid,
        protected.binding.digest()?.as_bytes(),
    )
}

fn require_installed(protected: &ProtectedBinding) -> Result<()> {
    if !marker(protected, "install.intent")?
        || !marker(protected, "install.confirmed")?
        || marker(protected, "remove.intent")?
        || marker(protected, "remove.confirmed")?
    {
        return Err(Error::Unknown(
            "verifier installation is incomplete, being removed, or removed; reconcile explicitly"
                .into(),
        ));
    }
    Ok(())
}

fn manager(access: u32) -> Result<ScHandle> {
    let raw = unsafe { OpenSCManagerW(null(), null(), access) };
    if raw.is_null() {
        return Err(win_error("OpenSCManagerW verifier"));
    }
    Ok(ScHandle(raw))
}

fn open_service(manager: &ScHandle, profile: Uuid, access: u32) -> Result<Option<ScHandle>> {
    let raw = unsafe { OpenServiceW(manager.0, wide(service_name(profile)).as_ptr(), access) };
    if !raw.is_null() {
        return Ok(Some(ScHandle(raw)));
    }
    if unsafe { GetLastError() } == ERROR_SERVICE_DOES_NOT_EXIST {
        return Ok(None);
    }
    Err(win_error("OpenServiceW verifier"))
}

fn required_service(profile: Uuid, access: u32) -> Result<ScHandle> {
    open_service(&manager(SC_MANAGER_CONNECT)?, profile, access)?.ok_or_else(|| {
        Error::Denied("the explicitly enrolled protected verifier service is absent".into())
    })
}

fn service_status(service: &ScHandle) -> Result<SERVICE_STATUS_PROCESS> {
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0;
    check(
        unsafe {
            QueryServiceStatusEx(
                service.0,
                SC_STATUS_PROCESS_INFO,
                (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
                size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            )
        },
        "QueryServiceStatusEx verifier",
    )?;
    Ok(status)
}

fn verify_service(service: &ScHandle, protected: &ProtectedBinding) -> Result<()> {
    let mut config = vec![0_usize; 8192_usize.div_ceil(size_of::<usize>())];
    let mut needed = 0;
    check(
        unsafe { QueryServiceConfigW(service.0, config.as_mut_ptr().cast(), 8192, &mut needed) },
        "QueryServiceConfigW verifier",
    )?;
    let config = unsafe { &*config.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
    if config.dwServiceType != SERVICE_WIN32_OWN_PROCESS
        || config.dwStartType != SERVICE_AUTO_START
        || unsafe { native_string(config.lpBinaryPathName)? }
            != protected.binding.image_command(&protected.paths)
        || unsafe { native_string(config.lpServiceStartName)? } != "LocalSystem"
        || (!config.lpDependencies.is_null() && unsafe { *config.lpDependencies } != 0)
    {
        return Err(Error::Denied(
            "verifier SCM account, image, arguments, dependencies, or startup mode differs".into(),
        ));
    }
    let mut sid = SERVICE_SID_INFO::default();
    check(
        unsafe {
            QueryServiceConfig2W(
                service.0,
                SERVICE_CONFIG_SERVICE_SID_INFO,
                (&mut sid as *mut SERVICE_SID_INFO).cast(),
                size_of::<SERVICE_SID_INFO>() as u32,
                &mut needed,
            )
        },
        "QueryServiceConfig2W verifier SID",
    )?;
    if sid.dwServiceSidType != SERVICE_SID_TYPE_UNRESTRICTED {
        return Err(Error::Denied(
            "verifier service SID configuration differs".into(),
        ));
    }
    let mut security = vec![0_usize; 8192_usize.div_ceil(size_of::<usize>())];
    check(
        unsafe {
            QueryServiceObjectSecurity(
                service.0,
                SECURITY,
                security.as_mut_ptr().cast(),
                8192,
                &mut needed,
            )
        },
        "QueryServiceObjectSecurity verifier",
    )?;
    verify_descriptor(
        security.as_mut_ptr().cast(),
        &protected.binding.profile.owner_sid,
        SERVICE_READ,
        SERVICE_ALL_ACCESS,
    )
}

fn process_identity(pid: u32, image: &Path) -> Result<OwnedHandle> {
    let process = handle(
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) },
        "OpenProcess verifier peer",
    )?;
    if platform::process_user_sid(process.as_raw_handle())? != SYSTEM_SID {
        return Err(Error::Denied("verifier peer is not LocalSystem".into()));
    }
    let mut path = vec![0_u16; 32768];
    let mut length = path.len() as u32;
    check(
        unsafe {
            QueryFullProcessImageNameW(process.as_raw_handle(), 0, path.as_mut_ptr(), &mut length)
        },
        "QueryFullProcessImageNameW verifier",
    )?;
    let actual = String::from_utf16(&path[..length as usize])
        .map_err(|_| invalid("invalid verifier process image"))?;
    if !actual.eq_ignore_ascii_case(&image.to_string_lossy())
        || unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } != WAIT_TIMEOUT
    {
        return Err(Error::Denied(
            "verifier peer image differs or process has exited".into(),
        ));
    }
    Ok(process)
}

fn running_peer(service: &ScHandle, protected: &ProtectedBinding) -> Result<(u32, OwnedHandle)> {
    verify_service(service, protected)?;
    let status = service_status(service)?;
    if status.dwCurrentState != SERVICE_RUNNING || status.dwProcessId == 0 {
        return Err(Error::Denied("protected verifier is not running".into()));
    }
    let process = process_identity(status.dwProcessId, &protected.paths.image())?;
    Ok((status.dwProcessId, process))
}

struct Impersonation {
    active: bool,
}

impl Impersonation {
    fn finish(mut self) -> Result<()> {
        check(unsafe { RevertToSelf() }, "RevertToSelf verifier")?;
        self.active = false;
        Ok(())
    }
}

impl Drop for Impersonation {
    fn drop(&mut self) {
        if self.active && unsafe { RevertToSelf() } == 0 {
            fatal("cannot revert verifier impersonation");
        }
    }
}

fn token_user(token: HANDLE) -> Result<String> {
    let mut bytes = vec![0_usize; 256];
    let mut needed = 0;
    check(
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                bytes.as_mut_ptr().cast(),
                (bytes.len() * size_of::<usize>()) as u32,
                &mut needed,
            )
        },
        "GetTokenInformation verifier client",
    )?;
    unsafe { sid_string((*bytes.as_ptr().cast::<TOKEN_USER>()).User.Sid) }
}

fn authenticate_client(pipe: HANDLE, owner: &str) -> Result<()> {
    check(
        unsafe { ImpersonateNamedPipeClient(pipe) },
        "ImpersonateNamedPipeClient verifier",
    )?;
    let impersonation = Impersonation { active: true };
    let mut raw = null_mut();
    check(
        unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) },
        "OpenThreadToken verifier client",
    )?;
    let token = handle(raw, "verifier client token")?;
    let mut appcontainer = 0_u32;
    let mut needed = 0;
    check(
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenIsAppContainer,
                (&mut appcontainer as *mut u32).cast(),
                size_of::<u32>() as u32,
                &mut needed,
            )
        },
        "GetTokenInformation verifier client AppContainer",
    )?;
    let sid = token_user(token.as_raw_handle())?;
    impersonation.finish()?;
    if sid != owner || appcontainer != 0 {
        return Err(Error::Denied(
            "verifier client is not the enrolled non-AppContainer owner".into(),
        ));
    }
    Ok(())
}

struct Operation {
    event: OwnedHandle,
    overlapped: OVERLAPPED,
}

impl Operation {
    fn new() -> Result<Self> {
        let event = handle(
            unsafe { CreateEventW(null(), 1, 0, null()) },
            "CreateEventW verifier IO",
        )?;
        Ok(Self {
            overlapped: OVERLAPPED {
                hEvent: event.as_raw_handle(),
                ..Default::default()
            },
            event,
        })
    }

    fn cancel(&mut self, pipe: HANDLE) {
        // The kernel must release OVERLAPPED and buffer storage before either is dropped.
        if unsafe { CancelIoEx(pipe, &self.overlapped) } == 0
            && unsafe { GetLastError() } != ERROR_NOT_FOUND
        {
            report_error(&win_error("CancelIoEx verifier").to_string());
        }
        if unsafe { WaitForSingleObject(self.event.as_raw_handle(), 1000) } != WAIT_OBJECT_0 {
            fatal(
                "verifier IO cancellation did not complete; refusing to reuse pending IO storage",
            );
        }
    }

    fn finish(
        &mut self,
        pipe: HANDLE,
        initial: i32,
        deadline: Instant,
        stop: Option<&AtomicBool>,
    ) -> Result<u32> {
        if initial == 0 && unsafe { GetLastError() } != ERROR_IO_PENDING {
            return Err(win_error("verifier pipe IO dispatch"));
        }
        loop {
            let mut bytes = 0;
            if unsafe { GetOverlappedResult(pipe, &self.overlapped, &mut bytes, 0) } != 0 {
                return Ok(bytes);
            }
            if unsafe { GetLastError() } != ERROR_IO_INCOMPLETE {
                return Err(win_error("GetOverlappedResult verifier"));
            }
            if Instant::now() >= deadline || stop.is_some_and(|stop| stop.load(Ordering::Acquire)) {
                self.cancel(pipe);
                return Err(Error::Deadline);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let wait = remaining.as_millis().clamp(1, 100) as u32;
            match unsafe { WaitForSingleObject(self.event.as_raw_handle(), wait) } {
                WAIT_OBJECT_0 | WAIT_TIMEOUT => {}
                _ => {
                    let error = win_error("WaitForSingleObject verifier IO");
                    self.cancel(pipe);
                    return Err(error);
                }
            }
        }
    }
}

fn transfer(
    pipe: HANDLE,
    bytes: &mut [u8],
    writing: bool,
    deadline: Instant,
    stop: Option<&AtomicBool>,
) -> Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        let mut operation = Operation::new()?;
        let count = (bytes.len() - offset) as u32;
        let initial = unsafe {
            if writing {
                WriteFile(
                    pipe,
                    bytes[offset..].as_ptr(),
                    count,
                    null_mut(),
                    &mut operation.overlapped,
                )
            } else {
                ReadFile(
                    pipe,
                    bytes[offset..].as_mut_ptr(),
                    count,
                    null_mut(),
                    &mut operation.overlapped,
                )
            }
        };
        let transferred = operation.finish(pipe, initial, deadline, stop)? as usize;
        if transferred == 0 || transferred > bytes.len() - offset {
            return Err(Error::Protocol("invalid verifier pipe transfer length"));
        }
        offset += transferred;
    }
    Ok(())
}

fn send(
    pipe: HANDLE,
    value: &impl Serialize,
    deadline: Instant,
    stop: Option<&AtomicBool>,
) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.is_empty() || bytes.len() > FRAME_BYTES {
        return Err(invalid("verifier frame exceeds its bound"));
    }
    let mut framed = (bytes.len() as u32).to_le_bytes().to_vec();
    framed.extend(bytes);
    transfer(pipe, &mut framed, true, deadline, stop)
}

fn receive<T: DeserializeOwned>(
    pipe: HANDLE,
    deadline: Instant,
    stop: Option<&AtomicBool>,
) -> Result<T> {
    let mut length = [0_u8; 4];
    transfer(pipe, &mut length, false, deadline, stop)?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > FRAME_BYTES {
        return Err(invalid("invalid verifier frame length"));
    }
    let mut bytes = vec![0; length];
    transfer(pipe, &mut bytes, false, deadline, stop)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn verify_protected(protected: &ProtectedBinding) -> Result<()> {
    require_installed(protected)?;
    let binding = &protected.binding;
    let service = required_service(binding.profile.id, SERVICE_READ)?;
    let (pid, process) = running_peer(&service, protected)?;
    let deadline = Instant::now() + QUERY_TIME;
    let pipe = handle(
        unsafe {
            CreateFileW(
                pipe_name(binding.profile.id).as_ptr(),
                PIPE_CLIENT,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                null_mut(),
            )
        },
        "CreateFileW enrolled verifier pipe",
    )?;
    let mut pipe_pid = 0;
    check(
        unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pipe_pid) },
        "GetNamedPipeServerProcessId verifier",
    )?;
    if pipe_pid != pid {
        return Err(Error::Denied(
            "verifier pipe is not owned by the enrolled service process".into(),
        ));
    }
    let nonce = Uuid::new_v4();
    let binding_sha256 = binding.digest()?;
    send(
        pipe.as_raw_handle(),
        &Request {
            nonce,
            binding_sha256: binding_sha256.clone(),
        },
        deadline,
        None,
    )?;
    let response: Response = receive(pipe.as_raw_handle(), deadline, None)?;
    let result = verify_response(response, nonce, &binding_sha256);
    verify_service(&service, protected)?;
    let after = service_status(&service)?;
    if after.dwCurrentState != SERVICE_RUNNING
        || after.dwProcessId != pid
        || unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } != WAIT_TIMEOUT
    {
        return Err(Error::Denied(
            "verifier exited or changed during the query".into(),
        ));
    }
    send(
        pipe.as_raw_handle(),
        &Acknowledgment { nonce },
        deadline,
        None,
    )?;
    result
}

pub fn verify(store: &Store, plan: &Plan) -> Result<()> {
    let expected = Binding::new(&store.profile, plan)?;
    let protected = read_binding(store.profile.id, plan.id, &store.profile.owner_sid)?;
    require_binding(&protected, &expected)?;
    verify_protected(&protected)
}

pub fn status(store: &Store, id: Uuid) -> Result<Value> {
    let plan = endpoint::load(store, id)?;
    verify(store, &plan)?;
    Ok(json!({
        "state": "verified_read_only_not_effect_certified",
        "profile": store.profile.id, "plan": id,
        "service": service_name(store.profile.id),
        "policy": plan.policy_id, "effect_gate_pass": false,
        "scope": "fresh authenticated exact owned App Control inventory and installed-byte verification only"
    }))
}

fn authorize(
    store: &Store,
    id: Uuid,
    approval: &ChangeApproval<'_>,
    install: bool,
) -> Result<(Plan, Binding)> {
    let plan = endpoint::load(store, id)?;
    endpoint::authorize_change(
        store,
        &plan,
        approval.authorized_lab,
        approval.profile_digest,
        approval.plan_digest,
        false,
    )?;
    if install {
        store.profile.verify_host()?;
    }
    let binding = Binding::new(&store.profile, &plan)?;
    Ok((plan, binding))
}

fn create_service(protected: &ProtectedBinding) -> Result<ScHandle> {
    let private = SecurityDescriptor::from_sddl("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)")?;
    let mut owner = null_mut();
    let mut dacl = null_mut();
    let mut defaulted = 0;
    let mut present = 0;
    unsafe {
        check(
            GetSecurityDescriptorOwner(private.as_ptr(), &mut owner, &mut defaulted),
            "GetSecurityDescriptorOwner service creation",
        )?;
        check(
            GetSecurityDescriptorDacl(private.as_ptr(), &mut present, &mut dacl, &mut defaulted),
            "GetSecurityDescriptorDacl service creation",
        )?;
    }
    let mut raw = null_mut();
    check(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &mut raw) },
        "OpenProcessToken service creation",
    )?;
    let source = handle(raw, "service creation source token")?;
    check(
        unsafe {
            DuplicateTokenEx(
                source.as_raw_handle(),
                TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_IMPERSONATE,
                null(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut raw,
            )
        },
        "DuplicateTokenEx service creation",
    )?;
    let token = handle(raw, "service creation token")?;
    let owner = TOKEN_OWNER { Owner: owner };
    let dacl = TOKEN_DEFAULT_DACL { DefaultDacl: dacl };
    unsafe {
        check(
            SetTokenInformation(
                token.as_raw_handle(),
                TokenOwner,
                (&owner as *const TOKEN_OWNER).cast(),
                size_of::<TOKEN_OWNER>() as u32,
            ),
            "SetTokenInformation service default administrator owner",
        )?;
        check(
            SetTokenInformation(
                token.as_raw_handle(),
                TokenDefaultDacl,
                (&dacl as *const TOKEN_DEFAULT_DACL).cast(),
                size_of::<TOKEN_DEFAULT_DACL>() as u32,
            ),
            "SetTokenInformation service default administrator DACL",
        )?;
        check(
            ImpersonateLoggedOnUser(token.as_raw_handle()),
            "ImpersonateLoggedOnUser service creation",
        )?;
    }
    let impersonation = Impersonation { active: true };
    let manager = manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
    let raw = unsafe {
        CreateServiceW(
            manager.0,
            wide(service_name(protected.binding.profile.id)).as_ptr(),
            wide(service_name(protected.binding.profile.id)).as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            wide(protected.binding.image_command(&protected.paths)).as_ptr(),
            null(),
            null_mut(),
            null(),
            null(),
            null(),
        )
    };
    let result = if raw.is_null() {
        Err(win_error("CreateServiceW protected verifier"))
    } else {
        Ok(ScHandle(raw))
    };
    impersonation.finish()?;
    let service = result?;
    let security = service_descriptor(&protected.binding.profile.owner_sid)?;
    let mut owner = null_mut();
    let mut dacl = null_mut();
    let mut defaulted = 0;
    let mut present = 0;
    unsafe {
        check(
            GetSecurityDescriptorOwner(security.as_ptr(), &mut owner, &mut defaulted),
            "GetSecurityDescriptorOwner verifier service",
        )?;
        check(
            GetSecurityDescriptorDacl(security.as_ptr(), &mut present, &mut dacl, &mut defaulted),
            "GetSecurityDescriptorDacl verifier service",
        )?;
    }
    let status = unsafe {
        SetSecurityInfo(
            service.0,
            SE_SERVICE,
            SECURITY | PROTECTED_DACL_SECURITY_INFORMATION,
            owner,
            null_mut(),
            dacl,
            null_mut(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(Error::Windows {
            operation: "SetSecurityInfo verifier service",
            source: std::io::Error::from_raw_os_error(status as i32),
        });
    }
    let mut sid = SERVICE_SID_INFO {
        dwServiceSidType: SERVICE_SID_TYPE_UNRESTRICTED,
    };
    check(
        unsafe {
            ChangeServiceConfig2W(
                service.0,
                SERVICE_CONFIG_SERVICE_SID_INFO,
                (&mut sid as *mut SERVICE_SID_INFO).cast(),
            )
        },
        "ChangeServiceConfig2W verifier SID",
    )?;
    verify_service(&service, protected)?;
    Ok(service)
}

fn wait_state(service: &ScHandle, expected: u32) -> Result<()> {
    let deadline = Instant::now() + CHANGE_TIME;
    loop {
        let status = service_status(service)?;
        if status.dwCurrentState == expected {
            return Ok(());
        }
        if Instant::now() >= deadline
            || (expected == SERVICE_RUNNING && status.dwCurrentState == SERVICE_STOPPED)
        {
            return Err(Error::Unknown(format!(
                "verifier SCM state {}, Win32 exit {}, service exit {}; reconcile without replay",
                status.dwCurrentState, status.dwWin32ExitCode, status.dwServiceSpecificExitCode
            )));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn install(store: &Store, id: Uuid, approval: ChangeApproval<'_>) -> Result<Value> {
    let _control = store.control_lock()?;
    let (_, binding) = authorize(store, id, &approval, true)?;
    endpoint::verify_native_identity(&binding.policy)?;
    let manager = manager(SC_MANAGER_CONNECT)?;
    if open_service(&manager, binding.profile.id, SERVICE_READ)?.is_some() {
        return Err(Error::Unknown(
            "a verifier service already exists; inspect/reconcile it, never overwrite it".into(),
        ));
    }
    let paths = Paths::new(binding.profile.id, id)?;
    if paths.profile.try_exists()? {
        let _pin = verify_directory(&paths.profile, &binding.profile.owner_sid)?;
    } else {
        let parent = paths
            .profile
            .parent()
            .ok_or_else(|| invalid("missing Program Files parent"))?;
        files::check_no_reparse(parent)?;
        create_directory(&paths.profile, &binding.profile.owner_sid)?;
    }
    let _profile_pin = verify_directory(&paths.profile, &binding.profile.owner_sid)?;
    cleanup::ensure_not_retired(&paths, id)?;
    create_directory(&paths.plan, &binding.profile.owner_sid)?;
    let _plan_pin = verify_directory(&paths.plan, &binding.profile.owner_sid)?;
    write_new(
        &paths.config(),
        &binding.profile.owner_sid,
        &serde_json::to_vec(&binding)?,
    )?;
    let (mut source, fingerprint) = files::pin(&std::env::current_exe()?, IMAGE_BYTES)?;
    if fingerprint.sha256 != binding.profile.binary_sha256 {
        return Err(Error::Denied("verifier source image changed".into()));
    }
    let mut image = create_file(&paths.image(), &binding.profile.owner_sid)?;
    std::io::copy(&mut source, &mut image)?;
    image.sync_all()?;
    drop(image);
    let protected = read_binding(binding.profile.id, id, &binding.profile.owner_sid)?;
    require_binding(&protected, &binding)?;
    mark(&protected, "install.intent")?;
    let service = create_service(&protected)?;
    check(
        unsafe { StartServiceW(service.0, 0, null()) },
        "StartServiceW explicitly enrolled verifier",
    )?;
    wait_state(&service, SERVICE_RUNNING)?;
    let _peer = running_peer(&service, &protected)?;
    mark(&protected, "install.confirmed")?;
    verify_protected(&protected)?;
    Ok(json!({
        "state": "installed_read_only_not_effect_certified",
        "profile": binding.profile.id, "plan": id,
        "binding_sha256": binding.digest()?, "effect_gate_pass": false,
        "restart": "automatic SCM startup; reboot/recovery behavior still needs authorized-lab effect qualification"
    }))
}

pub fn remove(store: &Store, id: Uuid, approval: ChangeApproval<'_>) -> Result<Value> {
    let _control = store.control_lock()?;
    let (_, binding) = authorize(store, id, &approval, false)?;
    let protected = read_binding(store.profile.id, id, &binding.profile.owner_sid)?;
    require_binding(&protected, &binding)?;
    if marker(&protected, "remove.intent")? || marker(&protected, "remove.confirmed")? {
        return Err(Error::Unknown(
            "verifier removal was already dispatched; reconcile without repeating it".into(),
        ));
    }
    let manager = manager(SC_MANAGER_CONNECT)?;
    let service = open_service(
        &manager,
        binding.profile.id,
        SERVICE_READ | SERVICE_STOP | DELETE,
    )?;
    if let Some(service) = &service {
        verify_service(service, &protected)?;
    }
    mark(&protected, "remove.intent")?;
    if let Some(service) = service {
        let status = service_status(&service)?;
        if status.dwCurrentState != SERVICE_STOPPED {
            let mut status = SERVICE_STATUS::default();
            check(
                unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) },
                "ControlService explicitly enrolled verifier",
            )?;
            wait_state(&service, SERVICE_STOPPED)?;
        }
        check(
            unsafe { DeleteService(service.0) },
            "DeleteService owned verifier",
        )?;
        drop(service);
    }
    if open_service(&manager, binding.profile.id, SERVICE_READ)?.is_some() {
        return Err(Error::Unknown(
            "verifier deletion is not yet confirmed; reconcile explicitly".into(),
        ));
    }
    mark(&protected, "remove.confirmed")?;
    Ok(json!({
        "state": "removed", "profile": binding.profile.id, "plan": id,
        "protection": "daily protected-service verification now refuses",
        "retained": "protected binding, frozen image and immutable lifecycle evidence; never replay this plan",
        "effect_gate_pass": false
    }))
}

pub fn reconcile(store: &Store, id: Uuid, approval: ChangeApproval<'_>) -> Result<Value> {
    let _control = store.control_lock()?;
    let (_, binding) = authorize(store, id, &approval, false)?;
    let protected = read_binding(store.profile.id, id, &binding.profile.owner_sid)?;
    require_binding(&protected, &binding)?;
    let manager = manager(SC_MANAGER_CONNECT)?;
    let service = open_service(&manager, binding.profile.id, SERVICE_READ)?;
    if marker(&protected, "remove.intent")? {
        if service.is_some() {
            return Err(Error::Unknown(
                "removal was dispatched but the service still exists; reconciliation never repeats stop/delete".into(),
            ));
        }
        if !marker(&protected, "remove.confirmed")? {
            mark(&protected, "remove.confirmed")?;
        }
        return Ok(
            json!({"state": "removed", "mutation_replayed": false, "effect_gate_pass": false}),
        );
    }
    if !marker(&protected, "install.intent")? {
        return Err(Error::Unknown(
            "protected files exist but installation was not dispatched; use explicitly reviewed removal, not install replay".into(),
        ));
    }
    let service = service.ok_or_else(|| Error::Unknown(
        "installation was dispatched but service is absent; reconciliation does not create/start it".into(),
    ))?;
    let _peer = running_peer(&service, &protected)?;
    endpoint::verify_native_identity(&binding.policy)?;
    if !marker(&protected, "install.confirmed")? {
        mark(&protected, "install.confirmed")?;
    }
    verify_protected(&protected)?;
    Ok(
        json!({"state": "installed_read_only_not_effect_certified", "mutation_replayed": false, "effect_gate_pass": false}),
    )
}

static SERVICE_PROFILE: OnceLock<(Uuid, Uuid, String)> = OnceLock::new();
static SERVICE_STOPPING: AtomicBool = AtomicBool::new(false);
static SERVICE_STATUS_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

fn report_error(message: &str) {
    let message: String = util::literal(message).chars().take(2048).collect();
    eprintln!("Shield verifier: {message}");
    unsafe {
        let source = RegisterEventSourceW(null(), wide("Shield.Verifier").as_ptr());
        if source.is_null() {
            eprintln!("Shield verifier: {}", win_error("RegisterEventSourceW"));
            return;
        }
        let message = wide(message);
        let strings = [message.as_ptr()];
        if ReportEventW(
            source,
            EVENTLOG_ERROR_TYPE,
            0,
            1,
            null_mut(),
            1,
            0,
            strings.as_ptr(),
            null(),
        ) == 0
        {
            eprintln!("Shield verifier: {}", win_error("ReportEventW"));
        }
        if DeregisterEventSource(source) == 0 {
            eprintln!("Shield verifier: {}", win_error("DeregisterEventSource"));
        }
    }
}

fn fatal(message: &str) -> ! {
    report_error(message);
    std::process::abort()
}

fn set_status(state: u32, error: bool) -> Result<()> {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: if error {
            ERROR_SERVICE_SPECIFIC_ERROR
        } else {
            0
        },
        dwServiceSpecificExitCode: u32::from(error),
        dwCheckPoint: u32::from(matches!(
            state,
            SERVICE_START_PENDING | SERVICE_STOP_PENDING
        )),
        dwWaitHint: if matches!(state, SERVICE_START_PENDING | SERVICE_STOP_PENDING) {
            CHANGE_TIME.as_millis() as u32
        } else {
            0
        },
    };
    check(
        unsafe { SetServiceStatus(SERVICE_STATUS_HANDLE.load(Ordering::Acquire), &status) },
        "SetServiceStatus verifier",
    )
}

unsafe extern "system" fn control(
    code: u32,
    _event: u32,
    _data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match code {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            SERVICE_STOPPING.store(true, Ordering::Release);
            if let Err(error) = set_status(SERVICE_STOP_PENDING, false) {
                report_error(&error.to_string());
            }
            ERROR_SUCCESS
        }
        SERVICE_CONTROL_INTERROGATE => ERROR_SUCCESS,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

fn grant_peer_query(owner: &str) -> Result<()> {
    for (token, rights) in [
        (false, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE),
        (true, TOKEN_QUERY),
    ] {
        let descriptor = query_descriptor(owner, rights)?;
        let mut raw = null_mut();
        let owned;
        let object = if token {
            check(
                unsafe {
                    OpenProcessToken(
                        GetCurrentProcess(),
                        TOKEN_QUERY | WRITE_DAC | WRITE_OWNER,
                        &mut raw,
                    )
                },
                "OpenProcessToken verifier query-only grant",
            )?;
            owned = handle(raw, "verifier own token")?;
            owned.as_raw_handle()
        } else {
            unsafe { GetCurrentProcess() }
        };
        check(
            unsafe {
                SetKernelObjectSecurity(
                    object,
                    SECURITY | PROTECTED_DACL_SECURITY_INFORMATION,
                    descriptor.as_ptr(),
                )
            },
            "SetKernelObjectSecurity verifier query-only grant",
        )?;
    }
    Ok(())
}

fn new_pipe(profile: Uuid, owner: &str) -> Result<OwnedHandle> {
    let security = descriptor(owner, PIPE_CLIENT, false)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.as_ptr(),
        bInheritHandle: 0,
    };
    handle(
        unsafe {
            CreateNamedPipeW(
                pipe_name(profile).as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                FRAME_BYTES as u32 + 4,
                FRAME_BYTES as u32 + 4,
                1000,
                &attributes,
            )
        },
        "CreateNamedPipeW exclusive local verifier",
    )
}

fn connect(pipe: HANDLE, deadline: Instant, stop: Option<&AtomicBool>) -> Result<()> {
    let mut operation = Operation::new()?;
    let initial = unsafe { ConnectNamedPipe(pipe, &mut operation.overlapped) };
    if initial == 0 && unsafe { GetLastError() } == ERROR_PIPE_CONNECTED {
        return Ok(());
    }
    operation.finish(pipe, initial, deadline, stop)?;
    Ok(())
}

fn answer(pipe: HANDLE, protected: &ProtectedBinding, stop: &AtomicBool) -> Result<()> {
    let deadline = Instant::now() + QUERY_TIME;
    let request: Request = receive(pipe, deadline, Some(stop))?;
    authenticate_client(pipe, &protected.binding.profile.owner_sid)?;
    let expected = protected.binding.digest()?;
    verify_request(&request, &expected)?;
    let checked = (|| {
        protected.binding.profile.verify_platform_image()?;
        if stop.load(Ordering::Acquire) {
            return Err(Error::Denied("verifier is stopping".into()));
        }
        endpoint::verify_native_identity(&protected.binding.policy)
    })();
    let response = match checked {
        Ok(()) => Response::Verified {
            nonce: request.nonce,
            binding_sha256: expected,
        },
        Err(error) => {
            report_error(&error.to_string());
            Response::Failed {
                nonce: request.nonce,
                reason: error.to_string().chars().take(1024).collect(),
            }
        }
    };
    send(pipe, &response, deadline, Some(stop))?;
    let acknowledged: Acknowledgment = receive(pipe, deadline, Some(stop))?;
    if acknowledged.nonce != request.nonce {
        return Err(Error::Protocol("verifier acknowledgment differs"));
    }
    Ok(())
}

fn serve(profile: Uuid, plan: Uuid, owner: &str) -> Result<()> {
    if platform::current_user_sid()? != SYSTEM_SID {
        return Err(Error::Denied(
            "protected verifier must run as LocalSystem under SCM".into(),
        ));
    }
    let protected = read_binding(profile, plan, owner)?;
    protected.binding.profile.verify_platform_image()?;
    if !marker(&protected, "install.intent")?
        || marker(&protected, "remove.intent")?
        || marker(&protected, "remove.confirmed")?
    {
        return Err(Error::Denied("verifier lifecycle forbids startup".into()));
    }
    let service = required_service(profile, SERVICE_READ)?;
    verify_service(&service, &protected)?;
    grant_peer_query(&protected.binding.profile.owner_sid)?;
    let pipe = new_pipe(profile, &protected.binding.profile.owner_sid)?;
    set_status(SERVICE_RUNNING, false)?;
    while !SERVICE_STOPPING.load(Ordering::Acquire) {
        match connect(
            pipe.as_raw_handle(),
            Instant::now() + Duration::from_secs(1),
            Some(&SERVICE_STOPPING),
        ) {
            Ok(()) => {
                if let Err(error) = answer(pipe.as_raw_handle(), &protected, &SERVICE_STOPPING) {
                    report_error(&error.to_string());
                }
                check(
                    unsafe { DisconnectNamedPipe(pipe.as_raw_handle()) },
                    "DisconnectNamedPipe verifier",
                )?;
            }
            Err(Error::Deadline) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let Some((profile, plan, owner)) = SERVICE_PROFILE.get() else {
        report_error("missing SCM verifier binding");
        return;
    };
    let raw = unsafe {
        RegisterServiceCtrlHandlerExW(wide(service_name(*profile)).as_ptr(), Some(control), null())
    };
    if raw.is_null() {
        report_error(&win_error("RegisterServiceCtrlHandlerExW verifier").to_string());
        return;
    }
    SERVICE_STATUS_HANDLE.store(raw, Ordering::Release);
    let result =
        set_status(SERVICE_START_PENDING, false).and_then(|()| serve(*profile, *plan, owner));
    if let Err(error) = &result {
        report_error(&error.to_string());
    }
    if let Err(error) = set_status(SERVICE_STOPPED, result.is_err()) {
        report_error(&error.to_string());
    }
}

pub fn run_service(profile: Uuid, plan: Uuid, owner: String) -> Result<()> {
    if profile.is_nil() || plan.is_nil() || platform::current_user_sid()? != SYSTEM_SID {
        return Err(Error::Denied(
            "hidden verifier action is SCM-only LocalSystem execution, not a broker elevation route".into(),
        ));
    }
    let mut raw = null_mut();
    check(
        unsafe { ConvertStringSidToSidW(wide(&owner).as_ptr(), &mut raw) },
        "ConvertStringSidToSidW verifier SCM owner",
    )?;
    let _sid = LocalAllocation(raw);
    if sid_string(raw)? != owner || matches!(owner.as_str(), SYSTEM_SID | ADMIN_SID) {
        return Err(invalid(
            "verifier SCM owner must be a canonical enrolled user SID",
        ));
    }
    SERVICE_PROFILE
        .set((profile, plan, owner))
        .map_err(|_| invalid("verifier dispatcher is already bound"))?;
    let mut name = wide(service_name(profile));
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    check(
        unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) },
        "StartServiceCtrlDispatcherW verifier (direct launch is not supported)",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::tests::AuthorizationContext;

    fn fixture_pipe(profile: Uuid) -> OwnedHandle {
        let owner = platform::current_user_sid().unwrap();
        let descriptor =
            SecurityDescriptor::from_sddl(&format!("O:{owner}D:P(A;;FA;;;{owner})")).unwrap();
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.as_ptr(),
            bInheritHandle: 0,
        };
        handle(
            unsafe {
                CreateNamedPipeW(
                    pipe_name(profile).as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    1,
                    FRAME_BYTES as u32 + 4,
                    FRAME_BYTES as u32 + 4,
                    1000,
                    &attributes,
                )
            },
            "owned unprivileged test pipe",
        )
        .unwrap()
    }

    fn fixture_client(profile: Uuid) -> OwnedHandle {
        handle(
            unsafe {
                CreateFileW(
                    pipe_name(profile).as_ptr(),
                    PIPE_CLIENT,
                    0,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    null_mut(),
                )
            },
            "owned unprivileged pipe client",
        )
        .unwrap()
    }

    #[test]
    fn all_protected_binding_fields_change_the_authenticated_digest() {
        let mut profile = Profile::draft("test".into()).unwrap();
        profile.endpoint_verifier = EndpointVerifier::ProtectedService;
        let binding = Binding {
            schema: 1,
            plan: Uuid::new_v4(),
            plan_sha256: util::digest(b"reviewed plan"),
            policy: PolicyIdentity {
                policy_id: profile.id,
                revision: 1,
                cip_sha256: util::digest(b"native policy"),
            },
            profile,
        };
        binding.validate(binding.profile.id, binding.plan).unwrap();
        let digest = binding.digest().unwrap();
        let mut changes = vec![binding.clone(); 8];
        changes[0].profile.binary_sha256 = util::digest(b"other image");
        changes[1].profile.owner_sid.push_str("-1");
        changes[2].profile.windows_revision += 1;
        changes[3].policy.revision += 1;
        changes[4].policy.cip_sha256 = util::digest(b"other policy");
        changes[5].plan = Uuid::new_v4();
        changes[6].plan_sha256 = util::digest(b"other plan");
        changes[7].profile.endpoint_verifier = EndpointVerifier::Direct;
        for changed in &changes {
            assert_ne!(changed.digest().unwrap(), digest);
        }
        assert!(
            changes[7]
                .validate(binding.profile.id, binding.plan)
                .is_err()
        );
        let mut value = serde_json::to_value(&binding).unwrap();
        value["command"] = json!("arbitrary privileged command");
        assert!(serde_json::from_value::<Binding>(value).is_err());
    }

    #[test]
    fn windows_authz_allows_queries_but_denies_daily_user_object_mutation() {
        let owner = platform::current_user_sid().unwrap();
        let mut sid = null_mut();
        check(
            unsafe { ConvertStringSidToSidW(wide(&owner).as_ptr(), &mut sid) },
            "test identity SID",
        )
        .unwrap();
        let _sid = LocalAllocation(sid);
        let context = AuthorizationContext::new(sid);
        for (descriptor, allowed, denied) in [
            (
                descriptor(&owner, FILE_READ_EXECUTE, true).unwrap(),
                FILE_READ_EXECUTE,
                vec![
                    FILE_WRITE_DATA,
                    FILE_APPEND_DATA,
                    FILE_DELETE_CHILD,
                    DELETE,
                    WRITE_DAC,
                    WRITE_OWNER,
                ],
            ),
            (
                service_descriptor(&owner).unwrap(),
                SERVICE_READ,
                vec![
                    SERVICE_START,
                    SERVICE_STOP,
                    SERVICE_CHANGE_CONFIG,
                    DELETE,
                    WRITE_DAC,
                    WRITE_OWNER,
                ],
            ),
            (
                descriptor(&owner, PIPE_CLIENT, false).unwrap(),
                PIPE_CLIENT,
                vec![FILE_CREATE_PIPE_INSTANCE, DELETE, WRITE_DAC, WRITE_OWNER],
            ),
            (
                query_descriptor(&owner, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE).unwrap(),
                PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                vec![
                    PROCESS_TERMINATE,
                    PROCESS_VM_READ,
                    PROCESS_VM_WRITE,
                    PROCESS_DUP_HANDLE,
                    PROCESS_CREATE_THREAD,
                    WRITE_DAC,
                    WRITE_OWNER,
                ],
            ),
            (
                query_descriptor(&owner, TOKEN_QUERY).unwrap(),
                TOKEN_QUERY,
                vec![
                    TOKEN_DUPLICATE,
                    TOKEN_IMPERSONATE,
                    TOKEN_ADJUST_DEFAULT,
                    TOKEN_ADJUST_PRIVILEGES,
                    TOKEN_ASSIGN_PRIMARY,
                    WRITE_DAC,
                    WRITE_OWNER,
                ],
            ),
        ] {
            assert_eq!(
                context.access(descriptor.as_ptr(), allowed),
                (allowed, ERROR_SUCCESS)
            );
            for denied in denied {
                let (granted, error) = context.access(descriptor.as_ptr(), denied);
                assert_eq!(
                    error, ERROR_ACCESS_DENIED,
                    "unexpected access mask {denied:#x}"
                );
                assert_eq!(granted & denied, 0);
            }
        }
        let service = service_descriptor(&owner).unwrap();
        verify_descriptor(service.as_ptr(), &owner, SERVICE_READ, SERVICE_ALL_ACCESS).unwrap();
    }

    #[test]
    fn actual_owned_pipe_round_trip_authenticates_the_client_and_reverts_impersonation() {
        let profile = Uuid::new_v4();
        let pipe = fixture_pipe(profile);
        let client = fixture_client(profile);
        let mut server_pid = 0;
        check(
            unsafe { GetNamedPipeServerProcessId(client.as_raw_handle(), &mut server_pid) },
            "native fixture pipe server PID",
        )
        .unwrap();
        assert_eq!(server_pid, unsafe { GetCurrentProcessId() });
        let owner = platform::current_user_sid().unwrap();
        let nonce = Uuid::new_v4();
        let binding = util::digest(b"owned pipe fixture; not a privileged service");
        let deadline = Instant::now() + QUERY_TIME;
        std::thread::scope(|scope| {
            let server = scope.spawn(|| {
                connect(pipe.as_raw_handle(), deadline, None).unwrap();
                let request: Request = receive(pipe.as_raw_handle(), deadline, None).unwrap();
                authenticate_client(pipe.as_raw_handle(), &owner).unwrap();
                assert!(authenticate_client(pipe.as_raw_handle(), SYSTEM_SID).is_err());
                let mut raw = null_mut();
                assert_eq!(
                    unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) },
                    0
                );
                assert_eq!(unsafe { GetLastError() }, ERROR_NO_TOKEN);
                verify_request(&request, &binding).unwrap();
                send(
                    pipe.as_raw_handle(),
                    &Response::Verified {
                        nonce: request.nonce,
                        binding_sha256: binding.clone(),
                    },
                    deadline,
                    None,
                )
                .unwrap();
                let ack: Acknowledgment = receive(pipe.as_raw_handle(), deadline, None).unwrap();
                assert_eq!(ack.nonce, nonce);
            });
            send(
                client.as_raw_handle(),
                &Request {
                    nonce,
                    binding_sha256: binding.clone(),
                },
                deadline,
                None,
            )
            .unwrap();
            let response = receive(client.as_raw_handle(), deadline, None).unwrap();
            verify_response(response, nonce, &binding).unwrap();
            send(
                client.as_raw_handle(),
                &Acknowledgment { nonce },
                deadline,
                None,
            )
            .unwrap();
            server.join().unwrap();
        });
    }

    #[test]
    fn native_pipe_deadlines_cancel_owned_connect_and_read_without_reusing_pending_storage() {
        let profile = Uuid::new_v4();
        let pipe = fixture_pipe(profile);
        let start = Instant::now();
        assert!(matches!(
            connect(
                pipe.as_raw_handle(),
                start + Duration::from_millis(50),
                None
            ),
            Err(Error::Deadline)
        ));
        assert!(start.elapsed() < Duration::from_secs(3));
        let client = fixture_client(profile);
        connect(pipe.as_raw_handle(), Instant::now() + QUERY_TIME, None).unwrap();
        let start = Instant::now();
        assert!(matches!(
            receive::<Request>(
                pipe.as_raw_handle(),
                start + Duration::from_millis(50),
                None
            ),
            Err(Error::Deadline)
        ));
        assert!(start.elapsed() < Duration::from_secs(3));
        let nonce = Uuid::new_v4();
        send(
            client.as_raw_handle(),
            &Acknowledgment { nonce },
            Instant::now() + QUERY_TIME,
            None,
        )
        .unwrap();
        let read: Acknowledgment =
            receive(pipe.as_raw_handle(), Instant::now() + QUERY_TIME, None).unwrap();
        assert_eq!(read.nonce, nonce);
    }

    #[test]
    fn native_pipe_rejects_oversize_frames_before_allocating_the_declared_body() {
        for length in [0_u32, FRAME_BYTES as u32 + 1, u32::MAX] {
            let profile = Uuid::new_v4();
            let pipe = fixture_pipe(profile);
            let client = fixture_client(profile);
            connect(pipe.as_raw_handle(), Instant::now() + QUERY_TIME, None).unwrap();
            let mut header = length.to_le_bytes();
            transfer(
                client.as_raw_handle(),
                &mut header,
                true,
                Instant::now() + QUERY_TIME,
                None,
            )
            .unwrap();
            assert!(matches!(
                receive::<Request>(pipe.as_raw_handle(), Instant::now() + QUERY_TIME, None),
                Err(Error::Invalid(_))
            ));
        }
    }

    #[test]
    fn client_close_preserves_the_ack_and_allows_server_disconnect() {
        let profile = Uuid::new_v4();
        let pipe = fixture_pipe(profile);
        let client = fixture_client(profile);
        let deadline = Instant::now() + QUERY_TIME;
        connect(pipe.as_raw_handle(), deadline, None).unwrap();
        let nonce = Uuid::new_v4();
        send(
            client.as_raw_handle(),
            &Acknowledgment { nonce },
            deadline,
            None,
        )
        .unwrap();
        drop(client);
        let read: Acknowledgment = receive(pipe.as_raw_handle(), deadline, None).unwrap();
        assert_eq!(read.nonce, nonce);
        check(
            unsafe { DisconnectNamedPipe(pipe.as_raw_handle()) },
            "disconnect after client close",
        )
        .unwrap();
    }

    #[test]
    fn administrator_file_security_is_checked_before_bounded_content_capture() {
        let directory = tempfile::tempdir().unwrap();
        platform::protect_directory(directory.path(), None).unwrap();
        let path = directory.path().join("untrusted-binding.json");
        std::fs::write(&path, b"not privileged configuration").unwrap();
        assert!(matches!(
            protected_pin(&path, &platform::current_user_sid().unwrap(), 0),
            Err(Error::Denied(_))
        ));
    }

    #[test]
    fn absent_protected_binding_is_not_created_or_treated_as_a_service_pass() {
        let profile = Uuid::new_v4();
        let plan = Uuid::new_v4();
        let paths = Paths::new(profile, plan).unwrap();
        assert!(
            matches!(read_binding(profile, plan, &platform::current_user_sid().unwrap()), Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound)
        );
        assert!(!paths.profile.exists());
        assert!(!paths.plan.exists());
    }

    #[test]
    fn protocol_rejects_changed_authority_and_stale_success() {
        let binding = util::digest(b"binding");
        let nonce = Uuid::new_v4();
        assert!(
            verify_request(
                &Request {
                    nonce,
                    binding_sha256: binding.clone()
                },
                &binding
            )
            .is_ok()
        );
        assert!(
            verify_request(
                &Request {
                    nonce: Uuid::nil(),
                    binding_sha256: binding.clone()
                },
                &binding
            )
            .is_err()
        );
        assert!(
            verify_response(
                Response::Verified {
                    nonce: Uuid::new_v4(),
                    binding_sha256: binding.clone()
                },
                nonce,
                &binding
            )
            .is_err()
        );
        assert!(
            verify_response(
                Response::Verified {
                    nonce,
                    binding_sha256: util::digest(b"other")
                },
                nonce,
                &binding
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<Request>(
                json!({"nonce":nonce,"binding_sha256":binding,"command":"anything"})
            )
            .is_err()
        );
        assert!(serde_json::from_value::<Response>(json!({"result":"verified","nonce":nonce,"binding_sha256":binding,"policy":"another"})).is_err());
        assert!(
            serde_json::from_value::<Acknowledgment>(json!({"nonce":nonce,"ok":true})).is_err()
        );
    }

    #[test]
    fn protected_acl_requires_admin_ownership_and_exact_read_only_role() {
        let owner = platform::current_user_sid().unwrap();
        let security = descriptor(&owner, FILE_READ_EXECUTE, true).unwrap();
        verify_descriptor(
            security.as_ptr(),
            &owner,
            FILE_READ_EXECUTE,
            FILE_ALL_ACCESS,
        )
        .unwrap();
        for sddl in [
            format!(
                "O:{owner}G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x{FILE_READ_EXECUTE:x};;;{owner})"
            ),
            format!("O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x{FILE_READ_EXECUTE:x};;;{owner})"),
            format!("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{owner})"),
            format!(
                "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x{FILE_READ_EXECUTE:x};;;{owner})(A;;FR;;;WD)"
            ),
        ] {
            let changed = SecurityDescriptor::from_sddl(&sddl).unwrap();
            assert!(
                verify_descriptor(changed.as_ptr(), &owner, FILE_READ_EXECUTE, FILE_ALL_ACCESS)
                    .is_err()
            );
        }
        assert_eq!(
            SERVICE_READ
                & (SERVICE_START
                    | SERVICE_STOP
                    | SERVICE_CHANGE_CONFIG
                    | DELETE
                    | WRITE_DAC
                    | WRITE_OWNER),
            0
        );
        assert_eq!(PIPE_CLIENT & FILE_CREATE_PIPE_INSTANCE, 0);
    }

    #[test]
    fn a_matching_same_user_image_is_not_an_authenticated_system_peer() {
        assert_ne!(platform::current_user_sid().unwrap(), SYSTEM_SID);
        assert!(
            process_identity(
                unsafe { GetCurrentProcessId() },
                &std::env::current_exe().unwrap()
            )
            .is_err()
        );
    }
}
