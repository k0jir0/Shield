use std::ffi::{CStr, OsStr, c_void};
use std::fs::File;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::process::{Child, Command};
use std::ptr::{null, null_mut};
use std::sync::{Mutex, MutexGuard};

use serde::Serialize;
use uuid::Uuid;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Networking::WinSock as winsock;
use windows_sys::Win32::Security::Authorization::*;
use windows_sys::Win32::Security::Credentials::*;
use windows_sys::Win32::Security::Isolation::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::System::JobObjects::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Pipes::{CreatePipe, PeekNamedPipe};
use windows_sys::Win32::System::Registry::*;
use windows_sys::Win32::System::Threading::*;
use zeroize::Zeroizing;

use crate::error::{Error, Result, invalid};
use crate::protocol::{LoopbackConnection, SocketOperation};

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

fn process_creation_lock() -> io::Result<MutexGuard<'static, ()>> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock()
        .map_err(|_| io::Error::other("Shield process-creation coordination is poisoned"))
}

/// Coordinate ordinary launches with the sandbox's temporary inheritable handles.
pub fn spawn_command(command: &mut Command) -> io::Result<Child> {
    let _creation = process_creation_lock()?;
    command.spawn()
}

/// Read a uniquely owned pipe without allowing an idle writer to outlive the deadline.
pub fn pipe_reader_until(
    pipe: impl io::Read + AsRawHandle,
    deadline: std::time::Instant,
) -> impl io::Read {
    DeadlinePipe { pipe, deadline }
}

struct DeadlinePipe<T> {
    pipe: T,
    deadline: std::time::Instant,
}

impl<T: io::Read + AsRawHandle> io::Read for DeadlinePipe<T> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            if std::time::Instant::now() >= self.deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "pipe deadline expired",
                ));
            }
            let mut available = 0;
            if unsafe {
                PeekNamedPipe(
                    self.pipe.as_raw_handle(),
                    null_mut(),
                    0,
                    null_mut(),
                    &mut available,
                    null_mut(),
                )
            } == 0
            {
                let source = io::Error::last_os_error();
                if source.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                    if std::time::Instant::now() >= self.deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "pipe deadline expired",
                        ));
                    }
                    return Ok(0);
                }
                return Err(source);
            }
            if available == 0 {
                std::thread::sleep(
                    std::time::Duration::from_millis(5).min(
                        self.deadline
                            .saturating_duration_since(std::time::Instant::now()),
                    ),
                );
                continue;
            }
            // A sole reader consumes no more than the bytes the pipe already holds.
            let amount = (available as usize).min(buffer.len());
            let count = self.pipe.read(&mut buffer[..amount])?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "pipe made no progress after reporting readable bytes",
                ));
            }
            return Ok(count);
        }
    }
}

/// Drain an exclusively read pipe; EOF, byte bounds and deadline are independent.
pub fn read_pipe_until(
    pipe: impl io::Read + AsRawHandle,
    limit: u64,
    deadline: std::time::Instant,
) -> Result<Vec<u8>> {
    crate::util::read_bounded(pipe_reader_until(pipe, deadline), limit).map_err(|error| match error
    {
        Error::Io(source) if source.kind() == io::ErrorKind::TimedOut => Error::Deadline,
        Error::Io(source) => Error::Windows {
            operation: "bounded pipe read",
            source,
        },
        error => error,
    })
}

pub(crate) struct SystemLibrary(HMODULE);

impl SystemLibrary {
    pub(crate) fn load(name: &'static str) -> Result<Self> {
        let raw = unsafe {
            LoadLibraryExW(
                wide(name).as_ptr(),
                null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if raw.is_null() {
            return Err(Error::Windows {
                operation: "LoadLibraryExW fixed system DLL",
                source: io::Error::last_os_error(),
            });
        }
        Ok(Self(raw))
    }

    pub(crate) fn export(
        &self,
        name: &'static [u8],
    ) -> Result<unsafe extern "system" fn() -> isize> {
        let name = CStr::from_bytes_with_nul(name)
            .map_err(|_| invalid("system API export must be exactly one NUL-terminated name"))?;
        unsafe { GetProcAddress(self.0, name.as_ptr().cast()) }.ok_or_else(|| Error::Windows {
            operation: "GetProcAddress fixed system API",
            source: io::Error::last_os_error(),
        })
    }
}

impl Drop for SystemLibrary {
    fn drop(&mut self) {
        if unsafe { FreeLibrary(self.0) } == 0 {
            eprintln!(
                "Shield: FreeLibrary fixed system DLL: {}",
                io::Error::last_os_error()
            );
        }
    }
}

pub(crate) fn check(value: i32, operation: &'static str) -> Result<()> {
    if value == 0 {
        Err(Error::Windows {
            operation,
            source: io::Error::last_os_error(),
        })
    } else {
        Ok(())
    }
}

fn hresult(value: i32, operation: &'static str) -> Result<()> {
    if value < 0 {
        Err(Error::Unsupported(format!(
            "{operation} returned HRESULT 0x{:08x}",
            value as u32
        )))
    } else {
        Ok(())
    }
}

struct LocalMemory(*mut c_void);

impl Drop for LocalMemory {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

pub(crate) struct SecurityDescriptor(LocalMemory);

impl SecurityDescriptor {
    pub(crate) fn from_sddl(sddl: &str) -> Result<Self> {
        let mut raw = null_mut();
        unsafe {
            check(
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide(sddl).as_ptr(),
                    1,
                    &mut raw,
                    null_mut(),
                ),
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            )?;
        }
        Ok(Self(LocalMemory(raw)))
    }

    pub(crate) fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0.0
    }
}

pub(crate) fn sid_string(sid: PSID) -> Result<String> {
    let mut pointer = null_mut();
    unsafe {
        check(
            ConvertSidToStringSidW(sid, &mut pointer),
            "ConvertSidToStringSidW",
        )?;
        let allocation = LocalMemory(pointer.cast());
        let mut length = 0;
        while *pointer.add(length) != 0 {
            length += 1;
        }
        let value = String::from_utf16(std::slice::from_raw_parts(pointer, length))
            .map_err(|_| invalid("Windows returned an invalid SID string"))?;
        drop(allocation);
        Ok(value)
    }
}

pub fn current_user_sid() -> Result<String> {
    process_user_sid(unsafe { GetCurrentProcess() })
}

pub(crate) fn process_user_sid(process: HANDLE) -> Result<String> {
    unsafe {
        let mut raw = null_mut();
        check(
            OpenProcessToken(process, TOKEN_QUERY, &mut raw),
            "OpenProcessToken",
        )?;
        let token = OwnedHandle::from_raw_handle(raw);
        let mut size = 0;
        GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut size);
        if size == 0 {
            return Err(Error::Windows {
                operation: "GetTokenInformation size",
                source: io::Error::last_os_error(),
            });
        }
        let words = (size as usize).div_ceil(size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        check(
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                size,
                &mut size,
            ),
            "GetTokenInformation",
        )?;
        sid_string((*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid)
    }
}

pub fn is_elevated() -> Result<bool> {
    unsafe {
        let mut raw = null_mut();
        check(
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw),
            "OpenProcessToken elevation",
        )?;
        let token = OwnedHandle::from_raw_handle(raw);
        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = 0;
        check(
            GetTokenInformation(
                token.as_raw_handle(),
                TokenElevation,
                std::ptr::from_mut(&mut elevation).cast(),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            ),
            "GetTokenInformation elevation",
        )?;
        Ok(elevation.TokenIsElevated != 0)
    }
}

pub fn protect_directory(path: &Path, worker_sid: Option<&str>) -> Result<()> {
    let owner = current_user_sid()?;
    let mut sddl = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{owner})");
    if let Some(sid) = worker_sid {
        sddl.push_str(&format!("(A;OICI;GRGX;;;{sid})"));
    }
    unsafe {
        let descriptor = SecurityDescriptor::from_sddl(&sddl)?;
        let raw = descriptor.as_ptr();
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = null_mut();
        check(
            GetSecurityDescriptorDacl(raw, &mut present, &mut dacl, &mut defaulted),
            "GetSecurityDescriptorDacl",
        )?;
        if present == 0 || dacl.is_null() {
            return Err(invalid("refusing a missing or NULL protection DACL"));
        }
        let result = SetNamedSecurityInfoW(
            wide(path).as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        );
        drop(descriptor);
        if result != ERROR_SUCCESS {
            return Err(Error::Windows {
                operation: "SetNamedSecurityInfoW",
                source: io::Error::from_raw_os_error(result as i32),
            });
        }
    }
    Ok(())
}

pub fn verify_private_directory(path: &Path) -> Result<()> {
    let owner = current_user_sid()?;
    unsafe {
        let mut descriptor = null_mut();
        let mut actual_owner = null_mut();
        let mut dacl = null_mut();
        let code = GetNamedSecurityInfoW(
            wide(path).as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut actual_owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        );
        if code != 0 {
            return Err(Error::Windows {
                operation: "GetNamedSecurityInfoW private state",
                source: io::Error::from_raw_os_error(code as i32),
            });
        }
        let _descriptor = LocalMemory(descriptor);
        let mut control = 0;
        let mut revision = 0;
        check(
            GetSecurityDescriptorControl(descriptor, &mut control, &mut revision),
            "GetSecurityDescriptorControl",
        )?;
        if actual_owner.is_null()
            || sid_string(actual_owner)? != owner
            || control & SE_DACL_PROTECTED == 0
            || dacl.is_null()
            || (*dacl).AceCount != 2
        {
            return Err(Error::Denied(
                "state directory owner or protected two-principal ACL changed".into(),
            ));
        }
        let mut principals = Vec::new();
        for index in 0..2 {
            let mut raw = null_mut();
            check(GetAce(dacl, index, &mut raw), "GetAce private state")?;
            let header = &*raw.cast::<ACE_HEADER>();
            if header.AceType != 0 || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
            {
                return Err(Error::Denied(
                    "private state contains an unsupported access-control entry".into(),
                ));
            }
            let ace = &*raw.cast::<ACCESS_ALLOWED_ACE>();
            if u32::from(ace.Header.AceFlags) != (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
                || ace.Mask != windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS
            {
                return Err(Error::Denied(
                    "state directory contains an unexpected access-control entry".into(),
                ));
            }
            principals.push(sid_string(
                std::ptr::addr_of!(ace.SidStart).cast_mut().cast(),
            )?);
        }
        principals.sort();
        let mut expected = vec![owner, "S-1-5-18".to_owned()];
        expected.sort();
        if principals != expected {
            return Err(Error::Denied(
                "private state is readable by an unexpected principal".into(),
            ));
        }
    }
    Ok(())
}

fn registry_string(name: &str) -> Result<String> {
    let key = wide("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
    let name = wide(name);
    let mut buffer = vec![0_u16; 512];
    let mut size = (buffer.len() * 2) as u32;
    let result = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if result != ERROR_SUCCESS {
        return Err(Error::Windows {
            operation: "RegGetValueW inventory",
            source: io::Error::from_raw_os_error(result as i32),
        });
    }
    let length = buffer
        .iter()
        .position(|value| *value == 0)
        .ok_or_else(|| invalid("Windows registry inventory string is not NUL terminated"))?;
    String::from_utf16(&buffer[..length]).map_err(|_| invalid("invalid Windows inventory encoding"))
}

#[derive(Debug, Clone, Serialize)]
pub struct Environment {
    pub build: u32,
    pub revision: u32,
    pub edition: String,
    pub architecture: &'static str,
    pub user_sid: String,
}

pub fn environment() -> Result<Environment> {
    let mut revision = 0_u32;
    let mut size = size_of::<u32>() as u32;
    let code = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            wide("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion").as_ptr(),
            wide("UBR").as_ptr(),
            RRF_RT_REG_DWORD,
            null_mut(),
            std::ptr::from_mut(&mut revision).cast(),
            &mut size,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(Error::Windows {
            operation: "RegGetValueW Windows revision",
            source: io::Error::from_raw_os_error(code as i32),
        });
    }
    Ok(Environment {
        build: registry_string("CurrentBuildNumber")?
            .parse()
            .map_err(|_| invalid("Windows build number is not numeric"))?,
        revision,
        edition: registry_string("EditionID")?,
        architecture: std::env::consts::ARCH,
        user_sid: current_user_sid()?,
    })
}

pub fn credential_write(target: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 2048 || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(invalid(
            "credential must contain 1..2048 printable non-whitespace ASCII bytes",
        ));
    }
    let mut name = wide(target);
    let mut bytes = Zeroizing::new(value.as_bytes().to_vec());
    let mut credential: CREDENTIALW = unsafe { zeroed() };
    credential.Type = CRED_TYPE_GENERIC;
    credential.TargetName = name.as_mut_ptr();
    credential.CredentialBlobSize = bytes.len() as u32;
    credential.CredentialBlob = bytes.as_mut_ptr();
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
    unsafe { check(CredWriteW(&credential, 0), "CredWriteW") }
}

pub fn credential_read(target: &str) -> Result<Zeroizing<String>> {
    unsafe {
        let mut pointer = null_mut();
        check(
            CredReadW(wide(target).as_ptr(), CRED_TYPE_GENERIC, 0, &mut pointer),
            "CredReadW",
        )?;
        let credential = &*pointer;
        let bytes = if credential.CredentialBlobSize == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(
                credential.CredentialBlob,
                credential.CredentialBlobSize as usize,
            )
            .to_vec()
        };
        CredFree(pointer.cast());
        let bytes = Zeroizing::new(bytes);
        let value = std::str::from_utf8(&bytes)
            .map_err(|_| invalid("stored credential is not UTF-8"))?
            .to_owned();
        if value.is_empty() {
            return Err(invalid("stored credential is empty"));
        }
        Ok(Zeroizing::new(value))
    }
}

pub fn credential_delete(target: &str) -> Result<()> {
    unsafe {
        check(
            CredDeleteW(wide(target).as_ptr(), CRED_TYPE_GENERIC, 0),
            "CredDeleteW",
        )
    }
}

struct Container {
    name: Vec<u16>,
    sid: PSID,
    active: bool,
}

impl Container {
    fn create(id: Uuid) -> Result<Self> {
        let name = wide(format!("Shield.Worker.{id}"));
        let mut sid = null_mut();
        unsafe {
            hresult(
                CreateAppContainerProfile(
                    name.as_ptr(),
                    name.as_ptr(),
                    wide("Shield task-scoped restricted worker").as_ptr(),
                    null(),
                    0,
                    &mut sid,
                ),
                "CreateAppContainerProfile",
            )?;
        }
        Ok(Self {
            name,
            sid,
            active: true,
        })
    }

    fn close(&mut self) -> Result<()> {
        if self.active {
            unsafe {
                hresult(
                    DeleteAppContainerProfile(self.name.as_ptr()),
                    "DeleteAppContainerProfile",
                )?;
            }
            self.active = false;
        }
        Ok(())
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            eprintln!("Shield cleanup failure: {error}");
        }
        unsafe {
            FreeSid(self.sid);
        }
    }
}

struct Attributes {
    memory: Vec<usize>,
}

impl Attributes {
    fn new(count: u32) -> Result<Self> {
        let mut size = 0;
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), count, 0, &mut size);
        }
        if size == 0 {
            return Err(invalid("Windows returned an empty process-attribute size"));
        }
        let mut value = Self {
            memory: vec![0; size.div_ceil(size_of::<usize>())],
        };
        unsafe {
            check(
                InitializeProcThreadAttributeList(value.pointer(), count, 0, &mut size),
                "InitializeProcThreadAttributeList",
            )?;
        }
        Ok(value)
    }

    fn pointer(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.memory.as_mut_ptr().cast()
    }

    fn set<T>(&mut self, attribute: u32, value: &T) -> Result<()> {
        unsafe {
            check(
                UpdateProcThreadAttribute(
                    self.pointer(),
                    0,
                    attribute as usize,
                    std::ptr::from_ref(value).cast(),
                    size_of::<T>(),
                    null_mut(),
                    null(),
                ),
                "UpdateProcThreadAttribute",
            )
        }
    }
}

impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.pointer());
        }
    }
}

fn pipe() -> Result<(OwnedHandle, OwnedHandle)> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    unsafe {
        let mut read = null_mut();
        let mut write = null_mut();
        check(
            CreatePipe(&mut read, &mut write, &attributes, 0),
            "CreatePipe",
        )?;
        Ok((
            OwnedHandle::from_raw_handle(read),
            OwnedHandle::from_raw_handle(write),
        ))
    }
}

fn verify_worker_token(process: HANDLE, expected_sid: PSID) -> Result<()> {
    unsafe {
        let mut raw = null_mut();
        check(
            OpenProcessToken(process, TOKEN_QUERY, &mut raw),
            "OpenProcessToken worker",
        )?;
        let token = OwnedHandle::from_raw_handle(raw);
        let mut is_container = 0_u32;
        let mut size = 0;
        check(
            GetTokenInformation(
                token.as_raw_handle(),
                TokenIsAppContainer,
                std::ptr::from_mut(&mut is_container).cast(),
                4,
                &mut size,
            ),
            "GetTokenInformation TokenIsAppContainer",
        )?;
        if is_container != 1 {
            return Err(Error::Denied(
                "created worker token is not an AppContainer".into(),
            ));
        }
        for kind in [TokenCapabilities, TokenAppContainerSid] {
            let mut required = 0;
            GetTokenInformation(token.as_raw_handle(), kind, null_mut(), 0, &mut required);
            if required == 0 {
                return Err(invalid("worker token information size is unavailable"));
            }
            let mut data = vec![0_usize; (required as usize).div_ceil(size_of::<usize>())];
            check(
                GetTokenInformation(
                    token.as_raw_handle(),
                    kind,
                    data.as_mut_ptr().cast(),
                    required,
                    &mut required,
                ),
                "GetTokenInformation worker restrictions",
            )?;
            if kind == TokenCapabilities && (*data.as_ptr().cast::<TOKEN_GROUPS>()).GroupCount != 0
            {
                return Err(Error::Denied(
                    "worker inherited unexpected capabilities".into(),
                ));
            }
            if kind == TokenAppContainerSid
                && !expected_sid.is_null()
                && EqualSid(
                    (*data.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>()).TokenAppContainer,
                    expected_sid,
                ) == 0
            {
                return Err(Error::Denied(
                    "worker package SID does not match the created identity".into(),
                ));
            }
        }
    }
    Ok(())
}

fn verify_lpac_access(process: HANDLE) -> Result<()> {
    // LPAC must deny the ordinary-package marker and allow the restricted-package marker.
    let descriptor =
        SecurityDescriptor::from_sddl("O:SYG:SYD:(A;;0x3;;;WD)(A;;0x1;;;AC)(A;;0x2;;;S-1-15-2-2)")?;
    unsafe {
        let mut raw = null_mut();
        check(
            OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw),
            "open worker token for effective LPAC verification",
        )?;
        let primary = OwnedHandle::from_raw_handle(raw);
        check(
            DuplicateToken(primary.as_raw_handle(), SecurityImpersonation, &mut raw),
            "duplicate worker token for effective LPAC verification",
        )?;
        let token = OwnedHandle::from_raw_handle(raw);
        for (access, expected) in [(1, false), (2, true)] {
            let mut privileges = PRIVILEGE_SET::default();
            let mut length = size_of::<PRIVILEGE_SET>() as u32;
            let mut granted = 0;
            let mut allowed = 0;
            check(
                AccessCheck(
                    descriptor.as_ptr(),
                    token.as_raw_handle(),
                    access,
                    &GENERIC_MAPPING::default(),
                    &mut privileges,
                    &mut length,
                    &mut granted,
                    &mut allowed,
                ),
                "verify effective worker LPAC package access",
            )?;
            if (allowed != 0) != expected || granted != if expected { access } else { 0 } {
                return Err(Error::Denied(
                    "worker does not have the expected effective LPAC package restrictions".into(),
                ));
            }
        }
    }
    Ok(())
}

pub fn require_worker_context() -> Result<()> {
    unsafe {
        verify_worker_token(GetCurrentProcess(), null_mut())?;
        let mut assigned = 0;
        check(
            IsProcessInJob(GetCurrentProcess(), null_mut(), &mut assigned),
            "IsProcessInJob worker",
        )?;
        if assigned != 1 {
            return Err(Error::Denied("worker is not assigned to a job".into()));
        }
    }
    Ok(())
}

fn job_name(id: Uuid) -> Result<Vec<u16>> {
    Ok(wide(format!("Local\\Shield.{}.{id}", current_user_sid()?)))
}

pub fn terminate_task(id: Uuid) -> Result<bool> {
    unsafe {
        // The SDK's JOB_OBJECT_QUERY and JOB_OBJECT_TERMINATE access macros are not exported.
        let raw = OpenJobObjectW(0x0004 | 0x0008, 0, job_name(id)?.as_ptr());
        if raw.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) {
                return Ok(false);
            }
            return Err(Error::Windows {
                operation: "OpenJobObjectW task cancellation",
                source: error,
            });
        }
        let job = OwnedHandle::from_raw_handle(raw);
        check(
            TerminateJobObject(job.as_raw_handle(), 1),
            "TerminateJobObject task cancellation",
        )?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let mut information = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
            check(
                QueryInformationJobObject(
                    job.as_raw_handle(),
                    JobObjectBasicAccountingInformation,
                    std::ptr::from_mut(&mut information).cast(),
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    null_mut(),
                ),
                "QueryInformationJobObject cancellation verification",
            )?;
            if information.ActiveProcesses == 0 {
                return Ok(true);
            }
            if std::time::Instant::now() >= deadline {
                return Err(Error::Unknown("named job termination was requested but no empty-job observation arrived within five seconds".into()));
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }
}

pub fn cleanup_task_identity(id: Uuid) -> Result<()> {
    let result = unsafe { DeleteAppContainerProfile(wide(format!("Shield.Worker.{id}")).as_ptr()) };
    if matches!(result as u32, 0x80070002 | 0x80070003 | 0x80070490) {
        return Ok(());
    }
    hresult(result, "DeleteAppContainerProfile task recovery")
}

pub struct SandboxProcess {
    pub input: Option<File>,
    pub output: Option<File>,
    process: OwnedHandle,
    job: Option<OwnedHandle>,
    container: Container,
    finished: bool,
    pub pid: u32,
}

impl SandboxProcess {
    pub fn spawn(executable: &Path, directory: &Path, memory_bytes: usize) -> Result<Self> {
        Self::spawn_named(executable, directory, memory_bytes, Uuid::new_v4())
    }

    pub fn spawn_named(
        executable: &Path,
        directory: &Path,
        memory_bytes: usize,
        id: Uuid,
    ) -> Result<Self> {
        let container = Container::create(id)?;
        protect_directory(directory, Some(&sid_string(container.sid)?))?;
        // Rust's private spawn lock cannot cover these native inheritable pipe handles.
        let _creation = process_creation_lock()?;
        let (child_read, parent_write) = pipe()?;
        let (parent_read, child_write) = pipe()?;
        unsafe {
            check(
                SetHandleInformation(parent_write.as_raw_handle(), HANDLE_FLAG_INHERIT, 0),
                "SetHandleInformation stdin",
            )?;
            check(
                SetHandleInformation(parent_read.as_raw_handle(), HANDLE_FLAG_INHERIT, 0),
                "SetHandleInformation stdout",
            )?;
            SetLastError(0);
            let raw_job = CreateJobObjectW(null(), job_name(id)?.as_ptr());
            if raw_job.is_null() {
                return Err(Error::Windows {
                    operation: "CreateJobObjectW",
                    source: io::Error::last_os_error(),
                });
            }
            let job = OwnedHandle::from_raw_handle(raw_job);
            if GetLastError() == ERROR_ALREADY_EXISTS {
                return Err(Error::Denied("refusing an existing named task job".into()));
            }
            let limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
                BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                    LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
                        | JOB_OBJECT_LIMIT_JOB_MEMORY
                        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
                    ActiveProcessLimit: 1,
                    ..zeroed()
                },
                ProcessMemoryLimit: memory_bytes,
                JobMemoryLimit: memory_bytes,
                ..zeroed()
            };
            check(
                SetInformationJobObject(
                    job.as_raw_handle(),
                    JobObjectExtendedLimitInformation,
                    std::ptr::from_ref(&limits).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                ),
                "SetInformationJobObject limits",
            )?;
            let cpu = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
                ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE
                    | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
                Anonymous: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0 { CpuRate: 2000 },
            };
            check(
                SetInformationJobObject(
                    job.as_raw_handle(),
                    JobObjectCpuRateControlInformation,
                    std::ptr::from_ref(&cpu).cast(),
                    size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
                ),
                "SetInformationJobObject CPU cap",
            )?;
            let capabilities = SECURITY_CAPABILITIES {
                AppContainerSid: container.sid,
                Capabilities: null_mut(),
                CapabilityCount: 0,
                Reserved: 0,
            };
            let handles = [child_read.as_raw_handle(), child_write.as_raw_handle()];
            // The Windows SDK macro is not exposed by windows-sys.
            let disable_win32k: u64 = 1 << 28;
            let jobs = [job.as_raw_handle()];
            let opt_out_all_application_packages = 1_u32;
            let mut attributes = Attributes::new(5)?;
            attributes.set(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &capabilities)?;
            attributes.set(
                PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                &opt_out_all_application_packages,
            )?;
            attributes.set(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &handles)?;
            attributes.set(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &disable_win32k)?;
            attributes.set(PROC_THREAD_ATTRIBUTE_JOB_LIST, &jobs)?;
            let mut startup: STARTUPINFOEXW = zeroed();
            startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = child_read.as_raw_handle();
            startup.StartupInfo.hStdOutput = child_write.as_raw_handle();
            startup.StartupInfo.hStdError = child_write.as_raw_handle();
            startup.lpAttributeList = attributes.pointer();
            let executable_wide = wide(executable);
            let mut command = wide(format!("\"{}\" __worker", executable.display()));
            let mut environment = Vec::new();
            for name in [
                "APPDATA",
                "LOCALAPPDATA",
                "SystemRoot",
                "USERPROFILE",
                "WINDIR",
            ] {
                let value = std::env::var(name)
                    .map_err(|_| invalid(format!("{name} is missing; refusing worker launch")))?;
                environment.extend(wide(format!("{name}={value}")));
            }
            environment.push(0);
            let mut information: PROCESS_INFORMATION = zeroed();
            check(
                CreateProcessW(
                    executable_wide.as_ptr(),
                    command.as_mut_ptr(),
                    null(),
                    null(),
                    1,
                    EXTENDED_STARTUPINFO_PRESENT
                        | CREATE_SUSPENDED
                        | CREATE_NO_WINDOW
                        | CREATE_UNICODE_ENVIRONMENT,
                    environment.as_ptr().cast(),
                    wide(directory).as_ptr(),
                    &startup.StartupInfo,
                    &mut information,
                ),
                "CreateProcessW restricted worker",
            )?;
            let process = OwnedHandle::from_raw_handle(information.hProcess);
            let thread = OwnedHandle::from_raw_handle(information.hThread);
            let mut assigned = 0;
            check(
                IsProcessInJob(process.as_raw_handle(), job.as_raw_handle(), &mut assigned),
                "verify atomic job assignment",
            )?;
            if assigned != 1 {
                return Err(Error::Denied(
                    "worker was not atomically assigned to its task job".into(),
                ));
            }
            verify_worker_token(process.as_raw_handle(), container.sid)?;
            verify_lpac_access(process.as_raw_handle())?;
            if ResumeThread(thread.as_raw_handle()) == u32::MAX {
                let error = io::Error::last_os_error();
                check(
                    TerminateJobObject(job.as_raw_handle(), 1),
                    "TerminateJobObject",
                )?;
                return Err(Error::Windows {
                    operation: "ResumeThread",
                    source: error,
                });
            }
            drop(child_read);
            drop(child_write);
            Ok(Self {
                input: Some(File::from(parent_write)),
                output: Some(File::from(parent_read)),
                process,
                job: Some(job),
                container,
                finished: false,
                pid: information.dwProcessId,
            })
        }
    }

    pub fn terminate(&self) -> Result<()> {
        if let Some(job) = &self.job {
            unsafe {
                check(
                    TerminateJobObject(job.as_raw_handle(), 1),
                    "TerminateJobObject",
                )?;
            }
        } else {
            unsafe {
                let mut exit = 0;
                check(
                    GetExitCodeProcess(self.process.as_raw_handle(), &mut exit),
                    "GetExitCodeProcess before termination",
                )?;
                if exit == 259 {
                    check(
                        TerminateProcess(self.process.as_raw_handle(), 1),
                        "TerminateProcess without job handle",
                    )?;
                }
            }
        }
        Ok(())
    }

    pub fn job_handle(&self) -> Result<OwnedHandle> {
        self.job
            .as_ref()
            .ok_or_else(|| invalid("worker job handle is already closed"))?
            .try_clone()
            .map_err(Error::from)
    }

    pub fn close_job(&mut self) {
        self.job.take();
    }

    pub fn finish(&mut self, timeout_ms: u32) -> Result<u32> {
        self.input.take();
        unsafe {
            let wait = WaitForSingleObject(self.process.as_raw_handle(), timeout_ms);
            if wait == WAIT_TIMEOUT {
                self.terminate()?;
                check(
                    i32::from(
                        WaitForSingleObject(self.process.as_raw_handle(), 5000) == WAIT_OBJECT_0,
                    ),
                    "verify worker termination",
                )?;
                self.output.take();
                self.job.take();
                self.container.close()?;
                self.finished = true;
                return Err(Error::Deadline);
            }
            if wait != WAIT_OBJECT_0 {
                return Err(Error::Windows {
                    operation: "WaitForSingleObject worker",
                    source: io::Error::last_os_error(),
                });
            }
            let mut exit = 0;
            check(
                GetExitCodeProcess(self.process.as_raw_handle(), &mut exit),
                "GetExitCodeProcess",
            )?;
            self.output.take();
            self.job.take();
            self.container.close()?;
            self.finished = true;
            Ok(exit)
        }
    }
}

pub fn terminate_job(handle: &OwnedHandle) -> Result<()> {
    unsafe {
        check(
            TerminateJobObject(handle.as_raw_handle(), 1),
            "TerminateJobObject watchdog",
        )
    }
}

impl Drop for SandboxProcess {
    fn drop(&mut self) {
        if !self.finished {
            if let Err(error) = self.terminate() {
                eprintln!("Shield emergency worker termination failed: {error}");
            }
            unsafe {
                if WaitForSingleObject(self.process.as_raw_handle(), 5000) != WAIT_OBJECT_0 {
                    eprintln!("Shield could not verify emergency worker termination");
                }
            }
        }
    }
}

pub fn can_open_process_memory(pid: u32) -> bool {
    unsafe {
        for right in [
            PROCESS_VM_READ,
            PROCESS_VM_WRITE,
            PROCESS_VM_OPERATION,
            PROCESS_DUP_HANDLE,
            PROCESS_CREATE_THREAD,
        ] {
            let handle = OpenProcess(right, 0, pid);
            if !handle.is_null() {
                drop(OwnedHandle::from_raw_handle(handle));
                return true;
            }
        }
        false
    }
}

struct WinsockSession;

impl Drop for WinsockSession {
    fn drop(&mut self) {
        unsafe {
            if winsock::WSACleanup() != 0 {
                eprintln!(
                    "Shield Winsock probe cleanup failed: {}",
                    winsock::WSAGetLastError()
                );
            }
        }
    }
}

struct ProbeSocket(winsock::SOCKET);

impl Drop for ProbeSocket {
    fn drop(&mut self) {
        unsafe {
            if winsock::closesocket(self.0) != 0 {
                eprintln!(
                    "Shield probe socket cleanup failed: {}",
                    winsock::WSAGetLastError()
                );
            }
        }
    }
}

pub fn probe_loopback(port: u16) -> Result<LoopbackConnection> {
    if port == 0 {
        return Err(invalid(
            "loopback probe requires an explicit nonzero listener port",
        ));
    }
    let failed = |operation, windows_error| LoopbackConnection::Failed {
        operation,
        windows_error,
    };
    unsafe {
        let mut data = winsock::WSADATA::default();
        let startup = winsock::WSAStartup(0x0202, &mut data);
        if startup != 0 {
            return Ok(failed(SocketOperation::Startup, startup));
        }
        let _session = WinsockSession;
        let raw = winsock::WSASocketW(
            i32::from(winsock::AF_INET),
            winsock::SOCK_STREAM,
            winsock::IPPROTO_TCP,
            null(),
            0,
            winsock::WSA_FLAG_NO_HANDLE_INHERIT,
        );
        if raw == winsock::INVALID_SOCKET {
            return Ok(failed(SocketOperation::Create, winsock::WSAGetLastError()));
        }
        let socket = ProbeSocket(raw);
        let mut nonblocking = 1;
        if winsock::ioctlsocket(socket.0, winsock::FIONBIO, &mut nonblocking) != 0 {
            return Ok(failed(
                SocketOperation::Nonblocking,
                winsock::WSAGetLastError(),
            ));
        }
        let address = winsock::SOCKADDR_IN {
            sin_family: winsock::AF_INET,
            sin_port: port.to_be(),
            sin_addr: winsock::IN_ADDR {
                S_un: winsock::IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes([127, 0, 0, 1]),
                },
            },
            sin_zero: [0; 8],
        };
        if winsock::connect(
            socket.0,
            std::ptr::from_ref(&address).cast(),
            size_of::<winsock::SOCKADDR_IN>() as i32,
        ) == 0
        {
            return Ok(LoopbackConnection::Connected {});
        }
        let error = winsock::WSAGetLastError();
        if error != winsock::WSAEWOULDBLOCK {
            return Ok(failed(SocketOperation::Connect, error));
        }
        let mut writable = winsock::FD_SET {
            fd_count: 1,
            ..Default::default()
        };
        writable.fd_array[0] = socket.0;
        let mut exceptional = writable;
        let timeout = winsock::TIMEVAL {
            tv_sec: 0,
            tv_usec: 300_000,
        };
        let ready = winsock::select(0, null_mut(), &mut writable, &mut exceptional, &timeout);
        if ready == 0 {
            return Ok(LoopbackConnection::TimedOut {});
        }
        if ready < 0 {
            return Ok(failed(SocketOperation::Wait, winsock::WSAGetLastError()));
        }
        let mut error = 0_i32;
        let mut length = size_of::<i32>() as i32;
        if winsock::getsockopt(
            socket.0,
            winsock::SOL_SOCKET,
            winsock::SO_ERROR,
            std::ptr::from_mut(&mut error).cast(),
            &mut length,
        ) != 0
        {
            return Ok(failed(
                SocketOperation::ReadError,
                winsock::WSAGetLastError(),
            ));
        }
        if error != 0 {
            return Ok(failed(SocketOperation::Connect, error));
        }
        if length != size_of::<i32>() as i32 || writable.fd_count != 1 {
            return Err(invalid(
                "native loopback probe returned an inconsistent completion",
            ));
        }
        Ok(LoopbackConnection::Connected {})
    }
}

#[cfg(test)]
mod pipe_reader_tests {
    use super::*;
    use std::io::Write;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    fn test_pipe() -> (File, File) {
        let mut read = null_mut();
        let mut write = null_mut();
        assert_ne!(
            unsafe { CreatePipe(&mut read, &mut write, null(), 4096) },
            0
        );
        unsafe {
            (
                File::from(OwnedHandle::from_raw_handle(read)),
                File::from(OwnedHandle::from_raw_handle(write)),
            )
        }
    }

    #[test]
    fn interactive_frames_arrive_without_eof_but_stalled_writers_still_expire() {
        let (read, mut write) = test_pipe();
        write.write_all(b"first\n").unwrap();
        let (release, released) = mpsc::channel::<()>();
        let holder = thread::spawn(move || {
            let _held_writer = write;
            let _ = released.recv_timeout(Duration::from_secs(2));
        });
        let mut reader = io::BufReader::new(pipe_reader_until(
            read,
            Instant::now() + Duration::from_millis(100),
        ));
        assert_eq!(
            crate::util::read_frame(&mut reader, 32).unwrap().unwrap(),
            b"first"
        );
        let stalled = crate::util::read_frame(&mut reader, 32);
        let returned_before_release = release.send(()).is_ok();
        holder.join().unwrap();
        assert!(
            matches!(stalled, Err(Error::Io(error)) if error.kind() == io::ErrorKind::TimedOut)
        );
        assert!(returned_before_release);
    }

    #[test]
    fn open_writer_cannot_extend_the_pipe_reader_deadline() {
        let (read, write) = test_pipe();
        let (release, released) = mpsc::channel::<()>();
        let holder = thread::spawn(move || {
            let _held_writer = write;
            let _ = released.recv_timeout(Duration::from_secs(2));
        });
        let started = Instant::now();
        let result = read_pipe_until(read, 64, started + Duration::from_millis(50));
        let elapsed = started.elapsed();
        let reader_returned_before_release = release.send(()).is_ok();
        holder.join().unwrap();
        assert!(
            matches!(result, Err(Error::Deadline)),
            "an open writer must not turn a deadline into successful EOF"
        );
        assert!(reader_returned_before_release);
        assert!(
            elapsed < Duration::from_secs(1),
            "pipe deadline exceeded its test grace period"
        );
    }

    #[test]
    fn pipe_reader_accepts_exact_bound_only_after_eof() {
        let (read, mut write) = test_pipe();
        write.write_all(b"data").unwrap();
        drop(write);
        assert_eq!(
            read_pipe_until(read, 4, Instant::now() + Duration::from_secs(1)).unwrap(),
            b"data",
        );
    }

    #[test]
    fn pipe_reader_rejects_excess_bytes_without_waiting_for_eof() {
        let (read, mut write) = test_pipe();
        write.write_all(b"extra").unwrap();
        assert!(matches!(
            read_pipe_until(read, 4, Instant::now() + Duration::from_secs(1)),
            Err(Error::Invalid(_)),
        ));
    }

    #[test]
    fn expired_pipe_deadline_never_accepts_available_output() {
        let (read, mut write) = test_pipe();
        write.write_all(b"data").unwrap();
        drop(write);
        assert!(matches!(
            read_pipe_until(read, 4, Instant::now()),
            Err(Error::Deadline),
        ));
    }

    #[test]
    fn pipe_reader_refuses_regular_files() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"not pipe data").unwrap();
        assert!(matches!(
            read_pipe_until(file, 64, Instant::now() + Duration::from_secs(1)),
            Err(Error::Windows { .. }),
        ));
    }
}

#[cfg(test)]
mod inheritance_tests {
    use super::*;
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use windows_sys::Win32::Storage::FileSystem::WriteFile;

    #[test]
    fn coordinated_launch_does_not_inherit_an_unrelated_temporary_pipe() {
        const CHILD_HANDLE: &str = "SHIELD_OWNED_INHERITANCE_PROBE";
        const MARKER: &[u8] = b"owned-inheritance-marker";
        if let Ok(value) = std::env::var(CHILD_HANDLE) {
            let handle = value.parse::<usize>().unwrap() as HANDLE;
            let mut written = 0;
            unsafe {
                WriteFile(
                    handle,
                    MARKER.as_ptr(),
                    MARKER.len() as u32,
                    &mut written,
                    null_mut(),
                );
            }
            return;
        }
        for coordinated in [false, true] {
            let guard = process_creation_lock().unwrap();
            let (read, write) = pipe().unwrap();
            assert_ne!(
                unsafe { SetHandleInformation(read.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) },
                0
            );
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "platform::windows::inheritance_tests::coordinated_launch_does_not_inherit_an_unrelated_temporary_pipe",
                ])
                .env(CHILD_HANDLE, (write.as_raw_handle() as usize).to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let (ready_sender, ready) = mpsc::channel();
            let (done_sender, done) = mpsc::channel();
            let launcher = thread::spawn(move || {
                ready_sender.send(()).unwrap();
                let mut child = if coordinated {
                    spawn_command(&mut command).unwrap()
                } else {
                    // Positive control deliberately bypasses Shield's coordination.
                    command.spawn().unwrap()
                };
                let status = child.wait().unwrap();
                done_sender.send(status).unwrap();
            });
            ready.recv_timeout(Duration::from_secs(5)).unwrap();
            let early = done.recv_timeout(Duration::from_secs(1));
            let blocked = matches!(early, Err(mpsc::RecvTimeoutError::Timeout));
            drop(write);
            drop(guard);
            let status = if let Ok(status) = early {
                status
            } else {
                done.recv_timeout(Duration::from_secs(5)).unwrap()
            };
            launcher.join().unwrap();
            assert!(status.success());
            let observed = crate::util::read_bounded(File::from(read), 64).unwrap();
            if coordinated {
                assert!(
                    observed.is_empty(),
                    "unrelated pipe authority leaked: {} marker bytes",
                    observed.len()
                );
                assert!(
                    blocked,
                    "ordinary launch escaped the process-creation guard"
                );
            } else {
                assert_eq!(
                    observed, MARKER,
                    "native inheritance positive control failed"
                );
            }
        }
    }
}
