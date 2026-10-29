use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};

use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use windows_sys::Win32::Foundation::{GENERIC_ALL, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::{DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows_sys::core::GUID;

use crate::error::{Error, Result};
use crate::{files, platform, util};

const FLAGS: u32 = FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
const POLICY_READ: u32 = READ_CONTROL | FWPM_ACTRL_READ;
const POLICY_RECOVERY: u32 = DELETE
    | READ_CONTROL
    | WRITE_DAC
    | WRITE_OWNER
    | FWPM_ACTRL_READ
    | FWPM_ACTRL_WRITE
    | FWPM_ACTRL_ADD_LINK;
const LAYERS: [GUID; 6] = [
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWPM_LAYER_ALE_AUTH_LISTEN_V4,
    FWPM_LAYER_ALE_AUTH_LISTEN_V6,
];

#[derive(Debug, Serialize)]
pub struct NetworkBoundary {
    pub worker_sha256: String,
    pub persistent_exact_image_filters: usize,
    pub scope: &'static str,
}

fn check(code: u32, operation: &'static str) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(Error::Windows {
            operation,
            source: std::io::Error::from_raw_os_error(code as i32),
        })
    }
}

fn policy_security() -> Result<platform::SecurityDescriptor> {
    let owner = platform::current_user_sid()?;
    let descriptor = platform::SecurityDescriptor::from_sddl(&format!(
        "O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x{POLICY_READ:08x};;;{owner})"
    ))?;
    verify_policy_security(descriptor.as_ptr())?;
    Ok(descriptor)
}

fn verify_policy_security(descriptor: PSECURITY_DESCRIPTOR) -> Result<()> {
    let user = platform::current_user_sid()?;
    unsafe {
        if descriptor.is_null() || IsValidSecurityDescriptor(descriptor) == 0 {
            return Err(Error::Denied(
                "invalid WFP object security descriptor".into(),
            ));
        }
        let mut owner = null_mut();
        let mut defaulted = 0;
        platform::check(
            GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted),
            "read WFP object security owner",
        )?;
        let mut control = 0;
        let mut revision = 0;
        platform::check(
            GetSecurityDescriptorControl(descriptor, &mut control, &mut revision),
            "read WFP object security control",
        )?;
        let mut present = 0;
        let mut dacl = null_mut();
        platform::check(
            GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted),
            "read WFP object access-control list",
        )?;
        if owner.is_null()
            || platform::sid_string(owner)? != "S-1-5-32-544"
            || control & SE_DACL_PROTECTED == 0
            || present == 0
            || dacl.is_null()
            || IsValidAcl(dacl) == 0
            || (*dacl).AceCount != 3
        {
            return Err(Error::Denied(
                "WFP objects require administrator ownership and a protected three-principal ACL"
                    .into(),
            ));
        }
        let mut principals = Vec::new();
        for index in 0..3 {
            let mut raw = null_mut();
            platform::check(
                GetAce(dacl, index, &mut raw),
                "read WFP object access entry",
            )?;
            let header = &*raw.cast::<ACE_HEADER>();
            let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
            if header.AceType != 0
                || header.AceFlags != 0
                || usize::from(header.AceSize) < sid_offset + 8
            {
                return Err(Error::Denied(
                    "WFP object contains an unsupported access entry".into(),
                ));
            }
            let ace = &*raw.cast::<ACCESS_ALLOWED_ACE>();
            let sid: PSID = std::ptr::addr_of!(ace.SidStart).cast_mut().cast();
            let sid_length = 8 + 4 * usize::from(*sid.cast::<u8>().add(1));
            if sid_offset + sid_length > usize::from(header.AceSize) || IsValidSid(sid) == 0 {
                return Err(Error::Denied("WFP access entry has an invalid SID".into()));
            }
            let principal = platform::sid_string(sid)?;
            let permitted = if principal == user {
                ace.Mask == POLICY_READ
            } else if principal == "S-1-5-18" || principal == "S-1-5-32-544" {
                ace.Mask == GENERIC_ALL || ace.Mask & POLICY_RECOVERY == POLICY_RECOVERY
            } else {
                false
            };
            if !permitted {
                return Err(Error::Denied(
                    "WFP object permissions differ from administrator control and owner read-only access"
                        .into(),
                ));
            }
            principals.push(principal);
        }
        principals.sort();
        let mut expected = vec![user, "S-1-5-18".to_owned(), "S-1-5-32-544".to_owned()];
        expected.sort();
        if principals != expected {
            return Err(Error::Denied(
                "WFP object has duplicate or unexpected security principals".into(),
            ));
        }
    }
    Ok(())
}

type ReadSecurity = unsafe extern "system" fn(
    HANDLE,
    *const GUID,
    u32,
    *mut PSID,
    *mut PSID,
    *mut *mut ACL,
    *mut *mut ACL,
    *mut PSECURITY_DESCRIPTOR,
) -> u32;

fn verify_object_security(engine: &Engine, key: &GUID, read: ReadSecurity) -> Result<()> {
    let mut descriptor = null_mut();
    unsafe {
        check(
            read(
                engine.0,
                key,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            ),
            "read required Shield WFP object permissions",
        )?;
    }
    let _allocation = Allocation(descriptor);
    verify_policy_security(descriptor)
}

fn key(profile: Uuid, index: u128) -> GUID {
    let digest = Sha256::digest(format!("Shield.WFP.1/{profile}/{index}").as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    GUID::from_u128(u128::from_be_bytes(bytes))
}

pub fn owned_keys(profile: Uuid) -> serde_json::Value {
    let text = |index| {
        let value = key(profile, index);
        Uuid::from_fields(value.data1, value.data2, value.data3, &value.data4).to_string()
    };
    serde_json::json!({
        "provider": text(0), "sublayer": text(1),
        "filters": (0..LAYERS.len()).map(|index| text(index as u128 + 2)).collect::<Vec<_>>()
    })
}

fn same(left: GUID, right: GUID) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
}

struct Allocation(*mut c_void);

impl Drop for Allocation {
    fn drop(&mut self) {
        unsafe { FwpmFreeMemory0(&mut self.0) };
    }
}

struct Engine(HANDLE);

impl Engine {
    fn open() -> Result<Self> {
        let mut handle = null_mut();
        unsafe {
            check(
                FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), null(), &mut handle),
                "FwpmEngineOpen0 (required network policy access)",
            )?;
        }
        Ok(Self(handle))
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        let code = unsafe { FwpmEngineClose0(self.0) };
        if code != 0 {
            eprintln!("Shield WFP engine cleanup failed: Windows code {code}");
        }
    }
}

struct Change<'a> {
    engine: &'a Engine,
    committed: bool,
}

impl<'a> Change<'a> {
    fn begin(engine: &'a Engine) -> Result<Self> {
        unsafe { check(FwpmTransactionBegin0(engine.0, 0), "FwpmTransactionBegin0")? };
        Ok(Self {
            engine,
            committed: false,
        })
    }

    fn commit(mut self) -> Result<()> {
        unsafe {
            check(
                FwpmTransactionCommit0(self.engine.0),
                "FwpmTransactionCommit0",
            )?
        };
        self.committed = true;
        Ok(())
    }
}

impl Drop for Change<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let code = unsafe { FwpmTransactionAbort0(self.engine.0) };
            if code != 0 {
                eprintln!("Shield WFP transaction abort failed: Windows code {code}");
            }
        }
    }
}

fn application(path: &Path) -> Result<(*mut FWP_BYTE_BLOB, Allocation)> {
    files::check_no_reparse(path)?;
    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut blob = null_mut();
    unsafe {
        check(
            FwpmGetAppIdFromFileName0(path.as_ptr(), &mut blob),
            "FwpmGetAppIdFromFileName0",
        )?
    };
    Ok((blob, Allocation(blob.cast())))
}

unsafe fn equal_blob(left: *const FWP_BYTE_BLOB, right: *const FWP_BYTE_BLOB) -> bool {
    if left.is_null() || right.is_null() {
        return false;
    }
    unsafe {
        if (*left).size == 0
            || (*left).size != (*right).size
            || (*left).data.is_null()
            || (*right).data.is_null()
        {
            return false;
        }
        std::slice::from_raw_parts((*left).data, (*left).size as usize)
            == std::slice::from_raw_parts((*right).data, (*right).size as usize)
    }
}

pub fn verify(profile: Uuid, worker: &Path, expected_hash: &str) -> Result<NetworkBoundary> {
    if util::file_digest(worker)? != expected_hash {
        return Err(Error::Denied(
            "dedicated worker image differs from the frozen executable".into(),
        ));
    }
    let engine = Engine::open()?;
    let (application, _allocation) = application(worker)?;
    unsafe {
        let mut provider = null_mut();
        check(
            FwpmProviderGetByKey0(engine.0, &key(profile, 0), &mut provider),
            "read required Shield WFP provider",
        )?;
        let _provider = Allocation(provider.cast());
        if (*provider).flags != FWPM_PROVIDER_FLAG_PERSISTENT {
            return Err(Error::Denied(
                "network provider is disabled, nonpersistent, or changed".into(),
            ));
        }
        verify_object_security(&engine, &key(profile, 0), FwpmProviderGetSecurityInfoByKey0)?;
        let mut sublayer = null_mut();
        check(
            FwpmSubLayerGetByKey0(engine.0, &key(profile, 1), &mut sublayer),
            "read required Shield WFP sublayer",
        )?;
        let _sublayer = Allocation(sublayer.cast());
        if (*sublayer).flags != FWPM_SUBLAYER_FLAG_PERSISTENT
            || (*sublayer).weight != u16::MAX
            || (*sublayer).providerKey.is_null()
            || !same(*(*sublayer).providerKey, key(profile, 0))
        {
            return Err(Error::Denied(
                "network sublayer does not match the owned policy".into(),
            ));
        }
        verify_object_security(&engine, &key(profile, 1), FwpmSubLayerGetSecurityInfoByKey0)?;
        for (index, layer) in LAYERS.iter().enumerate() {
            let mut filter = null_mut();
            check(
                FwpmFilterGetByKey0(engine.0, &key(profile, index as u128 + 2), &mut filter),
                "read required Shield WFP deny filter",
            )?;
            let _filter = Allocation(filter.cast());
            let filter = &*filter;
            if !same(filter.layerKey, *layer)
                || !same(filter.subLayerKey, key(profile, 1))
                || filter.flags != FLAGS
                || filter.action.r#type != FWP_ACTION_BLOCK
                || filter.providerKey.is_null()
                || !same(*filter.providerKey, key(profile, 0))
                || filter.weight.r#type != FWP_UINT8
                || filter.weight.Anonymous.uint8 != u8::MAX
                || filter.numFilterConditions != 1
                || filter.filterCondition.is_null()
            {
                return Err(Error::Denied(
                    "network filter has unexpected ownership, scope, weight, flags, or action"
                        .into(),
                ));
            }
            let condition = &*filter.filterCondition;
            if !same(condition.fieldKey, FWPM_CONDITION_ALE_APP_ID)
                || condition.matchType != FWP_MATCH_EQUAL
                || condition.conditionValue.r#type != FWP_BYTE_BLOB_TYPE
                || !equal_blob(condition.conditionValue.Anonymous.byteBlob, application)
            {
                return Err(Error::Denied(
                    "network filter is not bound to the exact dedicated worker image".into(),
                ));
            }
            verify_object_security(
                &engine,
                &key(profile, index as u128 + 2),
                FwpmFilterGetSecurityInfoByKey0,
            )?;
        }
    }
    Ok(NetworkBoundary {
        worker_sha256: expected_hash.into(),
        persistent_exact_image_filters: LAYERS.len(),
        scope: "Exact-image IPv4/IPv6 ALE connect, accept and listen denial. Inventory is not an effect test or proof against brokered/indirect egress.",
    })
}

pub fn install(profile: Uuid, worker: &Path, expected_hash: &str) -> Result<NetworkBoundary> {
    if !crate::platform::is_elevated()? {
        return Err(Error::Denied("network setup requires an explicitly elevated, authorized lab operator; the runtime must remain unelevated".into()));
    }
    if util::file_digest(worker)? != expected_hash {
        return Err(Error::Denied(
            "refusing policy installation for a changed worker".into(),
        ));
    }
    let engine = Engine::open()?;
    let security = policy_security()?;
    let (application, _allocation) = application(worker)?;
    let change = Change::begin(&engine)?;
    let mut provider_key = key(profile, 0);
    let mut name: Vec<u16> = format!("Shield owned worker boundary {profile}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let display = FWPM_DISPLAY_DATA0 {
        name: name.as_mut_ptr(),
        description: null_mut(),
    };
    unsafe {
        let provider = FWPM_PROVIDER0 {
            providerKey: provider_key,
            displayData: display,
            flags: FWPM_PROVIDER_FLAG_PERSISTENT,
            ..Default::default()
        };
        check(
            FwpmProviderAdd0(engine.0, &provider, security.as_ptr()),
            "install owned WFP provider (existing objects are not overwritten)",
        )?;
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: key(profile, 1),
            displayData: display,
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey: &mut provider_key,
            weight: u16::MAX,
            ..Default::default()
        };
        check(
            FwpmSubLayerAdd0(engine.0, &sublayer, security.as_ptr()),
            "install owned WFP sublayer",
        )?;
        for (index, layer) in LAYERS.iter().enumerate() {
            let mut condition = FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_APP_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        byteBlob: application,
                    },
                },
            };
            let filter = FWPM_FILTER0 {
                filterKey: key(profile, index as u128 + 2),
                displayData: display,
                flags: FLAGS,
                providerKey: &mut provider_key,
                layerKey: *layer,
                subLayerKey: key(profile, 1),
                weight: FWP_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_VALUE0_0 { uint8: u8::MAX },
                },
                numFilterConditions: 1,
                filterCondition: &mut condition,
                action: FWPM_ACTION0 {
                    r#type: FWP_ACTION_BLOCK,
                    ..Default::default()
                },
                ..Default::default()
            };
            check(
                FwpmFilterAdd0(engine.0, &filter, security.as_ptr(), null_mut()),
                "install exact-image WFP deny filter",
            )?;
        }
    }
    change.commit()?;
    verify(profile, worker, expected_hash)
}

pub fn remove(profile: Uuid, worker: &Path, expected_hash: &str) -> Result<()> {
    if !crate::platform::is_elevated()? {
        return Err(Error::Denied(
            "network removal requires an explicitly elevated, authorized lab operator".into(),
        ));
    }
    verify(profile, worker, expected_hash)?;
    let engine = Engine::open()?;
    let change = Change::begin(&engine)?;
    unsafe {
        for index in 0..LAYERS.len() {
            check(
                FwpmFilterDeleteByKey0(engine.0, &key(profile, index as u128 + 2)),
                "remove verified owned WFP filter",
            )?;
        }
        check(
            FwpmSubLayerDeleteByKey0(engine.0, &key(profile, 1)),
            "remove verified owned WFP sublayer",
        )?;
        check(
            FwpmProviderDeleteByKey0(engine.0, &key(profile, 0)),
            "remove verified owned WFP provider",
        )?;
    }
    change.commit()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, LUID};
    use windows_sys::Win32::Security::Authorization::*;

    pub(crate) struct AuthorizationContext {
        manager: AUTHZ_RESOURCE_MANAGER_HANDLE,
        client: AUTHZ_CLIENT_CONTEXT_HANDLE,
    }

    impl AuthorizationContext {
        pub(crate) fn new(sid: PSID) -> Self {
            let mut context = Self {
                manager: null_mut(),
                client: null_mut(),
            };
            unsafe {
                platform::check(
                    AuthzInitializeResourceManager(
                        AUTHZ_RM_FLAG_NO_AUDIT,
                        None,
                        None,
                        None,
                        null(),
                        &mut context.manager,
                    ),
                    "initialize in-memory ACL test resource manager",
                )
                .unwrap();
                platform::check(
                    AuthzInitializeContextFromSid(
                        AUTHZ_SKIP_TOKEN_GROUPS,
                        sid,
                        context.manager,
                        null(),
                        LUID::default(),
                        null(),
                        &mut context.client,
                    ),
                    "initialize identity-only ACL test context",
                )
                .unwrap();
            }
            context
        }

        pub(crate) fn access(&self, descriptor: PSECURITY_DESCRIPTOR, access: u32) -> (u32, u32) {
            let request = AUTHZ_ACCESS_REQUEST {
                DesiredAccess: access,
                ..Default::default()
            };
            let mut granted = 0;
            let mut error = 0;
            let mut reply = AUTHZ_ACCESS_REPLY {
                ResultListLength: 1,
                GrantedAccessMask: &mut granted,
                Error: &mut error,
                ..Default::default()
            };
            unsafe {
                platform::check(
                    AuthzAccessCheck(
                        0,
                        self.client,
                        &request,
                        null_mut(),
                        descriptor,
                        null(),
                        0,
                        &mut reply,
                        null_mut(),
                    ),
                    "evaluate in-memory identity ACL",
                )
                .unwrap();
            }
            (granted, error)
        }
    }

    impl Drop for AuthorizationContext {
        fn drop(&mut self) {
            unsafe {
                for (handle, release, operation) in [
                    (
                        self.client,
                        AuthzFreeContext as unsafe extern "system" fn(*mut c_void) -> i32,
                        "free in-memory ACL test context",
                    ),
                    (
                        self.manager,
                        AuthzFreeResourceManager,
                        "free in-memory ACL test resource manager",
                    ),
                ] {
                    if !handle.is_null()
                        && let Err(error) = platform::check(release(handle), operation)
                    {
                        eprintln!("Shield ACL test cleanup failed: {error}");
                    }
                }
            }
        }
    }

    #[test]
    fn windows_access_evaluation_denies_policy_mutation_to_the_daily_identity() {
        let descriptor = policy_security().unwrap();
        let mut dacl = null_mut();
        let mut present = 0;
        let mut defaulted = 0;
        let mut raw = null_mut();
        unsafe {
            platform::check(
                GetSecurityDescriptorDacl(
                    descriptor.as_ptr(),
                    &mut present,
                    &mut dacl,
                    &mut defaulted,
                ),
                "read in-memory ACL test entries",
            )
            .unwrap();
            platform::check(GetAce(dacl, 2, &mut raw), "read in-memory daily-user ACE").unwrap();
        }
        let sid: PSID = unsafe {
            std::ptr::addr_of!((*raw.cast::<ACCESS_ALLOWED_ACE>()).SidStart)
                .cast_mut()
                .cast()
        };
        let context = AuthorizationContext::new(sid);
        assert_eq!(
            context.access(descriptor.as_ptr(), POLICY_READ),
            (POLICY_READ, 0)
        );
        for forbidden in [
            DELETE,
            WRITE_DAC,
            WRITE_OWNER,
            FWPM_ACTRL_ADD,
            FWPM_ACTRL_ADD_LINK,
            FWPM_ACTRL_WRITE,
        ] {
            assert_eq!(
                context.access(descriptor.as_ptr(), forbidden),
                (0, ERROR_ACCESS_DENIED),
                "daily identity must not receive policy right 0x{forbidden:08x}"
            );
        }
    }

    #[test]
    fn owned_policy_security_gives_the_daily_user_only_read_access() {
        let descriptor = policy_security().unwrap();
        verify_policy_security(descriptor.as_ptr()).unwrap();
        let user = platform::current_user_sid().unwrap();
        let variants = [
            format!("O:{user}G:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x{POLICY_READ:08x};;;{user})"),
            format!("O:BAG:BAD:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x{POLICY_READ:08x};;;{user})"),
            format!("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{user})"),
            format!("O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x{POLICY_READ:08x};;;WD)"),
            "O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;SY)".to_owned(),
        ];
        for sddl in variants {
            let descriptor = platform::SecurityDescriptor::from_sddl(&sddl).unwrap();
            assert!(verify_policy_security(descriptor.as_ptr()).is_err());
        }
        for permission in [
            DELETE,
            WRITE_DAC,
            WRITE_OWNER,
            FWPM_ACTRL_WRITE,
            FWPM_ACTRL_ADD_LINK,
        ] {
            let mask = POLICY_READ | permission;
            let descriptor = platform::SecurityDescriptor::from_sddl(&format!(
                "O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x{mask:08x};;;{user})"
            ))
            .unwrap();
            assert!(verify_policy_security(descriptor.as_ptr()).is_err());
        }
    }

    #[test]
    fn each_profile_and_filter_has_a_distinct_owned_key() {
        let profile = Uuid::new_v4();
        let adjacent_profile = Uuid::from_u128(profile.as_u128() ^ 1);
        for left in 0..8 {
            for right in 0..8 {
                assert_eq!(same(key(profile, left), key(profile, right)), left == right);
            }
            assert!(!same(key(profile, left), key(Uuid::new_v4(), left)));
            for right in 0..8 {
                assert!(!same(key(profile, left), key(adjacent_profile, right)));
            }
        }
    }
}
