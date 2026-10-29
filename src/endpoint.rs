use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

use crate::error::{Error, Result, invalid};
use crate::files::Fingerprint;
use crate::state::{EndpointChange, Store};
use crate::{files, platform, util};

const AUTHOR: &str = include_str!("endpoint-author.ps1");
const POLICY_BYTES: u64 = 4 * 1024 * 1024;
const APPLICATION_BYTES: u64 = 128 * 1024 * 1024;
const REQUIRED_OPTIONS: [&str; 3] = [
    "Enabled:UMCI",
    "Enabled:Unsigned System Integrity Policy",
    "Enabled:Update Policy No Reboot",
];
const SUPPORTED_OPTIONS: [&str; 11] = [
    "Enabled:UMCI",
    "Enabled:Unsigned System Integrity Policy",
    "Enabled:Update Policy No Reboot",
    "Enabled:Boot Menu Protection",
    "Enabled:Advanced Boot Options Menu",
    "Enabled:Inherit Default Policy",
    "Required:Enforce Store Applications",
    "Enabled:Dynamic Code Security",
    "Enabled:Revoked Expired As Unsigned",
    "Disabled:Flight Signing",
    "Required:WHQL",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct NativePolicy {
    id: Uuid,
    base: Uuid,
    name: String,
    version: u64,
    system: bool,
    signed: bool,
    on_disk: bool,
    enforced: bool,
    authorized: bool,
    status: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    policies: Vec<NativePolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Application {
    pub path: PathBuf,
    pub fingerprint: Fingerprint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema_version: u32,
    pub id: Uuid,
    pub policy_id: Uuid,
    pub profile_digest: String,
    pub previous: Option<Uuid>,
    pub revision: u16,
    pub baseline_sha256: String,
    pub author_sha256: String,
    pub xml_sha256: String,
    pub cip_sha256: String,
    pub options: Vec<String>,
    pub applications: Vec<Application>,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyIdentity {
    pub policy_id: Uuid,
    pub revision: u16,
    pub cip_sha256: String,
}

impl Plan {
    pub fn digest(&self) -> Result<String> {
        util::json_digest(self)
    }

    pub(crate) fn policy_identity(&self) -> PolicyIdentity {
        PolicyIdentity {
            policy_id: self.policy_id,
            revision: self.revision,
            cip_sha256: self.cip_sha256.clone(),
        }
    }

    fn validate(&self, store: &Store) -> Result<()> {
        if self.schema_version != 1
            || self.id.is_nil()
            || self.policy_id != store.profile.id
            || self.profile_digest != store.profile.digest()?
            || self.previous == Some(self.id)
            || self.previous.is_some() != (self.revision > 0)
            || self.applications.is_empty()
            || self.applications.len() > 64
            || self.expires_at.checked_sub(self.created_at) != Some(3600)
        {
            return Err(invalid(
                "endpoint plan identity, revision, inputs or lifetime is invalid",
            ));
        }
        for digest in [
            &self.baseline_sha256,
            &self.author_sha256,
            &self.xml_sha256,
            &self.cip_sha256,
        ] {
            if digest.len() != 64 || hex::decode(digest).is_err() {
                return Err(invalid("endpoint plan has an invalid artifact digest"));
            }
        }
        if self.author_sha256 != util::digest(AUTHOR.as_bytes()) {
            return Err(invalid(
                "endpoint plan does not bind the fixed native authoring asset",
            ));
        }
        if self.options.len() > SUPPORTED_OPTIONS.len()
            || self
                .options
                .iter()
                .any(|option| !SUPPORTED_OPTIONS.contains(&option.as_str()))
            || REQUIRED_OPTIONS
                .iter()
                .any(|option| !self.options.iter().any(|value| value == option))
            || self.options.iter().collect::<BTreeSet<_>>().len() != self.options.len()
        {
            return Err(invalid(
                "endpoint plan has missing, expanding or unsupported native options",
            ));
        }
        let mut digests = BTreeSet::new();
        for application in &self.applications {
            files::validate_path(&application.path)?;
            let fingerprint = &application.fingerprint;
            if fingerprint.bytes == 0
                || fingerprint.bytes > APPLICATION_BYTES
                || fingerprint.sha256.len() != 64
                || hex::decode(&fingerprint.sha256).is_err()
                || !digests.insert(&fingerprint.sha256)
            {
                return Err(invalid(
                    "endpoint application identities must be bounded and distinct",
                ));
            }
        }
        Ok(())
    }
}

fn system_directory() -> Result<PathBuf> {
    let mut buffer = [0_u16; 32768];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(Error::Windows {
            operation: "GetSystemDirectoryW",
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(PathBuf::from(
        String::from_utf16(&buffer[..length])
            .map_err(|_| Error::Protocol("invalid system-directory encoding"))?,
    ))
}

struct NativeChild {
    child: Child,
    finished: bool,
}

impl Drop for NativeChild {
    fn drop(&mut self) {
        if !self.finished {
            if let Err(error) = self.child.kill() {
                eprintln!("Shield owned native-helper termination failed: {error}");
            }
            if let Err(error) = self.child.wait() {
                eprintln!("Shield owned native-helper reaping failed: {error}");
            }
        }
    }
}

fn native(
    program: &Path,
    arguments: &[&std::ffi::OsStr],
    input: Option<&Value>,
    temporary: Option<&Path>,
) -> Result<Vec<u8>> {
    let bytes = input.map(serde_json::to_vec).transpose()?;
    if bytes.as_ref().is_some_and(|bytes| bytes.len() > 64 * 1024) {
        return Err(invalid("native authoring input exceeds its byte bound"));
    }
    let mut command = Command::new(program);
    command
        .args(arguments)
        .current_dir(system_directory()?)
        .env_clear()
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in [
        "APPDATA",
        "LOCALAPPDATA",
        "SystemRoot",
        "USERPROFILE",
        "WINDIR",
    ] {
        let value = std::env::var_os(name)
            .ok_or_else(|| invalid("a required native-helper environment variable is absent"))?;
        command.env(name, value);
    }
    if let Some(temporary) = temporary {
        command.env("TEMP", temporary).env("TMP", temporary);
    }
    let mut child = NativeChild {
        child: platform::spawn_command(&mut command)?,
        finished: false,
    };
    let output = child
        .child
        .stdout
        .take()
        .ok_or(Error::Protocol("native stdout was not captured"))?;
    let errors = child
        .child
        .stderr
        .take()
        .ok_or(Error::Protocol("native stderr was not captured"))?;
    let reader = thread::spawn(move || util::read_bounded(output, 1024 * 1024));
    let error_reader = thread::spawn(move || util::read_bounded(errors, 16 * 1024));
    let writer = if let Some(bytes) = bytes {
        let mut pipe = child
            .child
            .stdin
            .take()
            .ok_or(Error::Protocol("native stdin was not captured"))?;
        Some(thread::spawn(move || pipe.write_all(&bytes)))
    } else {
        None
    };
    let deadline = Instant::now()
        + if input.is_some() {
            Duration::from_secs(60)
        } else {
            Duration::from_secs(5)
        };
    let status = loop {
        if let Some(status) = child.child.try_wait()? {
            child.finished = true;
            break Some(status);
        }
        if Instant::now() >= deadline {
            child.child.kill()?;
            child.child.wait()?;
            child.finished = true;
            break None;
        }
        thread::sleep(Duration::from_millis(25));
    };
    let output = reader
        .join()
        .map_err(|_| Error::Protocol("native output reader panicked"))??;
    let errors = error_reader
        .join()
        .map_err(|_| Error::Protocol("native error reader panicked"))??;
    let status = status.ok_or(Error::Deadline)?;
    if let Some(writer) = writer {
        writer
            .join()
            .map_err(|_| Error::Protocol("native input writer panicked"))??;
    }
    if !status.success() {
        return Err(Error::Unsupported(format!(
            "native policy helper failed with exit {status}; raw output was not logged and no elevation or permissive fallback was attempted"
        )));
    }
    if !errors.is_empty() {
        return Err(Error::Protocol(
            "native policy helper returned stderr; output is not verified state",
        ));
    }
    Ok(output)
}

fn native_json(bytes: &[u8]) -> Result<Value> {
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| Error::Protocol("native helper did not return supported UTF-8 JSON"))?;
    if value.get("OperationResult").and_then(Value::as_i64) != Some(0) {
        return Err(Error::Unsupported(
            "CiTool did not report a successful native operation".into(),
        ));
    }
    Ok(value)
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value.get(name).ok_or(Error::Protocol(
        "native policy inventory omitted a required field",
    ))
}

fn boolean(value: &Value) -> Result<bool> {
    match value {
        Value::Bool(value) => Ok(*value),
        Value::String(value) if value.eq_ignore_ascii_case("true") => Ok(true),
        Value::String(value) if value.eq_ignore_ascii_case("false") => Ok(false),
        _ => Err(Error::Protocol(
            "native policy inventory has an unsupported boolean",
        )),
    }
}

fn number(value: &Value) -> Result<u64> {
    if let Some(value) = value.as_u64() {
        return Ok(value);
    }
    value
        .as_str()
        .and_then(|value| value.parse().ok())
        .ok_or(Error::Protocol(
            "native policy inventory has an unsupported integer",
        ))
}

fn guid(value: &Value) -> Result<Uuid> {
    value
        .as_str()
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(Error::Protocol(
            "native policy inventory has an invalid GUID",
        ))
}

fn snapshot(value: &Value) -> Result<Snapshot> {
    let rows = field(value, "Policies")?.as_array().ok_or(Error::Protocol(
        "native policy inventory has no policy array",
    ))?;
    if rows.len() > 128 {
        return Err(Error::Unsupported(
            "native policy count exceeds the implemented bound".into(),
        ));
    }
    let mut policies = Vec::new();
    let mut ids = BTreeSet::new();
    for row in rows {
        let id = guid(field(row, "PolicyID")?)?;
        let name = field(row, "FriendlyName")?
            .as_str()
            .filter(|value| value.len() <= 512)
            .ok_or(Error::Protocol("native policy name is invalid or too long"))?
            .to_owned();
        if !ids.insert(id) {
            return Err(Error::Protocol(
                "native policy inventory has duplicate policy identities",
            ));
        }
        policies.push(NativePolicy {
            id,
            base: guid(field(row, "BasePolicyID")?)?,
            name,
            version: number(field(row, "Version")?)?,
            system: boolean(field(row, "IsSystemPolicy")?)?,
            signed: boolean(field(row, "IsSignedPolicy")?)?,
            on_disk: boolean(field(row, "IsOnDisk")?)?,
            enforced: boolean(field(row, "IsEnforced")?)?,
            authorized: boolean(field(row, "IsAuthorized")?)?,
            status: number(field(row, "Status")?)?,
        });
    }
    policies.sort_by_key(|policy| policy.id);
    Ok(Snapshot { policies })
}

fn current() -> Result<Snapshot> {
    let program = system_directory()?.join("CiTool.exe");
    let bytes = native(&program, &["-lp".as_ref(), "-json".as_ref()], None, None)?;
    snapshot(&native_json(&bytes)?)
}

pub fn authoring_support() -> Result<Value> {
    let system = system_directory()?;
    let windows = system
        .parent()
        .ok_or_else(|| invalid("system directory has no Windows parent"))?;
    let module = system.join(r"WindowsPowerShell\v1.0\Modules\ConfigCI\ConfigCI.psd1");
    let baseline =
        windows.join(r"schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml");
    let powershell = system.join(r"WindowsPowerShell\v1.0\powershell.exe");
    Ok(json!({
        "module": module, "module_present": module.try_exists()?,
        "baseline": baseline, "baseline_present": baseline.try_exists()?,
        "powershell": powershell, "powershell_present": powershell.try_exists()?,
        "available": module.try_exists()? && baseline.try_exists()? && powershell.try_exists()?,
        "warning": "Authoring-tool presence is not deployment eligibility or E0/E1 evidence."
    }))
}

pub fn inventory() -> Result<Value> {
    Ok(json!({
        "native_inventory": current()?,
        "shield_endpoint_admission": "owned_app_control_backend_unqualified",
        "authoring": authoring_support()?,
        "effect_tests": "not_performed",
        "warning": "Inventory is not effect verification. Policies apply computer-wide; existing protections are never disabled."
    }))
}

fn directory(store: &Store, id: Uuid) -> PathBuf {
    store.root.join("endpoint").join(id.to_string())
}

fn pin_system_file(path: &Path) -> Result<(File, String)> {
    files::check_no_reparse(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(Error::Denied(
            "native policy source is not an ordinary system file".into(),
        ));
    }
    let bytes = util::read_bounded(&mut file, POLICY_BYTES)?;
    Ok((file, util::digest(&bytes)))
}

pub(crate) fn load(store: &Store, id: Uuid) -> Result<Plan> {
    let path = directory(store, id).join("plan.json");
    let (bytes, _) = files::snapshot(&path, 128 * 1024)?;
    let plan: Plan = serde_json::from_slice(&bytes)?;
    plan.validate(store)?;
    if plan.id != id {
        return Err(invalid("endpoint plan path/identity mismatch"));
    }
    Ok(plan)
}

fn pin_artifacts(store: &Store, plan: &Plan) -> Result<Vec<File>> {
    let mut pins = Vec::new();
    for (name, expected) in [
        ("author.ps1", &plan.author_sha256),
        ("policy.xml", &plan.xml_sha256),
        ("policy.cip", &plan.cip_sha256),
    ] {
        let (file, fingerprint) = files::pin(&directory(store, plan.id).join(name), POLICY_BYTES)?;
        if fingerprint.sha256 != *expected {
            return Err(Error::Denied(
                "endpoint policy artifacts changed after preparation".into(),
            ));
        }
        pins.push(file);
    }
    Ok(pins)
}

pub fn inspect(store: &Store, id: Uuid) -> Result<Value> {
    let plan = load(store, id)?;
    let _pins = pin_artifacts(store, &plan)?;
    Ok(json!({
        "plan_digest": plan.digest()?, "plan": plan,
        "matching": "DefaultWindows baseline plus native ConfigCI image-hash rules; not whole-file release-digest matching",
        "scope": "computer-wide additional base allowlist, not a task launcher or behavior firewall",
        "effect_gate_pass": false,
    }))
}

pub fn prepare(
    store: &mut Store,
    applications: &[PathBuf],
    previous: Option<Uuid>,
) -> Result<Value> {
    let _control = store.control_lock()?;
    store.profile.verify_host()?;
    if platform::is_elevated()? {
        return Err(Error::Denied("prepare admission artifacts as the unelevated owner; only explicit lab installation/removal is privileged".into()));
    }
    let support = authoring_support()?;
    if support["available"] != true {
        return Err(Error::Unsupported("ConfigCI, PowerShell or the native DefaultWindows_Enforced template is absent; use an authorized compatible authoring lab, not a weakened policy or invented replacement".into()));
    }
    if applications.len() > 63 {
        return Err(invalid(
            "select at most 63 additional executable/DLL artifacts",
        ));
    }
    let revision = match previous {
        None => 0,
        Some(id) => load(store, id)?
            .revision
            .checked_add(1)
            .ok_or_else(|| Error::Quota("endpoint policy revision exhausted".into()))?,
    };
    let root = store.root.join("endpoint");
    if !root.try_exists()? {
        std::fs::create_dir(&root)?;
    }
    files::check_no_reparse(&root)?;
    let mut count = 0;
    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir()
            || Uuid::parse_str(&entry.file_name().to_string_lossy()).is_err()
        {
            return Err(invalid(
                "unexpected object in the private endpoint-plan directory",
            ));
        }
        count += 1;
    }
    if count >= 64 {
        return Err(Error::Quota(
            "this profile permits at most 64 retained admission plans".into(),
        ));
    }
    let id = Uuid::new_v4();
    let path = directory(store, id);
    std::fs::create_dir(&path)?;
    let temporary = path.join("temp");
    std::fs::create_dir(&temporary)?;
    let mut inputs = Vec::new();
    let mut pins = Vec::new();
    let mut digests = BTreeSet::new();
    for application in std::iter::once(std::env::current_exe()?).chain(applications.iter().cloned())
    {
        let extension = application
            .extension()
            .and_then(|value| value.to_str())
            .map(str::to_ascii_lowercase);
        if !matches!(extension.as_deref(), Some("exe" | "dll")) {
            return Err(invalid(
                "admission inputs must be explicitly selected EXE/DLL files",
            ));
        }
        let (file, fingerprint) = files::pin(&application, APPLICATION_BYTES)?;
        if digests.insert(fingerprint.sha256.clone()) {
            inputs.push(Application {
                path: application,
                fingerprint,
            });
            pins.push(file);
        }
    }
    let baseline = PathBuf::from(
        support["baseline"]
            .as_str()
            .ok_or(Error::Protocol("missing native baseline path"))?,
    );
    let (baseline_pin, baseline_sha256) = pin_system_file(&baseline)?;
    pins.push(baseline_pin);
    let script = path.join("author.ps1");
    files::create_new(&script, AUTHOR.as_bytes())?;
    let (script_pin, script_fingerprint) = files::pin(&script, 64 * 1024)?;
    if script_fingerprint.sha256 != util::digest(AUTHOR.as_bytes()) {
        return Err(Error::Denied("endpoint authoring script changed".into()));
    }
    pins.push(script_pin);
    let version = format!("1.0.0.{revision}");
    let request = json!({
        "directory": path,
        "policy_id": format!("{{{}}}", store.profile.id), "name": format!("Shield {}", store.profile.id),
        "version": version, "applications": inputs.iter().map(|input| &input.path).collect::<Vec<_>>(),
    });
    let powershell = PathBuf::from(
        support["powershell"]
            .as_str()
            .ok_or(Error::Protocol("missing native PowerShell path"))?,
    );
    let result = native(
        &powershell,
        &[
            "-NoLogo".as_ref(),
            "-NoProfile".as_ref(),
            "-NonInteractive".as_ref(),
            "-File".as_ref(),
            script.as_os_str(),
        ],
        Some(&request),
        Some(&temporary),
    )?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Authored {
        policy_id: Uuid,
        base_policy_id: Uuid,
        version: String,
        options: Vec<String>,
    }
    let authored: Authored = serde_json::from_slice(&result)
        .map_err(|_| Error::Protocol("native authoring returned unsupported metadata"))?;
    if authored.policy_id != store.profile.id
        || authored.base_policy_id != store.profile.id
        || authored.version != version
    {
        return Err(Error::Denied(
            "native authoring produced a different policy identity or revision".into(),
        ));
    }
    for input in &inputs {
        if files::pin(&input.path, APPLICATION_BYTES)?.1 != input.fingerprint {
            return Err(Error::Denied(
                "an admission input changed during native rule generation".into(),
            ));
        }
    }
    let created_at = util::now()?;
    let plan = Plan {
        schema_version: 1,
        id,
        policy_id: store.profile.id,
        profile_digest: store.profile.digest()?,
        previous,
        revision,
        baseline_sha256,
        author_sha256: script_fingerprint.sha256,
        xml_sha256: files::pin(&path.join("policy.xml"), POLICY_BYTES)?.1.sha256,
        cip_sha256: files::pin(&path.join("policy.cip"), POLICY_BYTES)?.1.sha256,
        options: authored.options,
        applications: inputs,
        created_at,
        expires_at: created_at
            .checked_add(3600)
            .ok_or_else(|| invalid("endpoint lifetime overflow"))?,
    };
    plan.validate(store)?;
    files::create_new(&path.join("plan.json"), &serde_json::to_vec_pretty(&plan)?)?;
    store.event(None, "endpoint_plan_prepared", json!({
        "plan": id, "plan_digest": plan.digest()?, "policy": plan.policy_id,
        "revision": revision, "artifact_count": plan.applications.len(), "effect_gate_pass": false,
    }))?;
    inspect(store, id)
}

fn installed_path(id: Uuid) -> Result<PathBuf> {
    Ok(system_directory()?
        .join(r"CodeIntegrity\CiPolicies\Active")
        .join(format!("{{{id}}}.cip")))
}

fn owned_metadata<'a>(
    snapshot: &'a Snapshot,
    plan: &Plan,
    active: bool,
) -> Result<&'a NativePolicy> {
    owned_identity(snapshot, &plan.policy_identity(), active)
}

fn owned_identity<'a>(
    snapshot: &'a Snapshot,
    identity: &PolicyIdentity,
    active: bool,
) -> Result<&'a NativePolicy> {
    let policy = snapshot
        .policies
        .iter()
        .find(|policy| policy.id == identity.policy_id)
        .ok_or_else(|| Error::Denied("the enrolled endpoint policy is absent".into()))?;
    if policy.base != identity.policy_id
        || policy.name != format!("Shield {}", identity.policy_id)
        || policy.version != (1_u64 << 48) | u64::from(identity.revision)
        || policy.system
        || policy.signed
        || policy.status != 0
        || !policy.on_disk
        || (active && (!policy.enforced || !policy.authorized))
    {
        return Err(Error::Denied("endpoint policy ownership, version or effective state does not match the reviewed unsigned base policy".into()));
    }
    Ok(policy)
}

fn verify_owned(snapshot: &Snapshot, plan: &Plan, active: bool) -> Result<()> {
    owned_metadata(snapshot, plan, active)?;
    if pin_system_file(&installed_path(plan.policy_id)?)?.1 != plan.cip_sha256 {
        return Err(Error::Denied(
            "installed endpoint policy bytes differ from the enrolled artifact".into(),
        ));
    }
    Ok(())
}

pub(crate) fn verify_native_identity(identity: &PolicyIdentity) -> Result<()> {
    owned_identity(&current()?, identity, true)?;
    if pin_system_file(&installed_path(identity.policy_id)?)?.1 != identity.cip_sha256 {
        return Err(Error::Denied(
            "installed endpoint policy bytes differ from the protected verifier binding".into(),
        ));
    }
    Ok(())
}

fn unchanged_others(before: &Snapshot, after: &Snapshot, owned: Uuid) -> Result<()> {
    let before: Vec<_> = before
        .policies
        .iter()
        .filter(|policy| policy.id != owned)
        .collect();
    let after: Vec<_> = after
        .policies
        .iter()
        .filter(|policy| policy.id != owned)
        .collect();
    if before != after {
        return Err(Error::Unknown("unrelated native policy state changed; do not retry, remove or overwrite policies automatically".into()));
    }
    Ok(())
}

fn removed(snapshot: &Snapshot, id: Uuid) -> Result<bool> {
    let absent = snapshot
        .policies
        .iter()
        .all(|policy| policy.id != id || (!policy.on_disk && !policy.enforced));
    Ok(absent && !installed_path(id)?.try_exists()?)
}

pub(crate) fn authorize_change(
    store: &Store,
    plan: &Plan,
    authorized_lab: bool,
    profile_digest: &str,
    plan_digest: &str,
    install: bool,
) -> Result<()> {
    if !authorized_lab || store.profile.digest()? != profile_digest || plan.digest()? != plan_digest
    {
        return Err(Error::Denied(
            "endpoint changes require an authorized disposable lab and exact profile/plan digests"
                .into(),
        ));
    }
    if !platform::is_elevated()? {
        return Err(Error::Denied("only the separately authorized elevated same-owner helper may change native endpoint policy; the broker never elevates".into()));
    }
    if install {
        store.profile.verify_host()?;
        let now = util::now()?;
        if now < plan.created_at || now >= plan.expires_at {
            return Err(Error::Denied(
                "endpoint installation approval is stale; prepare and review a fresh plan".into(),
            ));
        }
    } else {
        store.profile.verify_recovery_host()?;
    }
    if store
        .tasks()?
        .iter()
        .any(|task| matches!(task.phase.as_str(), "running" | "revoking" | "publishing"))
    {
        return Err(Error::Denied(
            "close and reconcile active work before changing computer-wide admission".into(),
        ));
    }
    Ok(())
}

pub struct ChangeApproval<'a> {
    pub authorized_lab: bool,
    pub profile_digest: &'a str,
    pub plan_digest: &'a str,
}

pub fn change(
    store: &mut Store,
    id: Uuid,
    install: bool,
    approval: ChangeApproval<'_>,
) -> Result<Value> {
    let _control = store.control_lock()?;
    let plan = load(store, id)?;
    authorize_change(
        store,
        &plan,
        approval.authorized_lab,
        approval.profile_digest,
        approval.plan_digest,
        install,
    )?;
    let _artifacts = pin_artifacts(store, &plan)?;
    let mut pins = Vec::new();
    if install {
        for input in &plan.applications {
            let (file, fingerprint) = files::pin(&input.path, APPLICATION_BYTES)?;
            if fingerprint != input.fingerprint {
                return Err(Error::Denied(
                    "an approved application changed; prepare a new exact native-hash revision"
                        .into(),
                ));
            }
            pins.push(file);
        }
    }
    let before = current()?;
    let existing = before
        .policies
        .iter()
        .find(|policy| policy.id == plan.policy_id);
    if install
        && let Some(previous) = plan.previous
        && load(store, previous)?.revision.checked_add(1) != Some(plan.revision)
    {
        return Err(Error::Denied(
            "endpoint update is not the next reviewed revision".into(),
        ));
    }
    if install {
        match (existing, plan.previous) {
            (None, None) => {}
            (Some(_), Some(previous)) => {
                let previous = load(store, previous)?;
                verify_owned(&before, &previous, true)?;
            }
            (None, Some(previous)) => {
                let changes = store.endpoint_changes()?;
                let last = changes.iter().rev().find(|change| change.state == "confirmed");
                if !matches!(last, Some(change) if change.plan == previous && change.action == "remove")
                    || !removed(&before, plan.policy_id)?
                {
                    return Err(Error::Denied("an absent prior policy has no confirmed owned removal; reconcile instead of reinstalling".into()));
                }
            }
            _ => return Err(Error::Denied("the native policy identity already exists or its prior revision is missing; never overwrite an unowned policy".into())),
        }
    } else {
        verify_owned(&before, &plan, false)?;
    }
    let action = if install { "install" } else { "remove" };
    let operation = store.reserve_endpoint_change(
        id,
        action,
        &plan.digest()?,
        &serde_json::to_value(&before)?,
    )?;
    store.endpoint_outcome(operation, "dispatched")?;
    let program = system_directory()?.join("CiTool.exe");
    let argument = if install {
        directory(store, id).join("policy.cip").into_os_string()
    } else {
        format!("{{{}}}", plan.policy_id).into()
    };
    let command = if install { "-up" } else { "-rp" };
    let effect: Result<bool> = (|| {
        native_json(&native(
            &program,
            &[command.as_ref(), &argument, "-json".as_ref()],
            None,
            None,
        )?)?;
        let after = current()?;
        unchanged_others(&before, &after, plan.policy_id)?;
        if install {
            verify_owned(&after, &plan, false)?;
            let policy = owned_metadata(&after, &plan, false)?;
            Ok(policy.enforced && policy.authorized)
        } else {
            removed(&after, plan.policy_id)
        }
    })();
    match effect {
        Ok(active) => {
            if let Err(error) =
                store.endpoint_outcome(operation, if active { "confirmed" } else { "pending" })
            {
                return Err(Error::Unknown(format!(
                    "native endpoint effect was observed but operation {operation} could not be durably finalized: {error}"
                )));
            }
            if !active {
                return Err(Error::Unsupported("owned endpoint change is staged but native activation/removal is not verified; perform the authorized lab reboot/recovery and reconcile, not an automatic retry".into()));
            }
            Ok(json!({
                "operation": operation, "plan": id, "action": action,
                "configuration": "verified", "effects": "not_certified", "integrated_gate_pass": false,
            }))
        }
        Err(error) => {
            if let Err(journal) = store.endpoint_outcome(operation, "unknown") {
                return Err(Error::Unknown(format!(
                    "native endpoint operation {operation} failed ({error}) and its uncertain outcome could not be recorded: {journal}"
                )));
            }
            Err(Error::Unknown(format!(
                "owned endpoint change {operation} requires reconciliation: {error}"
            )))
        }
    }
}

pub fn reconcile(store: &mut Store, id: Uuid, approval: ChangeApproval<'_>) -> Result<Value> {
    let _control = store.control_lock()?;
    let plan = load(store, id)?;
    authorize_change(
        store,
        &plan,
        approval.authorized_lab,
        approval.profile_digest,
        approval.plan_digest,
        false,
    )?;
    let changes = store.endpoint_changes()?;
    let change = changes
        .iter()
        .rev()
        .find(|change| {
            change.plan == id
                && matches!(
                    change.state.as_str(),
                    "reserved" | "dispatched" | "pending" | "unknown"
                )
        })
        .ok_or_else(|| Error::Denied("this plan has no unresolved native change".into()))?;
    if change.parameters_digest != plan.digest()? {
        return Err(Error::Denied(
            "endpoint change journal does not bind this artifact".into(),
        ));
    }
    if change.state == "reserved" {
        store.endpoint_outcome(change.id, "denied")?;
        return Ok(
            json!({"operation": change.id, "state": "denied", "native_dispatch": "not_started", "replayed": false}),
        );
    }
    let _artifacts = pin_artifacts(store, &plan)?;
    let before: Snapshot = serde_json::from_value(change.before.clone())?;
    let after = current()?;
    unchanged_others(&before, &after, plan.policy_id)?;
    let active = if change.action == "install" {
        verify_owned(&after, &plan, false)?;
        let policy = owned_metadata(&after, &plan, false)?;
        policy.enforced && policy.authorized
    } else if !removed(&after, plan.policy_id)? {
        return Err(Error::Unknown(
            "owned removal is not verified; reboot/recovery remains outstanding".into(),
        ));
    } else {
        true
    };
    if let Err(error) = store.endpoint_outcome(change.id, "confirmed") {
        return Err(Error::Unknown(format!(
            "endpoint configuration was observed but reconciliation could not be durably recorded: {error}"
        )));
    }
    Ok(
        json!({"operation": change.id, "configuration": if active { "reconciled" } else { "staged_not_active" },
            "activation_required": !active, "owned_removal_permitted": !active,
            "replayed": false, "effect_gate_pass": false}),
    )
}

fn latest(changes: &[EndpointChange]) -> Result<&EndpointChange> {
    if changes.iter().any(|change| {
        matches!(
            change.state.as_str(),
            "reserved" | "dispatched" | "pending" | "unknown"
        )
    }) {
        return Err(Error::Denied(
            "endpoint setup has an unresolved change; no live authority may start".into(),
        ));
    }
    let change = changes
        .iter()
        .rev()
        .find(|change| change.state == "confirmed")
        .ok_or_else(|| {
            Error::Denied("no owned endpoint policy has a confirmed enrollment".into())
        })?;
    if change.action != "install" {
        return Err(Error::Denied(
            "the enrolled endpoint policy was removed".into(),
        ));
    }
    Ok(change)
}

pub fn active_plan(store: &Store) -> Result<Plan> {
    let changes = store.endpoint_changes()?;
    let change = latest(&changes)?;
    let plan = load(store, change.plan)?;
    let _pins = pin_artifacts(store, &plan)?;
    if change.parameters_digest != plan.digest()? {
        return Err(Error::Denied(
            "confirmed endpoint enrollment no longer binds the policy artifact".into(),
        ));
    }
    match store.profile.endpoint_verifier {
        crate::profile::EndpointVerifier::Direct => verify_plan(&plan)?,
        crate::profile::EndpointVerifier::ProtectedService => {
            crate::verifier::verify(store, &plan)?
        }
    }
    Ok(plan)
}

pub fn verify_plan(plan: &Plan) -> Result<()> {
    verify_owned(&current()?, plan, true)
}

pub fn status(store: &Store) -> Result<Value> {
    if store.endpoint_changes()?.is_empty() {
        return Ok(
            json!({"state": "not_configured", "backend": "owned_app_control_unqualified", "effect_gate_pass": false}),
        );
    }
    let plan = active_plan(store)?;
    Ok(
        json!({"state": "configured_not_effect_certified", "policy": plan.policy_id, "plan": plan.id, "revision": plan.revision, "effect_gate_pass": false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native_policy(id: Uuid) -> Value {
        json!({
            "PolicyID": id, "BasePolicyID": id, "FriendlyName": "test", "Version": "281474976710656",
            "IsSystemPolicy": false, "IsSignedPolicy": false, "IsOnDisk": "True",
            "IsEnforced": true, "IsAuthorized": "True", "Status": 0,
        })
    }

    #[test]
    fn inventory_requires_typed_complete_unique_native_policies() {
        let policy = native_policy(Uuid::new_v4());
        let value = json!({"Policies": [policy], "OperationResult": 0});
        assert_eq!(snapshot(&value).unwrap().policies.len(), 1);
        let mut duplicate = value.clone();
        duplicate["Policies"]
            .as_array_mut()
            .unwrap()
            .push(value["Policies"][0].clone());
        assert!(snapshot(&duplicate).is_err());
        let mut missing = value.clone();
        missing["Policies"][0]
            .as_object_mut()
            .unwrap()
            .remove("IsEnforced");
        assert!(snapshot(&missing).is_err());
        let mut false_boolean = value;
        false_boolean["Policies"][0]["IsAuthorized"] = json!("anything");
        assert!(snapshot(&false_boolean).is_err());
        assert!(native_json(br#"{"Policies":[],"OperationResult":-2147024891}"#).is_err());
        assert!(native_json(br#"{"Policies":[]}"#).is_err());
    }

    #[test]
    fn changing_unrelated_native_policy_state_is_not_a_success() {
        let owned = Uuid::new_v4();
        let other = Uuid::new_v4();
        let before =
            snapshot(&json!({"Policies": [native_policy(owned), native_policy(other)]})).unwrap();
        let mut after = before.clone();
        after.policies.retain(|policy| policy.id != owned);
        unchanged_others(&before, &after, owned).unwrap();
        after.policies[0].enforced = false;
        assert!(unchanged_others(&before, &after, owned).is_err());
    }

    #[test]
    fn unresolved_or_removed_enrollment_cannot_authorize_live_work() {
        let mut change = EndpointChange {
            id: Uuid::new_v4(),
            plan: Uuid::new_v4(),
            action: "install".into(),
            state: "confirmed".into(),
            parameters_digest: "0".repeat(64),
            before: json!({}),
        };
        assert!(latest(&[]).is_err());
        assert!(latest(&[change.clone()]).is_ok());
        change.state = "unknown".into();
        assert!(latest(&[change.clone()]).is_err());
        change.state = "confirmed".into();
        change.action = "remove".into();
        assert!(latest(&[change]).is_err());
    }

    #[test]
    fn authoring_never_bypasses_native_execution_policy_or_uses_shell_substitution() {
        assert!(AUTHOR.contains("-DriverFilePath $application -Level Hash"));
        assert!(AUTHOR.contains("DtdProcessing]::Prohibit"));
        assert!(AUTHOR.contains("'Enabled:Audit Mode'"));
        assert!(AUTHOR.contains("'Enabled:Allow Supplemental Policies'"));
        assert!(!AUTHOR.contains("ExecutionPolicy Bypass"));
        assert!(!AUTHOR.contains("Invoke-Expression"));
    }

    fn example_plan(policy: Uuid) -> Plan {
        Plan {
            schema_version: 1,
            id: Uuid::new_v4(),
            policy_id: policy,
            profile_digest: "0".repeat(64),
            previous: None,
            revision: 0,
            baseline_sha256: "0".repeat(64),
            author_sha256: util::digest(AUTHOR.as_bytes()),
            xml_sha256: "0".repeat(64),
            cip_sha256: "0".repeat(64),
            options: REQUIRED_OPTIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            applications: Vec::new(),
            created_at: 1,
            expires_at: 3601,
        }
    }

    #[test]
    fn staged_policy_can_be_identified_for_owned_recovery_but_never_as_active() {
        let id = Uuid::new_v4();
        let plan = example_plan(id);
        let mut policy = native_policy(id);
        policy["FriendlyName"] = json!(format!("Shield {id}"));
        policy["IsEnforced"] = json!(false);
        policy["IsAuthorized"] = json!(false);
        let staged = snapshot(&json!({"Policies": [policy]})).unwrap();
        owned_metadata(&staged, &plan, false).unwrap();
        assert!(owned_metadata(&staged, &plan, true).is_err());
        let mut wrong_owner = staged.clone();
        wrong_owner.policies[0].signed = true;
        assert!(owned_metadata(&wrong_owner, &plan, false).is_err());
        let mut wrong_revision = staged;
        wrong_revision.policies[0].version += 1;
        assert!(owned_metadata(&wrong_revision, &plan, false).is_err());
    }

    #[test]
    fn plan_never_accepts_audit_expansion_duplicate_inputs_or_changed_profile() {
        let directory = tempfile::tempdir().unwrap();
        let profile = crate::profile::Profile::draft("endpoint unit fixture".into()).unwrap();
        let store = Store::initialize(&directory.path().join("state"), profile).unwrap();
        let executable = std::env::current_exe().unwrap();
        let (_, fingerprint) = files::pin(&executable, APPLICATION_BYTES).unwrap();
        let mut plan = example_plan(store.profile.id);
        plan.profile_digest = store.profile.digest().unwrap();
        plan.applications.push(Application {
            path: executable,
            fingerprint,
        });
        plan.validate(&store).unwrap();
        let mut author = plan.clone();
        author.author_sha256 = "1".repeat(64);
        assert!(author.validate(&store).is_err());
        let mut audit = plan.clone();
        audit.options.push("Enabled:Audit Mode".into());
        assert!(audit.validate(&store).is_err());
        let mut expanded = plan.clone();
        expanded
            .options
            .push("Enabled:Allow Supplemental Policies".into());
        assert!(expanded.validate(&store).is_err());
        let mut duplicate = plan.clone();
        duplicate.applications.push(plan.applications[0].clone());
        assert!(duplicate.validate(&store).is_err());
        let mut changed = plan;
        changed.profile_digest = "1".repeat(64);
        assert!(changed.validate(&store).is_err());
    }
}
