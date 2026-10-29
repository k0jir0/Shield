use std::os::windows::fs::OpenOptionsExt;

use super::*;
use crate::files::Fingerprint;

const RECORD_BYTES: u64 = 16 * 1024;
const MAX_ATTEMPTS: usize = 16;
const MAX_ROOT_ENTRIES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Artifact {
    Binding,
    Image,
    InstallIntent,
    InstallConfirmed,
    RemoveIntent,
    RemoveConfirmed,
}

impl Artifact {
    const ALL: [Self; 6] = [
        Self::Binding,
        Self::Image,
        Self::InstallIntent,
        Self::InstallConfirmed,
        Self::RemoveIntent,
        Self::RemoveConfirmed,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Binding => "binding.json",
            Self::Image => "shield-verifier.exe",
            Self::InstallIntent => "install.intent",
            Self::InstallConfirmed => "install.confirmed",
            Self::RemoveIntent => "remove.intent",
            Self::RemoveConfirmed => "remove.confirmed",
        }
    }

    fn limit(self) -> u64 {
        match self {
            Self::Binding => CONFIG_BYTES,
            Self::Image => IMAGE_BYTES,
            _ => 64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryIdentity {
    volume: u32,
    file_index: u64,
}

fn directory_identity(file: &File) -> Result<DirectoryIdentity> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    check(
        unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) },
        "GetFileInformationByHandle verifier cleanup directory",
    )?;
    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(Error::Denied(
            "cleanup target is not a non-reparse directory".into(),
        ));
    }
    Ok(DirectoryIdentity {
        volume: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    artifact: Artifact,
    fingerprint: Fingerprint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Retirement {
    schema: u32,
    id: Uuid,
    created_at: u64,
    profile: Uuid,
    plan: Uuid,
    binding_sha256: String,
    directory: DirectoryIdentity,
    entries: Vec<Entry>,
}

impl Retirement {
    fn digest(&self) -> Result<String> {
        domain_digest(b"Shield/verifier-retirement/v1\0", self)
    }

    fn validate(&self, binding: &Binding) -> Result<()> {
        if self.schema != 1
            || self.id.is_nil()
            || self.created_at == 0
            || self.profile != binding.profile.id
            || self.plan != binding.plan
            || self.binding_sha256 != binding.digest()?
            || self.entries.len() > Artifact::ALL.len()
            || self
                .entries
                .windows(2)
                .any(|entries| entries[0].artifact >= entries[1].artifact)
        {
            return Err(invalid("invalid protected verifier retirement record"));
        }
        for required in [
            Artifact::Binding,
            Artifact::Image,
            Artifact::RemoveIntent,
            Artifact::RemoveConfirmed,
        ] {
            if !self.entries.iter().any(|entry| entry.artifact == required) {
                return Err(invalid("retirement record lacks a required owned artifact"));
            }
        }
        if self
            .entries
            .iter()
            .any(|entry| entry.artifact == Artifact::InstallConfirmed)
            && !self
                .entries
                .iter()
                .any(|entry| entry.artifact == Artifact::InstallIntent)
        {
            return Err(invalid(
                "retirement install confirmation lacks its dispatch intent",
            ));
        }
        for entry in &self.entries {
            if !digest_valid(&entry.fingerprint.sha256)
                || entry.fingerprint.bytes == 0
                || entry.fingerprint.bytes > entry.artifact.limit()
            {
                return Err(invalid("invalid retirement artifact fingerprint"));
            }
            match entry.artifact {
                Artifact::Image if entry.fingerprint.sha256 != binding.profile.binary_sha256 => {
                    return Err(Error::Denied(
                        "retirement image is not the frozen binary".into(),
                    ));
                }
                Artifact::Binding | Artifact::Image => {}
                _ if entry.fingerprint.bytes != 64
                    || entry.fingerprint.sha256 != util::digest(self.binding_sha256.as_bytes()) =>
                {
                    return Err(Error::Denied("retirement lifecycle marker differs".into()));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attempt {
    schema: u32,
    id: Uuid,
    created_at: u64,
    profile: Uuid,
    plan: Uuid,
    binding_sha256: String,
    retirement_sha256: String,
    reviewed_cleanup_digest: String,
}

impl Attempt {
    fn validate(&self, review: &str, binding: &Binding, retirement: &Retirement) -> Result<()> {
        if self.schema != 1
            || self.id.is_nil()
            || self.created_at == 0
            || self.profile != binding.profile.id
            || self.plan != binding.plan
            || self.binding_sha256 != binding.digest()?
            || self.retirement_sha256 != retirement.digest()?
            || self.reviewed_cleanup_digest != review
            || !digest_valid(&self.reviewed_cleanup_digest)
        {
            return Err(invalid("invalid protected verifier cleanup attempt"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedEntry {
    artifact: Artifact,
    fingerprint: Option<Fingerprint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttemptDigest {
    id: Uuid,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: u32,
    binding_sha256: String,
    scm_service_absent: bool,
    directory: Option<DirectoryIdentity>,
    entries: Vec<ObservedEntry>,
    retirement_sha256: Option<String>,
    attempts: Vec<AttemptDigest>,
    confirmed: bool,
}

impl Snapshot {
    fn digest(&self) -> Result<String> {
        domain_digest(b"Shield/verifier-cleanup-review/v1\0", self)
    }
}

fn domain_digest(domain: &[u8], value: &impl Serialize) -> Result<String> {
    let mut bytes = domain.to_vec();
    bytes.extend(serde_json::to_vec(value)?);
    Ok(util::digest(&bytes))
}

fn retired_path(paths: &Paths, plan: Uuid) -> PathBuf {
    paths.profile.join(format!("retired.{plan}.json"))
}

fn confirmed_path(paths: &Paths, plan: Uuid) -> PathBuf {
    paths.profile.join(format!("cleanup.{plan}.confirmed"))
}

fn exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn ensure_not_retired(paths: &Paths, plan: Uuid) -> Result<()> {
    if exists(&retired_path(paths, plan))? {
        return Err(Error::Denied(
            "verifier enrollment is retired; it cannot start or be reinstalled/replayed".into(),
        ));
    }
    Ok(())
}

fn require_service_absent(profile: Uuid) -> Result<()> {
    if open_service(&manager(SC_MANAGER_CONNECT)?, profile, SERVICE_READ)?.is_some() {
        return Err(Error::Denied(
            "cleanup requires confirmed native service absence; it never stops/deletes a service"
                .into(),
        ));
    }
    Ok(())
}

fn read_json<T: DeserializeOwned>(path: &Path, owner: &str) -> Result<(T, String)> {
    let (mut file, fingerprint) = protected_pin(path, owner, RECORD_BYTES)?;
    let bytes = util::read_bounded(&mut file, RECORD_BYTES)?;
    Ok((serde_json::from_slice(&bytes)?, fingerprint.sha256))
}

fn read_retirement(paths: &Paths, binding: &Binding) -> Result<Option<Retirement>> {
    let path = retired_path(paths, binding.plan);
    if !exists(&path)? {
        return Ok(None);
    }
    let (record, _): (Retirement, _) = read_json(&path, &binding.profile.owner_sid)?;
    record.validate(binding)?;
    Ok(Some(record))
}

fn artifacts(paths: &Paths) -> Result<Vec<Artifact>> {
    let mut artifacts = Vec::new();
    for entry in std::fs::read_dir(&paths.plan)? {
        let entry = entry?;
        if artifacts.len() >= Artifact::ALL.len() {
            return Err(Error::Denied(
                "unexpected contents in verifier cleanup directory".into(),
            ));
        }
        let name = entry.file_name();
        let artifact = Artifact::ALL
            .into_iter()
            .find(|artifact| Some(artifact.name()) == name.to_str())
            .ok_or_else(|| {
                Error::Denied(
                    "unknown verifier directory entry; nothing is recursively deleted".into(),
                )
            })?;
        artifacts.push(artifact);
    }
    artifacts.sort();
    Ok(artifacts)
}

fn attempts(
    paths: &Paths,
    binding: &Binding,
    retirement: Option<&Retirement>,
) -> Result<Vec<AttemptDigest>> {
    let prefix = format!("cleanup.{}.", binding.plan);
    let mut attempts = Vec::new();
    for (count, entry) in std::fs::read_dir(&paths.profile)?.enumerate() {
        if count >= MAX_ROOT_ENTRIES {
            return Err(Error::Quota(
                "protected verifier metadata directory exceeds its inspection bound".into(),
            ));
        }
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(invalid("non-Unicode protected verifier metadata name"));
        };
        if !name.starts_with(&prefix) || !name.ends_with(".intent.json") {
            continue;
        }
        if attempts.len() >= MAX_ATTEMPTS {
            return Err(Error::Quota(
                "verifier cleanup attempt records exceed their bound".into(),
            ));
        }
        let review = attempt_review(name, &prefix)?;
        let retirement =
            retirement.ok_or_else(|| invalid("cleanup attempt lacks retirement record"))?;
        let (attempt, sha256): (Attempt, _) = read_json(&entry.path(), &binding.profile.owner_sid)?;
        attempt.validate(review, binding, retirement)?;
        attempts.push(AttemptDigest {
            id: attempt.id,
            sha256,
        });
    }
    attempts.sort_by_key(|attempt| attempt.id);
    Ok(attempts)
}

fn attempt_review<'a>(name: &'a str, prefix: &str) -> Result<&'a str> {
    let review = name
        .strip_prefix(prefix)
        .and_then(|name| name.strip_suffix(".intent.json"))
        .filter(|review| digest_valid(review))
        .ok_or_else(|| invalid("invalid verifier cleanup attempt name"))?;
    Ok(review)
}

fn verify_remaining(original: &[Entry], observed: &[ObservedEntry]) -> Result<()> {
    if original.len() != observed.len() {
        return Err(Error::Denied(
            "cleanup artifact inventory differs from retirement".into(),
        ));
    }
    for (original, observed) in original.iter().zip(observed) {
        if original.artifact != observed.artifact
            || observed
                .fingerprint
                .as_ref()
                .is_some_and(|fingerprint| fingerprint != &original.fingerprint)
        {
            return Err(Error::Denied(
                "a remaining cleanup object was changed/replaced; do not delete it".into(),
            ));
        }
    }
    Ok(())
}

fn snapshot(paths: &Paths, binding: &Binding) -> Result<(Snapshot, Option<Retirement>)> {
    let _profile_pin = verify_directory(&paths.profile, &binding.profile.owner_sid)?;
    require_service_absent(binding.profile.id)?;
    let retirement = read_retirement(paths, binding)?;
    let mut entries = Vec::new();
    let directory = if exists(&paths.plan)? {
        let directory = verify_directory(&paths.plan, &binding.profile.owner_sid)?;
        let identity = directory_identity(&directory)?;
        let present = artifacts(paths)?;
        if let Some(retirement) = &retirement {
            if identity != retirement.directory
                || present.iter().any(|artifact| {
                    !retirement
                        .entries
                        .iter()
                        .any(|entry| entry.artifact == *artifact)
                })
            {
                return Err(Error::Denied(
                    "retired verifier directory was changed/replaced".into(),
                ));
            }
            for entry in &retirement.entries {
                let fingerprint = if present.contains(&entry.artifact) {
                    Some(
                        protected_pin(
                            &paths.plan.join(entry.artifact.name()),
                            &binding.profile.owner_sid,
                            entry.artifact.limit(),
                        )?
                        .1,
                    )
                } else {
                    None
                };
                entries.push(ObservedEntry {
                    artifact: entry.artifact,
                    fingerprint,
                });
            }
            verify_remaining(&retirement.entries, &entries)?;
        } else {
            let protected =
                read_binding(binding.profile.id, binding.plan, &binding.profile.owner_sid)?;
            require_binding(&protected, binding)?;
            if !marker(&protected, "remove.intent")? || !marker(&protected, "remove.confirmed")? {
                return Err(Error::Denied(
                    "cleanup requires a confirmed owned service removal".into(),
                ));
            }
            let install_intent = marker(&protected, "install.intent")?;
            if marker(&protected, "install.confirmed")? && !install_intent {
                return Err(Error::Denied(
                    "verifier install confirmation lacks its dispatch intent".into(),
                ));
            }
            for artifact in present {
                let (_, fingerprint) = protected_pin(
                    &paths.plan.join(artifact.name()),
                    &binding.profile.owner_sid,
                    artifact.limit(),
                )?;
                entries.push(ObservedEntry {
                    artifact,
                    fingerprint: Some(fingerprint),
                });
            }
        }
        Some(identity)
    } else {
        let retirement = retirement.as_ref().ok_or_else(|| {
            Error::Unknown("verifier directory is missing without a retirement record".into())
        })?;
        entries.extend(retirement.entries.iter().map(|entry| ObservedEntry {
            artifact: entry.artifact,
            fingerprint: None,
        }));
        None
    };
    let attempts = attempts(paths, binding, retirement.as_ref())?;
    let confirmation = confirmed_path(paths, binding.plan);
    let confirmed = if exists(&confirmation)? {
        let retirement = retirement
            .as_ref()
            .ok_or_else(|| invalid("cleanup confirmation lacks retirement"))?;
        let (mut file, _) = protected_pin(&confirmation, &binding.profile.owner_sid, 64)?;
        if util::read_bounded(&mut file, 64)? != retirement.digest()?.as_bytes()
            || directory.is_some()
            || entries.iter().any(|entry| entry.fingerprint.is_some())
            || attempts.is_empty()
        {
            return Err(Error::Denied(
                "cleanup confirmation does not match actual absence".into(),
            ));
        }
        true
    } else {
        false
    };
    Ok((
        Snapshot {
            schema: 1,
            binding_sha256: binding.digest()?,
            scm_service_absent: true,
            directory,
            entries,
            retirement_sha256: retirement.as_ref().map(Retirement::digest).transpose()?,
            attempts,
            confirmed,
        },
        retirement,
    ))
}

fn atomic_record(path: &Path, owner: &str, bytes: &[u8]) -> Result<()> {
    if bytes.len() as u64 > RECORD_BYTES {
        return Err(invalid("cleanup record exceeds its bound"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("missing cleanup record parent"))?;
    let temporary = parent.join(format!("cleanup-staging.{}.json", Uuid::new_v4()));
    write_new(&temporary, owner, bytes)?;
    check(
        unsafe {
            MoveFileExW(
                wide(&temporary).as_ptr(),
                wide(path).as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        },
        "MoveFileExW immutable cleanup record (existing records are not overwritten)",
    )
}

fn disposition(file: &File) -> Result<()> {
    let information = FILE_DISPOSITION_INFO { DeleteFile: true };
    check(
        unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileDispositionInfo,
                (&information as *const FILE_DISPOSITION_INFO).cast(),
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        },
        "SetFileInformationByHandle reviewed verifier cleanup",
    )
}

fn delete_matching_file(file: &mut File, expected: &Fingerprint, limit: u64) -> Result<()> {
    let (_, actual) = files::read_opened(file, limit)?;
    if &actual != expected {
        return Err(Error::Denied(
            "opened cleanup object differs from the reviewed fingerprint".into(),
        ));
    }
    disposition(file)
}

fn delete_file(paths: &Paths, binding: &Binding, entry: &Entry) -> Result<()> {
    let path = paths.plan.join(entry.artifact.name());
    files::check_no_reparse(&path)?;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .access_mode(GENERIC_READ | DELETE)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&path)?;
    verify_file_security(&file, &binding.profile.owner_sid)?;
    delete_matching_file(&mut file, &entry.fingerprint, entry.artifact.limit())
}

fn delete_matching_directory(file: &File, expected: DirectoryIdentity) -> Result<()> {
    if directory_identity(file)? != expected {
        return Err(Error::Denied(
            "opened cleanup directory differs from the reviewed identity".into(),
        ));
    }
    // The native disposition operation refuses a nonempty directory; it never recurses.
    disposition(file)
}

fn delete_directory(paths: &Paths, binding: &Binding, expected: DirectoryIdentity) -> Result<()> {
    files::check_no_reparse(&paths.plan)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .access_mode(GENERIC_READ | DELETE)
        .share_mode(0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&paths.plan)?;
    verify_file_security(&file, &binding.profile.owner_sid)?;
    delete_matching_directory(&file, expected)
}

fn report(snapshot: &Snapshot, binding: &Binding) -> Result<Value> {
    Ok(json!({
        "state": if snapshot.confirmed { "cleaned" } else if snapshot.retirement_sha256.is_some() {
            "retired_cleanup_pending_fresh_review"
        } else { "removed_ready_for_reviewed_cleanup" },
        "profile": binding.profile.id, "plan": binding.plan,
        "cleanup_digest": snapshot.digest()?, "snapshot": snapshot,
        "scope": "fixed owned verifier files only; native policy, credentials, user state and retained retirement/attempt evidence are not removed",
        "effect_gate_pass": false,
    }))
}

fn confirm_absence(paths: &Paths, binding: &Binding, retirement: &Retirement) -> Result<Value> {
    let (after, actual) = snapshot(paths, binding)?;
    if after.directory.is_some()
        || after
            .entries
            .iter()
            .any(|entry| entry.fingerprint.is_some())
        || after.attempts.is_empty()
        || actual.as_ref().map(Retirement::digest).transpose()? != Some(retirement.digest()?)
    {
        return Err(Error::Unknown("cleanup absence is not confirmed".into()));
    }
    atomic_record(
        &confirmed_path(paths, binding.plan),
        &binding.profile.owner_sid,
        retirement.digest()?.as_bytes(),
    )?;
    let (confirmed, _) = snapshot(paths, binding)?;
    report(&confirmed, binding)
}

pub fn inspect_cleanup(store: &Store, id: Uuid, approval: ChangeApproval<'_>) -> Result<Value> {
    let _control = store.control_lock()?;
    let (_, binding) = authorize(store, id, &approval, false)?;
    let paths = Paths::new(binding.profile.id, id)?;
    let (snapshot, _) = snapshot(&paths, &binding)?;
    report(&snapshot, &binding)
}

pub fn perform_cleanup(
    store: &Store,
    id: Uuid,
    approval: ChangeApproval<'_>,
    reviewed_digest: &str,
) -> Result<Value> {
    let _control = store.control_lock()?;
    let (_, binding) = authorize(store, id, &approval, false)?;
    let paths = Paths::new(binding.profile.id, id)?;
    let _profile_pin = verify_directory(&paths.profile, &binding.profile.owner_sid)?;
    let (before, retirement) = snapshot(&paths, &binding)?;
    if !digest_valid(reviewed_digest) || before.digest()? != reviewed_digest {
        return Err(Error::Denied(
            "cleanup state changed or was not exactly reviewed; inspect again".into(),
        ));
    }
    if before.confirmed {
        return Err(Error::Denied(
            "cleanup is already confirmed; inspect evidence instead of replaying it".into(),
        ));
    }
    if before.attempts.len() >= MAX_ATTEMPTS && before.directory.is_some() {
        return Err(Error::Quota(
            "cleanup attempt budget exhausted; preserve evidence for reviewed recovery".into(),
        ));
    }
    let (_, caller) = files::pin(&std::env::current_exe()?, IMAGE_BYTES)?;
    if before.entries.iter().any(|entry| {
        entry.artifact == Artifact::Image
            && entry.fingerprint.as_ref().is_some_and(|fingerprint| {
                fingerprint.volume == caller.volume && fingerprint.file_index == caller.file_index
            })
    }) {
        return Err(Error::Denied("run cleanup from a separate copy of the exact frozen binary, not the image being removed".into()));
    }
    let retirement = match retirement {
        Some(retirement) => retirement,
        None => {
            let entries = before
                .entries
                .iter()
                .map(|entry| {
                    Ok(Entry {
                        artifact: entry.artifact,
                        fingerprint: entry
                            .fingerprint
                            .clone()
                            .ok_or_else(|| invalid("initial cleanup artifact is missing"))?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let retirement = Retirement {
                schema: 1,
                id: Uuid::new_v4(),
                created_at: util::now()?,
                profile: binding.profile.id,
                plan: id,
                binding_sha256: binding.digest()?,
                directory: before
                    .directory
                    .ok_or_else(|| invalid("initial cleanup directory is missing"))?,
                entries,
            };
            retirement.validate(&binding)?;
            atomic_record(
                &retired_path(&paths, id),
                &binding.profile.owner_sid,
                &serde_json::to_vec(&retirement)?,
            )?;
            retirement
        }
    };
    if before.directory.is_none() && !before.attempts.is_empty() {
        return confirm_absence(&paths, &binding, &retirement).map_err(|error| {
            Error::Unknown(format!(
                "verifier cleanup confirmation may be partial: {error}; inspect the retained state before any further action"
            ))
        });
    }
    let attempt = Attempt {
        schema: 1,
        id: Uuid::new_v4(),
        created_at: util::now()?,
        profile: binding.profile.id,
        plan: id,
        binding_sha256: binding.digest()?,
        retirement_sha256: retirement.digest()?,
        reviewed_cleanup_digest: reviewed_digest.to_owned(),
    };
    attempt.validate(reviewed_digest, &binding, &retirement)?;
    let path = paths
        .profile
        .join(format!("cleanup.{id}.{reviewed_digest}.intent.json"));
    atomic_record(
        &path,
        &binding.profile.owner_sid,
        &serde_json::to_vec(&attempt)?,
    )?;
    let removed = (|| {
        require_service_absent(binding.profile.id)?;
        if before.directory.is_some() {
            let directory = verify_directory(&paths.plan, &binding.profile.owner_sid)?;
            if directory_identity(&directory)? != retirement.directory {
                return Err(Error::Denied(
                    "cleanup directory changed before deletion".into(),
                ));
            }
            for observed in &before.entries {
                if observed.fingerprint.is_some() {
                    let entry = retirement
                        .entries
                        .iter()
                        .find(|entry| entry.artifact == observed.artifact)
                        .ok_or_else(|| {
                            invalid("reviewed cleanup artifact lacks retirement identity")
                        })?;
                    delete_file(&paths, &binding, entry)?;
                }
            }
            drop(directory);
            delete_directory(&paths, &binding, retirement.directory)?;
        }
        confirm_absence(&paths, &binding, &retirement)
    })();
    removed.map_err(|error| Error::Unknown(format!(
        "verifier cleanup was dispatched and may be partial: {error}; inspect and approve the fresh remaining-state digest, never replay the old request"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deletion_handle(path: &Path, directory: bool) -> File {
        std::fs::OpenOptions::new()
            .read(true)
            .access_mode(GENERIC_READ | DELETE)
            .share_mode(0)
            .custom_flags(
                FILE_FLAG_OPEN_REPARSE_POINT
                    | if directory {
                        FILE_FLAG_BACKUP_SEMANTICS
                    } else {
                        0
                    },
            )
            .open(path)
            .unwrap()
    }

    fn example() -> (Binding, Retirement) {
        let mut profile = Profile::draft("cleanup test".into()).unwrap();
        profile.endpoint_verifier = EndpointVerifier::ProtectedService;
        let binding = Binding {
            schema: 1,
            plan: Uuid::new_v4(),
            plan_sha256: util::digest(b"plan"),
            policy: PolicyIdentity {
                policy_id: profile.id,
                revision: 1,
                cip_sha256: util::digest(b"policy"),
            },
            profile,
        };
        let record = Retirement {
            schema: 1,
            id: Uuid::new_v4(),
            created_at: 1,
            profile: binding.profile.id,
            plan: binding.plan,
            binding_sha256: binding.digest().unwrap(),
            directory: DirectoryIdentity {
                volume: 1,
                file_index: 2,
            },
            entries: [
                Artifact::Binding,
                Artifact::Image,
                Artifact::RemoveIntent,
                Artifact::RemoveConfirmed,
            ]
            .into_iter()
            .map(|artifact| Entry {
                artifact,
                fingerprint: Fingerprint {
                    volume: 1,
                    file_index: 3 + artifact as u64,
                    write_time: 1,
                    bytes: if matches!(artifact, Artifact::Binding | Artifact::Image) {
                        1
                    } else {
                        64
                    },
                    sha256: match artifact {
                        Artifact::Image => binding.profile.binary_sha256.clone(),
                        Artifact::Binding => util::digest(b"binding"),
                        _ => util::digest(binding.digest().unwrap().as_bytes()),
                    },
                },
            })
            .collect(),
        };
        (binding, record)
    }

    #[test]
    fn retirement_requires_exact_binding_fixed_artifacts_and_bound_lifecycle_evidence() {
        let (binding, record) = example();
        record.validate(&binding).unwrap();
        let mut changes = vec![record.clone(); 5];
        changes[0].binding_sha256 = util::digest(b"other");
        changes[1].entries.pop();
        let duplicate = changes[2].entries[0].clone();
        changes[2].entries.push(duplicate);
        changes[3].entries[1].fingerprint.sha256 = util::digest(b"unapproved image");
        changes[4].entries[2].fingerprint.sha256 = util::digest(b"unbound marker");
        for changed in changes {
            assert!(changed.validate(&binding).is_err());
        }
        assert!(serde_json::from_value::<Artifact>(json!("..\\arbitrary.exe")).is_err());
        let mut value = serde_json::to_value(record).unwrap();
        value["recursive"] = json!(true);
        assert!(serde_json::from_value::<Retirement>(value).is_err());
    }

    #[test]
    fn interrupted_cleanup_accepts_only_absence_or_the_original_unchanged_objects() {
        let (_, record) = example();
        let mut observed: Vec<_> = record
            .entries
            .iter()
            .map(|entry| ObservedEntry {
                artifact: entry.artifact,
                fingerprint: Some(entry.fingerprint.clone()),
            })
            .collect();
        verify_remaining(&record.entries, &observed).unwrap();
        observed[0].fingerprint = None;
        verify_remaining(&record.entries, &observed).unwrap();
        observed[1].fingerprint.as_mut().unwrap().file_index += 1;
        assert!(verify_remaining(&record.entries, &observed).is_err());
        observed[1].fingerprint = None;
        observed.swap(0, 1);
        assert!(verify_remaining(&record.entries, &observed).is_err());
    }

    #[test]
    fn review_digest_changes_after_retirement_dispatch_partial_effect_or_confirmation() {
        let (binding, record) = example();
        let original = Snapshot {
            schema: 1,
            binding_sha256: binding.digest().unwrap(),
            scm_service_absent: true,
            directory: Some(record.directory),
            entries: record
                .entries
                .iter()
                .map(|entry| ObservedEntry {
                    artifact: entry.artifact,
                    fingerprint: Some(entry.fingerprint.clone()),
                })
                .collect(),
            retirement_sha256: None,
            attempts: Vec::new(),
            confirmed: false,
        };
        let reviewed = original.digest().unwrap();
        let mut changed = original.clone();
        changed.retirement_sha256 = Some(record.digest().unwrap());
        assert_ne!(reviewed, changed.digest().unwrap());
        let retired = changed.digest().unwrap();
        changed.attempts.push(AttemptDigest {
            id: Uuid::new_v4(),
            sha256: util::digest(b"dispatch"),
        });
        assert_ne!(retired, changed.digest().unwrap());
        let dispatched = changed.digest().unwrap();
        changed.entries[0].fingerprint = None;
        assert_ne!(dispatched, changed.digest().unwrap());
        let partial = changed.digest().unwrap();
        changed.confirmed = true;
        assert_ne!(partial, changed.digest().unwrap());
    }

    #[test]
    fn attempt_names_consume_one_exact_review_and_malformed_names_never_panic() {
        let (binding, retirement) = example();
        let review = util::digest(b"review");
        let attempt = Attempt {
            schema: 1,
            id: Uuid::new_v4(),
            created_at: 1,
            profile: binding.profile.id,
            plan: binding.plan,
            binding_sha256: binding.digest().unwrap(),
            retirement_sha256: retirement.digest().unwrap(),
            reviewed_cleanup_digest: review.clone(),
        };
        attempt.validate(&review, &binding, &retirement).unwrap();
        assert!(
            attempt
                .validate(&util::digest(b"other review"), &binding, &retirement)
                .is_err()
        );
        let prefix = format!("cleanup.{}.", binding.plan);
        assert_eq!(
            attempt_review(&format!("{prefix}{review}.intent.json"), &prefix).unwrap(),
            review,
        );
        for name in [
            format!("cleanup.{}.intent.json", binding.plan),
            format!("{prefix}.intent.json"),
            format!("{prefix}{}.intent.json", Uuid::new_v4()),
            format!("{prefix}{}.intent.json", "a".repeat(65)),
            format!("{prefix}{}.intent.json", "A".repeat(64)),
        ] {
            assert!(attempt_review(&name, &prefix).is_err(), "{name}");
        }
    }

    #[test]
    fn retirement_presence_including_damaged_evidence_blocks_reenrollment_without_parsing() {
        let root = tempfile::tempdir().unwrap();
        let plan = Uuid::new_v4();
        let paths = Paths {
            profile: root.path().to_owned(),
            plan: root.path().join(plan.to_string()),
        };
        ensure_not_retired(&paths, plan).unwrap();
        std::fs::write(retired_path(&paths, plan), b"interrupted/damaged evidence").unwrap();
        assert!(ensure_not_retired(&paths, plan).is_err());
        ensure_not_retired(&paths, Uuid::new_v4()).unwrap();
    }

    #[test]
    fn cleanup_file_wrapper_refuses_user_owned_objects_without_deleting_them() {
        let (binding, _) = example();
        let root = tempfile::tempdir().unwrap();
        let paths = Paths {
            profile: root.path().to_owned(),
            plan: root.path().join(binding.plan.to_string()),
        };
        std::fs::create_dir(&paths.plan).unwrap();
        let path = paths.config();
        std::fs::write(&path, b"not administrator protected").unwrap();
        let (_, fingerprint) = files::pin(&path, CONFIG_BYTES).unwrap();
        let error = delete_file(
            &paths,
            &binding,
            &Entry {
                artifact: Artifact::Binding,
                fingerprint,
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("not administrator/SYSTEM owned"));
        assert_eq!(std::fs::read(path).unwrap(), b"not administrator protected");
    }

    #[test]
    fn ordinary_user_cannot_inspect_or_dispatch_privileged_cleanup_even_with_exact_reviews() {
        let directory = tempfile::tempdir().unwrap();
        let mut profile = Profile::draft("cleanup authorization fixture".into()).unwrap();
        profile.endpoint_verifier = EndpointVerifier::ProtectedService;
        let store = Store::initialize(&directory.path().join("state"), profile).unwrap();
        let image = std::env::current_exe().unwrap();
        let (_, fingerprint) = files::pin(&image, IMAGE_BYTES).unwrap();
        let plan = Plan {
            schema_version: 1,
            id: Uuid::new_v4(),
            policy_id: store.profile.id,
            profile_digest: store.profile.digest().unwrap(),
            previous: None,
            revision: 0,
            baseline_sha256: util::digest(b"synthetic baseline; never installed"),
            author_sha256: util::digest(include_bytes!("..\\endpoint-author.ps1")),
            xml_sha256: util::digest(b"synthetic xml; never installed"),
            cip_sha256: util::digest(b"synthetic cip; never installed"),
            options: [
                "Enabled:UMCI",
                "Enabled:Unsigned System Integrity Policy",
                "Enabled:Update Policy No Reboot",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            applications: vec![endpoint::Application {
                path: image,
                fingerprint,
            }],
            created_at: 1,
            expires_at: 3601,
        };
        let location = store.root.join("endpoint").join(plan.id.to_string());
        std::fs::create_dir_all(&location).unwrap();
        let bytes = serde_json::to_vec(&plan).unwrap();
        std::fs::write(location.join("plan.json"), &bytes).unwrap();
        let profile_digest = store.profile.digest().unwrap();
        let plan_digest = plan.digest().unwrap();
        assert_eq!(
            endpoint::load(&store, plan.id).unwrap().digest().unwrap(),
            plan_digest
        );
        let approval = || ChangeApproval {
            authorized_lab: true,
            profile_digest: &profile_digest,
            plan_digest: &plan_digest,
        };
        for error in [
            inspect_cleanup(&store, plan.id, approval()).unwrap_err(),
            perform_cleanup(&store, plan.id, approval(), &util::digest(b"review")).unwrap_err(),
        ] {
            assert!(
                error
                    .to_string()
                    .contains("separately authorized elevated same-owner helper")
            );
        }
        assert_eq!(std::fs::read(location.join("plan.json")).unwrap(), bytes);
        assert_eq!(std::fs::read_dir(location).unwrap().count(), 1);
    }

    #[test]
    fn native_by_handle_deletion_removes_only_the_exact_reviewed_regular_file() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let untouched = directory.path().join("untouched");
        std::fs::write(&target, b"reviewed").unwrap();
        std::fs::write(&untouched, b"retained").unwrap();
        let (_, fingerprint) = files::pin(&target, 64).unwrap();
        let mut file = deletion_handle(&target, false);
        delete_matching_file(&mut file, &fingerprint, 64).unwrap();
        drop(file);
        assert!(!target.exists());
        assert_eq!(std::fs::read(untouched).unwrap(), b"retained");
    }

    #[test]
    fn native_deletion_rejects_replaced_objects_and_hardlinks() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("target");
        std::fs::write(&path, b"original").unwrap();
        let (_, expected) = files::pin(&path, 64).unwrap();
        std::fs::write(&path, b"changed").unwrap();
        let mut file = deletion_handle(&path, false);
        assert!(delete_matching_file(&mut file, &expected, 64).is_err());
        drop(file);
        let retained = directory.path().join("retained-original");
        std::fs::rename(&path, &retained).unwrap();
        std::fs::write(&path, b"original").unwrap();
        let mut file = deletion_handle(&path, false);
        assert!(delete_matching_file(&mut file, &expected, 64).is_err());
        drop(file);
        let link = directory.path().join("linked");
        std::fs::hard_link(&path, &link).unwrap();
        let mut file = deletion_handle(&path, false);
        assert!(delete_matching_file(&mut file, &expected, 64).is_err());
        drop(file);
        assert_eq!(std::fs::read(path).unwrap(), b"original");
        assert_eq!(std::fs::read(link).unwrap(), b"original");
        assert_eq!(std::fs::read(retained).unwrap(), b"changed");
    }

    #[test]
    fn native_directory_disposition_refuses_nonempty_or_differently_identified_directories() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("owned");
        std::fs::create_dir(&target).unwrap();
        let file = deletion_handle(&target, true);
        let identity = directory_identity(&file).unwrap();
        assert!(
            delete_matching_directory(
                &file,
                DirectoryIdentity {
                    file_index: identity.file_index + 1,
                    ..identity
                }
            )
            .is_err()
        );
        drop(file);
        let child = target.join("unexpected");
        std::fs::write(&child, b"never recursively deleted").unwrap();
        let file = deletion_handle(&target, true);
        assert!(delete_matching_directory(&file, identity).is_err());
        drop(file);
        assert_eq!(std::fs::read(&child).unwrap(), b"never recursively deleted");
        std::fs::remove_file(child).unwrap();
        let file = deletion_handle(&target, true);
        delete_matching_directory(&file, identity).unwrap();
        drop(file);
        assert!(!target.exists());
    }
}
