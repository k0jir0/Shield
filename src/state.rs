use std::fs::{File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::error::{Error, Result, invalid};
use crate::files::{self, Fingerprint};
use crate::profile::Profile;
use crate::{platform, util};

const JOURNAL_PAGE_BYTES: u64 = 4096;
const JOURNAL_MAX_PAGES: u64 = 16384;
const JOURNAL_RETAINED_WAL_BYTES: i64 = 1048576;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    Live,
    ManualLab,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub provider: String,
    pub resource: String,
    pub version: Option<String>,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSpec {
    pub id: Uuid,
    pub kind: TaskKind,
    pub profile_digest: String,
    pub original_path: PathBuf,
    pub original: Fingerprint,
    pub reference: Reference,
    pub instruction: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub id: Uuid,
    pub task_id: Uuid,
    pub epoch: Uuid,
    pub profile_digest: String,
    pub binary_sha256: String,
    pub note_sha256: String,
    pub reference_sha256: String,
    pub model: String,
    pub inference_destination: String,
    pub expires_at: u64,
    pub max_calls: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Task {
    pub spec: TaskSpec,
    pub phase: String,
    pub epoch: Uuid,
    pub expires_at: u64,
    pub model_calls: u32,
    pub output_digest: Option<String>,
    pub error: Option<String>,
    pub grant: Option<Grant>,
}

impl Task {
    pub(crate) fn require_cancellable(&self) -> Result<()> {
        if matches!(
            self.phase.as_str(),
            "publishing" | "published" | "recovery_required"
        ) {
            return Err(Error::Denied(
                "completed or uncertain publication requires explicit recovery, not cancellation"
                    .into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Operation {
    pub id: Uuid,
    pub state: String,
    pub replay: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointChange {
    pub id: Uuid,
    pub plan: Uuid,
    pub action: String,
    pub state: String,
    pub parameters_digest: String,
    pub before: serde_json::Value,
}

pub struct Store {
    pub root: PathBuf,
    pub profile: Profile,
    connection: Connection,
}

pub struct ControlLock {
    _file: File,
}

fn audit(
    transaction: &Transaction<'_>,
    task: Option<Uuid>,
    kind: &str,
    data: serde_json::Value,
) -> Result<()> {
    let data = serde_json::to_string(&data)?;
    if data.len() > 4096 {
        return Err(invalid("audit event exceeds the fixed metadata-only bound"));
    }
    let previous: Option<(u64, String)> = transaction
        .query_row(
            "SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (sequence, previous) = match previous {
        Some((sequence, previous)) => (sequence + 1, previous),
        None => (1, "0".repeat(64)),
    };
    let timestamp = util::now()?;
    let task = task.map(|value| value.to_string());
    let payload = json!([sequence, timestamp, task, kind, data, previous]);
    let hash = util::json_digest(&payload)?;
    transaction.execute(
        "INSERT INTO audit(seq, timestamp, task, kind, data, previous_hash, hash) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![sequence, timestamp, task, kind, data, previous, hash],
    )?;
    Ok(())
}

fn task_from_connection(connection: &Connection, id: Uuid) -> Result<Task> {
    let row = connection
        .query_row(
            "SELECT spec, phase, epoch, expires_at, model_calls, output_digest, error, grant_json FROM tasks WHERE id=?1",
            [id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?, row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?, row.get::<_, u64>(3)?,
                    row.get::<_, u32>(4)?, row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?, row.get::<_, Option<String>>(7)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| Error::Denied("unknown task identifier".into()))?;
    let spec: TaskSpec = serde_json::from_str(&row.0)?;
    if spec.id != id {
        return Err(invalid("journal task identity mismatch"));
    }
    Ok(Task {
        spec,
        phase: row.1,
        epoch: Uuid::parse_str(&row.2).map_err(|_| invalid("invalid journal epoch"))?,
        expires_at: row.3,
        model_calls: row.4,
        output_digest: row.5,
        error: row.6,
        grant: row
            .7
            .map(|value| serde_json::from_str(&value))
            .transpose()?,
    })
}

fn authorize(task: &Task, epoch: Uuid, profile: &str) -> Result<()> {
    if task.phase != "running"
        || task.epoch != epoch
        || task.spec.profile_digest != profile
        || util::now()? >= task.expires_at
    {
        return Err(Error::Denied(
            "task is not running under the current unexpired grant/epoch".into(),
        ));
    }
    Ok(())
}

fn configure_journal(connection: &Connection) -> Result<()> {
    connection.busy_timeout(Duration::from_secs(2))?;
    let page_bytes: u64 = connection.query_row("PRAGMA page_size", [], |row| row.get(0))?;
    if page_bytes != JOURNAL_PAGE_BYTES {
        return Err(Error::Unsupported(
            "state journal requires 4096-byte pages; automatic migration is forbidden".into(),
        ));
    }
    let pages: u64 = connection.query_row("PRAGMA page_count", [], |row| row.get(0))?;
    if pages > JOURNAL_MAX_PAGES {
        return Err(Error::Quota(
            "state journal exceeds its 64 MiB database budget; retain evidence for reviewed recovery"
                .into(),
        ));
    }
    // SQLite does not persist these limits when the connection closes.
    let maximum: u64 = connection.query_row(
        &format!("PRAGMA max_page_count={JOURNAL_MAX_PAGES}"),
        [],
        |row| row.get(0),
    )?;
    if maximum != JOURNAL_MAX_PAGES {
        return Err(Error::Denied(
            "state journal did not accept its exact page-count limit".into(),
        ));
    }
    connection.pragma_update(None, "journal_size_limit", JOURNAL_RETAINED_WAL_BYTES)?;
    connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")?;
    Ok(())
}

impl Store {
    pub fn initialize(root: &Path, profile: Profile) -> Result<Self> {
        if platform::is_elevated()? {
            return Err(Error::Denied(
                "initialize private runtime state as its unelevated owner, not an administrator"
                    .into(),
            ));
        }
        profile.verify_host()?;
        files::validate_path(root)?;
        let parent = root
            .parent()
            .ok_or_else(|| invalid("state directory needs a parent"))?;
        files::check_no_reparse(parent)?;
        std::fs::create_dir(root)?;
        platform::protect_directory(root, None)?;
        std::fs::create_dir(root.join("tasks"))?;
        std::fs::create_dir(root.join("worker"))?;
        files::create_new(
            &root.join("profile.json"),
            &serde_json::to_vec_pretty(&profile)?,
        )?;
        std::fs::copy(
            std::env::current_exe()?,
            root.join("worker").join("shield-worker.exe"),
        )?;
        let connection = Connection::open(root.join("journal.db"))?;
        configure_journal(&connection)?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE tasks(
                id TEXT PRIMARY KEY, spec TEXT NOT NULL,
                phase TEXT NOT NULL CHECK(phase IN ('preparing','prepared','running','revoking','closed','publishing','published','recovery_required')),
                epoch TEXT NOT NULL, expires_at INTEGER NOT NULL DEFAULT 0,
                model_calls INTEGER NOT NULL DEFAULT 0,
                output_digest TEXT, error TEXT, grant_json TEXT
             );
             CREATE TABLE usage(profile_digest TEXT PRIMARY KEY, calls INTEGER NOT NULL, token_allowances INTEGER NOT NULL);
             CREATE TABLE operations(
                id TEXT PRIMARY KEY, task TEXT NOT NULL REFERENCES tasks(id),
                request_key TEXT NOT NULL, parameters_digest TEXT NOT NULL,
                kind TEXT NOT NULL CHECK(kind IN ('inference','publication','restoration')),
                state TEXT NOT NULL CHECK(state IN ('reserved','dispatched','succeeded','denied','failed','unknown')),
                result_digest TEXT, created_at INTEGER NOT NULL,
                UNIQUE(task, request_key)
             );
             CREATE TABLE approvals(
                id TEXT PRIMARY KEY, task TEXT NOT NULL REFERENCES tasks(id),
                artifact_digest TEXT NOT NULL, expires_at INTEGER NOT NULL, used_by TEXT
             );
             CREATE TABLE audit(
                seq INTEGER PRIMARY KEY, timestamp INTEGER NOT NULL, task TEXT,
                kind TEXT NOT NULL, data TEXT NOT NULL,
                previous_hash TEXT NOT NULL, hash TEXT NOT NULL
             );",
        )?;
        connection.execute("INSERT INTO meta VALUES('schema','1')", [])?;
        connection.execute(
            "INSERT INTO meta VALUES('profile_digest',?1)",
            [profile.digest()?],
        )?;
        connection.execute("INSERT INTO usage VALUES(?1,0,0)", [profile.digest()?])?;
        drop(connection);
        Self::open(root)
    }

    pub fn open(root: &Path) -> Result<Self> {
        files::check_no_reparse(root)?;
        platform::verify_private_directory(root)?;
        let profile = Profile::load(&root.join("profile.json"))?;
        if profile.owner_sid != platform::current_user_sid()? {
            return Err(Error::Denied(
                "state belongs to a different Windows user".into(),
            ));
        }
        let connection = Connection::open_with_flags(
            root.join("journal.db"),
            OpenFlags::SQLITE_OPEN_READ_WRITE,
        )?;
        configure_journal(&connection)?;
        let schema: String =
            connection.query_row("SELECT value FROM meta WHERE key='schema'", [], |row| {
                row.get(0)
            })?;
        let expected: String = connection.query_row(
            "SELECT value FROM meta WHERE key='profile_digest'",
            [],
            |row| row.get(0),
        )?;
        if schema != "1" || expected != profile.digest()? {
            return Err(Error::Denied(
                "journal schema or frozen profile changed; re-enrollment is required".into(),
            ));
        }
        Ok(Self {
            root: root.to_owned(),
            profile,
            connection,
        })
    }

    pub fn task_directory(&self, id: Uuid) -> PathBuf {
        self.root.join("tasks").join(id.to_string())
    }

    pub fn worker_path(&self) -> PathBuf {
        self.root.join("worker").join("shield-worker.exe")
    }

    pub fn control_lock(&self) -> Result<ControlLock> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0)
            .open(self.root.join("controller.lock"))?;
        Ok(ControlLock { _file: file })
    }

    pub fn event(&mut self, task: Option<Uuid>, kind: &str, data: serde_json::Value) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        audit(&transaction, task, kind, data)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn endpoint_changes(&self) -> Result<Vec<EndpointChange>> {
        let version: Option<String> = self
            .connection
            .query_row(
                "SELECT value FROM meta WHERE key='endpoint_schema'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        match version.as_deref() {
            None => return Ok(Vec::new()),
            Some("1") => {}
            _ => return Err(invalid("unsupported endpoint journal extension")),
        }
        let mut statement = self.connection.prepare(
            "SELECT id,plan,action,state,parameters_digest,before_json FROM endpoint_changes ORDER BY rowid",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;
        let mut changes = Vec::new();
        for row in rows {
            let (id, plan, action, state, parameters_digest, before) = row?;
            changes.push(EndpointChange {
                id: Uuid::parse_str(&id).map_err(|_| invalid("corrupt endpoint operation ID"))?,
                plan: Uuid::parse_str(&plan).map_err(|_| invalid("corrupt endpoint plan ID"))?,
                action,
                state,
                parameters_digest,
                before: serde_json::from_str(&before)?,
            });
        }
        Ok(changes)
    }

    pub fn reserve_endpoint_change(
        &mut self,
        plan: Uuid,
        action: &str,
        parameters_digest: &str,
        before: &serde_json::Value,
    ) -> Result<Uuid> {
        if !matches!(action, "install" | "remove")
            || plan.is_nil()
            || parameters_digest.len() != 64
            || hex::decode(parameters_digest).is_err()
        {
            return Err(invalid("invalid endpoint change binding"));
        }
        let before = serde_json::to_string(before)?;
        if before.len() > 128 * 1024 {
            return Err(invalid(
                "native endpoint snapshot exceeds the journal bound",
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS endpoint_changes(
                id TEXT PRIMARY KEY, plan TEXT NOT NULL, action TEXT NOT NULL CHECK(action IN ('install','remove')),
                state TEXT NOT NULL CHECK(state IN ('reserved','dispatched','confirmed','pending','unknown','denied')),
                parameters_digest TEXT NOT NULL, before_json TEXT NOT NULL,
                UNIQUE(plan,action)
             );
             INSERT OR IGNORE INTO meta(key,value) VALUES('endpoint_schema','1');",
        )?;
        let version: String = transaction.query_row(
            "SELECT value FROM meta WHERE key='endpoint_schema'",
            [],
            |row| row.get(0),
        )?;
        if version != "1" {
            return Err(invalid("unsupported endpoint journal extension"));
        }
        let (count, unresolved): (u64, bool) = transaction.query_row(
            "SELECT count(*),coalesce(max(state IN ('reserved','dispatched','pending','unknown')),0) FROM endpoint_changes",
            [], |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if unresolved {
            return Err(Error::Denied(
                "reconcile the existing endpoint change; automatic replay is forbidden".into(),
            ));
        }
        if count >= 128 {
            return Err(Error::Quota(
                "this profile permits at most 128 retained endpoint changes".into(),
            ));
        }
        let exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM endpoint_changes WHERE plan=?1 AND action=?2)",
            params![plan.to_string(), action],
            |row| row.get(0),
        )?;
        if exists {
            return Err(Error::Denied("this exact endpoint plan/action already has a journal entry; inspect it rather than replaying".into()));
        }
        let id = Uuid::new_v4();
        transaction.execute(
            "INSERT INTO endpoint_changes(id,plan,action,state,parameters_digest,before_json) VALUES(?1,?2,?3,'reserved',?4,?5)",
            params![id.to_string(), plan.to_string(), action, parameters_digest, before],
        )?;
        audit(
            &transaction,
            None,
            "endpoint_change_reserved",
            json!({
                "operation": id, "plan": plan, "action": action,
                "parameters_digest": parameters_digest,
            }),
        )?;
        transaction.commit()?;
        Ok(id)
    }

    pub fn endpoint_outcome(&mut self, id: Uuid, state: &str) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: String = transaction.query_row(
            "SELECT state FROM endpoint_changes WHERE id=?1",
            [id.to_string()],
            |row| row.get(0),
        )?;
        let permitted = matches!(
            (current.as_str(), state),
            ("reserved", "dispatched" | "denied")
                | ("dispatched", "confirmed" | "pending" | "unknown")
                | ("pending" | "unknown", "confirmed")
        );
        if !permitted {
            return Err(Error::Denied("endpoint outcome transition is invalid; uncertain changes cannot be reset or replayed".into()));
        }
        transaction.execute(
            "UPDATE endpoint_changes SET state=?2 WHERE id=?1",
            params![id.to_string(), state],
        )?;
        audit(
            &transaction,
            None,
            "endpoint_change_outcome",
            json!({
                "operation": id, "state": state,
            }),
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn task(&self, id: Uuid) -> Result<Task> {
        task_from_connection(&self.connection, id)
    }

    pub fn tasks(&self) -> Result<Vec<Task>> {
        let mut statement = self
            .connection
            .prepare("SELECT id FROM tasks ORDER BY rowid")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut tasks = Vec::new();
        for id in rows {
            let id = Uuid::parse_str(&id?).map_err(|_| invalid("corrupt task identifier"))?;
            tasks.push(self.task(id)?);
        }
        Ok(tasks)
    }

    pub fn prepare(
        &mut self,
        kind: TaskKind,
        note: &Path,
        instruction: String,
        reference_bytes: &[u8],
        reference: Reference,
    ) -> Result<Uuid> {
        self.profile.verify_host()?;
        if instruction.is_empty() || instruction.len() > 4096 {
            return Err(invalid(
                "task instructions must contain 1..4096 UTF-8 bytes",
            ));
        }
        util::text(instruction.as_bytes())?;
        util::text(reference_bytes)?;
        if reference_bytes.len() as u64 > self.profile.limits.input_bytes
            || reference.sha256 != util::digest(reference_bytes)
            || reference.bytes != reference_bytes.len() as u64
        {
            return Err(invalid(
                "reference snapshot does not match its digest or bound",
            ));
        }
        if kind == TaskKind::Live {
            let graph = self.profile.require_graph()?;
            if reference.provider != "microsoft_graph"
                || reference.resource != format!("{}/{}", graph.drive_id, graph.item_id)
            {
                return Err(Error::Denied(
                    "reference is outside the configured provider ceiling".into(),
                ));
            }
        } else if reference.provider != "manual_lab_fixture" {
            return Err(invalid(
                "manual laboratory tasks need explicit fixture provenance",
            ));
        }
        let (note_bytes, original) = files::snapshot(note, self.profile.limits.input_bytes)?;
        let id = Uuid::new_v4();
        let spec = TaskSpec {
            id,
            kind,
            profile_digest: self.profile.digest()?,
            original_path: note.to_owned(),
            original,
            reference,
            instruction,
            created_at: util::now()?,
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: u64 =
            transaction.query_row("SELECT count(*) FROM tasks", [], |row| row.get(0))?;
        if count >= 128 {
            return Err(Error::Quota(
                "this bounded state directory permits at most 128 retained tasks".into(),
            ));
        }
        transaction.execute(
            "INSERT INTO tasks(id,spec,phase,epoch) VALUES(?1,?2,'preparing',?3)",
            params![
                id.to_string(),
                serde_json::to_string(&spec)?,
                Uuid::new_v4().to_string()
            ],
        )?;
        audit(
            &transaction,
            Some(id),
            "task_preparing",
            json!({"kind": kind, "profile_digest": spec.profile_digest}),
        )?;
        transaction.commit()?;
        let directory = self.task_directory(id);
        std::fs::create_dir(&directory)?;
        files::create_new(&directory.join("original.txt"), &note_bytes)?;
        files::create_new(&directory.join("reference.txt"), reference_bytes)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "UPDATE tasks SET phase='prepared' WHERE id=?1 AND phase='preparing'",
            [id.to_string()],
        )?;
        audit(
            &transaction,
            Some(id),
            "task_prepared",
            json!({"note_sha256": spec.original.sha256, "reference_sha256": spec.reference.sha256}),
        )?;
        transaction.commit()?;
        Ok(id)
    }

    pub fn inputs(&self, task: &Task) -> Result<(String, String)> {
        let directory = self.task_directory(task.spec.id);
        let note = util::read_bounded(
            std::fs::File::open(directory.join("original.txt"))?,
            self.profile.limits.input_bytes,
        )?;
        let reference = util::read_bounded(
            std::fs::File::open(directory.join("reference.txt"))?,
            self.profile.limits.input_bytes,
        )?;
        if util::digest(&note) != task.spec.original.sha256
            || util::digest(&reference) != task.spec.reference.sha256
        {
            return Err(Error::Denied("staged input changed after capture".into()));
        }
        Ok((
            util::text(&note)?.to_owned(),
            util::text(&reference)?.to_owned(),
        ))
    }

    pub fn begin(&mut self, id: Uuid) -> Result<Grant> {
        self.profile.verify_host()?;
        let digest = self.profile.digest()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let task = task_from_connection(&transaction, id)?;
        if task.phase != "prepared"
            || task.spec.kind != TaskKind::Live
            || task.spec.profile_digest != digest
        {
            return Err(Error::Denied(
                "only a prepared live task in the current profile may start".into(),
            ));
        }
        let active: u64 = transaction.query_row(
            "SELECT count(*) FROM tasks WHERE phase IN ('running','revoking')",
            [],
            |row| row.get(0),
        )?;
        if active != 0 {
            return Err(Error::Denied(
                "single-task profile already has running or unreconciled authority".into(),
            ));
        }
        let grant = Grant {
            id: Uuid::new_v4(),
            task_id: id,
            epoch: Uuid::new_v4(),
            profile_digest: digest,
            binary_sha256: self.profile.binary_sha256.clone(),
            note_sha256: task.spec.original.sha256,
            reference_sha256: task.spec.reference.sha256,
            model: self.profile.model.clone(),
            inference_destination: "https://api.openai.com/v1/responses".into(),
            expires_at: util::now()? + u64::from(self.profile.limits.deadline_seconds),
            max_calls: self.profile.limits.model_calls_per_task,
        };
        transaction.execute(
            "UPDATE tasks SET phase='running', epoch=?2, expires_at=?3, grant_json=?4 WHERE id=?1",
            params![
                id.to_string(),
                grant.epoch.to_string(),
                grant.expires_at,
                serde_json::to_string(&grant)?
            ],
        )?;
        audit(
            &transaction,
            Some(id),
            "task_granted",
            json!({"grant_digest": util::json_digest(&grant)?, "expires_at": grant.expires_at}),
        )?;
        transaction.commit()?;
        Ok(grant)
    }

    pub fn authorize(&self, id: Uuid, epoch: Uuid) -> Result<()> {
        authorize(&self.task(id)?, epoch, &self.profile.digest()?)
    }

    pub fn reserve_model(
        &mut self,
        id: Uuid,
        epoch: Uuid,
        request_key: &str,
        parameters_digest: &str,
    ) -> Result<Operation> {
        if request_key.is_empty() || request_key.len() > 128 || parameters_digest.len() != 64 {
            return Err(invalid(
                "operation requires a bounded retry key and parameter digest",
            ));
        }
        let profile_digest = self.profile.digest()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let task = task_from_connection(&transaction, id)?;
        authorize(&task, epoch, &profile_digest)?;
        let existing: Option<(String, String, String)> = transaction.query_row(
            "SELECT id,state,parameters_digest FROM operations WHERE task=?1 AND request_key=?2",
            params![id.to_string(), request_key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional()?;
        if let Some((operation, state, expected)) = existing {
            if expected != parameters_digest {
                return Err(Error::Denied(
                    "retry key was reused with changed parameters".into(),
                ));
            }
            return Ok(Operation {
                id: Uuid::parse_str(&operation).map_err(|_| invalid("corrupt operation ID"))?,
                state,
                replay: true,
            });
        }
        let (calls, allowances): (u64, u64) = transaction.query_row(
            "SELECT calls,token_allowances FROM usage WHERE profile_digest=?1",
            [&profile_digest],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let tokens = u64::from(self.profile.limits.output_tokens_per_call);
        if task.model_calls >= self.profile.limits.model_calls_per_task
            || calls >= u64::from(self.profile.limits.model_calls_per_profile)
            || allowances.saturating_add(tokens)
                > self.profile.limits.output_token_allowances_per_profile
        {
            return Err(Error::Quota(
                "task or shared profile inference allowance is exhausted".into(),
            ));
        }
        let operation = Uuid::new_v4();
        transaction.execute(
            "UPDATE usage SET calls=calls+1,token_allowances=token_allowances+?2 WHERE profile_digest=?1",
            params![profile_digest, tokens],
        )?;
        transaction.execute(
            "UPDATE tasks SET model_calls=model_calls+1 WHERE id=?1",
            [id.to_string()],
        )?;
        transaction.execute(
            "INSERT INTO operations(id,task,request_key,parameters_digest,kind,state,created_at) VALUES(?1,?2,?3,?4,'inference','reserved',?5)",
            params![operation.to_string(), id.to_string(), request_key, parameters_digest, util::now()?],
        )?;
        audit(
            &transaction,
            Some(id),
            "model_allowance_reserved",
            json!({"operation": operation, "output_token_allowance": tokens, "parameters_digest": parameters_digest}),
        )?;
        transaction.commit()?;
        Ok(Operation {
            id: operation,
            state: "reserved".into(),
            replay: false,
        })
    }

    pub fn dispatched(&mut self, operation: Uuid) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (id, kind): (String, String) = transaction.query_row(
            "SELECT task,kind FROM operations WHERE id=?1",
            [operation.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let id = Uuid::parse_str(&id).map_err(|_| invalid("corrupt operation task identifier"))?;
        let task = task_from_connection(&transaction, id)?;
        if kind == "inference" {
            let grant = task
                .grant
                .as_ref()
                .ok_or_else(|| Error::Denied("inference has no task grant".into()))?;
            authorize(&task, grant.epoch, &self.profile.digest()?)?;
        } else {
            let valid: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM approvals WHERE used_by=?1 AND task=?2 AND expires_at>?3)",
                params![operation.to_string(), id.to_string(), util::now()?], |row| row.get(0),
            )?;
            if task.phase != "publishing" || !valid {
                return Err(Error::Denied(
                    "publication/restoration has no current reserved approval".into(),
                ));
            }
        }
        if transaction.execute(
            "UPDATE operations SET state='dispatched' WHERE id=?1 AND state='reserved'",
            [operation.to_string()],
        )? != 1
        {
            return Err(Error::Denied(
                "operation is not reserved or has already been dispatched".into(),
            ));
        }
        audit(
            &transaction,
            None,
            "operation_dispatched",
            json!({"operation": operation}),
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn outcome(
        &mut self,
        operation: Uuid,
        state: &str,
        result_digest: Option<&str>,
    ) -> Result<()> {
        if !matches!(state, "succeeded" | "denied" | "failed" | "unknown") {
            return Err(invalid("unsupported operation outcome"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if transaction.execute(
            "UPDATE operations SET state=?2,result_digest=?3 WHERE id=?1 AND state='dispatched'",
            params![operation.to_string(), state, result_digest],
        )? != 1
        {
            return Err(Error::Denied(
                "operation outcome cannot replace an undispatched or final result".into(),
            ));
        }
        audit(
            &transaction,
            None,
            "operation_outcome",
            json!({"operation": operation, "state": state, "result_digest": result_digest}),
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn close(&mut self, id: Uuid, output: Option<&[u8]>, error: Option<&str>) -> Result<()> {
        let task = self.task(id)?;
        if !matches!(task.phase.as_str(), "running" | "revoking")
            && !(task.phase == "prepared" && task.spec.kind == TaskKind::ManualLab)
        {
            return Err(Error::Denied(
                "task is not eligible for verified local closure".into(),
            ));
        }
        let output_digest = if let Some(bytes) = output {
            if error.is_some() || bytes.len() as u64 > self.profile.limits.output_bytes {
                return Err(invalid(
                    "failed or oversized tasks cannot produce a publishable artifact",
                ));
            }
            util::text(bytes)?;
            let path = self.task_directory(id).join("proposal.txt");
            files::create_new(&path, bytes)?;
            Some(util::digest(bytes))
        } else {
            None
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = task_from_connection(&transaction, id)?;
        if current.epoch != task.epoch || current.phase != task.phase {
            return Err(Error::Denied(
                "task changed during closure; reconcile before continuing".into(),
            ));
        }
        if output.is_some() && (current.error.is_some() || current.phase == "revoking") {
            return Err(Error::Denied(
                "revoked task cannot regain publication authority during closure".into(),
            ));
        }
        if output.is_some() && current.spec.kind == TaskKind::Live {
            authorize(&current, task.epoch, &self.profile.digest()?)?;
        }
        let error = current.error.as_deref().or(error);
        transaction.execute(
            "UPDATE tasks SET phase='closed',epoch=?2,output_digest=?3,error=?4 WHERE id=?1",
            params![
                id.to_string(),
                Uuid::new_v4().to_string(),
                output_digest,
                error
            ],
        )?;
        audit(
            &transaction,
            Some(id),
            "local_task_closed",
            json!({"output_digest": output_digest, "error_code": error, "provider_revocation": "not_implied"}),
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn revoke(&mut self, id: Uuid) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let task = task_from_connection(&transaction, id)?;
        task.require_cancellable()?;
        let phase = if matches!(task.phase.as_str(), "running" | "revoking") {
            "revoking"
        } else {
            "closed"
        };
        transaction.execute(
            "UPDATE tasks SET phase=?2,epoch=?3,error='cancelled' WHERE id=?1",
            params![id.to_string(), phase, Uuid::new_v4().to_string()],
        )?;
        transaction.execute(
            "DELETE FROM approvals WHERE task=?1 AND used_by IS NULL",
            [id.to_string()],
        )?;
        audit(
            &transaction,
            Some(id),
            "task_revoked",
            json!({"local_termination": "verification_required_if_running", "external_effects": "not_recalled"}),
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn proposal(&self, id: Uuid) -> Result<Vec<u8>> {
        let task = self.task(id)?;
        if task.phase != "closed" || task.error.is_some() {
            return Err(Error::Denied(
                "only a successfully closed task has reviewable publication authority".into(),
            ));
        }
        let bytes = util::read_bounded(
            std::fs::File::open(self.task_directory(id).join("proposal.txt"))?,
            self.profile.limits.output_bytes,
        )?;
        if task.output_digest.as_deref() != Some(&util::digest(&bytes)) {
            return Err(Error::Denied("proposal changed after local closure".into()));
        }
        Ok(bytes)
    }

    pub fn approve(&mut self, id: Uuid, exact_digest: &str) -> Result<Uuid> {
        self.profile.verify_host()?;
        let bytes = self.proposal(id)?;
        if exact_digest != util::digest(&bytes) {
            return Err(Error::Denied(
                "reviewed digest does not match the immutable proposal".into(),
            ));
        }
        let approval = Uuid::new_v4();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = task_from_connection(&transaction, id)?;
        if current.phase != "closed"
            || current.error.is_some()
            || current.output_digest.as_deref() != Some(exact_digest)
        {
            return Err(Error::Denied(
                "task changed or was cancelled during review".into(),
            ));
        }
        transaction.execute(
            "INSERT INTO approvals(id,task,artifact_digest,expires_at) VALUES(?1,?2,?3,?4)",
            params![
                approval.to_string(),
                id.to_string(),
                exact_digest,
                util::now()? + 300
            ],
        )?;
        audit(
            &transaction,
            Some(id),
            "publication_approved",
            json!({"approval": approval, "artifact_digest": exact_digest, "lifetime_seconds": 300}),
        )?;
        transaction.commit()?;
        Ok(approval)
    }

    pub fn publish(&mut self, id: Uuid, approval: Uuid) -> Result<Uuid> {
        self.profile.verify_host()?;
        let task = self.task(id)?;
        let bytes = self.proposal(id)?;
        self.inputs(&task)?;
        let digest = util::digest(&bytes);
        let mut target = files::Publication::lock(
            &task.spec.original_path,
            &task.spec.original,
            self.profile.limits.input_bytes,
        )?;
        let operation = Uuid::new_v4();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = task_from_connection(&transaction, id)?;
        if current.phase != "closed" || current.error.is_some() || current.epoch != task.epoch {
            return Err(Error::Denied(
                "task changed or was cancelled before publication reservation".into(),
            ));
        }
        if transaction.execute(
            "UPDATE approvals SET used_by=?3 WHERE id=?1 AND task=?2 AND used_by IS NULL AND expires_at>?4 AND artifact_digest=?5",
            params![approval.to_string(), id.to_string(), operation.to_string(), util::now()?, digest],
        )? != 1 {
            return Err(Error::Denied("publication approval is expired, used, revoked, or mismatched".into()));
        }
        transaction.execute(
            "INSERT INTO operations(id,task,request_key,parameters_digest,kind,state,created_at) VALUES(?1,?2,?3,?4,'publication','reserved',?5)",
            params![operation.to_string(), id.to_string(), format!("publish-{approval}"), digest, util::now()?],
        )?;
        transaction.execute(
            "UPDATE tasks SET phase='publishing' WHERE id=?1",
            [id.to_string()],
        )?;
        audit(
            &transaction,
            Some(id),
            "publication_reserved",
            json!({"operation": operation, "approval": approval, "artifact_digest": digest}),
        )?;
        transaction.commit()?;
        self.dispatched(operation)?;
        let effect = target.commit(&bytes);
        let (outcome, phase, error) = if effect.is_ok() {
            ("succeeded", "published", None)
        } else {
            ("unknown", "recovery_required", Some("publication_unknown"))
        };
        if let Err(error) = self.finish_publication(id, operation, outcome, phase, error, &digest) {
            return Err(Error::Unknown(format!(
                "publication {operation} could not be finalized: {error}; do not retry"
            )));
        }
        if let Err(error) = effect {
            return Err(Error::Unknown(format!(
                "publication {operation} failed write/readback: {error}; original snapshot retained"
            )));
        }
        Ok(operation)
    }

    fn finish_publication(
        &mut self,
        id: Uuid,
        operation: Uuid,
        outcome: &str,
        phase: &str,
        error: Option<&str>,
        digest: &str,
    ) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if transaction.execute(
            "UPDATE operations SET state=?2,result_digest=?3 WHERE id=?1 AND state='dispatched'",
            params![
                operation.to_string(),
                outcome,
                if outcome == "succeeded" {
                    Some(digest)
                } else {
                    None
                }
            ],
        )? != 1
        {
            return Err(Error::Denied(
                "publication operation is not dispatched".into(),
            ));
        }
        transaction.execute(
            "UPDATE tasks SET phase=?2,error=?3 WHERE id=?1",
            params![id.to_string(), phase, error],
        )?;
        audit(
            &transaction,
            Some(id),
            "publication_outcome",
            json!({"operation": operation, "state": outcome, "artifact_digest": digest}),
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn save_model_result(&mut self, id: Uuid, operation: Uuid, bytes: &[u8]) -> Result<()> {
        if bytes.len() as u64 > self.profile.limits.output_bytes {
            return Err(invalid("model result exceeds the artifact bound"));
        }
        let valid: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE id=?1 AND task=?2 AND kind='inference' AND state='dispatched')",
            params![operation.to_string(), id.to_string()], |row| row.get(0),
        )?;
        if !valid {
            return Err(Error::Denied(
                "model result does not belong to this task's dispatched operation".into(),
            ));
        }
        files::create_new(
            &self
                .task_directory(id)
                .join(format!("{operation}.response.txt")),
            bytes,
        )?;
        self.outcome(operation, "succeeded", Some(&util::digest(bytes)))
    }

    pub fn cached_model_result(&self, id: Uuid, epoch: Uuid, operation: Uuid) -> Result<String> {
        self.authorize(id, epoch)?;
        let expected: Option<String> = self.connection.query_row(
            "SELECT result_digest FROM operations WHERE id=?1 AND task=?2 AND kind='inference' AND state='succeeded'",
            params![operation.to_string(), id.to_string()], |row| row.get(0),
        )?;
        let bytes = util::read_bounded(
            File::open(
                self.task_directory(id)
                    .join(format!("{operation}.response.txt")),
            )?,
            self.profile.limits.output_bytes,
        )?;
        if expected.as_deref() != Some(&util::digest(&bytes)) {
            return Err(Error::Denied("cached model result is inconsistent".into()));
        }
        self.authorize(id, epoch)?;
        Ok(util::text(&bytes)?.to_owned())
    }

    pub fn reconcile(&mut self, id: Uuid) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let task = task_from_connection(&transaction, id)?;
        let publication = task.phase == "publishing" || task.phase == "recovery_required";
        let publication_uncertain: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE task=?1 AND kind IN ('publication','restoration') AND state IN ('dispatched','unknown'))",
            [id.to_string()], |row| row.get(0),
        )?;
        let pending: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE task=?1 AND state IN ('reserved','dispatched'))",
            [id.to_string()], |row| row.get(0),
        )?;
        transaction.execute(
            "UPDATE operations SET state='unknown' WHERE task=?1 AND state='dispatched'",
            [id.to_string()],
        )?;
        transaction.execute(
            "UPDATE operations SET state='denied' WHERE task=?1 AND state='reserved'",
            [id.to_string()],
        )?;
        transaction.execute(
            "DELETE FROM approvals WHERE task=?1 AND used_by IS NULL",
            [id.to_string()],
        )?;
        if matches!(task.phase.as_str(), "running" | "revoking")
            || (task.phase == "closed" && pending)
        {
            transaction.execute(
                "UPDATE tasks SET phase='closed',epoch=?2,error='controller_lost_no_external_replay' WHERE id=?1",
                params![id.to_string(), Uuid::new_v4().to_string()],
            )?;
        } else if publication && publication_uncertain {
            transaction.execute(
                "UPDATE tasks SET phase='recovery_required',epoch=?2,error='publication_unknown' WHERE id=?1",
                params![id.to_string(), Uuid::new_v4().to_string()],
            )?;
        } else if task.phase == "publishing" {
            transaction.execute(
                "UPDATE tasks SET phase='closed',epoch=?2,error=NULL WHERE id=?1",
                params![id.to_string(), Uuid::new_v4().to_string()],
            )?;
        } else {
            return Err(Error::Denied(
                "task has no interrupted runtime or publication to reconcile".into(),
            ));
        }
        audit(
            &transaction,
            Some(id),
            "task_reconciled",
            json!({
                "publication_recovery_required": publication && publication_uncertain,
                "dispatched_operations": "unknown_no_automatic_replay",
                "reserved_operations": "denied_allowances_retained",
                "remote_revocation": "not_implied"
            }),
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn restoration_target(&self, id: Uuid) -> Result<Fingerprint> {
        let task = self.task(id)?;
        if task.phase != "recovery_required" {
            return Err(Error::Denied(
                "task has no uncertain local publication to restore".into(),
            ));
        }
        let (_, actual) = files::snapshot_bytes(
            &task.spec.original_path,
            self.profile
                .limits
                .input_bytes
                .max(self.profile.limits.output_bytes),
        )?;
        if actual.volume != task.spec.original.volume
            || actual.file_index != task.spec.original.file_index
        {
            return Err(Error::Denied(
                "recovery target is no longer the originally selected file object".into(),
            ));
        }
        Ok(actual)
    }

    pub fn restore(&mut self, id: Uuid, reviewed_current_digest: &str) -> Result<()> {
        self.profile.verify_host()?;
        let task = self.task(id)?;
        let current = self.restoration_target(id)?;
        if current.sha256 != reviewed_current_digest {
            return Err(Error::Denied(
                "recovery approval does not match the current destination bytes".into(),
            ));
        }
        let original = util::read_bounded(
            File::open(self.task_directory(id).join("original.txt"))?,
            self.profile.limits.input_bytes,
        )?;
        if util::digest(&original) != task.spec.original.sha256 {
            return Err(Error::Denied("protected recovery snapshot changed".into()));
        }
        let mut target = files::Publication::lock(
            &task.spec.original_path,
            &current,
            self.profile
                .limits
                .input_bytes
                .max(self.profile.limits.output_bytes),
        )?;
        let operation = Uuid::new_v4();
        let approval = Uuid::new_v4();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let latest = task_from_connection(&transaction, id)?;
        if latest.phase != "recovery_required" || latest.epoch != task.epoch {
            return Err(Error::Denied(
                "recovery state changed during approval".into(),
            ));
        }
        transaction.execute(
            "INSERT INTO approvals(id,task,artifact_digest,expires_at,used_by) VALUES(?1,?2,?3,?4,?5)",
            params![approval.to_string(), id.to_string(), task.spec.original.sha256, util::now()? + 300, operation.to_string()],
        )?;
        transaction.execute(
            "INSERT INTO operations(id,task,request_key,parameters_digest,kind,state,created_at) VALUES(?1,?2,?3,?4,'restoration','reserved',?5)",
            params![operation.to_string(), id.to_string(), format!("restore-{approval}"), task.spec.original.sha256, util::now()?],
        )?;
        transaction.execute(
            "UPDATE tasks SET phase='publishing' WHERE id=?1",
            [id.to_string()],
        )?;
        audit(
            &transaction,
            Some(id),
            "local_restoration_approved",
            json!({
                "operation": operation, "current_sha256": current.sha256, "restore_sha256": task.spec.original.sha256
            }),
        )?;
        transaction.commit()?;
        self.dispatched(operation)?;
        let effect = target.commit(&original);
        let (outcome, phase, error) = if effect.is_ok() {
            (
                "succeeded",
                "closed",
                Some("local_snapshot_restored_external_effects_not_recalled"),
            )
        } else {
            ("unknown", "recovery_required", Some("restoration_unknown"))
        };
        if let Err(error) = self.finish_publication(
            id,
            operation,
            outcome,
            phase,
            error,
            &task.spec.original.sha256,
        ) {
            return Err(Error::Unknown(format!(
                "local restoration could not be finalized: {error}"
            )));
        }
        if let Err(error) = effect {
            return Err(Error::Unknown(format!(
                "local restoration failed write/readback: {error}"
            )));
        }
        Ok(())
    }

    pub fn verify_audit(&self) -> Result<u64> {
        let mut previous = "0".repeat(64);
        let mut sequence = 0;
        let mut statement = self.connection.prepare(
            "SELECT seq,timestamp,task,kind,data,previous_hash,hash FROM audit ORDER BY seq",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            sequence += 1;
            let actual_sequence: u64 = row.get(0)?;
            let timestamp: u64 = row.get(1)?;
            let task: Option<String> = row.get(2)?;
            let kind: String = row.get(3)?;
            let data: String = row.get(4)?;
            let expected_previous: String = row.get(5)?;
            let hash: String = row.get(6)?;
            if actual_sequence != sequence
                || previous != expected_previous
                || hash
                    != util::json_digest(&json!([sequence, timestamp, task, kind, data, previous]))?
            {
                return Err(Error::Denied(
                    "audit sequence/hash chain is inconsistent".into(),
                ));
            }
            previous = hash;
        }
        Ok(sequence)
    }

    pub fn evidence(&self) -> Result<Vec<serde_json::Value>> {
        self.verify_audit()?;
        let mut statement = self
            .connection
            .prepare("SELECT seq,timestamp,task,kind,data,hash FROM audit ORDER BY seq")?;
        let mut rows = statement.query([])?;
        let mut result = Vec::new();
        while let Some(row) = rows.next()? {
            let data: String = row.get(4)?;
            result.push(json!({
                "sequence": row.get::<_, u64>(0)?, "timestamp": row.get::<_, u64>(1)?,
                "task": row.get::<_, Option<String>>(2)?, "kind": row.get::<_, String>(3)?,
                "data": serde_json::from_str::<serde_json::Value>(&data)?, "hash": row.get::<_, String>(5)?
            }));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Graph;
    use std::sync::{Arc, Barrier};

    fn setup(kind: TaskKind, profile_calls: u32) -> (tempfile::TempDir, Store, Uuid) {
        let directory = tempfile::tempdir().unwrap();
        let note = directory.path().join("note.txt");
        std::fs::write(&note, "original note\n").unwrap();
        let mut profile = Profile::draft("journal test".into()).unwrap();
        profile.limits.model_calls_per_profile = profile_calls;
        if kind == TaskKind::Live {
            profile.graph = Some(Graph {
                tenant_id: Uuid::new_v4(),
                client_id: Uuid::new_v4(),
                drive_id: "drive".into(),
                item_id: "reference".into(),
                forbidden_item_id: Some("forbidden".into()),
                download_hosts: vec!["tenant.sharepoint.com".into()],
            });
        }
        let mut store = Store::initialize(&directory.path().join("state"), profile).unwrap();
        let reference = Reference {
            provider: if kind == TaskKind::Live {
                "microsoft_graph"
            } else {
                "manual_lab_fixture"
            }
            .into(),
            resource: if kind == TaskKind::Live {
                "drive/reference"
            } else {
                "fixture"
            }
            .into(),
            version: None,
            sha256: util::digest(b"reference"),
            bytes: 9,
        };
        let id = store
            .prepare(kind, &note, "edit note".into(), b"reference", reference)
            .unwrap();
        (directory, store, id)
    }

    #[test]
    fn publication_requires_exact_one_use_approval_and_preserves_backup() {
        let (_directory, mut store, id) = setup(TaskKind::ManualLab, 16);
        store.close(id, Some(b"reviewed note\n"), None).unwrap();
        assert!(store.approve(id, &util::digest(b"different")).is_err());
        let digest = util::digest(b"reviewed note\n");
        let approval = store.approve(id, &digest).unwrap();
        store.publish(id, approval).unwrap();
        assert!(store.publish(id, approval).is_err());
        assert_eq!(
            std::fs::read(&store.task(id).unwrap().spec.original_path).unwrap(),
            b"reviewed note\n"
        );
        assert_eq!(
            std::fs::read(store.task_directory(id).join("original.txt")).unwrap(),
            b"original note\n"
        );
        assert_eq!(store.task(id).unwrap().phase, "published");
        assert!(store.verify_audit().unwrap() >= 7);
    }

    #[test]
    fn changed_original_and_cancelled_approval_never_write() {
        let (_directory, mut store, id) = setup(TaskKind::ManualLab, 16);
        store.close(id, Some(b"proposal"), None).unwrap();
        let approval = store.approve(id, &util::digest(b"proposal")).unwrap();
        let path = store.task(id).unwrap().spec.original_path;
        std::fs::write(&path, "concurrent edit").unwrap();
        assert!(store.publish(id, approval).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "concurrent edit");
        store.revoke(id).unwrap();
        assert!(store.approve(id, &util::digest(b"proposal")).is_err());
        assert!(store.publish(id, approval).is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "concurrent edit");
    }

    #[test]
    fn duplicate_operation_does_not_spend_twice_and_revocation_blocks_cached_release() {
        let (_directory, mut store, id) = setup(TaskKind::Live, 16);
        let grant = store.begin(id).unwrap();
        let digest = util::digest(b"parameters");
        let operation = store
            .reserve_model(id, grant.epoch, "request", &digest)
            .unwrap();
        store.dispatched(operation.id).unwrap();
        store
            .save_model_result(id, operation.id, b"model result")
            .unwrap();
        let duplicate = store
            .reserve_model(id, grant.epoch, "request", &digest)
            .unwrap();
        assert!(duplicate.replay);
        assert_eq!(duplicate.id, operation.id);
        assert_eq!(store.task(id).unwrap().model_calls, 1);
        assert!(
            store
                .reserve_model(
                    id,
                    grant.epoch,
                    "request",
                    &util::digest(b"changed parameters")
                )
                .is_err()
        );
        assert_eq!(
            store
                .cached_model_result(id, grant.epoch, operation.id)
                .unwrap(),
            "model result"
        );
        store.revoke(id).unwrap();
        assert!(
            store
                .cached_model_result(id, grant.epoch, operation.id)
                .is_err()
        );
        assert!(
            store
                .reserve_model(id, grant.epoch, "request", &digest)
                .is_err()
        );
        assert!(store.close(id, Some(b"stale output"), None).is_err());
        store.close(id, None, Some("cancelled")).unwrap();
        assert!(store.task(id).unwrap().output_digest.is_none());
    }

    #[test]
    fn concurrent_reservations_cannot_exceed_a_single_task_allowance() {
        let (_directory, mut store, id) = setup(TaskKind::Live, 16);
        let grant = store.begin(id).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let mut threads = Vec::new();
        for request in ["first", "second"] {
            let root = store.root.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                let mut connection = Store::open(&root).unwrap();
                barrier.wait();
                connection
                    .reserve_model(id, grant.epoch, request, &util::digest(b"parameters"))
                    .is_ok()
            }));
        }
        let successes = threads
            .into_iter()
            .map(|thread| usize::from(thread.join().unwrap()))
            .sum::<usize>();
        assert_eq!(successes, 1);
        assert_eq!(store.task(id).unwrap().model_calls, 1);
        store.revoke(id).unwrap();
        let operation: String = store
            .connection
            .query_row(
                "SELECT id FROM operations WHERE task=?1",
                [id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            store
                .dispatched(Uuid::parse_str(&operation).unwrap())
                .is_err()
        );
    }

    #[test]
    fn unknown_attempts_and_expiry_do_not_restore_allowances_after_reopen() {
        let (directory, mut store, first) = setup(TaskKind::Live, 1);
        let grant = store.begin(first).unwrap();
        let operation = store
            .reserve_model(first, grant.epoch, "request", &util::digest(b"parameters"))
            .unwrap();
        store.dispatched(operation.id).unwrap();
        store.outcome(operation.id, "unknown", None).unwrap();
        store.close(first, None, Some("inference_unknown")).unwrap();
        let root = store.root.clone();
        drop(store);
        let mut store = Store::open(&root).unwrap();
        let source = Reference {
            provider: "microsoft_graph".into(),
            resource: "drive/reference".into(),
            version: None,
            sha256: util::digest(b"reference"),
            bytes: 9,
        };
        let second = store
            .prepare(
                TaskKind::Live,
                &directory.path().join("note.txt"),
                "edit".into(),
                b"reference",
                source,
            )
            .unwrap();
        let grant = store.begin(second).unwrap();
        assert!(matches!(
            store.reserve_model(second, grant.epoch, "new", &util::digest(b"parameters")),
            Err(Error::Quota(_))
        ));
        store
            .connection
            .execute(
                "UPDATE tasks SET expires_at=0 WHERE id=?1",
                [second.to_string()],
            )
            .unwrap();
        assert!(store.authorize(second, grant.epoch).is_err());
        let calls: u64 = store
            .connection
            .query_row("SELECT calls FROM usage", [], |row| row.get(0))
            .unwrap();
        assert_eq!(calls, 1);
    }

    #[test]
    fn interrupted_publication_restores_only_the_same_reviewed_file_object() {
        let (_directory, mut store, id) = setup(TaskKind::ManualLab, 16);
        store.close(id, Some(b"proposal"), None).unwrap();
        let operation = Uuid::new_v4();
        store.connection.execute(
                    "INSERT INTO operations(id,task,request_key,parameters_digest,kind,state,created_at) VALUES(?1,?2,'interrupted',?3,'publication','dispatched',?4)",
                    params![operation.to_string(), id.to_string(), util::digest(b"proposal"), util::now().unwrap()],
                ).unwrap();
        store
            .connection
            .execute(
                "UPDATE tasks SET phase='publishing' WHERE id=?1",
                [id.to_string()],
            )
            .unwrap();
        let path = store.task(id).unwrap().spec.original_path;
        std::fs::write(&path, b"partial\xff").unwrap();
        store.reconcile(id).unwrap();
        let current = store.restoration_target(id).unwrap();
        assert!(store.restore(id, &util::digest(b"unreviewed")).is_err());
        store.restore(id, &current.sha256).unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"original note\n");
        assert_eq!(store.task(id).unwrap().phase, "closed");
        assert!(store.proposal(id).is_err());
        let state: String = store
            .connection
            .query_row(
                "SELECT state FROM operations WHERE id=?1",
                [operation.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "unknown");
        store.verify_audit().unwrap();
    }

    #[test]
    fn corrupted_audit_is_an_explicit_failure_not_a_green_status() {
        let (_directory, store, _id) = setup(TaskKind::ManualLab, 16);
        store
            .connection
            .execute("UPDATE audit SET kind='modified' WHERE seq=1", [])
            .unwrap();
        assert!(store.verify_audit().is_err());
        assert!(store.evidence().is_err());
    }

    #[test]
    fn journal_connection_limits_survive_initialization_and_reopening() {
        let (_directory, store, _) = setup(TaskKind::ManualLab, 16);
        let root = store.root.clone();
        let verify = |store: &Store| {
            let page_bytes: u64 = store
                .connection
                .query_row("PRAGMA page_size", [], |row| row.get(0))
                .unwrap();
            let max_pages: u64 = store
                .connection
                .query_row("PRAGMA max_page_count", [], |row| row.get(0))
                .unwrap();
            let retained_wal_bytes: i64 = store
                .connection
                .query_row("PRAGMA journal_size_limit", [], |row| row.get(0))
                .unwrap();
            assert_eq!(page_bytes, 4096);
            assert_eq!(max_pages, 16384);
            assert_eq!(retained_wal_bytes, 1048576);
        };
        verify(&store);
        verify(&Store::open(&root).unwrap());
        drop(store);
        verify(&Store::open(&root).unwrap());
    }

    #[test]
    fn journal_growth_beyond_64_mib_is_refused_without_advancing_authority() {
        let (_directory, store, id) = setup(TaskKind::ManualLab, 16);
        let events = store.verify_audit().unwrap();
        store
            .connection
            .execute_batch("CREATE TABLE capacity_probe(payload BLOB)")
            .unwrap();
        let result = store.connection.execute(
            "INSERT INTO capacity_probe VALUES(zeroblob(?1))",
            [64 * 1024 * 1024],
        );
        assert!(matches!(
            result,
            Err(rusqlite::Error::SqliteFailure(code, _))
                if code.code == rusqlite::ErrorCode::DiskFull
        ));
        let rows: u64 = store
            .connection
            .query_row("SELECT count(*) FROM capacity_probe", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 0);
        assert_eq!(store.task(id).unwrap().phase, "prepared");
        assert_eq!(store.task(id).unwrap().model_calls, 0);
        assert_eq!(store.verify_audit().unwrap(), events);
    }

    #[test]
    fn journal_with_changed_page_size_is_refused_without_migration() {
        let (_directory, store, _) = setup(TaskKind::ManualLab, 16);
        let root = store.root.clone();
        drop(store);
        let connection = Connection::open(root.join("journal.db")).unwrap();
        connection
            .execute_batch("PRAGMA journal_mode=DELETE; PRAGMA page_size=8192; VACUUM;")
            .unwrap();
        drop(connection);
        assert!(matches!(Store::open(&root), Err(Error::Unsupported(_))));
        let connection = Connection::open(root.join("journal.db")).unwrap();
        let page_bytes: u64 = connection
            .query_row("PRAGMA page_size", [], |row| row.get(0))
            .unwrap();
        assert_eq!(page_bytes, 8192);
    }

    #[test]
    fn journal_already_larger_than_the_budget_is_refused_without_truncation() {
        let (_directory, store, _) = setup(TaskKind::ManualLab, 16);
        let root = store.root.clone();
        drop(store);
        let connection = Connection::open(root.join("journal.db")).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE capacity_probe(payload BLOB);
             INSERT INTO capacity_probe VALUES(zeroblob(67108864));",
            )
            .unwrap();
        drop(connection);
        let path = root.join("journal.db");
        let bytes = std::fs::metadata(&path).unwrap().len();
        assert!(bytes > 64 * 1024 * 1024);
        assert!(matches!(Store::open(&root), Err(Error::Quota(_))));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), bytes);
    }

    #[test]
    fn only_one_controller_or_setup_operation_can_own_a_profile() {
        let (_directory, store, _id) = setup(TaskKind::ManualLab, 16);
        let first = store.control_lock().unwrap();
        assert!(store.control_lock().is_err());
        drop(first);
        assert!(store.control_lock().is_ok());
    }

    #[test]
    fn recovery_never_replays_reserved_publication_or_revives_unused_approvals() {
        let (_directory, mut store, id) = setup(TaskKind::ManualLab, 16);
        store.close(id, Some(b"proposal"), None).unwrap();
        let digest = util::digest(b"proposal");
        let first = store.approve(id, &digest).unwrap();
        let unused = store.approve(id, &digest).unwrap();
        let operation = Uuid::new_v4();
        store
            .connection
            .execute(
                "UPDATE approvals SET used_by=?2 WHERE id=?1",
                params![first.to_string(), operation.to_string()],
            )
            .unwrap();
        store.connection.execute(
            "INSERT INTO operations(id,task,request_key,parameters_digest,kind,state,created_at) VALUES(?1,?2,'never-dispatched',?3,'publication','reserved',?4)",
            params![operation.to_string(), id.to_string(), digest, util::now().unwrap()],
        ).unwrap();
        store
            .connection
            .execute(
                "UPDATE tasks SET phase='publishing' WHERE id=?1",
                [id.to_string()],
            )
            .unwrap();
        store.reconcile(id).unwrap();
        assert_eq!(store.task(id).unwrap().phase, "closed");
        let outcome: String = store
            .connection
            .query_row(
                "SELECT state FROM operations WHERE id=?1",
                [operation.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(outcome, "denied");
        assert!(store.publish(id, unused).is_err());
        assert_eq!(
            std::fs::read(&store.task(id).unwrap().spec.original_path).unwrap(),
            b"original note\n"
        );
        let fresh = store.approve(id, &digest).unwrap();
        store.publish(id, fresh).unwrap();
        assert_eq!(
            std::fs::read(&store.task(id).unwrap().spec.original_path).unwrap(),
            b"proposal"
        );
    }

    #[test]
    fn missing_native_policy_refuses_live_authority_before_any_dispatch() {
        let (_directory, mut store, id) = setup(TaskKind::Live, 16);
        let approved = crate::runtime::disclosure_digest(&store, id).unwrap();
        let error = crate::runtime::run(&mut store, id, &approved).unwrap_err();
        assert!(matches!(error, Error::Windows { .. }));
        let task = store.task(id).unwrap();
        assert_eq!(task.phase, "prepared");
        assert!(task.grant.is_none());
        assert_eq!(task.model_calls, 0);
        assert!(
            !store
                .evidence()
                .unwrap()
                .iter()
                .any(|event| event["kind"] == "native_preflight")
        );
    }

    #[test]
    fn endpoint_journal_is_additive_and_never_replays_unknown_changes() {
        let (_directory, mut store, task) = setup(TaskKind::ManualLab, 16);
        assert!(store.endpoint_changes().unwrap().is_empty());
        let plan = Uuid::new_v4();
        let parameters = util::digest(b"reviewed native policy");
        let operation = store
            .reserve_endpoint_change(plan, "install", &parameters, &json!({"policies": []}))
            .unwrap();
        let mut other = Store::open(&store.root).unwrap();
        assert!(
            other
                .reserve_endpoint_change(Uuid::new_v4(), "install", &parameters, &json!({}))
                .is_err()
        );
        assert!(store.endpoint_outcome(operation, "confirmed").is_err());
        store.endpoint_outcome(operation, "dispatched").unwrap();
        store.endpoint_outcome(operation, "unknown").unwrap();
        assert!(
            other
                .reserve_endpoint_change(plan, "install", &parameters, &json!({}))
                .is_err()
        );
        let reopened = Store::open(&store.root).unwrap();
        assert_eq!(reopened.endpoint_changes().unwrap()[0].state, "unknown");
        assert_eq!(reopened.task(task).unwrap().phase, "prepared");
        assert!(store.endpoint_outcome(operation, "dispatched").is_err());
        store.endpoint_outcome(operation, "confirmed").unwrap();
        assert!(
            other
                .reserve_endpoint_change(plan, "install", &util::digest(b"changed"), &json!({}))
                .is_err()
        );
        let removal = other
            .reserve_endpoint_change(plan, "remove", &parameters, &json!({}))
            .unwrap();
        other.endpoint_outcome(removal, "denied").unwrap();
        store.verify_audit().unwrap();
        let schema: String = store
            .connection
            .query_row("SELECT value FROM meta WHERE key='schema'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(schema, "1");
    }

    #[test]
    fn endpoint_reservation_requires_known_actions_and_exact_parameter_binding() {
        let (_directory, mut store, _) = setup(TaskKind::ManualLab, 16);
        assert!(
            store
                .reserve_endpoint_change(
                    Uuid::new_v4(),
                    "replace-any-policy",
                    &"0".repeat(64),
                    &json!({})
                )
                .is_err()
        );
        assert!(
            store
                .reserve_endpoint_change(Uuid::nil(), "install", &"0".repeat(64), &json!({}))
                .is_err()
        );
        assert!(
            store
                .reserve_endpoint_change(Uuid::new_v4(), "install", "not-a-digest", &json!({}))
                .is_err()
        );
        assert!(store.endpoint_changes().unwrap().is_empty());
    }
}
