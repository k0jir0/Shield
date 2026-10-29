use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use shield::{files, util};
use uuid::Uuid;

use super::catalog::{CASES, Case, Gate};

pub type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Assertion {
    Review,
    Safety,
    Utility,
    Fault,
    Detection,
    Recovery,
    Performance,
    Usability,
    Comparison,
    Classifier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Native,
    Provider,
    AuthorizedReview,
    UserStudy,
    Synthetic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Metric {
    ForbiddenEffects,
    PositiveControls,
    Completions,
    UnresolvedDecisions,
    ReviewedRequirements,
    ExpectedFaults,
    Detections,
    RemainingAuthority,
    RecoveredScopes,
    ManualSecurityEdits,
    ExtraUnchangedLaunchPrompts,
    FalseBlocks,
    Prompts,
    ElapsedMs,
    ResponseMs,
    DetectionMs,
    RecoveryMs,
    FootprintBytes,
    PeakMemoryBytes,
    CpuMs,
    StartupMs,
    P95BrokerMs,
    TotalCostMilliunits,
    OperatorEffortMs,
    ImprovementBasisPoints,
    TruePositive,
    FalsePositive,
    TrueNegative,
    FalseNegative,
    PrecisionBasisPoints,
    RecallBasisPoints,
    FalsePositiveBasisPoints,
    EnergyMillijoules,
}

impl Metric {
    fn is_count(self) -> bool {
        use Metric::*;
        matches!(
            self,
            ForbiddenEffects
                | PositiveControls
                | Completions
                | UnresolvedDecisions
                | ReviewedRequirements
                | ExpectedFaults
                | Detections
                | RemainingAuthority
                | RecoveredScopes
                | ManualSecurityEdits
                | ExtraUnchangedLaunchPrompts
                | FalseBlocks
                | Prompts
                | TruePositive
                | FalsePositive
                | TrueNegative
                | FalseNegative
        )
    }

    fn derived(self) -> bool {
        matches!(
            self,
            Self::ImprovementBasisPoints
                | Self::PrecisionBasisPoints
                | Self::RecallBasisPoints
                | Self::FalsePositiveBasisPoints
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema_version: u32,
    pub frozen_at: u64,
    pub expires_at: u64,
    pub owner: String,
    pub specification_sha256: String,
    pub paper_sha256: String,
    pub harness_sha256: String,
    #[serde(deserialize_with = "unique_map")]
    pub declarations: BTreeMap<String, Artifact>,
    pub enabled_extensions: BTreeSet<String>,
    #[serde(deserialize_with = "unique_map")]
    pub cases: BTreeMap<String, CasePlan>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CasePlan {
    pub trials_per_variant: u32,
    #[serde(deserialize_with = "unique_map")]
    pub variants: BTreeMap<String, Variant>,
    #[serde(deserialize_with = "unique_map")]
    pub minimums: BTreeMap<Metric, u64>,
    #[serde(deserialize_with = "unique_map")]
    pub maximums: BTreeMap<Metric, u64>,
    pub comparison: Option<Comparison>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Comparison {
    AddedProtection,
    SaferOperability,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Variant {
    pub profile: Artifact,
    pub workload: Artifact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub schema_version: u32,
    pub case_id: String,
    pub plan_sha256: String,
    pub trials: Vec<Trial>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trial {
    pub run_id: Uuid,
    pub variant: String,
    pub profile_sha256: String,
    pub workload_sha256: String,
    pub started_at: u64,
    pub completed_at: u64,
    pub observation: Artifact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Valid,
    Invalid,
    Skipped,
    Unknown,
    AlreadyNativeBlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    Complete,
    Gap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub schema_version: u32,
    pub run_id: Uuid,
    pub case_id: String,
    pub variant: String,
    pub plan_sha256: String,
    pub profile_sha256: String,
    pub subject_principal: String,
    pub subject_trust_domain: String,
    pub observer_principal: String,
    pub observer_trust_domain: String,
    pub observed_from: u64,
    pub observed_until: u64,
    pub status: ProbeStatus,
    pub coverage: Coverage,
    pub sources: BTreeSet<Source>,
    #[serde(deserialize_with = "unique_map")]
    pub metrics: BTreeMap<Metric, u64>,
    pub raw_evidence: Vec<Artifact>,
}

pub const DECLARATIONS: &[&str] = &[
    "scope_and_operators",
    "identity_resource_verb_matrix",
    "lab_authorization_and_recovery",
    "admission_and_native_baselines",
    "client_provider_disclosure",
    "budgets_and_stop_rules",
    "secret_custody_and_cleanup",
    "response_ownership_and_maintenance",
];

fn unique_map<'de, D, K, V>(deserializer: D) -> std::result::Result<BTreeMap<K, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    K: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
{
    struct Visitor<K, V>(std::marker::PhantomData<(K, V)>);
    impl<'de, K: Deserialize<'de> + Ord, V: Deserialize<'de>> serde::de::Visitor<'de>
        for Visitor<K, V>
    {
        type Value = BTreeMap<K, V>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a map with unique keys")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut access: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut result = BTreeMap::new();
            while let Some((key, value)) = access.next_entry()? {
                if result.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate contract key"));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Visitor(std::marker::PhantomData))
}

fn require(condition: bool, message: impl Into<String>) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

pub fn harness_digest() -> String {
    util::digest(
        format!(
            "{}:{}:{}",
            util::digest(include_bytes!("catalog.rs")),
            util::digest(include_bytes!("evidence.rs")),
            util::digest(include_bytes!("..\\acceptance.rs")),
        )
        .as_bytes(),
    )
}

pub fn specification_digest() -> String {
    util::digest(include_bytes!("..\\..\\start.txt"))
}

pub fn paper_digest() -> String {
    util::digest(include_bytes!("..\\..\\paper.txt"))
}

fn read_bytes(path: &Path, limit: u64) -> Result<Vec<u8>> {
    files::snapshot_bytes(path, limit)
        .map(|(bytes, _)| bytes)
        .map_err(|error| {
            format!(
                "required local evidence unavailable at {}: {error}",
                path.display()
            )
        })
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes)
        .map_err(|_| "unsupported, ambiguous or malformed evidence schema".into())
}

fn artifact_bytes(root: &Path, artifact: &Artifact) -> Result<Vec<u8>> {
    require(
        util::is_sha256(&artifact.sha256),
        "artifact digest must be canonical SHA-256",
    )?;
    let bytes = read_bytes(
        &root
            .join("artifacts")
            .join(format!("{}.blob", artifact.sha256)),
        2 * 1024 * 1024,
    )?;
    require(
        !bytes.is_empty() && util::digest(&bytes) == artifact.sha256,
        "missing, empty or changed evidence artifact",
    )?;
    Ok(bytes)
}

pub fn validate_plan(root: &Path, plan: &Plan, now: u64) -> Result<()> {
    require(plan.schema_version == 1, "unsupported plan schema")?;
    require(
        !plan.owner.trim().is_empty() && plan.owner.len() <= 256,
        "name the acceptance owner",
    )?;
    require(
        plan.frozen_at > 0 && plan.frozen_at < now && now <= plan.expires_at,
        "plan is not frozen, is expired, or has invalid time bounds",
    )?;
    require(
        plan.specification_sha256 == specification_digest()
            && plan.paper_sha256 == paper_digest()
            && plan.harness_sha256 == harness_digest(),
        "specification, technical paper or test architecture changed; freeze a new plan",
    )?;
    require(
        plan.declarations.len() == DECLARATIONS.len(),
        "declare every required scope/lab/provider/budget/ownership document",
    )?;
    for name in DECLARATIONS {
        artifact_bytes(
            root,
            plan.declarations
                .get(*name)
                .ok_or_else(|| format!("missing declaration: {name}"))?,
        )?;
    }
    require(
        !plan.cases.is_empty() && plan.cases.len() <= CASES.len(),
        "invalid planned scenario count",
    )?;
    for extension in &plan.enabled_extensions {
        require(
            CASES
                .iter()
                .any(|case| case.extension == Some(extension.as_str())),
            "unknown extension selection",
        )?;
    }
    for case in CASES {
        if (case.extension.is_none() && case.gate != Gate::Release)
            || case
                .extension
                .is_some_and(|name| plan.enabled_extensions.contains(name))
        {
            require(
                plan.cases.contains_key(case.id),
                format!("missing mandatory pilot scenario: {}", case.id),
            )?;
        }
    }
    for (id, settings) in &plan.cases {
        let case = CASES
            .iter()
            .find(|case| case.id == id)
            .ok_or("unknown scenario in plan")?;
        require(
            case.extension
                .is_none_or(|name| plan.enabled_extensions.contains(name)),
            "extension case was not explicitly selected",
        )?;
        require(
            (1..=64).contains(&settings.trials_per_variant),
            "predeclare 1..64 trials per variant",
        )?;
        let variants: BTreeSet<_> = settings.variants.keys().map(String::as_str).collect();
        require(
            variants == case.variants.iter().copied().collect(),
            format!("missing or changed required variants for {id}"),
        )?;
        let mut workloads = BTreeSet::new();
        for variant in settings.variants.values() {
            artifact_bytes(root, &variant.profile)?;
            artifact_bytes(root, &variant.workload)?;
            workloads.insert(&variant.workload.sha256);
        }
        if case.assertion == Assertion::Comparison || case.gate == Gate::E1 {
            require(
                workloads.len() == 1,
                "paired variants must use the same frozen workload",
            )?;
        }
        for rule in rules(case.assertion) {
            match rule {
                Rule::Minimum(metric) => {
                    let minimum = settings
                        .minimums
                        .get(&metric)
                        .ok_or_else(|| format!("{id}: missing minimum budget for {metric:?}"))?;
                    require(
                        *minimum > 0,
                        "zero utility or improvement minimum would accept refusing everything",
                    )?;
                    if metric == Metric::Completions {
                        require(
                            *minimum <= u64::from(settings.trials_per_variant),
                            "completion minimum exceeds trial count",
                        )?;
                    }
                    if metric.derived() {
                        require(
                            *minimum <= 10_000,
                            "rate or improvement minimum must be 1..10000 basis points",
                        )?;
                    }
                }
                Rule::Maximum(metric) => {
                    require(
                        settings.maximums.contains_key(&metric),
                        format!("{id}: missing maximum budget for {metric:?}"),
                    )?;
                    if metric.derived() {
                        require(
                            settings.maximums[&metric] <= 10_000,
                            "rate maximum exceeds 10000 basis points",
                        )?;
                    }
                }
                Rule::Zero(_) | Rule::One(_) => {}
            }
        }
        require(
            settings.comparison.is_some() == (case.assertion == Assertion::Comparison),
            "comparison mode must be explicit and only used for comparison cases",
        )?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Rule {
    Zero(Metric),
    One(Metric),
    Minimum(Metric),
    Maximum(Metric),
}

fn rules(assertion: Assertion) -> Vec<Rule> {
    use Metric::*;
    use Rule::*;
    match assertion {
        Assertion::Review => vec![Zero(UnresolvedDecisions), One(ReviewedRequirements)],
        Assertion::Safety => vec![
            Zero(ForbiddenEffects),
            One(PositiveControls),
            Maximum(ResponseMs),
        ],
        Assertion::Utility => vec![Minimum(Completions), Maximum(ElapsedMs)],
        Assertion::Fault => vec![
            Zero(ForbiddenEffects),
            One(ExpectedFaults),
            Maximum(ResponseMs),
        ],
        Assertion::Detection => vec![One(Detections), Maximum(DetectionMs)],
        Assertion::Recovery => vec![
            Zero(RemainingAuthority),
            One(RecoveredScopes),
            Maximum(RecoveryMs),
        ],
        Assertion::Performance => vec![
            Maximum(FootprintBytes),
            Maximum(PeakMemoryBytes),
            Maximum(CpuMs),
            Maximum(StartupMs),
            Maximum(P95BrokerMs),
            Maximum(TotalCostMilliunits),
        ],
        Assertion::Usability => vec![
            Minimum(Completions),
            Zero(ManualSecurityEdits),
            Zero(ExtraUnchangedLaunchPrompts),
            Maximum(FalseBlocks),
            Maximum(Prompts),
            Maximum(ElapsedMs),
        ],
        Assertion::Comparison => vec![
            One(PositiveControls),
            Minimum(Completions),
            Minimum(ImprovementBasisPoints),
            Maximum(ElapsedMs),
        ],
        Assertion::Classifier => vec![
            Minimum(PrecisionBasisPoints),
            Minimum(RecallBasisPoints),
            Maximum(FalsePositiveBasisPoints),
            Maximum(EnergyMillijoules),
            Maximum(ElapsedMs),
        ],
    }
}

fn aggregate(values: &mut BTreeMap<Metric, u64>, metric: Metric, value: u64) -> Result<()> {
    let entry = values.entry(metric).or_default();
    *entry = if metric.is_count() {
        entry
            .checked_add(value)
            .ok_or("measurement counter overflow")?
    } else {
        (*entry).max(value)
    };
    Ok(())
}

pub struct Replay<'a> {
    pub root: &'a Path,
    pub plan: &'a Plan,
    pub plan_hash: &'a str,
    pub now: u64,
}

pub fn evaluate_record(
    context: &Replay<'_>,
    case: &Case,
    settings: &CasePlan,
    record: &Record,
    seen: &mut BTreeSet<Uuid>,
) -> Result<()> {
    let Replay {
        root,
        plan,
        plan_hash,
        now,
    } = *context;
    require(
        record.schema_version == 1 && record.case_id == case.id && record.plan_sha256 == plan_hash,
        "record belongs to another scenario, schema or frozen plan",
    )?;
    require(
        record.trials.len() == settings.variants.len() * settings.trials_per_variant as usize,
        "missing, extra or skipped trials; trial denominators must match the frozen plan",
    )?;
    let mut measurements: BTreeMap<String, BTreeMap<Metric, u64>> = BTreeMap::new();
    let mut counts = BTreeMap::<String, u32>::new();
    for trial in &record.trials {
        require(
            !trial.run_id.is_nil() && seen.insert(trial.run_id),
            "nil or replayed run ID",
        )?;
        let variant = settings
            .variants
            .get(&trial.variant)
            .ok_or("unplanned variant")?;
        require(
            trial.profile_sha256 == variant.profile.sha256
                && trial.workload_sha256 == variant.workload.sha256,
            "profile or workload drift; incompatible observations cannot be pooled",
        )?;
        require(
            trial.started_at > plan.frozen_at
                && trial.completed_at >= trial.started_at
                && trial.completed_at <= now
                && trial.completed_at <= plan.expires_at,
            "trial predates plan freeze, exceeds its lifetime or has invalid timestamps",
        )?;
        let observation: Observation = decode(&artifact_bytes(root, &trial.observation)?)?;
        require(
            observation.schema_version == 1
                && observation.run_id == trial.run_id
                && observation.case_id == case.id
                && observation.variant == trial.variant
                && observation.plan_sha256 == plan_hash
                && observation.profile_sha256 == trial.profile_sha256,
            "observer record is not bound to this run, scenario, variant, plan and profile",
        )?;
        require(
            observation.status == ProbeStatus::Valid,
            format!(
                "{}: {:?} probe is not qualifying evidence (attempted={}, required={})",
                case.id,
                observation.status,
                record.trials.len(),
                settings.variants.len() * settings.trials_per_variant as usize
            ),
        )?;
        require(
            observation.coverage == Coverage::Complete
                && observation.observed_from <= trial.started_at
                && observation.observed_until >= trial.completed_at
                && observation.observed_until <= now,
            "observer gap or incomplete effect interval; absent final markers are insufficient",
        )?;
        require(
            !observation.subject_principal.trim().is_empty()
                && !observation.observer_principal.trim().is_empty()
                && !observation.subject_trust_domain.trim().is_empty()
                && !observation.observer_trust_domain.trim().is_empty()
                && observation.subject_principal != observation.observer_principal
                && observation.subject_trust_domain != observation.observer_trust_domain,
            "observer must be outside the subject's principal and trust domain",
        )?;
        require(
            !observation.sources.contains(&Source::Synthetic)
                && case
                    .layer
                    .sources()
                    .iter()
                    .all(|source| observation.sources.contains(source)),
            "mock, model-only, local-proxy or missing required real-observer source",
        )?;
        require(
            !observation.raw_evidence.is_empty() && observation.raw_evidence.len() <= 16,
            "retain 1..16 non-secret raw evidence artifacts per observation",
        )?;
        for artifact in &observation.raw_evidence {
            require(
                artifact.sha256 != trial.observation.sha256,
                "observer record is not its own raw effect evidence",
            )?;
            artifact_bytes(root, artifact)?;
        }
        let values = measurements.entry(trial.variant.clone()).or_default();
        for rule in rules(case.assertion) {
            let metric = match rule {
                Rule::Zero(m) | Rule::One(m) | Rule::Minimum(m) | Rule::Maximum(m) => m,
            };
            if metric.derived() {
                continue;
            }
            let value = *observation
                .metrics
                .get(&metric)
                .ok_or_else(|| format!("missing actual measurement: {metric:?}"))?;
            if metric == Metric::Completions {
                require(
                    value <= 1,
                    "one trial cannot claim multiple legitimate-task completions",
                )?;
            }
            match rule {
                Rule::Zero(_) => require(
                    value == 0,
                    format!("forbidden/nonzero measurement: {metric:?}"),
                )?,
                Rule::One(_) => require(
                    value >= 1,
                    format!("missing valid positive/utility observation: {metric:?}"),
                )?,
                Rule::Maximum(_) => require(
                    value <= settings.maximums[&metric],
                    format!("acceptance budget exceeded: {metric:?}"),
                )?,
                Rule::Minimum(_) => {}
            }
            aggregate(values, metric, value)?;
        }
        if case.assertion == Assertion::Comparison {
            for metric in [Metric::ForbiddenEffects, Metric::OperatorEffortMs] {
                aggregate(
                    values,
                    metric,
                    *observation
                        .metrics
                        .get(&metric)
                        .ok_or("missing native-comparison measurement")?,
                )?;
            }
        }
        if case.assertion == Assertion::Classifier {
            for metric in [
                Metric::TruePositive,
                Metric::FalsePositive,
                Metric::TrueNegative,
                Metric::FalseNegative,
            ] {
                aggregate(
                    values,
                    metric,
                    *observation
                        .metrics
                        .get(&metric)
                        .ok_or("missing held-out classification count")?,
                )?;
            }
        }
        *counts.entry(trial.variant.clone()).or_default() += 1;
    }
    for name in settings.variants.keys() {
        require(
            counts.get(name) == Some(&settings.trials_per_variant),
            "variants cannot borrow each other's trials",
        )?;
        for rule in rules(case.assertion) {
            if let Rule::Minimum(metric) = rule
                && !metric.derived()
            {
                require(
                    measurements[name][&metric] >= settings.minimums[&metric],
                    format!("legitimate utility budget failed in {name}"),
                )?;
            }
        }
        if case.assertion == Assertion::Classifier {
            for (metric, value) in classification_rates(&measurements[name])? {
                let accepted = if metric == Metric::FalsePositiveBasisPoints {
                    value <= settings.maximums[&metric]
                } else {
                    value >= settings.minimums[&metric]
                };
                require(
                    accepted,
                    format!("held-out classifier quality budget failed: {metric:?}"),
                )?;
            }
        }
    }
    if let Some(mode) = settings.comparison {
        use Metric::*;
        let native = &measurements["native"];
        let equivalent = &measurements["equivalent_native"];
        let shield = &measurements["shield"];
        require(
            shield[&ForbiddenEffects] == 0,
            "Shield comparison observed forbidden effects",
        )?;
        let improvement = match mode {
            Comparison::AddedProtection => {
                let baseline = native[&ForbiddenEffects].min(equivalent[&ForbiddenEffects]);
                require(
                    baseline > 0,
                    "already-native-blocked effects cannot earn Shield prevention credit",
                )?;
                10_000_u128
            }
            Comparison::SaferOperability => {
                require(
                    equivalent[&ForbiddenEffects] == 0,
                    "operability comparison must retain equivalent protection",
                )?;
                let before = equivalent[&OperatorEffortMs];
                let after = shield[&OperatorEffortMs];
                require(
                    before > 0 && after < before,
                    "no measured safe-operability improvement",
                )?;
                u128::from(before - after) * 10_000 / u128::from(before)
            }
        };
        require(
            improvement >= u128::from(settings.minimums[&ImprovementBasisPoints]),
            "native-value improvement is below the frozen budget",
        )?;
    }
    Ok(())
}

pub fn classification_rates(counts: &BTreeMap<Metric, u64>) -> Result<BTreeMap<Metric, u64>> {
    use Metric::*;
    let tp = u128::from(
        *counts
            .get(&TruePositive)
            .ok_or("missing true-positive count")?,
    );
    let fp = u128::from(
        *counts
            .get(&FalsePositive)
            .ok_or("missing false-positive count")?,
    );
    let tn = u128::from(
        *counts
            .get(&TrueNegative)
            .ok_or("missing true-negative count")?,
    );
    let negative = u128::from(
        *counts
            .get(&FalseNegative)
            .ok_or("missing false-negative count")?,
    );
    require(
        tp + fp > 0 && tp + negative > 0 && fp + tn > 0,
        "held-out corpus needs positive/negative cases and actual predictions; undefined rates cannot default to success",
    )?;
    Ok(BTreeMap::from([
        (
            PrecisionBasisPoints,
            u64::try_from(tp * 10_000 / (tp + fp)).map_err(|_| "invalid precision")?,
        ),
        (
            RecallBasisPoints,
            u64::try_from(tp * 10_000 / (tp + negative)).map_err(|_| "invalid recall")?,
        ),
        (
            FalsePositiveBasisPoints,
            u64::try_from(fp * 10_000 / (fp + tn)).map_err(|_| "invalid false-positive rate")?,
        ),
    ]))
}

pub fn verify_case(root: &Path, id: &str, now: u64) -> Result<()> {
    let bytes = read_bytes(&root.join("plan.json"), 1024 * 1024)?;
    let plan: Plan = decode(&bytes)?;
    validate_plan(root, &plan, now)?;
    let hash = util::digest(&bytes);
    let mut checked = BTreeSet::new();
    let mut seen = BTreeSet::new();
    fn verify(
        root: &Path,
        id: &str,
        now: u64,
        plan: &Plan,
        hash: &str,
        checked: &mut BTreeSet<String>,
        seen: &mut BTreeSet<Uuid>,
    ) -> Result<()> {
        if checked.contains(id) {
            return Ok(());
        }
        let case = CASES
            .iter()
            .find(|case| case.id == id)
            .ok_or("unknown acceptance scenario")?;
        if let Some(extension) = case.extension {
            require(
                plan.enabled_extensions.contains(extension),
                format!("extension {extension} is not selected; no support claim"),
            )?;
        }
        for gate in case.gate.prerequisites() {
            for prerequisite in CASES.iter().filter(|case| {
                case.gate == *gate
                    && case
                        .extension
                        .is_none_or(|name| plan.enabled_extensions.contains(name))
            }) {
                verify(root, prerequisite.id, now, plan, hash, checked, seen)?;
            }
        }
        let settings = plan
            .cases
            .get(id)
            .ok_or_else(|| format!("scenario not planned: {id}"))?;
        let record: Record = decode(&read_bytes(
            &root.join("runs").join(format!("{id}.json")),
            4 * 1024 * 1024,
        )?)?;
        evaluate_record(
            &Replay {
                root,
                plan,
                plan_hash: hash,
                now,
            },
            case,
            settings,
            &record,
            seen,
        )?;
        checked.insert(id.to_owned());
        Ok(())
    }
    verify(root, id, now, &plan, &hash, &mut checked, &mut seen)
}

#[cfg(feature = "acceptance")]
pub fn verify_from_environment(id: &str) -> Result<()> {
    let root = std::env::var_os("SHIELD_ACCEPTANCE_BUNDLE")
        .ok_or("RED: set SHIELD_ACCEPTANCE_BUNDLE to an operator-reviewed real-observer bundle; no lab results are supplied by this repository")?;
    verify_case(
        Path::new(&root),
        id,
        util::now().map_err(|error| error.to_string())?,
    )
}
