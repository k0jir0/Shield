use std::path::Path;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Error, Result, invalid};
use crate::{platform, util};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub http_response_bytes: u64,
    pub deadline_seconds: u32,
    pub http_timeout_seconds: u32,
    pub worker_memory_mib: u32,
    pub model_calls_per_task: u32,
    pub model_calls_per_profile: u32,
    pub output_tokens_per_call: u32,
    pub output_token_allowances_per_profile: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            input_bytes: 64 * 1024,
            output_bytes: 64 * 1024,
            http_response_bytes: 1024 * 1024,
            deadline_seconds: 90,
            http_timeout_seconds: 30,
            worker_memory_mib: 128,
            model_calls_per_task: 1,
            model_calls_per_profile: 16,
            output_tokens_per_call: 2048,
            output_token_allowances_per_profile: 32768,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Graph {
    pub tenant_id: Uuid,
    pub client_id: Uuid,
    pub drive_id: String,
    pub item_id: String,
    pub forbidden_item_id: Option<String>,
    pub download_hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema_version: u32,
    pub id: Uuid,
    pub name: String,
    pub owner_sid: String,
    pub windows_build: u32,
    pub windows_revision: u32,
    pub windows_edition: String,
    pub binary_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher_cert_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "EndpointVerifier::is_direct")]
    pub endpoint_verifier: EndpointVerifier,
    pub model: String,
    pub graph: Option<Graph>,
    pub limits: Limits,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointVerifier {
    #[default]
    Direct,
    ProtectedService,
}

impl EndpointVerifier {
    fn is_direct(&self) -> bool {
        *self == Self::Direct
    }
}

impl Profile {
    pub fn draft(name: String) -> Result<Self> {
        let host = platform::environment()?;
        let value = Self {
            schema_version: 1,
            id: Uuid::new_v4(),
            name,
            owner_sid: host.user_sid,
            windows_build: host.build,
            windows_revision: host.revision,
            windows_edition: host.edition,
            binary_sha256: util::file_digest(&std::env::current_exe()?)?,
            publisher_cert_sha256: None,
            endpoint_verifier: EndpointVerifier::Direct,
            model: "gpt-4.1-mini".into(),
            graph: None,
            limits: Limits::default(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = util::read_bounded(std::fs::File::open(path)?, 64 * 1024)?;
        let value: Self = serde_json::from_slice(&bytes)?;
        value.validate()?;
        Ok(value)
    }

    pub fn digest(&self) -> Result<String> {
        util::json_digest(self)
    }

    pub fn credential_target(&self, kind: &str) -> Result<String> {
        if !matches!(kind, "openai" | "graph") {
            return Err(invalid("credential kind must be openai or graph"));
        }
        Ok(format!("Shield/{}/{kind}", self.id))
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 || self.id.is_nil() {
            return Err(invalid("unsupported profile schema or nil profile ID"));
        }
        if self.name.is_empty()
            || self.name.len() > 80
            || !self
                .name
                .bytes()
                .all(|value| value.is_ascii_graphic() || value == b' ')
        {
            return Err(invalid(
                "profile name must be 1..80 printable ASCII characters",
            ));
        }
        if !self.owner_sid.starts_with("S-1-") || self.windows_build < 19041 {
            return Err(invalid(
                "profile requires a Windows owner SID and supported build",
            ));
        }
        if self.binary_sha256.len() != 64 || hex::decode(&self.binary_sha256).is_err() {
            return Err(invalid("profile requires an exact SHA-256 binary digest"));
        }
        if self
            .publisher_cert_sha256
            .as_ref()
            .is_some_and(|pin| !util::is_sha256(pin))
        {
            return Err(invalid(
                "publisher certificate pin must be a canonical lowercase SHA-256 digest",
            ));
        }
        if self.model.is_empty()
            || self.model.len() > 100
            || !self
                .model
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        {
            return Err(invalid(
                "model must be a bounded literal identifier, not a URL",
            ));
        }
        let limits = &self.limits;
        if !(1..=128 * 1024).contains(&limits.input_bytes)
            || !(1..=128 * 1024).contains(&limits.output_bytes)
            || !(1024..=4 * 1024 * 1024).contains(&limits.http_response_bytes)
            || !(5..=300).contains(&limits.deadline_seconds)
            || !(1..=60).contains(&limits.http_timeout_seconds)
            || limits.http_timeout_seconds > limits.deadline_seconds
            || !(64..=512).contains(&limits.worker_memory_mib)
            || !(1..=4).contains(&limits.model_calls_per_task)
            || !(1..=1000).contains(&limits.model_calls_per_profile)
            || !(16..=16384).contains(&limits.output_tokens_per_call)
            || limits.output_token_allowances_per_profile < u64::from(limits.output_tokens_per_call)
            || limits.output_token_allowances_per_profile > 10_000_000
        {
            return Err(invalid(
                "profile limits exceed the implemented finite safety ranges",
            ));
        }
        if let Some(graph) = &self.graph {
            if graph.tenant_id.is_nil() || graph.client_id.is_nil() {
                return Err(invalid("Graph tenant and client IDs must be non-nil"));
            }
            for value in [&graph.drive_id, &graph.item_id]
                .into_iter()
                .chain(graph.forbidden_item_id.iter())
            {
                if value.is_empty()
                    || value.len() > 256
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"!._-=".contains(&byte))
                {
                    return Err(invalid(
                        "Graph resource IDs must be bounded opaque identifiers",
                    ));
                }
            }
            if graph.forbidden_item_id.as_ref() == Some(&graph.item_id) {
                return Err(invalid("allowed and forbidden Graph resources must differ"));
            }
            if graph.download_hosts.is_empty() || graph.download_hosts.len() > 8 {
                return Err(invalid("configure 1..8 exact Graph download hostnames"));
            }
            for host in &graph.download_hosts {
                if host.len() > 253
                    || !host.contains('.')
                    || !host.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte)
                    })
                    || host.parse::<std::net::IpAddr>().is_ok()
                {
                    return Err(invalid(
                        "download hosts must be exact lowercase DNS names, without wildcards, URLs or IP literals",
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn verify_host(&self) -> Result<()> {
        if platform::current_user_sid()? != self.owner_sid {
            return Err(Error::Denied(
                "owner differs from the frozen profile".into(),
            ));
        }
        self.verify_platform_image()
    }

    pub(crate) fn verify_platform_image(&self) -> Result<()> {
        self.validate()?;
        let host = platform::environment()?;
        if host.build != self.windows_build
            || host.revision != self.windows_revision
            || host.edition != self.windows_edition
        {
            return Err(Error::Denied(
                "owner, Windows configuration, or executable differs from the frozen profile"
                    .into(),
            ));
        }
        self.verify_image(&std::env::current_exe()?)
    }

    pub(crate) fn verify_image(&self, path: &Path) -> Result<()> {
        if let Some(publisher) = &self.publisher_cert_sha256 {
            crate::release::verify(path, &self.binary_sha256, publisher)?;
        } else if util::file_digest(path)? != self.binary_sha256 {
            return Err(Error::Denied(
                "executable differs from the frozen profile".into(),
            ));
        }
        Ok(())
    }

    pub fn verify_recovery_host(&self) -> Result<()> {
        self.validate()?;
        if platform::current_user_sid()? != self.owner_sid {
            return Err(Error::Denied(
                "recovery helper owner differs from the frozen profile".into(),
            ));
        }
        self.verify_image(&std::env::current_exe()?)
    }

    pub fn require_graph(&self) -> Result<&Graph> {
        self.graph.as_ref().ok_or_else(|| {
            Error::Unsupported("Graph is not configured; draft/local-fixture profiles cannot run the live integrated task".into())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publisher_pinning_is_explicit_strict_and_keeps_legacy_digest_shape_when_absent() {
        let mut profile = Profile::draft("publisher binding test".into()).unwrap();
        let legacy = serde_json::to_value(&profile).unwrap();
        assert!(legacy.get("publisher_cert_sha256").is_none());
        let digest = profile.digest().unwrap();
        let restored: Profile = serde_json::from_value(legacy).unwrap();
        assert!(restored.publisher_cert_sha256.is_none());
        assert_eq!(digest, restored.digest().unwrap());
        profile.publisher_cert_sha256 = Some(util::digest(b"explicit publisher certificate"));
        profile.validate().unwrap();
        assert_ne!(digest, profile.digest().unwrap());
        for pin in ["", "a", &"G".repeat(64), &"a".repeat(65)] {
            profile.publisher_cert_sha256 = Some(pin.to_owned());
            assert!(profile.validate().is_err());
        }
    }

    #[test]
    fn opted_in_publisher_is_checked_for_host_service_recovery_and_state_creation() {
        let directory = tempfile::tempdir().unwrap();
        let mut profile = Profile::draft("publisher enforcement test".into()).unwrap();
        profile.publisher_cert_sha256 = Some(util::digest(b"not a signing authority"));
        for error in [
            profile.verify_host().unwrap_err(),
            profile.verify_platform_image().unwrap_err(),
            profile.verify_recovery_host().unwrap_err(),
        ] {
            assert!(error.to_string().contains("WinTrust status"));
        }
        let state = directory.path().join("must-not-exist");
        let result = crate::state::Store::initialize(&state, profile);
        assert!(result.is_err());
        assert!(!state.exists());
    }

    #[test]
    fn profile_is_strict_and_bounded() {
        let mut profile = Profile::draft("test".into()).unwrap();
        profile.validate().unwrap();
        assert!(profile.require_graph().is_err());
        profile.limits.model_calls_per_task = 0;
        assert!(profile.validate().is_err());
        profile.limits.model_calls_per_task = 1;
        profile.model = "https://attacker.example".into();
        assert!(profile.validate().is_err());
    }

    #[test]
    fn unexpected_authority_fields_are_rejected() {
        let profile = Profile::draft("test".into()).unwrap();
        let mut value = serde_json::to_value(profile).unwrap();
        value["allow_everything"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Profile>(value).is_err());
    }

    #[test]
    fn direct_verifier_keeps_old_profile_digest_shape_and_service_is_opt_in() {
        let mut profile = Profile::draft("test".into()).unwrap();
        let direct = serde_json::to_value(&profile).unwrap();
        assert!(direct.get("endpoint_verifier").is_none());
        let original_digest = profile.digest().unwrap();
        let loaded: Profile = serde_json::from_value(direct.clone()).unwrap();
        assert_eq!(loaded.endpoint_verifier, EndpointVerifier::Direct);
        assert_eq!(loaded.digest().unwrap(), original_digest);
        profile.endpoint_verifier = EndpointVerifier::ProtectedService;
        let service = serde_json::to_value(&profile).unwrap();
        assert_eq!(service["endpoint_verifier"], "protected_service");
        assert_ne!(profile.digest().unwrap(), original_digest);
        let mut invalid = direct;
        invalid["endpoint_verifier"] = serde_json::json!("automatic_elevation");
        assert!(serde_json::from_value::<Profile>(invalid).is_err());
    }
}
