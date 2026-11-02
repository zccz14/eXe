//! Local policy. A valid signature is not permission: the device decides what may run.
use serde::{Deserialize, Serialize};

use crate::protocol::PolicyDecision;

/// Conservative default: harmless tools only, `bash` must be enabled by a human.
pub const DEFAULT_TOML: &str = r#"# eXe local policy. A valid cloud signature is not permission to run anything here.
allow = ["echo", "sleep", "sysinfo"]
deny = ["bash"]
max_runtime_seconds = 60
max_output_bytes = 262144
"#;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default = "default_runtime")]
    pub max_runtime_seconds: u64,
    #[serde(default = "default_output")]
    pub max_output_bytes: usize,
    #[serde(default)]
    pub workdir: Option<String>,
}

fn default_runtime() -> u64 {
    60
}
fn default_output() -> usize {
    262_144
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allow: vec!["echo".into(), "sleep".into(), "sysinfo".into()],
            deny: vec!["bash".into()],
            max_runtime_seconds: default_runtime(),
            max_output_bytes: default_output(),
            workdir: None,
        }
    }
}

impl Policy {
    pub fn parse(text: &str) -> Result<Self, toml::de::Error> {
        let policy: Policy = toml::from_str(text)?;
        Ok(policy)
    }

    /// Deny always wins; anything not explicitly allowed is denied.
    pub fn decide(&self, name: &str) -> PolicyDecision {
        if self.deny.iter().any(|tool| tool == name) {
            return PolicyDecision::Deny(format!("tool `{name}` is denied by the local policy"));
        }
        if self.allow.iter().any(|tool| tool == name || tool == "*") {
            return PolicyDecision::Allow;
        }
        PolicyDecision::Deny(format!("tool `{name}` is not allowed by the local policy"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_denies_shell() {
        let policy = Policy::default();
        assert!(matches!(policy.decide("bash"), PolicyDecision::Deny(_)));
        assert_eq!(policy.decide("echo"), PolicyDecision::Allow);
        assert!(matches!(policy.decide("rm_rf"), PolicyDecision::Deny(_)));
    }

    #[test]
    fn deny_wins_over_allow() {
        let policy = Policy::parse("allow = [\"bash\"]\ndeny = [\"bash\"]").unwrap();
        assert!(matches!(policy.decide("bash"), PolicyDecision::Deny(_)));
    }

    #[test]
    fn shipped_default_parses() {
        let policy = Policy::parse(DEFAULT_TOML).unwrap();
        assert_eq!(policy.max_runtime_seconds, 60);
        assert_eq!(policy.decide("echo"), PolicyDecision::Allow);
    }
}
