//! Command mediation: policy-driven command interception and response injection.
//!
//! The mediation layer sits between the sandboxed AI agent and real tool binaries.
//! Instead of running a command directly, the sandbox's PATH resolves to a shim
//! that forwards the invocation over a Unix socket to this server running in the
//! unsandboxed parent.
//!
//! This layer can intercept any command invocation and either return a configured
//! static response or capture the output of the real binary and return a nonce
//! (phantom token pattern). On passthrough, nonce-bearing env vars are promoted
//! to their real values before exec-ing the real binary.
//!
//! All policy (which commands to intercept, what to do, which env vars to block)
//! lives in the profile's `mediation` section.

pub mod admin;
pub mod approval;
pub mod broker;
pub mod control;
pub mod policy;
pub mod server;
pub mod session;

use serde::{Deserialize, Serialize};

/// Top-level mediation configuration from a profile's `mediation` section.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct MediationConfig {
    /// Commands to mediate (intercept or pass through).
    #[serde(default)]
    pub commands: Vec<CommandEntry>,
    /// Environment variable policy for the sandboxed child.
    #[serde(default)]
    pub env: EnvPolicy,
}

impl MediationConfig {
    /// Returns true if there is any mediation configuration to apply.
    pub fn is_active(&self) -> bool {
        !self.commands.is_empty() || !self.env.block.is_empty()
    }
}

/// Per-command mediation entry.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommandEntry {
    /// The command name to mediate (resolved via `which` at session start).
    pub name: String,
    /// Optional absolute path to the real binary, overriding `which` resolution.
    /// Useful when the system `which` resolves to a wrapper that should not be exec'd.
    #[serde(default)]
    pub binary_path: Option<String>,
    /// Arg-prefix intercept rules. Checked in order; first match wins.
    #[serde(default)]
    pub intercept: Vec<InterceptRule>,
    /// Optional sandbox profile applied when exec-ing the real binary.
    #[serde(default)]
    pub sandbox: Option<CommandSandbox>,
}

/// An intercept rule: if `args_prefix` matches the invocation's positional args,
/// perform the configured action without (or with) calling the real binary.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InterceptRule {
    /// The leading positional args that must match (flags are ignored during matching).
    /// E.g. `["auth", "github", "token"]` matches `ddtool --debug auth github token`.
    pub args_prefix: Vec<String>,
    /// If true, the user must authenticate via a native macOS biometric/password dialog
    /// before the action is executed. Requires `nono-approve` to be installed alongside nono.
    /// Defaults to false.
    #[serde(default)]
    pub admin: bool,
    /// What to do when this rule matches.
    pub action: InterceptAction,
}

/// The action to take when an intercept rule fires.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InterceptAction {
    /// Return a static response without calling the real binary.
    Respond {
        #[serde(default)]
        stdout: String,
        #[serde(default)]
        exit_code: i32,
    },
    /// Capture a credential and return a nonce to the sandbox.
    ///
    /// If `script` is set, runs `sh -c "<script>"` and captures its stdout.
    /// If `script` is absent, runs the real binary with the original args.
    /// The captured stdout (trimmed) is stored in the broker; the nonce is returned.
    Capture {
        /// Optional shell script to run instead of the real binary.
        /// Runs via `sh -c` in the unsandboxed parent. Stdout is the credential.
        #[serde(default)]
        script: Option<String>,
    },
    /// Run the real binary and return its actual output (no nonce wrapping).
    ///
    /// Useful with `admin: true` to gate sensitive-but-non-secret commands
    /// behind an approval step while still showing the real output.
    /// If `script` is set, runs `sh -c "<script>"` instead of the real binary.
    Approve {
        /// Optional shell script to run instead of the real binary.
        #[serde(default)]
        script: Option<String>,
    },
}

/// Sandbox profile applied when exec-ing the real binary for a passthrough command.
///
/// Default (when absent): no sandbox applied — existing behavior.
/// Operators opt in per command. Applied via `pre_exec` in `exec_passthrough`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CommandSandbox {
    /// Network policy for the exec'd command. Default: allow all (no restriction).
    #[serde(default)]
    pub network: NetworkConfig,
    /// Directories the command may read.
    #[serde(default)]
    pub fs_read: Vec<String>,
    /// Individual files the command may read.
    #[serde(default)]
    pub fs_read_file: Vec<String>,
    /// Directories the command may write.
    #[serde(default)]
    pub fs_write: Vec<String>,
    /// Individual files the command may write.
    #[serde(default)]
    pub fs_write_file: Vec<String>,
    /// Commands allowed to execute directly (real binary, not shim) inside this
    /// per-command sandbox. Their output stays within the sandbox.
    #[serde(default)]
    pub allow_commands: Vec<String>,
}

/// Simple network config for per-command sandbox profiles.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct NetworkConfig {
    /// If true, block all outbound network. Default: false (allow all).
    #[serde(default)]
    pub block: bool,
    /// If non-empty, start a per-command proxy restricting outbound
    /// connections to these hosts. Mutually exclusive with `block`.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

/// Audit event for command logging.
///
/// Used by both shim-originated fire-and-forget events (audit mode) and
/// server-side response logging (mediated mode).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// The command name (basename of argv[0]).
    pub command: String,
    /// Positional arguments passed to the command.
    pub args: Vec<String>,
    /// Unix timestamp (seconds since epoch).
    pub ts: u64,
    /// Process exit code. Always present.
    pub exit_code: i32,
    /// Which intercept action fired (respond/capture/approve/passthrough/admin_passthrough).
    /// Only set for mediated commands; absent for audit-mode commands.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_type: Option<String>,
}

/// Environment variable policy for the sandboxed child process.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct EnvPolicy {
    /// Env var names to strip from the child environment (credential leakage prevention).
    #[serde(default)]
    pub block: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_config_allowed_hosts_deserializes() {
        let json = r#"{
            "allowed_hosts": ["github.com", "*.github.com", "api.github.com"]
        }"#;
        let config: NetworkConfig = serde_json::from_str(json).expect("deserialize");
        assert!(!config.block);
        assert_eq!(
            config.allowed_hosts,
            vec!["github.com", "*.github.com", "api.github.com"]
        );
    }

    #[test]
    fn test_network_config_block_and_allowed_hosts_coexist() {
        let json = r#"{"block": true, "allowed_hosts": ["github.com"]}"#;
        let config: NetworkConfig = serde_json::from_str(json).expect("deserialize");
        assert!(config.block);
        assert_eq!(config.allowed_hosts, vec!["github.com"]);
    }

    #[test]
    fn test_network_config_default_has_empty_allowed_hosts() {
        let config = NetworkConfig::default();
        assert!(!config.block);
        assert!(config.allowed_hosts.is_empty());
    }

    #[test]
    fn test_command_sandbox_allow_commands_deserializes() {
        let json = r#"{
            "allow_commands": ["ddtool", "kubectl"],
            "network": { "block": true }
        }"#;
        let sb: CommandSandbox = serde_json::from_str(json).expect("deserialize");
        assert_eq!(sb.allow_commands, vec!["ddtool", "kubectl"]);
        assert!(sb.network.block);
    }

    #[test]
    fn test_command_sandbox_allow_commands_defaults_empty() {
        let json = r#"{ "network": { "block": false } }"#;
        let sb: CommandSandbox = serde_json::from_str(json).expect("deserialize");
        assert!(sb.allow_commands.is_empty());
    }

    #[test]
    fn test_command_sandbox_default_has_empty_allow_commands() {
        let sb = CommandSandbox::default();
        assert!(sb.allow_commands.is_empty());
    }

    #[test]
    fn test_command_sandbox_fs_file_fields_deserialize() {
        let json = r#"{
            "fs_read": ["~/.config/gh"],
            "fs_read_file": ["~/.gitconfig", "~/.vault-token"],
            "fs_write": ["~/.config/ddtool"],
            "fs_write_file": ["~/.vault-token"]
        }"#;
        let sb: CommandSandbox = serde_json::from_str(json).expect("deserialize");
        assert_eq!(sb.fs_read, vec!["~/.config/gh"]);
        assert_eq!(sb.fs_read_file, vec!["~/.gitconfig", "~/.vault-token"]);
        assert_eq!(sb.fs_write, vec!["~/.config/ddtool"]);
        assert_eq!(sb.fs_write_file, vec!["~/.vault-token"]);
    }

    #[test]
    fn test_command_sandbox_fs_file_fields_default_empty() {
        let json = r#"{ "fs_read": ["~/.ssh"] }"#;
        let sb: CommandSandbox = serde_json::from_str(json).expect("deserialize");
        assert_eq!(sb.fs_read, vec!["~/.ssh"]);
        assert!(sb.fs_read_file.is_empty());
        assert!(sb.fs_write.is_empty());
        assert!(sb.fs_write_file.is_empty());
    }
}
