//! Audit logging for proxy requests.
//!
//! Logs all proxy requests with structured fields via `tracing`.
//! Sensitive data (authorization headers, tokens, request bodies)
//! is never included in audit logs.
//!
//! When a [`NetworkAuditConfig`] is provided at startup, every event is also
//! appended as a JSON line to `network.jsonl` in real-time, alongside the
//! in-memory buffer used for rollback metadata.

use nono::undo::{NetworkAuditDecision, NetworkAuditEvent, NetworkAuditMode};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// Maximum number of in-memory network audit events kept per proxy session.
const MAX_AUDIT_EVENTS: usize = 4096;

/// Configuration for writing network audit events to a JSONL file.
#[derive(Debug, Clone)]
pub struct NetworkAuditConfig {
    /// Path to the JSONL log file (e.g. `~/.nono/sessions/network.jsonl`).
    pub log_path: PathBuf,
    /// Session ID from the nono session registry.
    pub session_id: String,
    /// Human-readable session name.
    pub session_name: Option<String>,
    /// PID of the nono process (the unsandboxed supervisor).
    pub nono_pid: u32,
}

/// Shared audit log: in-memory buffer plus optional real-time file output.
pub struct AuditLog {
    events: Mutex<Vec<NetworkAuditEvent>>,
    file_config: Option<NetworkAuditConfig>,
}

/// Shared reference to the audit log, threaded through the proxy.
pub type SharedAuditLog = Arc<AuditLog>;

/// Proxy mode for audit logging.
#[derive(Debug, Clone, Copy)]
pub enum ProxyMode {
    /// CONNECT tunnel (host filtering only)
    Connect,
    /// Reverse proxy (credential injection)
    Reverse,
    /// External proxy passthrough (enterprise)
    External,
}

impl std::fmt::Display for ProxyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyMode::Connect => write!(f, "connect"),
            ProxyMode::Reverse => write!(f, "reverse"),
            ProxyMode::External => write!(f, "external"),
        }
    }
}

/// Create a shared audit log with optional file output.
#[must_use]
pub fn new_audit_log(file_config: Option<NetworkAuditConfig>) -> SharedAuditLog {
    Arc::new(AuditLog {
        events: Mutex::new(Vec::new()),
        file_config,
    })
}

/// Drain all network audit events collected so far.
#[must_use]
pub fn drain_audit_events(audit_log: &SharedAuditLog) -> Vec<NetworkAuditEvent> {
    match audit_log.events.lock() {
        Ok(mut events) => events.drain(..).collect(),
        Err(e) => {
            warn!(
                "Network audit log mutex poisoned while draining events: {}",
                e
            );
            Vec::new()
        }
    }
}

fn now_unix_millis() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let millis = duration.as_millis();
            if millis > u128::from(u64::MAX) {
                warn!("System clock millis exceeded u64::MAX; clamping audit timestamp");
                u64::MAX
            } else {
                millis as u64
            }
        }
        Err(e) => {
            warn!(
                "System clock before UNIX_EPOCH while generating audit timestamp: {}",
                e
            );
            0
        }
    }
}

fn map_mode(mode: ProxyMode) -> NetworkAuditMode {
    match mode {
        ProxyMode::Connect => NetworkAuditMode::Connect,
        ProxyMode::Reverse => NetworkAuditMode::Reverse,
        ProxyMode::External => NetworkAuditMode::External,
    }
}

/// JSON wrapper that flattens `NetworkAuditEvent` with session context fields.
#[derive(serde::Serialize)]
struct NetworkAuditLine<'a> {
    #[serde(flatten)]
    event: &'a NetworkAuditEvent,
    session_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_name: Option<&'a str>,
    nono_pid: u32,
}

/// Append a single network audit event as a JSON line to `network.jsonl`.
fn append_network_audit_log(config: &NetworkAuditConfig, event: &NetworkAuditEvent) {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let line = NetworkAuditLine {
        event,
        session_id: &config.session_id,
        session_name: config.session_name.as_deref(),
        nono_pid: config.nono_pid,
    };

    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    opts.mode(0o600);

    if let Ok(mut f) = opts.open(&config.log_path) {
        if let Ok(json) = serde_json::to_string(&line) {
            let _ = writeln!(f, "{}", json);
        }
    }
}

fn push_event(audit_log: Option<&SharedAuditLog>, event: NetworkAuditEvent) {
    let Some(audit_log) = audit_log else {
        return;
    };

    // Real-time file logging (best-effort, errors silently ignored)
    if let Some(ref config) = audit_log.file_config {
        append_network_audit_log(config, &event);
    }

    // In-memory buffer (existing behavior, unchanged)
    match audit_log.events.lock() {
        Ok(mut events) => {
            if events.len() < MAX_AUDIT_EVENTS {
                events.push(event);
            } else {
                warn!(
                    "Network audit buffer full ({} events); dropping event",
                    MAX_AUDIT_EVENTS
                );
            }
        }
        Err(e) => {
            warn!(
                "Network audit log mutex poisoned while recording event: {}",
                e
            );
        }
    }
}

/// Log an allowed proxy request.
pub fn log_allowed(
    audit_log: Option<&SharedAuditLog>,
    mode: ProxyMode,
    host: &str,
    port: u16,
    method: &str,
) {
    info!(
        target: "nono_proxy::audit",
        mode = %mode,
        host = host,
        port = port,
        method = method,
        decision = "allow",
        "proxy request allowed"
    );

    push_event(
        audit_log,
        NetworkAuditEvent {
            timestamp_unix_ms: now_unix_millis(),
            mode: map_mode(mode),
            decision: NetworkAuditDecision::Allow,
            target: host.to_string(),
            port: Some(port),
            method: Some(method.to_string()),
            path: None,
            status: None,
            reason: None,
        },
    );
}

/// Log a denied proxy request.
pub fn log_denied(
    audit_log: Option<&SharedAuditLog>,
    mode: ProxyMode,
    host: &str,
    port: u16,
    reason: &str,
) {
    info!(
        target: "nono_proxy::audit",
        mode = %mode,
        host = host,
        port = port,
        decision = "deny",
        reason = reason,
        "proxy request denied"
    );

    push_event(
        audit_log,
        NetworkAuditEvent {
            timestamp_unix_ms: now_unix_millis(),
            mode: map_mode(mode),
            decision: NetworkAuditDecision::Deny,
            target: host.to_string(),
            port: Some(port),
            method: None,
            path: None,
            status: None,
            reason: Some(reason.to_string()),
        },
    );
}

/// Log a reverse proxy request with service info.
pub fn log_reverse_proxy(
    audit_log: Option<&SharedAuditLog>,
    service: &str,
    method: &str,
    path: &str,
    status: u16,
) {
    info!(
        target: "nono_proxy::audit",
        mode = "reverse",
        service = service,
        method = method,
        path = path,
        status = status,
        "reverse proxy response"
    );

    push_event(
        audit_log,
        NetworkAuditEvent {
            timestamp_unix_ms: now_unix_millis(),
            mode: NetworkAuditMode::Reverse,
            decision: NetworkAuditDecision::Allow,
            target: service.to_string(),
            port: None,
            method: Some(method.to_string()),
            path: Some(path.to_string()),
            status: Some(status),
            reason: None,
        },
    );
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn log_allowed_records_event() {
        let log = new_audit_log(None);

        log_allowed(
            Some(&log),
            ProxyMode::Connect,
            "api.openai.com",
            443,
            "CONNECT",
        );

        let events = drain_audit_events(&log);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.mode, NetworkAuditMode::Connect);
        assert_eq!(event.decision, NetworkAuditDecision::Allow);
        assert_eq!(event.target, "api.openai.com");
        assert_eq!(event.port, Some(443));
        assert_eq!(event.method.as_deref(), Some("CONNECT"));
        assert!(event.timestamp_unix_ms > 0);
    }

    #[test]
    fn log_denied_records_reason() {
        let log = new_audit_log(None);

        log_denied(
            Some(&log),
            ProxyMode::External,
            "169.254.169.254",
            80,
            "blocked by metadata deny list",
        );

        let events = drain_audit_events(&log);
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.mode, NetworkAuditMode::External);
        assert_eq!(event.decision, NetworkAuditDecision::Deny);
        assert_eq!(
            event.reason.as_deref(),
            Some("blocked by metadata deny list")
        );
    }

    #[test]
    fn push_event_writes_jsonl_when_configured() {
        let dir = std::env::temp_dir().join(format!("nono-audit-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("network.jsonl");

        let config = NetworkAuditConfig {
            log_path: log_path.clone(),
            session_id: "test-session-123".to_string(),
            session_name: Some("my-session".to_string()),
            nono_pid: 42,
        };
        let log = new_audit_log(Some(config));

        log_allowed(Some(&log), ProxyMode::Connect, "github.com", 443, "CONNECT");

        // Verify in-memory
        let events = drain_audit_events(&log);
        assert_eq!(events.len(), 1);

        // Verify file output
        let contents = std::fs::read_to_string(&log_path).unwrap();
        let line: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(line["session_id"], "test-session-123");
        assert_eq!(line["session_name"], "my-session");
        assert_eq!(line["nono_pid"], 42);
        assert_eq!(line["target"], "github.com");
        assert_eq!(line["decision"], "allow");

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn push_event_no_file_without_config() {
        let log = new_audit_log(None);
        log_allowed(Some(&log), ProxyMode::Connect, "example.com", 443, "CONNECT");
        let events = drain_audit_events(&log);
        assert_eq!(events.len(), 1);
    }
}
