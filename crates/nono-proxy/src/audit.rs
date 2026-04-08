//! Audit logging for proxy requests.
//!
//! Logs all proxy requests with structured fields via `tracing`.
//! Sensitive data (authorization headers, tokens, request bodies)
//! is never included in audit logs.
//!
//! When a [`NetworkAuditConfig`] is provided at startup, every event is also
//! appended as a JSON line to `network.jsonl` with write-time deduplication.
//! Consecutive events matching the same `(target, port, mode, decision)` key
//! within a 30-second window are collapsed into a single line with a `count`
//! field. The in-memory buffer is unaffected by dedup.

use nono::undo::{NetworkAuditDecision, NetworkAuditEvent, NetworkAuditMode};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// Maximum number of in-memory network audit events kept per proxy session.
const MAX_AUDIT_EVENTS: usize = 4096;

/// Deduplication window: events with the same key within this period are collapsed.
const DEDUP_WINDOW_MS: u64 = 30_000;

/// Maximum size of `network.jsonl` before rotation (10 MiB).
const MAX_LOG_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Number of rotated log files to keep (network.1.jsonl through network.3.jsonl).
const MAX_ROTATED_FILES: u32 = 3;

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

/// Key for deduplicating consecutive network events in the JSONL output.
#[derive(PartialEq, Eq)]
struct DeduplicationKey {
    target: String,
    port: Option<u16>,
    mode: NetworkAuditMode,
    decision: NetworkAuditDecision,
}

impl DeduplicationKey {
    fn from_event(event: &NetworkAuditEvent) -> Self {
        Self {
            target: event.target.clone(),
            port: event.port,
            mode: event.mode.clone(),
            decision: event.decision.clone(),
        }
    }
}

/// A pending (not yet flushed) deduplicated event.
struct PendingEvent {
    key: DeduplicationKey,
    /// The first event in this dedup window (used for serialization).
    first_event: NetworkAuditEvent,
    /// Timestamp of the most recent occurrence in this window.
    last_seen_ts: u64,
    /// Number of events collapsed into this entry.
    count: u64,
}

/// File-writing state: config plus dedup tracking. Protected by its own mutex
/// so file I/O doesn't block the in-memory event buffer.
struct FileAuditState {
    config: NetworkAuditConfig,
    pending: Option<PendingEvent>,
}

impl FileAuditState {
    /// Process an incoming event: either merge into the pending entry or flush
    /// the pending entry and start a new one.
    fn push(&mut self, event: &NetworkAuditEvent) {
        let new_key = DeduplicationKey::from_event(event);

        if let Some(ref mut pending) = self.pending {
            let window_expired =
                event.timestamp_unix_ms.saturating_sub(pending.first_event.timestamp_unix_ms)
                    > DEDUP_WINDOW_MS;

            if !window_expired && pending.key == new_key {
                pending.count += 1;
                pending.last_seen_ts = event.timestamp_unix_ms;
                return;
            }

            // Flush the old pending entry before starting a new one.
            self.flush_pending();
        }

        self.pending = Some(PendingEvent {
            key: new_key,
            last_seen_ts: event.timestamp_unix_ms,
            first_event: event.clone(),
            count: 1,
        });
    }

    /// Flush the current pending entry to disk (if any), then rotate if over size limit.
    fn flush_pending(&mut self) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        append_network_audit_log(&self.config, &pending);
        maybe_rotate_log(&self.config.log_path);
    }
}

/// Shared audit log: in-memory buffer plus optional real-time file output.
pub struct AuditLog {
    events: Mutex<Vec<NetworkAuditEvent>>,
    file_state: Option<Mutex<FileAuditState>>,
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
    let file_state = file_config.map(|config| {
        Mutex::new(FileAuditState {
            config,
            pending: None,
        })
    });
    Arc::new(AuditLog {
        events: Mutex::new(Vec::new()),
        file_state,
    })
}

/// Drain all network audit events collected so far.
///
/// Flushes any pending deduplicated file entry before draining, so the
/// last collapsed event is written to `network.jsonl`.
#[must_use]
pub fn drain_audit_events(audit_log: &SharedAuditLog) -> Vec<NetworkAuditEvent> {
    // Flush pending file entry first.
    if let Some(ref file_state) = audit_log.file_state {
        if let Ok(mut state) = file_state.lock() {
            state.flush_pending();
        }
    }

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

/// JSON wrapper that flattens `NetworkAuditEvent` with session context and dedup count.
#[derive(serde::Serialize)]
struct NetworkAuditLine<'a> {
    #[serde(flatten)]
    event: &'a NetworkAuditEvent,
    count: u64,
    /// Timestamp of the last event in a collapsed group. Only meaningful when count > 1.
    #[serde(skip_serializing_if = "Option::is_none")]
    last_seen_unix_ms: Option<u64>,
    session_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_name: Option<&'a str>,
    nono_pid: u32,
}

/// Append a deduplicated network audit entry as a JSON line to `network.jsonl`.
fn append_network_audit_log(config: &NetworkAuditConfig, pending: &PendingEvent) {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let last_seen = if pending.count > 1 {
        Some(pending.last_seen_ts)
    } else {
        None
    };

    let line = NetworkAuditLine {
        event: &pending.first_event,
        count: pending.count,
        last_seen_unix_ms: last_seen,
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

/// Rotate `network.jsonl` if it exceeds `MAX_LOG_FILE_SIZE`.
///
/// Rotation scheme (best-effort, errors silently ignored):
///   network.jsonl → network.1.jsonl
///   network.1.jsonl → network.2.jsonl
///   network.2.jsonl → network.3.jsonl
///   network.3.jsonl → deleted
fn maybe_rotate_log(log_path: &std::path::Path) {
    let size = match std::fs::metadata(log_path) {
        Ok(m) => m.len(),
        Err(_) => return,
    };

    if size < MAX_LOG_FILE_SIZE {
        return;
    }

    let parent = match log_path.parent() {
        Some(p) => p,
        None => return,
    };
    let stem = "network";
    let ext = "jsonl";

    // Shift existing rotated files: N → N+1, deleting the oldest.
    for i in (1..MAX_ROTATED_FILES).rev() {
        let from = parent.join(format!("{}.{}.{}", stem, i, ext));
        let to = parent.join(format!("{}.{}.{}", stem, i + 1, ext));
        if from.exists() {
            let _ = std::fs::rename(&from, &to);
        }
    }

    // Rotate the current log to .1
    let rotated = parent.join(format!("{}.1.{}", stem, ext));
    let _ = std::fs::rename(log_path, &rotated);
}

fn push_event(audit_log: Option<&SharedAuditLog>, event: NetworkAuditEvent) {
    let Some(audit_log) = audit_log else {
        return;
    };

    // Deduplicated file logging (best-effort, errors silently ignored)
    if let Some(ref file_state) = audit_log.file_state {
        if let Ok(mut state) = file_state.lock() {
            state.push(&event);
        }
    }

    // In-memory buffer (existing behavior, unchanged — no dedup)
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

    fn temp_audit_dir() -> (std::path::PathBuf, std::path::PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "nono-audit-test-{}-{}-{}",
            std::process::id(),
            now_unix_millis(),
            id,
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("network.jsonl");
        (dir, log_path)
    }

    fn make_config(log_path: PathBuf) -> NetworkAuditConfig {
        NetworkAuditConfig {
            log_path,
            session_id: "test-session-123".to_string(),
            session_name: Some("my-session".to_string()),
            nono_pid: 42,
        }
    }

    fn read_jsonl_lines(log_path: &std::path::Path) -> Vec<serde_json::Value> {
        let contents = std::fs::read_to_string(log_path).unwrap_or_default();
        contents
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn dedup_collapses_identical_events() {
        let (dir, log_path) = temp_audit_dir();
        let log = new_audit_log(Some(make_config(log_path.clone())));

        // Push 5 identical events (same target/port/mode/decision)
        for _ in 0..5 {
            log_allowed(Some(&log), ProxyMode::Connect, "github.com", 443, "CONNECT");
        }

        // Nothing flushed yet — all within the same dedup window
        let lines = read_jsonl_lines(&log_path);
        assert_eq!(lines.len(), 0, "should not flush while events match");

        // Drain triggers flush
        let events = drain_audit_events(&log);
        assert_eq!(events.len(), 5, "in-memory buffer should have all 5 events");

        let lines = read_jsonl_lines(&log_path);
        assert_eq!(lines.len(), 1, "file should have exactly 1 collapsed line");
        assert_eq!(lines[0]["count"], 5);
        assert_eq!(lines[0]["target"], "github.com");
        assert_eq!(lines[0]["session_id"], "test-session-123");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dedup_flushes_on_different_key() {
        let (dir, log_path) = temp_audit_dir();
        let log = new_audit_log(Some(make_config(log_path.clone())));

        log_allowed(Some(&log), ProxyMode::Connect, "github.com", 443, "CONNECT");
        log_allowed(Some(&log), ProxyMode::Connect, "github.com", 443, "CONNECT");

        // Different target — flushes the pending github.com entry
        log_allowed(Some(&log), ProxyMode::Connect, "api.openai.com", 443, "CONNECT");

        let lines = read_jsonl_lines(&log_path);
        assert_eq!(lines.len(), 1, "first group should be flushed");
        assert_eq!(lines[0]["count"], 2);
        assert_eq!(lines[0]["target"], "github.com");

        // Drain flushes the second pending entry
        let _ = drain_audit_events(&log);

        let lines = read_jsonl_lines(&log_path);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1]["count"], 1);
        assert_eq!(lines[1]["target"], "api.openai.com");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dedup_flushes_on_window_expiry() {
        let (dir, log_path) = temp_audit_dir();
        let config = make_config(log_path.clone());
        let log = new_audit_log(Some(config));

        // Manually push events with controlled timestamps to simulate window expiry.
        // We go through push_event indirectly by manipulating the file_state directly.
        {
            let state_mutex = log.file_state.as_ref().unwrap();
            let mut state = state_mutex.lock().unwrap();

            let base_ts = 1_000_000_000_000u64;
            let event1 = NetworkAuditEvent {
                timestamp_unix_ms: base_ts,
                mode: NetworkAuditMode::Connect,
                decision: NetworkAuditDecision::Allow,
                target: "github.com".to_string(),
                port: Some(443),
                method: Some("CONNECT".to_string()),
                path: None,
                status: None,
                reason: None,
            };

            let event2 = NetworkAuditEvent {
                timestamp_unix_ms: base_ts + 10_000, // +10s, within window
                ..event1.clone()
            };

            let event3 = NetworkAuditEvent {
                timestamp_unix_ms: base_ts + 31_000, // +31s, outside window
                ..event1.clone()
            };

            state.push(&event1);
            state.push(&event2);

            // No flush yet
            let lines = read_jsonl_lines(&log_path);
            assert_eq!(lines.len(), 0);

            // event3 is past the window — flushes the first group
            state.push(&event3);

            let lines = read_jsonl_lines(&log_path);
            assert_eq!(lines.len(), 1);
            assert_eq!(lines[0]["count"], 2);

            // Flush remaining
            state.flush_pending();
        }

        let lines = read_jsonl_lines(&log_path);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1]["count"], 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn single_event_has_count_one_and_no_last_seen() {
        let (dir, log_path) = temp_audit_dir();
        let log = new_audit_log(Some(make_config(log_path.clone())));

        log_allowed(Some(&log), ProxyMode::Connect, "github.com", 443, "CONNECT");
        let _ = drain_audit_events(&log);

        let lines = read_jsonl_lines(&log_path);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["count"], 1);
        assert!(lines[0].get("last_seen_unix_ms").is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn collapsed_event_includes_last_seen() {
        let (dir, log_path) = temp_audit_dir();
        let log = new_audit_log(Some(make_config(log_path.clone())));

        log_allowed(Some(&log), ProxyMode::Connect, "github.com", 443, "CONNECT");
        log_allowed(Some(&log), ProxyMode::Connect, "github.com", 443, "CONNECT");
        let _ = drain_audit_events(&log);

        let lines = read_jsonl_lines(&log_path);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["count"], 2);
        assert!(lines[0].get("last_seen_unix_ms").is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn push_event_no_file_without_config() {
        let log = new_audit_log(None);
        log_allowed(Some(&log), ProxyMode::Connect, "example.com", 443, "CONNECT");
        let events = drain_audit_events(&log);
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn rotation_triggers_when_file_exceeds_max_size() {
        let (dir, log_path) = temp_audit_dir();

        // Write a file larger than MAX_LOG_FILE_SIZE
        let large_content = "x".repeat((MAX_LOG_FILE_SIZE as usize) + 1);
        std::fs::write(&log_path, &large_content).unwrap();
        assert!(log_path.exists());

        maybe_rotate_log(&log_path);

        // Original should be gone, rotated to .1
        assert!(!log_path.exists(), "original file should be renamed");
        let rotated = dir.join("network.1.jsonl");
        assert!(rotated.exists(), "rotated file should exist");
        assert_eq!(
            std::fs::read_to_string(&rotated).unwrap().len(),
            large_content.len()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_does_not_trigger_under_size_limit() {
        let (dir, log_path) = temp_audit_dir();

        std::fs::write(&log_path, "small content").unwrap();
        maybe_rotate_log(&log_path);

        assert!(log_path.exists(), "file should not be rotated");
        assert!(
            !dir.join("network.1.jsonl").exists(),
            "no rotated file should exist"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_shifts_existing_rotated_files() {
        let (dir, log_path) = temp_audit_dir();

        // Create existing rotated files
        std::fs::write(dir.join("network.1.jsonl"), "old-1").unwrap();
        std::fs::write(dir.join("network.2.jsonl"), "old-2").unwrap();

        // Write oversized current log
        let large_content = "x".repeat((MAX_LOG_FILE_SIZE as usize) + 1);
        std::fs::write(&log_path, &large_content).unwrap();

        maybe_rotate_log(&log_path);

        // network.jsonl → network.1.jsonl (new)
        // network.1.jsonl → network.2.jsonl (was "old-1")
        // network.2.jsonl → network.3.jsonl (was "old-2")
        assert!(!log_path.exists());
        assert_eq!(
            std::fs::read_to_string(dir.join("network.1.jsonl")).unwrap().len(),
            large_content.len()
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("network.2.jsonl")).unwrap(),
            "old-1"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("network.3.jsonl")).unwrap(),
            "old-2"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_deletes_oldest_when_full() {
        let (dir, log_path) = temp_audit_dir();

        // Fill all rotation slots
        std::fs::write(dir.join("network.1.jsonl"), "old-1").unwrap();
        std::fs::write(dir.join("network.2.jsonl"), "old-2").unwrap();
        std::fs::write(dir.join("network.3.jsonl"), "old-3").unwrap();

        let large_content = "x".repeat((MAX_LOG_FILE_SIZE as usize) + 1);
        std::fs::write(&log_path, &large_content).unwrap();

        maybe_rotate_log(&log_path);

        // old-3 is overwritten by old-2 shifting into slot 3
        assert_eq!(
            std::fs::read_to_string(dir.join("network.3.jsonl")).unwrap(),
            "old-2"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("network.2.jsonl")).unwrap(),
            "old-1"
        );
        // Slot 1 now has the current log
        assert_eq!(
            std::fs::read_to_string(dir.join("network.1.jsonl")).unwrap().len(),
            large_content.len()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
