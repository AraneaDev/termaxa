use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unix epoch milliseconds.
    pub ts_ms: u128,
    /// Human-readable UTC timestamp.
    pub ts: String,
    /// "hook" (agent-invoked) or "run" (CLI-invoked) or "check".
    pub source: String,
    pub command: String,
    /// allow | ask | deny
    pub decision: String,
    pub matched_rule: Option<String>,
    pub reason: String,
    /// Signals the context engine observed.
    pub signals: Vec<String>,
    /// Whether context escalated the base decision.
    pub escalated: bool,
    /// Agent session that caused this entry (from Claude Code hook events).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// Backup taken before execution, if any (see `termaxa backups`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<String>,
    /// Preview summary at decision time (e.g. "DELETE ALL from sessions
    /// ~120,000 rows") — persisted so reports can aggregate impact as fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
    /// Destructive-intent classification (v0.11+): file-delete | db-destroy
    /// | git-destructive | infra-destroy. Serde-defaulted so pre-v0.11 log
    /// lines parse as None (decision #7: backward-compatible audit schema).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    /// For "run": did the human approve an `ask`? For hook mode this is None
    /// (the agent harness owns the approval UI).
    pub approved: Option<bool>,
    /// For "run": process exit code if the command executed.
    pub exit_code: Option<i32>,
    pub cwd: String,
}

pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    /// Log lives at `<termaxa_dir>/logs/audit.jsonl`.
    pub fn new(termaxa_dir: &Path) -> Result<Self> {
        let dir = termaxa_dir.join("logs");
        fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
        Ok(Self {
            path: dir.join("audit.jsonl"),
        })
    }

    pub fn append(&self, entry: &AuditEntry) -> Result<()> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("cannot open {}", self.path.display()))?;
        let line = serde_json::to_string(entry)?;
        writeln!(f, "{}", line)?;
        Ok(())
    }

    pub fn read_last(&self, n: usize) -> Result<Vec<AuditEntry>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let raw = fs::read_to_string(&self.path)?;
        let mut entries: Vec<AuditEntry> = raw
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        let len = entries.len();
        if len > n {
            entries.drain(0..len - n);
        }
        Ok(entries)
    }
}

pub fn now() -> (u128, String) {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    (
        ms,
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testutil::TempTree;

    fn entry(command: &str) -> AuditEntry {
        let (ts_ms, ts) = now();
        AuditEntry {
            ts_ms,
            ts,
            source: "test".into(),
            command: command.into(),
            decision: "allow".into(),
            matched_rule: None,
            reason: "because".into(),
            signals: Vec::new(),
            escalated: false,
            session: None,
            backup: None,
            preview: None,
            intent: None,
            approved: None,
            exit_code: None,
            cwd: "/work".into(),
        }
    }

    fn log_in(tmp: &TempTree) -> AuditLog {
        AuditLog::new(&tmp.dir("state")).expect("the log directory must be creatable")
    }

    #[test]
    fn new_puts_the_log_under_the_state_dir_and_creates_it() {
        let tmp = TempTree::new("audit-new");
        let state = tmp.dir("state");
        let log = AuditLog::new(&state).expect("the log directory must be creatable");

        assert_eq!(log.path, state.join("logs").join("audit.jsonl"));
        assert!(
            state.join("logs").is_dir(),
            "the directory is created up front so appends never fail on a missing parent"
        );
    }

    #[test]
    fn read_last_on_a_log_that_was_never_written_is_empty() {
        let tmp = TempTree::new("audit-missing");
        let log = log_in(&tmp);

        let entries = log
            .read_last(10)
            .expect("no log yet is a fresh project, not a failure");
        assert!(entries.is_empty());
    }

    #[test]
    fn read_last_returns_exactly_the_tail_in_order() {
        let tmp = TempTree::new("audit-tail");
        let log = log_in(&tmp);
        for command in ["one", "two", "three", "four", "five"] {
            log.append(&entry(command)).expect("append must succeed");
        }

        let tail = log.read_last(2).expect("read must succeed");
        let commands: Vec<&str> = tail.iter().map(|e| e.command.as_str()).collect();
        // Exactly two, oldest first: reports read the tail as a timeline.
        assert_eq!(commands, ["four", "five"]);
    }

    #[test]
    fn read_last_asking_for_more_than_exists_returns_everything() {
        let tmp = TempTree::new("audit-short");
        let log = log_in(&tmp);
        for command in ["one", "two", "three"] {
            log.append(&entry(command)).expect("append must succeed");
        }

        // The boundary: asking for exactly the number held, and for more.
        let all = log.read_last(3).expect("read must succeed");
        assert_eq!(
            all.iter().map(|e| e.command.as_str()).collect::<Vec<_>>(),
            ["one", "two", "three"]
        );
        let more = log.read_last(99).expect("read must succeed");
        assert_eq!(more.len(), 3, "asking for more cannot invent entries");
    }

    #[test]
    fn read_last_skips_a_line_it_cannot_parse() {
        let tmp = TempTree::new("audit-corrupt");
        let log = log_in(&tmp);
        log.append(&entry("first")).expect("append must succeed");
        // A truncated write (a killed process mid-append) must not make the
        // whole history unreadable.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&log.path)
            .expect("log must be open-able");
        writeln!(f, "{{\"ts_ms\": 1, oh no").expect("write must succeed");
        drop(f);
        log.append(&entry("second")).expect("append must succeed");

        let entries = log.read_last(10).expect("read must succeed");
        assert_eq!(
            entries
                .iter()
                .map(|e| e.command.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
    }

    #[test]
    fn now_reports_the_same_instant_in_both_forms() {
        let (ms, ts) = now();

        // A stubbed clock (0, or 1) would sit in 1970.
        assert!(
            ms > 1_735_689_600_000,
            "epoch milliseconds should be recent, got {}",
            ms
        );
        let parsed = chrono::DateTime::parse_from_rfc3339(&ts)
            .unwrap_or_else(|e| panic!("`{}` must be RFC3339 UTC: {}", ts, e));
        let skew = (ms as i64 - parsed.timestamp_millis()).abs();
        assert!(
            skew < 2_000,
            "the two halves must describe one instant, {} ms apart",
            skew
        );
    }
}
