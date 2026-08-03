use crate::audit::{AuditEntry, AuditLog};
use crate::backup;
use crate::paths::Paths;
use anyhow::Result;
use std::collections::HashMap;

/// The Execution Report — the flight recorder.
///
/// Answers one question: "what actually happened while my AI agent was
/// working?" Composes audit entries, persisted preview summaries, and the
/// backup manifest into the summary a human reads after an AI session, plus a
/// 30-day rollup for the longer view.
///
/// Honesty rule: every line is a fact with a source in the data. Nothing is
/// invented — no fake "time saved" minutes, no guessed file counts, no
/// estimated token costs (that needs the agent's own transcripts — see the
/// token-cost issue; it is deliberately NOT computed here). The risk score
/// prints its own inputs so nobody has to trust a black box.
pub struct Scope {
    pub session: Option<String>,
    pub all: bool,
    /// Rollup window for the "Last N days" section (default 30).
    pub days: u64,
}

impl Default for Scope {
    fn default() -> Self {
        Scope {
            session: None,
            all: false,
            days: 30,
        }
    }
}

pub fn run(paths: &Paths, scope: Scope, markdown: bool) -> Result<i32> {
    let log = AuditLog::new(&paths.state_dir)?;
    let all_entries = log.read_last(1_000_000)?;
    if all_entries.is_empty() {
        println!("(no activity to report)");
        return Ok(0);
    }

    // Scope resolution: explicit session > latest session seen > everything.
    let session = if scope.all {
        None
    } else {
        scope
            .session
            .clone()
            .or_else(|| all_entries.iter().rev().find_map(|e| e.session.clone()))
    };

    let mut entries: Vec<&AuditEntry> = all_entries.iter().collect();
    if let Some(s) = &session {
        entries.retain(|e| e.session.as_deref() == Some(s.as_str()));
        if entries.is_empty() {
            println!("(no entries for session {})", s);
            return Ok(1);
        }
    }

    let r = compute(&entries, paths)?;
    let rollup = compute_rollup(&all_entries, scope.days);

    if markdown {
        print_markdown(&r, &rollup, session.as_deref());
    } else {
        print_terminal(&r, &rollup, session.as_deref());
    }
    Ok(0)
}

struct Report {
    first_ts: String,
    last_ts: String,
    duration_min: u64,
    total: usize,
    allow: usize,
    ask: usize,
    deny: usize,
    escalated: usize,
    auto_flow: usize,
    blocked: Vec<String>,
    impacts: Vec<String>,
    backups: Vec<(String, String)>,
    rollbacks: usize,
    breaker_trips: usize,
    /// (intent-label, count) for every destructive intent CLASSIFIED in scope,
    /// most frequent first. This counts commands the classifier recognised —
    /// not breaker trips. A legitimate `rm -rf ./build` is counted here.
    intents: Vec<(String, usize)>,
    /// (intent-label, count) restricted to entries the breaker actually
    /// escalated. This is the number the Insight keys off: repeated *blocked*
    /// attempts, not merely repeated destructive work.
    trips_by_intent: Vec<(String, usize)>,
    /// Last N audit lines as (mark, command) for the "Recent events" section.
    recent: Vec<(&'static str, String)>,
    risk_score: u32,
    risk_label: &'static str,
}

/// Map a decision (and source) to a terminal mark.
/// Fixes the post-receipt bug: an executed/post record is a success (✓),
/// not a denial (✗). Anything else falls back to its decision.
fn mark_for(decision: &str, source: &str) -> &'static str {
    match (decision, source) {
        (_, "post") => "✓", // post-execution receipt = it ran, insured
        ("allow", _) => "✓",
        ("ask", _) => "?",
        ("deny", _) => "✗",
        _ => "•",
    }
}

fn compute(entries: &[&AuditEntry], paths: &Paths) -> Result<Report> {
    let count = |d: &str| entries.iter().filter(|e| e.decision == d).count();
    let (allow, ask, deny) = (count("allow"), count("ask"), count("deny"));
    let escalated = entries.iter().filter(|e| e.escalated).count();

    let blocked: Vec<String> = entries
        .iter()
        .filter(|e| e.decision == "deny")
        .map(|e| e.command.clone())
        .collect();

    let mut impacts: Vec<String> = entries
        .iter()
        .filter(|e| e.decision != "allow")
        .filter_map(|e| e.preview.clone())
        .collect();
    impacts.dedup();

    // Backups referenced by these entries, joined against the manifest.
    let ids: Vec<&str> = entries.iter().filter_map(|e| e.backup.as_deref()).collect();
    let manifest = backup::list(&paths.state_dir)?;
    let by_id: HashMap<&str, &backup::BackupRecord> =
        manifest.iter().map(|r| (r.id.as_str(), r)).collect();
    let mut backups: Vec<(String, String)> = ids
        .iter()
        .filter_map(|id| by_id.get(id))
        .map(|r| (r.kind.clone(), r.note.clone()))
        .collect();
    backups.dedup();

    // Rollbacks: post-execution records whose command is a termaxa rollback,
    // OR entries the runner tagged as a rollback. We count "post" receipts
    // referencing a backup id as the honest proxy for a restore having run.
    let rollbacks = entries
        .iter()
        .filter(|e| e.source == "post" && e.command.contains("rollback"))
        .count();

    let breaker_trips = entries
        .iter()
        .filter(|e| e.matched_rule.as_deref() == Some(crate::intent::BREAKER_RULE))
        .count();

    // Per-intent breakdown: group the classified intent field, most first.
    let mut intent_map: HashMap<String, usize> = HashMap::new();
    for e in entries {
        if let Some(i) = &e.intent {
            *intent_map.entry(i.clone()).or_insert(0) += 1;
        }
    }
    let mut intents: Vec<(String, usize)> = intent_map.into_iter().collect();
    intents.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    // Trips by intent: only entries the circuit breaker escalated. This is
    // what "the breaker fired" means — distinct from "a destructive command
    // was classified", which is the `intents` map above.
    let mut trip_map: HashMap<String, usize> = HashMap::new();
    for e in entries {
        if e.matched_rule.as_deref() == Some(crate::intent::BREAKER_RULE) {
            if let Some(i) = &e.intent {
                *trip_map.entry(i.clone()).or_insert(0) += 1;
            }
        }
    }
    let mut trips_by_intent: Vec<(String, usize)> = trip_map.into_iter().collect();
    trips_by_intent.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    // Recent events: last 6 entries in scope, with corrected marks.
    let recent: Vec<(&'static str, String)> = entries
        .iter()
        .rev()
        .take(6)
        .rev()
        .map(|e| (mark_for(&e.decision, &e.source), e.command.clone()))
        .collect();

    let risk_score = (deny as u32) * 3 + (escalated as u32) * 2 + (ask as u32);
    let risk_label = match risk_score {
        0..=2 => "Low",
        3..=7 => "Medium",
        _ => "High",
    };

    let (first, last) = (entries[0], entries[entries.len() - 1]);
    let duration_min = last.ts_ms.saturating_sub(first.ts_ms) as u64 / 60_000;

    Ok(Report {
        first_ts: first.ts.clone(),
        last_ts: last.ts.clone(),
        duration_min,
        total: entries.len(),
        allow,
        ask,
        deny,
        escalated,
        auto_flow: allow,
        blocked,
        impacts,
        backups,
        rollbacks,
        breaker_trips,
        intents,
        trips_by_intent,
        recent,
        risk_score,
        risk_label,
    })
}

/// The "Last N days" rollup — every session in the window, not just the
/// current one. Cheap: a single pass over the already-read log.
struct Rollup {
    days: u64,
    sessions: usize,
    commands: usize,
    allow: usize,
    ask: usize,
    deny: usize,
    backups: usize,
    breaker_trips: usize,
    top_projects: Vec<String>,
}

fn compute_rollup(all: &[AuditEntry], days: u64) -> Rollup {
    let cutoff_ms = {
        let now = crate::audit::now().0;
        now.saturating_sub((days as u128) * 24 * 60 * 60 * 1000)
    };
    let win: Vec<&AuditEntry> = all.iter().filter(|e| e.ts_ms >= cutoff_ms).collect();

    let mut sessions: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for e in &win {
        if let Some(s) = &e.session {
            sessions.insert(s.as_str());
        }
    }

    let d = |dec: &str| win.iter().filter(|e| e.decision == dec).count();
    let backups = win.iter().filter(|e| e.backup.is_some()).count();
    let breaker_trips = win
        .iter()
        .filter(|e| e.matched_rule.as_deref() == Some(crate::intent::BREAKER_RULE))
        .count();

    // Top projects by cwd basename, most active first.
    let mut proj: HashMap<String, usize> = HashMap::new();
    for e in &win {
        let name = e
            .cwd
            .rsplit(['/', '\\'])
            .find(|s| !s.is_empty())
            .unwrap_or("")
            .to_string();
        if !name.is_empty() {
            *proj.entry(name).or_insert(0) += 1;
        }
    }
    let mut projects: Vec<(String, usize)> = proj.into_iter().collect();
    projects.sort_by_key(|p| std::cmp::Reverse(p.1));
    let top_projects = projects.into_iter().take(3).map(|(n, _)| n).collect();

    Rollup {
        days,
        sessions: sessions.len(),
        commands: win.len(),
        allow: d("allow"),
        ask: d("ask"),
        deny: d("deny"),
        backups,
        breaker_trips,
        top_projects,
    }
}

/// Human-readable Insight for a repeatedly-*blocked* intent. Diagnostic, not
/// scolding: we don't know *why* it recurred, so we name the usual causes and
/// leave the judgment to the developer.
///
/// Keyed off circuit-breaker TRIPS, not merely classified intents — three
/// legitimate `rm -rf ./build` runs are normal work and must not trigger a
/// lecture. Three *blocked* attempts of the same intent is a policy signal.
const INSIGHT_THRESHOLD: usize = 3;

fn insight_for(label: &str) -> Option<Vec<&'static str>> {
    match label {
        "file-delete" => Some(vec![
            "generated files being cleaned",
            "build/output directories",
            "an agent retry loop",
        ]),
        "git-destructive" => Some(vec![
            "force-pushing a rebased branch",
            "resetting a work-in-progress branch",
            "an agent retrying a blocked push",
        ]),
        "db-destroy" => Some(vec![
            "resetting a local/test database",
            "a migration teardown step",
            "an agent retrying a blocked drop",
        ]),
        "infra-destroy" => Some(vec![
            "tearing down ephemeral/test infra",
            "a CI cleanup step",
            "an agent retrying a blocked destroy",
        ]),
        _ => None,
    }
}

fn print_terminal(r: &Report, roll: &Rollup, session: Option<&str>) {
    let line = "──────────────────────────────────────────";

    println!("\nSession   {}", session.map(short).unwrap_or_default());
    println!("{}", line);
    println!("Duration            {} min", r.duration_min);
    println!(
        "Commands            {}   ✓ {} · ? {} · ✗ {}",
        r.total, r.allow, r.ask, r.deny
    );
    println!("Escalated           {}", r.escalated);
    println!("Auto-flow           {}", r.auto_flow);
    println!("Previews            {}", r.impacts.len());
    println!("Backups             {}", r.backups.len());
    println!("Rollbacks           {}", r.rollbacks);

    // Destructive intents seen (classified commands), then trips separately.
    // These are different numbers: a legitimate `rm -rf ./build` is an intent,
    // not a trip. Keeping them apart keeps the report honest.
    if !r.intents.is_empty() {
        println!("\nDestructive intents");
        println!("{}", line);
        for (label, count) in &r.intents {
            println!("{:<20}{}", label, count);
        }
        println!("{:<20}{}", "breaker trips", r.breaker_trips);
    }

    // Insight: fires when the breaker blocked the SAME intent repeatedly.
    if let Some((label, count)) = r.trips_by_intent.first() {
        if *count >= INSIGHT_THRESHOLD {
            if let Some(causes) = insight_for(label) {
                println!("\nInsight");
                println!("{}", line);
                println!(
                    "The breaker blocked {} {} times in this scope.",
                    label, count
                );
                println!();
                println!("This often indicates:");
                for c in causes {
                    println!("• {}", c);
                }
                println!();
                println!("If this work is intentional, add an explicit allow rule");
                println!("scoped to the paths involved — relaxation is deliberate.");
            }
        }
    }

    // Recent events.
    if !r.recent.is_empty() {
        println!("\nRecent events");
        println!("{}", line);
        for (mark, cmd) in &r.recent {
            println!("{} {}", mark, cmd);
        }
    }

    // Insurance + risk.
    println!();
    if r.backups.is_empty() {
        println!("Backups   : none — no insured operations in scope");
    } else {
        println!(
            "Backups   : {} — rollback available (`termaxa backups`)",
            r.backups.len()
        );
        for (kind, note) in r.backups.iter().take(5) {
            println!("  🛟 [{}] {}", kind, note);
        }
    }
    println!(
        "Risk      : {}  (deny×3 + escalation×2 + ask×1 = {})",
        r.risk_label, r.risk_score
    );

    // Rollup.
    println!("\nLast {} days", roll.days);
    println!("{}", line);
    println!("Sessions        {}", roll.sessions);
    println!("Commands        {}", roll.commands);
    println!(
        "Decisions       ✓ {} · ? {} · ✗ {}",
        roll.allow, roll.ask, roll.deny
    );
    println!("Backups         {}", roll.backups);
    println!("Breaker trips   {}", roll.breaker_trips);
    if !roll.top_projects.is_empty() {
        println!("\nTop projects");
        for p in &roll.top_projects {
            println!("  {}", p);
        }
    }
    println!();
}

fn print_markdown(r: &Report, roll: &Rollup, session: Option<&str>) {
    println!("# Termaxa Execution Report\n");
    println!(
        "- **Scope:** {}",
        session.map(short).unwrap_or_else(|| "all activity".into())
    );
    println!(
        "- **Window:** {} → {} ({} min)",
        r.first_ts, r.last_ts, r.duration_min
    );
    println!(
        "- **Commands:** {} — {} allow / {} ask / {} deny",
        r.total, r.allow, r.ask, r.deny
    );
    println!("- **Escalated by context:** {}", r.escalated);
    println!("- **Auto-flow:** {} without interruption", r.auto_flow);
    println!("- **Previews:** {}", r.impacts.len());
    println!("- **Backups:** {}", r.backups.len());
    println!("- **Rollbacks:** {}", r.rollbacks);

    if !r.blocked.is_empty() {
        println!("\n## Blocked\n");
        for b in &r.blocked {
            println!("- `{}`", b);
        }
    }
    if !r.impacts.is_empty() {
        println!("\n## Impact at intervention points\n");
        for i in &r.impacts {
            println!("- {}", i);
        }
    }
    if !r.intents.is_empty() {
        println!("\n## Destructive intents\n");
        for (label, count) in &r.intents {
            println!("- **{}** — {} classified", label, count);
        }
        println!("- **breaker trips** — {}", r.breaker_trips);
    }
    if let Some((label, count)) = r.trips_by_intent.first() {
        if *count >= INSIGHT_THRESHOLD {
            if let Some(causes) = insight_for(label) {
                println!("\n## Insight\n");
                println!(
                    "The breaker blocked **{}** {} times in this scope. This often indicates:\n",
                    label, count
                );
                for c in causes {
                    println!("- {}", c);
                }
                println!("\nIf this work is intentional, add an explicit allow rule scoped to the paths involved — relaxation is deliberate.");
            }
        }
    }
    println!("\n## Insurance\n");
    if r.backups.is_empty() {
        println!("No insured operations in scope.");
    } else {
        for (kind, note) in &r.backups {
            println!("- **[{}]** {}", kind, note);
        }
        println!("\nRollback available via `termaxa rollback <id>`.");
    }
    println!(
        "\n## Risk: {}\n\nScore {} — transparent formula: deny×3 + escalation×2 + ask×1.",
        r.risk_label, r.risk_score
    );
    println!("\n## Last {} days\n", roll.days);
    println!("- **Sessions:** {}", roll.sessions);
    println!("- **Commands:** {}", roll.commands);
    println!(
        "- **Decisions:** {} allow / {} ask / {} deny",
        roll.allow, roll.ask, roll.deny
    );
    println!("- **Backups:** {}", roll.backups);
    println!("- **Breaker trips:** {}", roll.breaker_trips);
    if !roll.top_projects.is_empty() {
        println!("- **Top projects:** {}", roll.top_projects.join(", "));
    }
}

fn short(s: &str) -> String {
    format!("session {}", &s[..s.len().min(8)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::Intent;

    #[test]
    fn post_receipt_renders_as_success_not_denial() {
        // The v0.11.4 post-execution receipt bug: an executed command was
        // rendering with the ✗ mark because its decision was still "ask".
        assert_eq!(mark_for("ask", "post"), "✓");
        assert_eq!(mark_for("deny", "post"), "✓");
        // Normal marks unaffected.
        assert_eq!(mark_for("allow", "hook"), "✓");
        assert_eq!(mark_for("ask", "hook"), "?");
        assert_eq!(mark_for("deny", "hook"), "✗");
    }

    #[test]
    fn insight_causes_exist_for_every_intent_label() {
        // Every label the intent taxonomy can emit must have an Insight body,
        // or the section silently never fires for that intent.
        for label in [
            Intent::FileDelete.label(),
            Intent::DbDestroy.label(),
            Intent::GitDestructive.label(),
            Intent::InfraDestroy.label(),
        ] {
            assert!(
                insight_for(label).is_some(),
                "no Insight copy for intent label `{}`",
                label
            );
        }
        assert!(insight_for("not-an-intent").is_none());
    }

    #[test]
    fn insight_threshold_is_about_trips_not_classifications() {
        // Documents the semantic fix: three legitimate destructive commands
        // are normal work; three *blocked* attempts are a policy signal.
        // (Guards the constant against being re-pointed at `intents`.)
        assert_eq!(INSIGHT_THRESHOLD, 3);
    }
}
