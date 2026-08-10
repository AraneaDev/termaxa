use std::process::Command;

/// An execution preview: what will actually happen if this command runs.
///
/// This module is the seed of the plugin system. `generate` inspects the
/// command and returns a preview if some plugin knows how to produce one.
/// Previews are strictly best-effort: any failure (not a repo, no remote,
/// tool missing) yields `None` and enforcement proceeds exactly as before.
/// A preview must never block or break a decision.
#[derive(Debug)]
pub struct Preview {
    pub title: String,
    /// Full preview lines, shown in `run` and `check`.
    pub lines: Vec<String>,
    /// One-line summary, embedded in the hook reason for Claude Code prompts.
    pub summary: String,
}

/// Generate a preview, optionally with knowledge of the project root.
///
/// The root lets the delete preview answer "is this target outside the
/// project?" — its single most useful signal, and one the process cwd cannot
/// supply: in hook mode the agent may spawn us from anywhere (see the Cursor
/// cwd bug). Callers that know the root pass it; callers that don't pass None
/// and the signal is omitted rather than guessed.
/// Build the consequence preview for a command.
///
/// `live` controls whether the preview may execute anything. When false, only
/// static analysis runs: parsing the command, resolving paths, scanning the
/// filesystem. No subprocess is spawned.
///
/// SECURITY (v0.14.2). `hook::run` generates the preview before returning a
/// decision, so a DENIED command still reached this function. v0.14.1 fixed
/// what the Postgres preview did with the arguments it was handed; it left
/// standing the structure that let a denied command reach a subprocess at all.
/// Confirmed with a stub `terraform` on PATH: a denied `terraform destroy`
/// caused `terraform plan -destroy` to run in the agent's working directory,
/// which initializes providers and evaluates `external` data sources.
///
/// The fix is not to skip the preview on deny — the denial message is more
/// useful with it ("DROP TABLE is blocked | DROP users"), and the delete
/// preview never spawns anything. It is to make "may this execute?" an
/// argument, so the caller that already knows the verdict decides.
/// Reported by Tim Schipper.
pub fn generate(command: &str, root: Option<&std::path::Path>, live: bool) -> Option<Preview> {
    // Deletes are checked across the whole command first: a compound like
    // `mkdir x && rm -rf /` must not have its delete masked by an earlier
    // segment producing a preview.
    if let Some(p) = crate::delete::preview_for(command, root) {
        return Some(p);
    }
    // Compound commands: preview the first segment that has one.
    let segments = crate::shell::split_segments(command);
    if segments.len() > 1 {
        return segments.iter().find_map(|s| generate_one(s, live));
    }
    generate_one(command, live)
}

fn generate_one(command: &str, live: bool) -> Option<Preview> {
    let cmd = crate::policy::normalize(command);
    if cmd.starts_with("git push") {
        // Entirely subprocess-derived: `git rev-parse`, `git log`. Nothing
        // static to fall back on, so a non-live preview has no answer.
        return if live { git_push_preview(&cmd) } else { None };
    }
    if cmd.starts_with("psql") || cmd.contains(" psql ") {
        return crate::pg::preview_for(command, live);
    }
    for bin in ["terraform", "tofu"] {
        if cmd.starts_with(&format!("{} apply", bin))
            || cmd.starts_with(&format!("{} destroy", bin))
        {
            // `terraform plan` is the confirmed case: it initializes
            // providers and evaluates `external` data sources, which execute
            // arbitrary programs.
            return if live {
                terraform_preview(bin, cmd.starts_with(&format!("{} destroy", bin)))
            } else {
                None
            };
        }
    }
    None
}

/// What would `git push` actually send?
///
/// The core question is "compared to what?" — three cases:
///   1. branch has an upstream        -> @{u}..HEAD
///   2. no upstream, origin/<b> exists -> origin/<b>..HEAD
///   3. brand-new branch               -> everything is new
fn git_push_preview(command: &str) -> Option<Preview> {
    let branch = git(&["rev-parse", "--abbrev-ref", "HEAD"])?;
    let force = command.contains("--force") || command.contains(" -f ");

    let (range, baseline) = if git(&["rev-parse", "--abbrev-ref", "@{u}"]).is_some() {
        ("@{u}..HEAD".to_string(), "upstream".to_string())
    } else {
        let remote_branch = format!("origin/{}", branch);
        if git(&["rev-parse", "--verify", "--quiet", &remote_branch]).is_some() {
            (format!("{}..HEAD", remote_branch), remote_branch)
        } else {
            // Case 3: nothing on the remote to compare against.
            let count = git(&["rev-list", "--count", "HEAD"])?;
            return Some(Preview {
                title: format!("push preview ({} -> new remote branch)", branch),
                lines: vec![format!(
                    "entire branch is new to the remote: {} commit(s)",
                    count
                )],
                summary: format!("new branch, {} commit(s)", count),
            });
        }
    };

    let count: u32 = git(&["rev-list", "--count", &range])?.parse().ok()?;

    // A force push's damage is what the remote LOSES — the reverse range.
    // Discovered live in v0.6.0: the preview said "nothing to push" while a
    // force push destroyed a commit. Gain and loss are different directions.
    let loss_range = range.replace("..HEAD", "").replace("HEAD", "");
    let mut loss_lines: Vec<String> = Vec::new();
    let mut loss_count: u32 = 0;
    if force && !loss_range.is_empty() {
        let reverse = format!("HEAD..{}", loss_range);
        if let Some(n) = git(&["rev-list", "--count", &reverse]).and_then(|s| s.parse().ok()) {
            loss_count = n;
            if n > 0 {
                loss_lines.push(format!("  ⚠ remote will LOSE {} commit(s):", n));
                if let Some(log) = git(&["log", "--oneline", "--no-decorate", &reverse]) {
                    for l in log.lines().take(5) {
                        loss_lines.push(format!("    ✗ {}", l));
                    }
                }
            }
        }
    }

    if count == 0 && loss_count == 0 {
        return Some(Preview {
            title: format!("push preview ({} -> {})", branch, baseline),
            lines: vec!["nothing to push — remote is up to date".to_string()],
            summary: "nothing to push".to_string(),
        });
    }

    let mut lines = loss_lines;

    // The commits that would be sent (cap at 5 to keep the prompt readable).
    if let Some(log) = git(&["log", "--oneline", "--no-decorate", &range]) {
        for (i, l) in log.lines().enumerate() {
            if i == 5 {
                lines.push(format!("  ... and {} more", count as usize - 5));
                break;
            }
            lines.push(format!("  {}", l));
        }
    }

    // File-level impact: last line of --stat is the totals summary.
    let mut files_changed = String::from("? files changed");
    if let Some(stat) = git(&["diff", "--stat", &range]) {
        if let Some(total) = stat.lines().last() {
            files_changed = total.trim().to_string();
        }
        let file_lines: Vec<&str> = stat.lines().collect();
        if file_lines.len() > 1 {
            lines.push(String::new());
            for l in file_lines.iter().take(file_lines.len() - 1).take(8) {
                lines.push(format!("  {}", l.trim()));
            }
            if file_lines.len() - 1 > 8 {
                lines.push(format!("  ... and {} more files", file_lines.len() - 1 - 8));
            }
        }
    }

    let mut summary = format!("{} commit(s); {}", count, files_changed);
    if loss_count > 0 {
        summary = format!("remote LOSES {} commit(s); {}", loss_count, summary);
    }
    Some(Preview {
        title: format!("push preview ({} -> {})", branch, baseline),
        lines,
        summary,
    })
}

/// Run a git command, returning trimmed stdout on success, None on any failure.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

// ---------------------------------------------------------------------------
// terraform / tofu: what would `apply` actually do?
// ---------------------------------------------------------------------------

/// Run `plan` and surface add/change/destroy counts before an apply.
/// -input=false and -lock=false are load-bearing: a preview must never hang
/// the hook waiting for interactive input or a state lock.
fn terraform_preview(bin: &str, destroy: bool) -> Option<Preview> {
    let mut args = vec!["plan", "-no-color", "-input=false", "-lock=false"];
    if destroy {
        args.push("-destroy");
    }
    let out = std::process::Command::new(bin).args(&args).output().ok()?;
    if !out.status.success() {
        return None; // uninitialized dir, bad config — best effort, stay silent
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let (add, change, del, resources) = parse_tf_plan(&text)?;

    let mut lines = Vec::new();
    if del > 0 {
        lines.push(format!("  ⚠ {} resource(s) will be DESTROYED", del));
    }
    for r in resources.iter().take(6) {
        lines.push(format!("  {}", r));
    }
    lines.push(format!(
        "  plan: {} to add, {} to change, {} to destroy",
        add, change, del
    ));

    Some(Preview {
        title: format!("{} plan preview", bin),
        lines,
        summary: format!("plan: +{} ~{} -{}", add, change, del),
    })
}

/// Pure parser: extract counts + resource action lines from plan output.
pub fn parse_tf_plan(text: &str) -> Option<(u32, u32, u32, Vec<String>)> {
    let mut resources = Vec::new();
    let mut counts = None;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("# ") && t.contains(" will be ") {
            resources.push(t.trim_start_matches("# ").to_string());
        }
        if let Some(rest) = t.strip_prefix("Plan: ") {
            // "3 to add, 1 to change, 2 to destroy."
            let nums: Vec<u32> = rest
                .split(|c: char| !c.is_ascii_digit())
                .filter(|s| !s.is_empty())
                .filter_map(|s| s.parse().ok())
                .collect();
            if nums.len() >= 3 {
                counts = Some((nums[0], nums[1], nums[2]));
            }
        }
        if t.starts_with("Destroy complete") || t.starts_with("No changes.") {
            counts = counts.or(Some((0, 0, 0)));
        }
    }
    counts.map(|(a, c, d)| (a, c, d, resources))
}

#[cfg(test)]
mod tf_tests {
    use super::*;

    #[test]
    fn parses_plan_summary_and_resources() {
        let out = r#"
Terraform will perform the following actions:

  # terraform_data.web[0] will be created
  # terraform_data.web[1] will be created
  # aws_instance.old will be destroyed

Plan: 2 to add, 0 to change, 1 to destroy.
"#;
        let (a, c, d, res) = parse_tf_plan(out).unwrap();
        assert_eq!((a, c, d), (2, 0, 1));
        assert_eq!(res.len(), 3);
        assert!(res[2].contains("will be destroyed"));
    }

    #[test]
    fn no_changes_is_zeroes() {
        let (a, c, d, _) = parse_tf_plan("No changes. Your infrastructure matches.").unwrap();
        assert_eq!((a, c, d), (0, 0, 0));
    }
}

#[cfg(test)]
mod live_gate_tests {
    use super::*;

    /// Schipper review, finding 4, confirmed with a stub `terraform` on PATH:
    /// a DENIED `terraform destroy` still caused `terraform plan -destroy` to
    /// run in the agent's working directory. `hook::run` generates the preview
    /// before returning the decision, so denying is what made it worse — the
    /// more correctly the gate behaved, the more confidently it ran the plan.
    #[test]
    fn a_non_live_preview_spawns_nothing_for_terraform() {
        assert!(generate("terraform destroy -auto-approve", None, false).is_none());
        assert!(generate("tofu destroy", None, false).is_none());
    }

    /// Same structure, the other two subprocess previews.
    #[test]
    fn a_non_live_preview_spawns_nothing_for_git_push() {
        assert!(generate("git push --force origin main", None, false).is_none());
    }

    /// The reason NOT to simply skip the preview on deny: static analysis is
    /// where the useful part of the denial message comes from. A denied
    /// `DROP TABLE` should still say which table, without connecting to the
    /// database it was just blocked from.
    #[test]
    fn a_non_live_preview_keeps_the_static_sql_analysis() {
        let p = generate(r#"psql -d shop -c "DROP TABLE users""#, None, false)
            .expect("static SQL analysis must still produce a preview");
        assert!(
            p.summary.contains("users"),
            "denial reason lost its detail: {}",
            p.summary
        );
    }

    /// Deletes never spawned anything, so they are unaffected either way —
    /// asserted so a future refactor can't quietly gate them too.
    #[test]
    fn deletes_preview_identically_whether_live_or_not() {
        let live = generate("rm -rf /tmp/tmx-none-such", None, true);
        let stat = generate("rm -rf /tmp/tmx-none-such", None, false);
        assert_eq!(live.map(|p| p.summary), stat.map(|p| p.summary));
    }
}
