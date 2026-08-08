/// Shell-aware command splitting.
///
/// Field report, v0.6.1: a live Claude Code session ran
///   `git status && echo "---" && git branch -vv && ...`
/// and the whole line rode through as `allow` because the `git status*`
/// wildcard matched the STRING by prefix — while the shell would execute
/// five separate commands. Wildcards see one string; shells see many
/// commands. This module closes that gap: split on shell operators, judge
/// every segment, let the most dangerous one govern.
///
/// Scope (deliberate):
///   - Splits on `&&`, `||`, `;`, `|`, `&`, and newlines, outside quotes.
///   - A single `&` IS a separator. Until v0.14.1 it was not — the reasoning
///     was that `2>&1` is more common than backgrounding, which is true but
///     answered the wrong question: an allow rule only has to be wrong once.
///     Redirection forms are excluded by shape instead (see
///     `is_redirection_amp`), which costs nothing and closes the bypass.
///   - `$(...)` and backticks cannot be statically analyzed — their PRESENCE
///     is reported so the context engine can escalate, rather than
///     pretending the contents were checked.
pub fn split_segments(s: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    let (mut in_single, mut in_double) = (false, false);

    while i < chars.len() {
        let c = chars[i];
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
                cur.push(c);
            }
            '"' if !in_single => {
                in_double = !in_double;
                cur.push(c);
            }
            '\\' if in_double && i + 1 < chars.len() => {
                cur.push(c);
                cur.push(chars[i + 1]);
                i += 1;
            }
            _ if in_single || in_double => cur.push(c),
            '&' if i + 1 < chars.len() && chars[i + 1] == '&' => {
                flush(&mut segments, &mut cur);
                i += 1; // consume second &
            }
            // A lone `&` IS a separator — it backgrounds the segment to its
            // left and starts a new command to its right. Treating it as
            // ordinary text reopened the v0.6.1 bypass on one character:
            // `git status & rm -rf /` stayed a single segment and matched the
            // `git status*` allow rule. The redirection forms it also appears
            // in are `2>&1` / `>&2` / `<&-` (preceded by `>` or `<`) and
            // `&>file` / `&>>file` (followed by `>`); those are not separators.
            '&' if !is_redirection_amp(&chars, i) => flush(&mut segments, &mut cur),
            '|' => {
                flush(&mut segments, &mut cur);
                if i + 1 < chars.len() && chars[i + 1] == '|' {
                    i += 1; // `||` — consume second |
                }
            }
            ';' | '\n' => flush(&mut segments, &mut cur),
            _ => cur.push(c),
        }
        i += 1;
    }
    flush(&mut segments, &mut cur);
    segments
}

/// Is the `&` at `i` part of a redirection rather than a command separator?
/// `2>&1`, `1>&2`, `<&-` have `>` or `<` immediately before; `&>log` and
/// `&>>log` have `>` immediately after.
fn is_redirection_amp(chars: &[char], i: usize) -> bool {
    let prev_is_redirect = i > 0 && matches!(chars[i - 1], '>' | '<');
    let next_is_redirect = chars.get(i + 1) == Some(&'>');
    prev_is_redirect || next_is_redirect
}

fn flush(segments: &mut Vec<String>, cur: &mut String) {
    let t = cur.trim();
    if !t.is_empty() {
        segments.push(t.to_string());
    }
    cur.clear();
}

/// Does the command contain command substitution we cannot see inside?
pub fn has_substitution(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    let mut in_single = false;
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\'' => in_single = !in_single,
            '`' if !in_single => return true,
            '$' if !in_single && chars.get(i + 1) == Some(&'(') => return true,
            _ => {}
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_the_field_report_command() {
        let cmd = r#"git status && echo "---" && git branch -vv && git log --oneline -5"#;
        let seg = split_segments(cmd);
        assert_eq!(
            seg,
            vec![
                "git status",
                r#"echo "---""#,
                "git branch -vv",
                "git log --oneline -5"
            ]
        );
    }

    #[test]
    fn splits_all_operators() {
        assert_eq!(
            split_segments("a; b | c || d && e"),
            vec!["a", "b", "c", "d", "e"]
        );
    }

    #[test]
    fn quotes_protect_operators() {
        assert_eq!(split_segments("echo 'a && b'"), vec!["echo 'a && b'"]);
        assert_eq!(split_segments(r#"echo "x; y""#), vec![r#"echo "x; y""#]);
    }

    #[test]
    fn redirections_survive() {
        // `&` inside a redirection is not an operator
        assert_eq!(split_segments("cmd 2>&1"), vec!["cmd 2>&1"]);
        assert_eq!(split_segments("cmd >&2"), vec!["cmd >&2"]);
        assert_eq!(split_segments("cmd &> log"), vec!["cmd &> log"]);
        assert_eq!(split_segments("cmd &>> log"), vec!["cmd &>> log"]);
        assert_eq!(split_segments("cmd <&-"), vec!["cmd <&-"]);
        assert_eq!(
            split_segments("make 2>&1 | tee log"),
            vec!["make 2>&1", "tee log"]
        );
    }

    /// Schipper review, finding 1. `&` backgrounds the left-hand command and
    /// starts a new one; leaving it unsplit meant the whole line matched the
    /// `git status*` allow rule and was ALLOWED.
    #[test]
    fn a_lone_ampersand_splits() {
        assert_eq!(
            split_segments("git status & rm -rf /"),
            vec!["git status", "rm -rf /"]
        );
        assert_eq!(split_segments("ls & rm -rf /"), vec!["ls", "rm -rf /"]);
        assert_eq!(split_segments("npm run dev &"), vec!["npm run dev"]);
        assert_eq!(split_segments("a & b & c"), vec!["a", "b", "c"]);
        // no spaces required, exactly as the shell reads it
        assert_eq!(
            split_segments("echo hi&rm -rf /"),
            vec!["echo hi", "rm -rf /"]
        );
    }

    /// The bypass was reachable because the two splitters disagreed about the
    /// same string. Since v0.14.1 `intent` calls this function, so the only
    /// way they can diverge again is if this test is deleted.
    #[test]
    fn newlines_split_too() {
        assert_eq!(
            split_segments("git status\nrm -rf /"),
            vec!["git status", "rm -rf /"]
        );
    }

    #[test]
    fn substitution_detected() {
        assert!(has_substitution("echo $(rm -rf /)"));
        assert!(has_substitution("echo `whoami`"));
        assert!(!has_substitution("echo '$(safe)'"));
        assert!(!has_substitution("git status"));
    }
}
