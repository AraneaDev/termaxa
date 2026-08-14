use crate::policy::{Notify, Policy};
use std::time::Duration;

/// Fire a webhook notification for a decision, if the policy asks for one.
///
/// Doctrine (same as previews): this layer must NEVER delay or break
/// enforcement. Hard 3-second timeout, every error swallowed. Slack being
/// down cannot make Termaxa hang or fail a decision that was already made.
pub fn maybe_send(policy: &Policy, decision: &str, command: &str, reason: &str, source: &str) {
    let Some(cfg) = &policy.notify else { return };
    if !cfg.on.iter().any(|d| d.eq_ignore_ascii_case(decision)) {
        return;
    }
    send(cfg, decision, command, reason, source);
}

fn send(cfg: &Notify, decision: &str, command: &str, reason: &str, source: &str) {
    let emoji = match decision {
        "deny" => "🛑",
        "ask" => "⚠️",
        _ => "✅",
    };
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let text = format!(
        "{} *termaxa {}* [{}]\n`{}`\n{}\n_{}_",
        emoji,
        decision.to_uppercase(),
        source,
        command,
        reason,
        cwd
    );
    let body = serde_json::json!({ "text": text }).to_string();

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(3))
        .build();
    // Fire and forget: success or failure, the decision already stands.
    let _ = agent
        .post(&cfg.webhook)
        .set("Content-Type", "application/json")
        .send_string(&body);
}

/// `termaxa notify --test`: send a probe and report LOUDLY.
///
/// The normal notification path is fire-and-forget by design, which means a
/// misconfigured webhook fails silently. This command is the counterweight:
/// explicit, verbose, and honest about what happened.
pub fn test(policy: &Policy) -> anyhow::Result<i32> {
    let Some(cfg) = &policy.notify else {
        eprintln!("no `notify:` section found in .termaxa/policy.yaml — nothing to test");
        return Ok(1);
    };
    println!("webhook : {}", cfg.webhook);
    println!("on      : {:?}", cfg.on);

    let body = serde_json::json!({
        "text": "✅ *termaxa notify --test* — if you can read this, notifications work."
    })
    .to_string();

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(5))
        .build();
    match agent
        .post(&cfg.webhook)
        .set("Content-Type", "application/json")
        .send_string(&body)
    {
        Ok(resp) => {
            println!("result  : HTTP {} — probe delivered", resp.status());
            Ok(0)
        }
        Err(ureq::Error::Status(code, _)) => {
            eprintln!(
                "result  : HTTP {} — endpoint reachable but rejected the probe",
                code
            );
            Ok(1)
        }
        Err(e) => {
            eprintln!("result  : FAILED — {}", e);
            eprintln!("hint    : check the URL, your network, or firewall");
            Ok(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    /// A listener that answers one request and hands back what it received.
    /// The webhook is fire-and-forget, so the only way to know what was sent
    /// is to be the thing receiving it.
    fn capture<F: FnOnce(String)>(status: &str, body_of: F) -> Option<String> {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a local port must be bindable");
        let port = listener
            .local_addr()
            .expect("the port must be readable")
            .port();
        let status = status.to_string();

        let handle = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().ok()?;
            sock.set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .ok()?;
            // The body follows the headers in its own packet, so one read
            // returns the request line and nothing that was sent.
            let mut raw = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                match sock.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => raw.extend_from_slice(&chunk[..n]),
                }
                let text = String::from_utf8_lossy(&raw);
                let Some((head, body)) = text.split_once("\r\n\r\n") else {
                    continue;
                };
                let want: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("Content-Length: "))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                if body.len() >= want {
                    break;
                }
            }
            let _ = sock.write_all(
                format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            );
            Some(String::from_utf8_lossy(&raw).into_owned())
        });

        body_of(format!("http://127.0.0.1:{port}/hook"));
        handle.join().ok().flatten()
    }

    fn policy_with(webhook: String, on: Vec<&str>) -> Policy {
        let yaml = format!(
            "version: 1\ndefault: ask\nrules: []\nnotify:\n  webhook: {}\n  on: [{}]\n",
            webhook,
            on.join(", ")
        );
        serde_yaml::from_str(&yaml).expect("policy must parse")
    }

    #[test]
    fn each_decision_carries_its_own_mark() {
        // The mark is the first thing a reader sees in the channel, and it is
        // the only part of the message that distinguishes a block from an
        // approval at a glance.
        for (decision, mark) in [("deny", "🛑"), ("ask", "⚠️"), ("allow", "✅")] {
            let got = capture("200 OK", |url| {
                let policy = policy_with(url, vec![decision]);
                maybe_send(&policy, decision, "rm -rf /", "matched a rule", "hook");
            })
            .unwrap_or_default();
            assert!(
                got.contains(mark),
                "a {decision} should be marked {mark}: {got:?}"
            );
            assert!(got.contains(&decision.to_uppercase()), "{got:?}");
        }
    }

    #[test]
    fn only_the_decisions_the_policy_asked_for_are_sent() {
        // `on: [deny]` is the default, and a webhook that fires on every
        // decision is one people mute.
        let listener = TcpListener::bind("127.0.0.1:0").expect("a port must be bindable");
        let port = listener.local_addr().expect("readable").port();
        listener.set_nonblocking(true).expect("non-blocking");
        let policy = policy_with(format!("http://127.0.0.1:{port}/hook"), vec!["deny"]);

        maybe_send(&policy, "allow", "ls", "no rule matched", "hook");
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            listener.accept().is_err(),
            "an allow must not reach a deny-only webhook"
        );
    }

    #[test]
    fn the_probe_reports_what_the_endpoint_actually_said() {
        // The normal path is fire-and-forget, which means a misconfigured
        // webhook fails silently. This command is the counterweight, so its
        // exit code has to distinguish delivered from rejected.
        let code = capture("200 OK", |url| {
            let policy = policy_with(url, vec!["deny"]);
            assert_eq!(test(&policy).expect("the probe must not error"), 0);
        });
        assert!(
            code.unwrap_or_default().contains("termaxa notify --test"),
            "the probe says which command sent it"
        );

        let sent = capture("500 Internal Server Error", |url| {
            let policy = policy_with(url, vec!["deny"]);
            assert_eq!(
                test(&policy).expect("a rejection is reported, not raised"),
                1,
                "an endpoint that rejects the probe is not a working webhook"
            );
        });
        assert!(sent.is_some(), "the endpoint was reached");
    }

    #[test]
    fn a_policy_with_no_notify_section_has_nothing_to_test() {
        let policy: Policy = serde_yaml::from_str("version: 1\ndefault: ask\nrules: []\n")
            .expect("policy must parse");
        assert_eq!(
            test(&policy).expect("a missing section is not an error"),
            1,
            "there is nothing to report on, and saying so is not success"
        );
        // And nothing is sent, which is why this cannot be asserted by a
        // listener: there is no request to observe.
        maybe_send(&policy, "deny", "rm -rf /", "matched", "hook");
    }
}
