//! The log of the questions.
//!
//! The text log has one block for each question: the subject, the action
//! and the node, then the answer, then the counters after the answer. The
//! text never holds a credential. A key id is not a secret, but the text
//! cuts it to four characters of its local part. The in-memory log keeps the
//! last entries with full values, for the admin endpoint and for tests.

use std::collections::VecDeque;

use serde_json::{Value, json};

use crate::counters::CounterView;

/// The most entries that the PDP keeps in memory.
pub const MAX_ENTRIES: usize = 10_000;

/// The most characters of one value in the text log.
const MAX_VALUE_CHARS: usize = 64;

/// The width at which the list of counters starts a new line.
const WRAP_COLUMN: usize = 60;

/// One question and its answer.
#[derive(Clone, Debug, PartialEq)]
pub struct LogEntry {
    /// The number of the question, from 1.
    pub seq: u64,
    /// `evaluation`, `evaluations` or `metadata`.
    pub endpoint: &'static str,
    /// The value of the request header `X-Request-ID`, when the request has one.
    pub request_id: Option<String>,
    /// The subject id.
    pub subject: String,
    /// The action name.
    pub action: String,
    /// The node, in the notation of section 13. A bad chain gives the type and the id.
    pub resource: String,
    /// True when the question has `context.usage`.
    pub usage: bool,
    /// The answer. It is `None` when the PDP gave no decision.
    pub answer: Option<Value>,
    /// The failure that the PDP made, as `error_503` or `delay 250`.
    pub fault: Option<String>,
    /// The counters after the answer.
    pub counters: Vec<CounterView>,
    /// The time of the clock, in seconds since the Unix epoch.
    pub time: u64,
}

impl LogEntry {
    /// The entry as JSON, with full values.
    pub fn to_value(&self) -> Value {
        json!({
            "seq": self.seq,
            "time": self.time,
            "endpoint": self.endpoint,
            "request_id": self.request_id,
            "subject": self.subject,
            "action": self.action,
            "resource": self.resource,
            "usage": self.usage,
            "answer": self.answer,
            "fault": self.fault,
            "counters": self.counters.iter().map(counter_to_value).collect::<Vec<_>>(),
        })
    }

    /// The entry as text, as the page of the tool shows it.
    pub fn to_text(&self) -> String {
        let mut out = format!(
            "q{}  {}  {}  {}\n",
            self.seq,
            short_subject(&self.subject),
            clean(&self.action),
            clean(short_resource(&self.resource)),
        );
        let mut line = String::from("   ");
        if let Some(answer) = &self.answer {
            let decision = answer["decision"].as_bool().unwrap_or(false);
            line.push_str(&format!(" {decision}"));
            let context = &answer["context"];
            if let Some(limits) = context.get("limits") {
                line.push_str(&format!("  limits {limits}"));
            }
            if let Some(units) = context["usage"]["units"].as_u64() {
                line.push_str(&format!("  units {units}"));
            }
            if let Some(reason) = context["reason"].as_str() {
                line.push_str(&format!("  {reason}"));
            }
            if let Some(seconds) = context["retry_after"].as_u64() {
                line.push_str(&format!("  retry_after {seconds}"));
            }
        }
        if let Some(fault) = &self.fault {
            if self.answer.is_some() {
                line.push_str(&format!("  fault {fault}"));
            } else {
                line.push_str(&format!(" fault {fault}"));
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
        out.push_str(&counters_text(&self.subject, &self.counters));
        out
    }
}

fn counter_to_value(counter: &CounterView) -> Value {
    json!({
        "service": counter.service,
        "subject": counter.subject,
        "limit": counter.limit,
        "window": counter.window.as_str(),
        "used": counter.used,
        "window_start": counter.window_start,
    })
}

/// A counter as JSON, for the admin endpoint.
pub fn counters_to_value(counters: &[CounterView]) -> Value {
    Value::Array(counters.iter().map(counter_to_value).collect())
}

/// Cut a value for the text log, and replace each control character.
fn clean(text: &str) -> String {
    let mut out: String = text
        .chars()
        .take(MAX_VALUE_CHARS)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if text.chars().count() > MAX_VALUE_CHARS {
        out.push('…');
    }
    out
}

/// A key id shows `key:` and four characters. A person shows the id.
fn short_subject(subject: &str) -> String {
    match subject.strip_prefix("key:") {
        Some(local) if local.chars().count() > 4 => {
            format!("key:{}…", clean(&local.chars().take(4).collect::<String>()))
        }
        _ => clean(subject),
    }
}

/// The node without the service, as the page shows it. The service itself stays whole.
fn short_resource(resource: &str) -> &str {
    match resource.split_once('/') {
        Some((first, rest)) if first.starts_with("service:") => rest,
        _ => resource,
    }
}

/// The name of a counter for the text log: `key` for the key of the question, the id for a person.
fn label(question_subject: &str, subject: &str) -> String {
    if subject == question_subject && subject.starts_with("key:") {
        "key".to_owned()
    } else {
        clean(subject)
    }
}

fn counters_text(question_subject: &str, counters: &[CounterView]) -> String {
    if counters.is_empty() {
        return String::new();
    }
    let several_limits = counters.iter().any(|c| c.limit != counters[0].limit);
    let items: Vec<String> = counters
        .iter()
        .map(|c| {
            let name = label(question_subject, &c.subject);
            if several_limits {
                format!("{name}/{}/{} {}", c.limit, c.window.as_str(), c.used)
            } else {
                format!("{name}/{} {}", c.window.as_str(), c.used)
            }
        })
        .collect();
    let first_prefix = "    counters  ";
    let next_prefix = " ".repeat(first_prefix.len());
    let mut out = String::new();
    let mut line = first_prefix.to_owned();
    let mut first_on_line = true;
    for item in items {
        if !first_on_line && line.len() + 2 + item.len() > WRAP_COLUMN {
            out.push_str(&line);
            out.push('\n');
            line = next_prefix.clone();
            first_on_line = true;
        }
        if !first_on_line {
            line.push_str("  ");
        }
        line.push_str(&item);
        first_on_line = false;
    }
    out.push_str(&line);
    out.push('\n');
    out
}

/// The entries in memory: the last [`MAX_ENTRIES`] questions.
#[derive(Debug, Default)]
pub struct EntryLog {
    entries: VecDeque<LogEntry>,
}

impl EntryLog {
    /// Add an entry. The oldest entry leaves when the log is full.
    pub fn push(&mut self, entry: LogEntry) {
        if self.entries.len() >= MAX_ENTRIES {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    /// The entries, oldest first.
    pub fn entries(&self) -> Vec<LogEntry> {
        self.entries.iter().cloned().collect()
    }

    /// Remove all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use procurauth_core::limits::Window;

    fn counter(subject: &str, window: Window, used: u64) -> CounterView {
        CounterView {
            service: "datastore".to_owned(),
            subject: subject.to_owned(),
            limit: "requests".to_owned(),
            window,
            used,
            window_start: 0,
        }
    }

    fn entry() -> LogEntry {
        LogEntry {
            seq: 1,
            endpoint: "evaluation",
            request_id: None,
            subject: "key:9b1c04e2aa71f0c3".to_owned(),
            action: "data.read".to_owned(),
            resource: "service:datastore/host:prod/database:test2".to_owned(),
            usage: true,
            answer: Some(json!({"decision": true, "context": {
                "limits": {"max_rows": 5000, "max_duration": 30}, "usage": {"units": 1}}})),
            fault: None,
            counters: vec![
                counter("key:9b1c04e2aa71f0c3", Window::Minute, 99),
                counter("alice", Window::Second, 9),
                counter("alice", Window::Minute, 299),
            ],
            time: 0,
        }
    }

    #[test]
    fn the_text_log_follows_the_page_of_the_tool() {
        let expected = "q1  key:9b1c…  data.read  host:prod/database:test2\n\
                        \x20   true  limits {\"max_duration\":30,\"max_rows\":5000}  units 1\n\
                        \x20   counters  key/minute 99  alice/second 9\n\
                        \x20             alice/minute 299\n";
        assert_eq!(entry().to_text(), expected);
    }

    #[test]
    fn the_text_log_shows_a_budget_refusal() {
        let mut e = entry();
        e.answer = Some(
            json!({"decision": false, "context": {"reason": "budget_exceeded", "retry_after": 12}}),
        );
        assert!(
            e.to_text()
                .contains("    false  budget_exceeded  retry_after 12\n")
        );
    }

    #[test]
    fn the_text_log_names_the_limit_when_a_use_counts_several_budgets() {
        let mut e = entry();
        e.counters[1].limit = "writes".to_owned();
        assert!(e.to_text().contains("alice/writes/second 9"));
        assert!(e.to_text().contains("key/requests/minute 99"));
    }

    #[test]
    fn the_text_log_shows_the_service_whole_and_a_person_whole() {
        let mut e = entry();
        e.subject = "alice".to_owned();
        e.resource = "service:datastore".to_owned();
        e.counters.clear();
        assert!(
            e.to_text()
                .starts_with("q1  alice  data.read  service:datastore\n")
        );
        assert!(!e.to_text().contains("counters"));
    }

    #[test]
    fn the_text_log_replaces_a_control_character_and_cuts_a_long_value() {
        let mut e = entry();
        e.subject = "ev\nil".to_owned();
        e.action = "x".repeat(200);
        let text = e.to_text();
        assert!(text.starts_with("q1  ev?il  "));
        assert_eq!(text.lines().count(), 3 + 1);
        assert!(text.lines().next().unwrap().contains('…'));
    }

    #[test]
    fn the_text_log_shows_a_failure() {
        let mut e = entry();
        e.answer = None;
        e.fault = Some("error_503".to_owned());
        e.counters.clear();
        assert!(e.to_text().contains("\n    fault error_503\n"));
    }

    #[test]
    fn the_log_in_memory_keeps_the_last_entries() {
        let mut log = EntryLog::default();
        for seq in 0..(MAX_ENTRIES as u64 + 5) {
            let mut e = entry();
            e.seq = seq;
            log.push(e);
        }
        let entries = log.entries();
        assert_eq!(entries.len(), MAX_ENTRIES);
        assert_eq!(entries[0].seq, 5);
        log.clear();
        assert!(log.entries().is_empty());
    }

    #[test]
    fn the_json_entry_has_full_values() {
        let value = entry().to_value();
        assert_eq!(value["subject"], "key:9b1c04e2aa71f0c3");
        assert_eq!(
            value["resource"],
            "service:datastore/host:prod/database:test2"
        );
        assert_eq!(value["counters"][1]["window"], "second");
    }
}
