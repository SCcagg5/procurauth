//! A check of the Simplified Technical English rules that a program can check.
//!
//! The test reads the documents, the descriptions of the schemas, the doc
//! comments and the messages of the code. It checks four rules.
//! A sentence has 25 words at most, and a paragraph has 6 sentences at most.
//! A word does not end in -ing, and a short list of words does not occur.
//! A program cannot check the other rules, for example the active voice.
//! The authors must check them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use procurauth_schema_check::repository_root;
use serde_json::Value;

/// Words that end in -ing and that are not a verb form: nouns and technical names.
/// The protocol uses binding, ceiling, meaning, nothing, signing, string and mapping.
/// The words finding and warning are the technical nouns of the reports of the tools.
const ALLOWED_ING: [&str; 24] = [
    "string",
    "strings",
    "ceiling",
    "ceilings",
    "nothing",
    "anything",
    "something",
    "everything",
    "during",
    "thing",
    "bring",
    "encoding",
    "padding",
    "being",
    "binding",
    "bindings",
    "meaning",
    "signing",
    "mapping",
    "remaining",
    "finding",
    "findings",
    "warning",
    "warnings",
];

/// Words that STE does not approve, with the word to use.
const BANNED: [(&str, &str); 12] = [
    ("ensure", "make sure"),
    ("ensures", "make sure"),
    ("provide", "give"),
    ("provides", "give"),
    ("allow", "let"),
    ("allows", "let"),
    ("allowed", "valid, or can"),
    ("utilize", "use"),
    ("e.g.", "for example"),
    ("i.e.", "that is"),
    ("etc.", "list each item"),
    ("via", "with"),
];

const PHRASAL: [&str; 24] = [
    "set up",
    "carry out",
    "turn on",
    "turn off",
    "look up",
    "find out",
    "fill in",
    "point out",
    "give up",
    "go on",
    "come back",
    "build up",
    "break down",
    "pick up",
    "write down",
    "clean up",
    "hand over",
    "take out",
    "cut off",
    "back up",
    "line up",
    "start up",
    "shut down",
    "log in",
];

struct Paragraph {
    origin: String,
    text: String,
}

fn files_with(dir: &Path, extension: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if name != "target" && name != ".git" && name != "docs" {
                files_with(&path, extension, out);
            }
        } else if path.extension().is_some_and(|e| e == extension) {
            out.push(path);
        }
    }
    out.sort();
}

fn markdown_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    files_with(&root.join("devdocs"), "md", &mut out);
    files_with(&root.join("notes"), "md", &mut out);
    out.push(root.join("conformance/README.md"));
    out.push(root.join("conformance/COVERAGE.md"));
    out.push(root.join("conformance/schema-check/README.md"));
    out.push(root.join("crates/procurauth-core/README.md"));
    out
}

/// Remove the inline markup of Markdown. A code span becomes the word X.
fn clean(text: &str) -> String {
    let mut out = String::new();
    let mut in_code = false;
    for c in text.chars() {
        if c == '`' {
            if in_code {
                out.push('X');
            }
            in_code = !in_code;
        } else if !in_code && c != '*' {
            out.push(c);
        }
    }
    out
}

fn list_marker_length(line: &str) -> usize {
    let trimmed = line.trim_start();
    let indent = line.len() - trimmed.len();
    if trimmed.starts_with("- ") {
        return indent + 2;
    }
    let digits = trimmed.chars().take_while(char::is_ascii_digit).count();
    if digits > 0 && trimmed[digits..].starts_with(". ") {
        return indent + digits + 2;
    }
    0
}

fn markdown_paragraphs(path: &Path) -> Vec<Paragraph> {
    let text = fs::read_to_string(path).unwrap();
    let mut out = Vec::new();
    let mut current = String::new();
    let mut start_line = 0;
    let mut fence = false;
    let origin = path
        .strip_prefix(repository_root())
        .unwrap()
        .display()
        .to_string();
    let flush = |current: &mut String, line: usize, out: &mut Vec<Paragraph>| {
        if !current.trim().is_empty() {
            out.push(Paragraph {
                origin: format!("{origin}:{line}"),
                text: clean(current.trim()),
            });
        }
        current.clear();
    };
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        if line.trim_start().starts_with("```") {
            flush(&mut current, start_line, &mut out);
            fence = !fence;
            continue;
        }
        if fence || line.starts_with('|') || line.trim().is_empty() {
            flush(&mut current, start_line, &mut out);
            continue;
        }
        if line.starts_with('#') {
            flush(&mut current, start_line, &mut out);
            out.push(Paragraph {
                origin: format!("{origin}:{number}"),
                text: clean(line.trim_start_matches('#').trim()),
            });
            continue;
        }
        let marker = list_marker_length(line);
        if marker > 0 {
            flush(&mut current, start_line, &mut out);
            start_line = number;
            current.push_str(&line[marker..]);
        } else {
            if current.is_empty() {
                start_line = number;
            } else {
                current.push(' ');
            }
            current.push_str(line.trim());
        }
    }
    flush(&mut current, start_line, &mut out);
    out
}

fn json_paragraphs(path: &Path) -> Vec<Paragraph> {
    let value: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let origin = path
        .strip_prefix(repository_root())
        .unwrap()
        .display()
        .to_string();
    let mut out = Vec::new();
    fn walk(value: &Value, pointer: &str, origin: &str, out: &mut Vec<Paragraph>) {
        match value {
            Value::Object(map) => {
                for (key, item) in map {
                    let next = format!("{pointer}/{key}");
                    if let Value::String(text) = item
                        && matches!(key.as_str(), "description" | "title" | "notes" | "name")
                        && text.contains(' ')
                    {
                        out.push(Paragraph {
                            origin: format!("{origin}#{next}"),
                            text: clean(text),
                        });
                    }
                    walk(item, &next, origin, out);
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    walk(item, &format!("{pointer}/{index}"), origin, out);
                }
            }
            _ => {}
        }
    }
    walk(&value, "", &origin, &mut out);
    out
}

fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    files_with(&root.join("crates"), "rs", &mut out);
    files_with(&root.join("conformance/schema-check"), "rs", &mut out);
    out
}

/// The doc comments of a Rust file, as paragraphs.
fn doc_paragraphs(path: &Path) -> Vec<Paragraph> {
    let text = fs::read_to_string(path).unwrap();
    let origin = path
        .strip_prefix(repository_root())
        .unwrap()
        .display()
        .to_string();
    let mut out = Vec::new();
    let mut current = String::new();
    let mut start_line = 0;
    let mut fence = false;
    let flush = |current: &mut String, line: usize, out: &mut Vec<Paragraph>| {
        if !current.trim().is_empty() {
            out.push(Paragraph {
                origin: format!("{origin}:{line}"),
                text: clean(current.trim()),
            });
        }
        current.clear();
    };
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let trimmed = raw.trim_start();
        let Some(body) = trimmed
            .strip_prefix("///")
            .or_else(|| trimmed.strip_prefix("//!"))
        else {
            flush(&mut current, start_line, &mut out);
            continue;
        };
        let line = body.strip_prefix(' ').unwrap_or(body);
        if line.trim_start().starts_with("```") {
            flush(&mut current, start_line, &mut out);
            fence = !fence;
            continue;
        }
        if fence || line.starts_with('|') || line.trim().is_empty() || line.starts_with('#') {
            flush(&mut current, start_line, &mut out);
            continue;
        }
        let marker = list_marker_length(line);
        if marker > 0 {
            flush(&mut current, start_line, &mut out);
            start_line = number;
            current.push_str(&line[marker..]);
        } else {
            if current.is_empty() {
                start_line = number;
            } else {
                current.push(' ');
            }
            current.push_str(line.trim());
        }
    }
    flush(&mut current, start_line, &mut out);
    out
}

/// The text of the string literals that look like a message, outside the tests.
fn message_paragraphs(path: &Path) -> Vec<Paragraph> {
    let text = fs::read_to_string(path).unwrap();
    let origin = path
        .strip_prefix(repository_root())
        .unwrap()
        .display()
        .to_string();
    let code = text.split("#[cfg(test)]").next().unwrap();
    let mut out = Vec::new();
    for (index, line) in code.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        let mut chars = line.char_indices().peekable();
        while let Some((start, c)) = chars.next() {
            if c != '"' {
                continue;
            }
            let mut literal = String::new();
            let mut escaped = false;
            for (_, d) in chars.by_ref() {
                if escaped {
                    literal.push(d);
                    escaped = false;
                } else if d == '\\' {
                    escaped = true;
                } else if d == '"' {
                    break;
                } else {
                    literal.push(d);
                }
            }
            let _ = start;
            let words = literal.split_whitespace().count();
            let first = literal.chars().next().unwrap_or(' ');
            if words >= 3 && first.is_uppercase() && literal.trim_end().ends_with(['.', '?']) {
                out.push(Paragraph {
                    origin: format!("{origin}:{}", index + 1),
                    text: placeholders(&literal),
                });
            }
        }
    }
    out
}

fn placeholders(text: &str) -> String {
    let mut out = String::new();
    let mut depth = 0;
    for c in text.chars() {
        match c {
            '{' => {
                if depth == 0 {
                    out.push('X');
                }
                depth += 1;
            }
            '}' if depth > 0 => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

fn sentences(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = text.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        current.push(*c);
        let ends =
            matches!(c, '.' | '?' | '!') && chars.get(i + 1).is_none_or(|n| n.is_whitespace());
        if ends {
            out.push(current.trim().to_owned());
            current.clear();
        }
    }
    if !current.trim().is_empty() {
        out.push(current.trim().to_owned());
    }
    out
}

fn violations(paragraph: &Paragraph, check_count: bool) -> Vec<String> {
    let mut found = Vec::new();
    let list = sentences(&paragraph.text);
    if check_count && list.len() > 6 {
        found.push(format!("{} sentences in one paragraph", list.len()));
    }
    for sentence in &list {
        let words: Vec<&str> = sentence.split_whitespace().collect();
        if words.len() > 25 {
            found.push(format!("{} words: {sentence}", words.len()));
        }
        for word in &words {
            let bare: String = word
                .trim_matches(|c: char| !c.is_alphanumeric() && c != '.')
                .to_lowercase();
            let letters = bare.trim_end_matches('.');
            if letters.len() >= 5
                && letters.ends_with("ing")
                && letters.chars().all(|c| c.is_ascii_alphabetic())
                && !ALLOWED_ING.contains(&letters)
            {
                found.push(format!("the -ing form `{letters}` in: {sentence}"));
            }
            for (banned, instead) in BANNED {
                if bare == banned || letters == banned {
                    found.push(format!(
                        "the word `{banned}` (use {instead}) in: {sentence}"
                    ));
                }
            }
        }
        let lower = format!(" {} ", sentence.to_lowercase());
        for phrase in PHRASAL {
            if lower.contains(&format!(" {phrase} ")) {
                found.push(format!("the phrasal verb `{phrase}` in: {sentence}"));
            }
        }
    }
    found
}

fn check_all(paragraphs: &[Paragraph], check_count: bool) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for paragraph in paragraphs {
        for problem in violations(paragraph, check_count) {
            let line = format!("{}: {problem}", paragraph.origin);
            if seen.insert(line.clone()) {
                out.push(line);
            }
        }
    }
    out
}

fn report(name: &str, problems: &[String]) {
    assert!(
        problems.is_empty(),
        "{name}: {} problems\n{}",
        problems.len(),
        problems.join("\n")
    );
}

#[test]
fn the_markdown_documents_follow_the_rules() {
    let root = repository_root();
    let mut paragraphs = Vec::new();
    for path in markdown_files(&root) {
        paragraphs.extend(markdown_paragraphs(&path));
    }
    assert!(paragraphs.len() > 100, "the documents are missing");
    report("documents", &check_all(&paragraphs, true));
}

#[test]
fn the_schemas_and_the_cases_follow_the_rules() {
    let root = repository_root();
    let mut files = Vec::new();
    files_with(&root.join("schemas"), "json", &mut files);
    files_with(&root.join("conformance"), "json", &mut files);
    let mut paragraphs = Vec::new();
    for path in files {
        paragraphs.extend(json_paragraphs(&path));
    }
    assert!(paragraphs.len() > 100, "the descriptions are missing");
    report("json texts", &check_all(&paragraphs, true));
}

#[test]
fn the_doc_comments_follow_the_rules() {
    let root = repository_root();
    let mut paragraphs = Vec::new();
    for path in rust_files(&root) {
        paragraphs.extend(doc_paragraphs(&path));
    }
    assert!(paragraphs.len() > 100, "the doc comments are missing");
    report("doc comments", &check_all(&paragraphs, true));
}

#[test]
fn the_messages_of_the_code_follow_the_rules() {
    let root = repository_root();
    let mut paragraphs = Vec::new();
    for path in rust_files(&root) {
        if path.components().any(|c| c.as_os_str() == "tests") {
            continue;
        }
        paragraphs.extend(message_paragraphs(&path));
    }
    assert!(paragraphs.len() > 50, "the messages are missing");
    report("messages", &check_all(&paragraphs, false));
}
