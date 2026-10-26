//! Rules of the source code and of the texts that the program prints.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::path::Path;

use common::go;

fn source_files() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        out.push((
            path.display().to_string(),
            fs::read_to_string(&path).unwrap(),
        ));
    }
    out
}

#[test]
fn the_program_reads_no_environment_variable() {
    for (name, text) in source_files() {
        for word in ["env::var", "env::vars", "var_os", "option_env!", "dotenv"] {
            assert!(!text.contains(word), "{name} uses {word}");
        }
    }
}

#[test]
fn the_program_writes_no_log_and_has_no_network_code() {
    for (name, text) in source_files() {
        for word in [
            "println!",
            "eprintln!",
            "dbg!",
            "log::",
            "tracing::",
            "std::net",
            "unsafe",
        ] {
            assert!(!text.contains(word), "{name} uses {word}");
        }
    }
}

fn long_sentences(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for paragraph in text.split("\n\n") {
        let flat = paragraph.split_whitespace().collect::<Vec<_>>().join(" ");
        let sentences: Vec<&str> = flat.split(". ").collect();
        if sentences.len() > 6 {
            out.push(format!("{} sentences: {flat}", sentences.len()));
        }
        for sentence in sentences {
            if sentence.split_whitespace().count() > 25 {
                out.push(format!("long sentence: {sentence}"));
            }
        }
    }
    out
}

#[test]
fn the_help_text_and_the_messages_follow_the_sentence_rules() {
    let help = go(&["--help"], b"").stdout;
    let mut texts = vec![help];
    let (key_text, _) = common::key_from_seed(1);
    for args in [
        vec![],
        vec!["--format", "x", common::FORMAT_PATH],
        vec!["--format", "json", "--format", "json", common::FORMAT_PATH],
        vec![common::FORMAT_PATH, "extra"],
    ] {
        texts.push(go(&args, key_text.as_bytes()).stderr);
    }
    texts.push(go(&[common::FORMAT_PATH], b"").stderr);
    texts.push(go(&[common::FORMAT_PATH], &vec![b'a'; 5000]).stderr);
    for text in texts {
        let problems = long_sentences(&text);
        assert!(problems.is_empty(), "{problems:?}");
        for word in text.split_whitespace() {
            let bare = word
                .trim_matches(|c: char| !c.is_ascii_alphabetic())
                .to_lowercase();
            let allowed = ["string", "encoding", "finding", "findings", "warning"];
            assert!(
                !(bare.len() >= 5 && bare.ends_with("ing") && !allowed.contains(&bare.as_str())),
                "the -ing form {bare} in: {text}"
            );
        }
    }
}
