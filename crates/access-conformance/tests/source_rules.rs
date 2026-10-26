//! Rules of the source code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::Path;

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
        for word in [
            "env::var",
            "env::vars",
            "var_os",
            "option_env!",
            "dotenv",
            "env!(",
        ] {
            // `env!("CARGO_PKG_VERSION")` and the build output are read at build time.
            if word == "env!(" {
                for line in text.lines().filter(|l| l.contains(word)) {
                    assert!(
                        line.contains("CARGO_PKG_VERSION") || line.contains("OUT_DIR"),
                        "{name} reads a build variable: {line}"
                    );
                }
                continue;
            }
            assert!(!text.contains(word), "{name} uses {word}");
        }
    }
}

#[test]
fn the_program_has_no_unsafe_code_no_debug_print_and_no_log_library() {
    for (name, text) in source_files() {
        let code = text.split("#[cfg(test)]").next().unwrap();
        for word in [
            "unsafe",
            "println!",
            "eprintln!",
            "dbg!",
            "use log",
            "log::info",
            "log::warn",
            "log::error",
            "tracing::",
        ] {
            assert!(!code.contains(word), "{name} uses {word}");
        }
    }
}

#[test]
fn the_program_has_no_colour_code() {
    for (name, text) in source_files() {
        assert!(
            !text.contains("\\x1b") && !text.contains("\\u{1b}"),
            "{name} writes a colour code"
        );
    }
}
