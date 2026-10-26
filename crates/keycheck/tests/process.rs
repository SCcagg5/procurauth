//! Tests of the real program: the process, its streams and its exit code.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use common::{FORMAT_PATH, GOLDEN_DIGEST, GOLDEN_KEY, scratch_file};
use procurauth_core::key_format::KeyFormat;
use procurauth_schema_check::Schemas;

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

fn program(args: &[&str], stdin: &[u8]) -> Out {
    let mut child = Command::new(env!("CARGO_BIN_EXE_keycheck"))
        .args(args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The program can exit before it reads all the input. Ignore a broken pipe.
    let _ = child.stdin.take().unwrap().write_all(stdin);
    let output = child.wait_with_output().unwrap();
    Out {
        code: output.status.code().unwrap(),
        stdout: String::from_utf8(output.stdout).unwrap(),
        stderr: String::from_utf8(output.stderr).unwrap(),
    }
}

#[test]
fn the_program_gives_the_exit_codes_0_1_and_2() {
    let good = program(&[FORMAT_PATH], format!("{GOLDEN_KEY}\n").as_bytes());
    assert_eq!(good.code, 0);
    assert_eq!(
        good.stdout,
        format!("good\nsha256: {GOLDEN_DIGEST}\nhint: aB3d\n")
    );
    assert_eq!(good.stderr, "");

    let bad = program(&[FORMAT_PATH], b"mcp_abc\n");
    assert_eq!(bad.code, 1);
    assert_eq!(
        bad.stdout,
        "bad: length (expected 53 characters, found 7)\n"
    );
    assert_eq!(bad.stderr, "");

    let usage = program(&[], b"");
    assert_eq!(usage.code, 2);
    assert_eq!(usage.stdout, "");
    assert!(usage.stderr.starts_with("keycheck: usage error: "));
}

#[test]
fn the_program_runs_with_an_empty_environment_and_shows_no_colour() {
    // The run uses `env_clear`: the program needs no variable.
    let run = program(&["--help"], b"");
    assert_eq!(run.code, 0);
    assert!(!run.stdout.contains('\u{1b}'));
    let version = program(&["--version"], b"");
    assert_eq!(
        version.stdout,
        format!("keycheck {}\nApache-2.0\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn p_3_8_the_program_checks_a_key_of_each_example_of_the_format_schema() {
    let schemas = Schemas::load().unwrap();
    let examples = schemas.examples("key-format");
    assert_eq!(examples.len(), 3);
    for (index, example) in examples.iter().enumerate() {
        let path = scratch_file(
            &format!("example_{index}.json"),
            example.to_string().as_bytes(),
        );
        let format = KeyFormat::from_value(example).unwrap();
        let random = "a".repeat(format.random_length());
        let checksum = format.checksum_for(&random).unwrap_or_default();
        let key = format!("{}{random}{checksum}", format.prefix);
        assert_eq!(key.chars().count(), format.length);
        let run = program(&[&path], key.as_bytes());
        assert_eq!(run.code, 0, "example {index}: {}", run.stderr);
        assert!(run.stdout.contains("hint: aaaa"), "example {index}");
        // A key with a bad last character is bad (the checksum or the alphabet).
        let mut broken = key.clone();
        broken.pop();
        broken.push('!');
        assert_eq!(
            program(&[&path], broken.as_bytes()).code,
            1,
            "example {index}"
        );
    }
}

#[test]
fn p_2_the_program_never_prints_the_key() {
    let (key, random) = common::key_from_seed(11);
    for args in [
        vec![FORMAT_PATH],
        vec!["--format", "json", FORMAT_PATH],
        vec![FORMAT_PATH, key.as_str()],
        vec![key.as_str()],
    ] {
        let run = program(&args, key.as_bytes());
        assert!(
            !run.stdout.contains(&random) && !run.stderr.contains(&random),
            "{args:?}"
        );
    }
}
