//! The command line, the format file and the exit codes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{FORMAT_PATH, GOLDEN_KEY, go, scratch_file};
use keycheck::Exit;

#[test]
fn help_goes_to_stdout_with_exit_0() {
    let run = go(&["--help"], b"");
    assert_eq!(run.exit, Exit::Clean);
    assert_eq!(run.stderr, "");
    assert!(
        run.stdout
            .contains("Usage: keycheck [--format text|json] <format-file>")
    );
    assert!(run.stdout.contains("Exit codes: 0 for a good key"));
    assert!(!run.stdout.contains('\u{1b}'), "no colour code");
}

#[test]
fn version_has_the_version_and_the_licence_line() {
    for flag in ["--version", "-V"] {
        let run = go(&[flag], b"");
        assert_eq!(run.exit, Exit::Clean);
        assert_eq!(
            run.stdout,
            format!("keycheck {}\nApache-2.0\n", env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(run.stderr, "");
    }
}

#[test]
fn the_exit_codes_are_0_1_and_2() {
    assert_eq!(Exit::Clean.code(), 0);
    assert_eq!(Exit::Findings.code(), 1);
    assert_eq!(Exit::Usage.code(), 2);
    assert_eq!(
        std::process::ExitCode::from(Exit::Findings),
        std::process::ExitCode::from(1)
    );
}

#[test]
fn the_format_defaults_to_text_and_both_forms_are_accepted() {
    let default = go(&[FORMAT_PATH], GOLDEN_KEY.as_bytes());
    let text = go(&["--format", "text", FORMAT_PATH], GOLDEN_KEY.as_bytes());
    let equals = go(&[FORMAT_PATH, "--format=json"], GOLDEN_KEY.as_bytes());
    assert_eq!(default.stdout, text.stdout);
    assert!(equals.stdout.starts_with("{\"verdict\":\"good\""));
}

#[test]
fn a_usage_error_gives_exit_2_and_no_result() {
    let cases: [&[&str]; 8] = [
        &[],
        &["--format"],
        &["--format", "xml", FORMAT_PATH],
        &["--format", "json", "--format", "text", FORMAT_PATH],
        &["--unknown", FORMAT_PATH],
        &[FORMAT_PATH, "second.json"],
        &["-x"],
        &["--format", "json"],
    ];
    for args in cases {
        let run = go(args, GOLDEN_KEY.as_bytes());
        assert_eq!(run.exit, Exit::Usage, "{args:?}");
        assert_eq!(run.stdout, "", "{args:?}");
        assert!(
            run.stderr.starts_with("keycheck: usage error: "),
            "{args:?}: {}",
            run.stderr
        );
    }
}

#[test]
fn a_usage_error_names_the_flag_and_the_expected_values() {
    let run = go(&["--format", "xml", FORMAT_PATH], b"");
    assert!(run.stderr.contains("`--format`"));
    assert!(run.stderr.contains("`text` or `json`"));
}

#[test]
fn the_flag_format_is_one_time_only() {
    let run = go(&["--format", "json", "--format", "json", FORMAT_PATH], b"");
    assert_eq!(run.exit, Exit::Usage);
    assert!(run.stderr.contains("two times"));
}

#[test]
fn a_format_file_that_does_not_exist_is_an_input_error() {
    let missing = common::scratch("absent.json");
    let run = go(&[missing.to_str().unwrap()], GOLDEN_KEY.as_bytes());
    assert_eq!(run.exit, Exit::Usage);
    assert_eq!(run.stdout, "");
    assert!(
        run.stderr
            .starts_with("keycheck: Cannot open the format file")
    );
}

#[test]
fn a_directory_as_the_format_file_is_an_input_error() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let run = go(&[dir], GOLDEN_KEY.as_bytes());
    assert_eq!(run.exit, Exit::Usage);
    assert_eq!(run.stdout, "");
    assert!(run.stderr.starts_with("keycheck: Cannot "));
}

fn format_error(name: &str, content: &[u8]) -> String {
    let path = scratch_file(name, content);
    let run = go(&[&path], GOLDEN_KEY.as_bytes());
    assert_eq!(run.exit, Exit::Usage, "{name}");
    assert_eq!(run.stdout, "", "{name}");
    run.stderr
}

#[test]
fn p_3_8_a_bad_format_file_gives_the_paths_of_the_strict_reader() {
    let e = format_error(
        "unknown.json",
        br#"{"prefix":"mcp_","length":53,"alphabet":"A-Za-z0-9","extra":1}"#,
    );
    assert!(e.contains("format file: error: $.extra: rule 3.8:"), "{e}");
    assert!(e.contains("unknown_member") || e.contains("extra"), "{e}");

    let e = format_error(
        "wrong_type.json",
        br#"{"prefix":"mcp_","length":"53","alphabet":"A-Za-z0-9"}"#,
    );
    assert!(e.contains("$.length"), "{e}");
    assert!(e.contains("53"), "the message gives the value: {e}");

    let e = format_error(
        "missing.json",
        br#"{"prefix":"mcp_","alphabet":"A-Za-z0-9"}"#,
    );
    assert!(e.contains("length"), "{e}");

    let e = format_error(
        "nested.json",
        br#"{"prefix":"mcp_","length":53,"alphabet":"A-Za-z0-9","checksum":{"algorithm":"md5","encoding":"base62","characters":6}}"#,
    );
    assert!(e.contains("$.checksum.algorithm"), "{e}");
    assert!(e.contains("md5"), "{e}");
}

#[test]
fn p_3_8_a_duplicate_member_in_the_format_file_stops_the_program() {
    let e = format_error(
        "duplicate.json",
        br#"{"prefix":"mcp_","prefix":"x","length":53,"alphabet":"A-Za-z0-9"}"#,
    );
    assert!(e.contains("duplicate member `prefix`"), "{e}");
}

#[test]
fn p_3_8_members_that_contradict_each_other_stop_the_program() {
    let e = format_error(
        "contradiction.json",
        br#"{"prefix":"mcp_","length":53,"alphabet":"a-z0-9","checksum":{"algorithm":"crc32","encoding":"base62","characters":6}}"#,
    );
    assert!(e.contains("$.alphabet"), "{e}");
    assert!(e.contains("lacks"), "{e}");
    let e = format_error(
        "short.json",
        br#"{"prefix":"mcp_","length":53,"alphabet":"A-Za-z0-9","checksum":{"algorithm":"crc32","encoding":"base62","characters":5}}"#,
    );
    assert!(e.contains("$.checksum.characters"), "{e}");
}

#[test]
fn p_3_8_every_problem_of_the_format_file_has_its_own_line() {
    let e = format_error(
        "many.json",
        br#"{"prefix":"","length":0,"alphabet":"","x":1}"#,
    );
    assert!(e.lines().count() >= 4, "{e}");
    assert!(
        e.lines()
            .all(|l| l.starts_with("keycheck: format file: error: $")),
        "{e}"
    );
}

#[test]
fn a_format_file_that_is_not_json_or_not_utf8_is_an_input_error() {
    let e = format_error("not_json.json", b"prefix = mcp_");
    assert!(
        e.starts_with("keycheck: format file: JSON error at $"),
        "{e}"
    );
    let e = format_error("empty.json", b"");
    assert!(e.contains("JSON error"), "{e}");
    let e = format_error("binary.json", b"{\"prefix\": \"\xff\"}");
    assert!(e.contains("UTF-8"), "{e}");
    let e = format_error("array.json", b"[]");
    assert!(e.contains("$"), "{e}");
}

#[test]
fn a_format_file_over_the_bound_is_refused() {
    let big = vec![b' '; keycheck::MAX_FORMAT_FILE_BYTES + 1];
    let e = format_error("big.json", &big);
    assert!(e.contains("more than 65536 bytes"), "{e}");
}

#[test]
fn the_format_file_is_read_before_the_standard_input() {
    // A bad format file stops the program, and the input does not matter.
    let path = scratch_file("order.json", b"{}");
    let run = go(&[&path], b"");
    assert_eq!(run.exit, Exit::Usage);
    assert!(run.stderr.contains("format file"));
    assert!(!run.stderr.contains("standard input"));
}

#[test]
fn p_3_8_a_format_without_a_checksum_works() {
    let path = scratch_file(
        "plain.json",
        br#"{"prefix":"k_","length":10,"alphabet":"a-z"}"#,
    );
    let run = go(&[&path], b"k_abcdefgh\n");
    assert_eq!(run.exit, Exit::Clean);
    assert!(run.stdout.ends_with("hint: abcd\n"));
    let run = go(&[&path], b"k_abcdefg1\n");
    assert_eq!(run.exit, Exit::Findings);
}

#[test]
fn p_3_8_a_format_with_a_checksum_over_the_prefix_and_in_hex() {
    let path = scratch_file(
        "hex.json",
        br#"{"prefix":"k_","length":18,"alphabet":"0-9a-f","checksum":{"algorithm":"crc32","encoding":"hex","characters":8,"covers":"prefix_and_random"}}"#,
    );
    let format =
        procurauth_core::key_format::KeyFormat::parse_str(&std::fs::read_to_string(&path).unwrap())
            .unwrap();
    let random = "01234567";
    let key = format!("k_{random}{}", format.checksum_for(random).unwrap());
    let run = go(&[&path], key.as_bytes());
    assert_eq!(run.exit, Exit::Clean, "{}", run.stderr);
    assert!(run.stdout.contains("hint: 0123"));
}

#[test]
fn p_3_2_the_subject_id_of_a_key_is_not_the_text_of_a_key() {
    // The subject id is not secret and it is not the text. The text has the prefix and 53 characters.
    let run = go(&[FORMAT_PATH], b"key:9b1c04e2aa71f0c3\n");
    assert_eq!(run.exit, Exit::Findings);
    assert_eq!(run.stdout, "bad: prefix (expected the prefix mcp_)\n");
}

#[test]
fn p_2_the_text_of_a_key_comes_from_the_standard_input_only() {
    // The text of the key as a second argument is a usage error, and the program does not read it.
    let run = go(&[FORMAT_PATH, GOLDEN_KEY], b"");
    assert_eq!(run.exit, Exit::Usage);
    assert!(!run.stderr.contains(GOLDEN_KEY));
}
