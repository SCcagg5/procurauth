//! The command line: the usage, the exit codes and the inputs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::thread;

use common::{datastore_document, run, write};

const GOOD: &str = "tests/fixtures/context/document.json";
const BAD: &str = "tests/fixtures/document/6.1_budget_with_min/fail.json";
const WARNING: &str = "tests/fixtures/document/5.3c_above_reader_minimum/fail.json";

#[test]
fn p_16_help_shows_the_usage_and_exits_with_0() {
    let result = run(&["--help"]);
    assert_eq!(result.code, 0);
    assert!(result.stdout.contains(
        "Usage: access-lint [--format text|json] [--grants FILE] [--options FILE] <document>"
    ));
    assert_eq!(result.stderr, "");
}

#[test]
fn p_16_version_shows_the_version_and_the_licence() {
    let result = run(&["--version"]);
    assert_eq!(result.code, 0);
    assert_eq!(
        result.stdout,
        format!("access-lint {}\nApache-2.0\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn p_16_no_argument_is_a_usage_error() {
    let result = run(&[]);
    assert_eq!(result.code, 2);
    assert_eq!(result.stdout, "");
    assert!(result.stderr.contains("<document>"), "{}", result.stderr);
}

#[test]
fn p_16_an_unknown_option_is_a_usage_error() {
    let result = run(&["--color", GOOD]);
    assert_eq!(result.code, 2);
    assert_eq!(result.stdout, "");
    assert!(result.stderr.contains("--color"), "{}", result.stderr);
}

#[test]
fn p_16_an_option_that_occurs_two_times_is_a_usage_error() {
    for args in [
        vec!["--format", "text", "--format", "json", GOOD],
        vec!["--grants", GOOD, "--grants", GOOD, GOOD],
        vec!["--options", GOOD, "--options", GOOD, GOOD],
    ] {
        let result = run(&args);
        assert_eq!(result.code, 2, "{args:?}");
        assert!(
            result.stderr.contains("cannot be used"),
            "{}",
            result.stderr
        );
    }
}

#[test]
fn p_16_a_second_document_is_a_usage_error() {
    assert_eq!(run(&[GOOD, GOOD]).code, 2);
}

#[test]
fn p_16_a_bad_format_names_the_value_and_the_choices() {
    let result = run(&["--format", "xml", GOOD]);
    assert_eq!(result.code, 2);
    assert!(result.stderr.contains("xml"), "{}", result.stderr);
    assert!(result.stderr.contains("text"), "{}", result.stderr);
    assert!(result.stderr.contains("json"), "{}", result.stderr);
}

#[test]
fn p_16_the_output_has_no_colour() {
    for args in [vec![GOOD], vec![BAD], vec!["--help"], vec!["--bad"]] {
        let result = run(&args);
        assert!(!result.stdout.contains('\u{1b}') && !result.stderr.contains('\u{1b}'));
    }
}

#[test]
fn p_16_exit_codes_0_and_1() {
    assert_eq!(run(&[GOOD]).code, 0);
    assert_eq!(run(&[BAD]).code, 1);
    assert_eq!(run(&["--format", "json", BAD]).code, 1);
}

#[test]
fn p_5_3c_a_warning_gives_exit_code_0() {
    let result = run(&[WARNING]);
    assert_eq!(result.code, 0);
    assert!(result.stdout.contains("1 warning"));
}

#[test]
fn p_5_3_a_bad_text_in_a_file_is_a_finding_and_not_a_read_error() {
    let file = write("not-json.json", "{");
    let result = run(&[&file]);
    assert_eq!(result.code, 1);
    assert!(result.stdout.contains("rule 5.3"), "{}", result.stdout);
}

#[test]
fn p_16_a_file_that_is_absent_is_exit_code_2_with_no_output() {
    let result = run(&["tests/fixtures/no-such-file.json"]);
    assert_eq!(result.code, 2);
    assert_eq!(result.stdout, "");
    assert!(
        result.stderr.contains("no-such-file.json"),
        "{}",
        result.stderr
    );
}

#[test]
fn p_16_a_directory_is_exit_code_2() {
    assert_eq!(run(&["tests/fixtures"]).code, 2);
}

#[test]
fn p_16_a_file_that_is_not_utf_8_is_exit_code_2() {
    let file = write("latin1.json", [0x7b, 0xe9, 0x7d]);
    let result = run(&[&file]);
    assert_eq!(result.code, 2);
    assert!(result.stderr.contains("not UTF-8"), "{}", result.stderr);
}

#[test]
fn p_16_a_grants_file_that_is_absent_stops_before_any_output() {
    let result = run(&["--grants", "tests/fixtures/none.json", GOOD]);
    assert_eq!(result.code, 2);
    assert_eq!(result.stdout, "");
    assert!(result.stderr.contains("none.json"));
}

#[test]
fn p_16_each_unreadable_input_is_named() {
    let result = run(&[
        "--grants",
        "tests/fixtures/none-a.json",
        "--options",
        "tests/fixtures/none-b.json",
        "tests/fixtures/none-c.json",
    ]);
    assert_eq!(result.code, 2);
    for name in ["none-a.json", "none-b.json", "none-c.json"] {
        assert!(result.stderr.contains(name), "{}", result.stderr);
    }
}

#[test]
fn p_5_1_an_https_url_is_exit_code_2() {
    let result = run(&["https://example.org/.well-known/procurauth/actions"]);
    assert_eq!(result.code, 2);
    assert_eq!(result.stdout, "");
    assert!(
        result.stderr.contains("https is not supported"),
        "{}",
        result.stderr
    );
}

fn serve_once(answer: Vec<u8>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap() > 0 {
            head.push(byte[0]);
        }
        stream.write_all(&answer).unwrap();
    });
    port
}

fn http_answer(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[test]
fn p_5_1_an_http_url_gives_the_document() {
    let body = serde_json::to_string(&datastore_document()).unwrap();
    let port = serve_once(http_answer(&body));
    let url = format!("http://127.0.0.1:{port}/.well-known/procurauth/actions");
    let result = run(&[&url]);
    assert_eq!(result.code, 0, "{}", result.stderr);
    assert_eq!(result.stdout, format!("{url}: no finding\n"));
}

#[test]
fn p_5_1_the_findings_of_a_url_are_reported() {
    let body = std::fs::read_to_string(BAD).unwrap();
    let port = serve_once(http_answer(&body));
    let url = format!("http://127.0.0.1:{port}/a");
    let result = run(&[&url]);
    assert_eq!(result.code, 1);
    assert!(result.stdout.starts_with(&format!("{url}: 1 error\n")));
}

#[test]
fn p_5_3_a_status_404_is_exit_code_2() {
    let port = serve_once(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec());
    let result = run(&[&format!("http://127.0.0.1:{port}/a")]);
    assert_eq!(result.code, 2);
    assert_eq!(result.stdout, "");
    assert!(result.stderr.contains("404"), "{}", result.stderr);
}

#[test]
fn p_5_3c_a_body_above_64_kib_is_exit_code_2() {
    let body = format!("{{\"server\": \"{}\"}}", "a".repeat(70_000));
    let port = serve_once(http_answer(&body));
    let result = run(&[&format!("http://127.0.0.1:{port}/a")]);
    assert_eq!(result.code, 2);
    assert!(result.stderr.contains("65536"), "{}", result.stderr);
}

#[test]
fn p_5_3c_a_file_above_64_kib_gets_a_warning_and_the_exit_code_0() {
    let mut document = datastore_document();
    document["resources"][0]["label"] = "label".into();
    let mut text = serde_json::to_string_pretty(&document).unwrap();
    text.push_str(&" ".repeat(70_000));
    let file = write("large-document.json", text);
    let result = run(&[&file]);
    assert_eq!(result.code, 0, "{}", result.stdout);
    assert!(result.stdout.contains("rule 5.3c"), "{}", result.stdout);
}

#[test]
fn p_16_the_program_runs_on_a_file_of_the_conformance_data() {
    let file = write(
        "datastore-document.json",
        serde_json::to_string_pretty(&datastore_document()).unwrap(),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_access-lint"))
        .arg(&file)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("{file}: no finding\n")
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn p_16_the_program_gives_exit_code_1_and_2() {
    let program = env!("CARGO_BIN_EXE_access-lint");
    let one = Command::new(program).arg(BAD).output().unwrap();
    assert_eq!(one.status.code(), Some(1));
    let two = Command::new(program).arg("--nothing").output().unwrap();
    assert_eq!(two.status.code(), Some(2));
    let help = Command::new(program).arg("--help").output().unwrap();
    assert_eq!(help.status.code(), Some(0));
}

#[test]
fn p_16_the_program_ignores_the_environment() {
    let program = env!("CARGO_BIN_EXE_access-lint");
    let plain = Command::new(program).arg(BAD).output().unwrap();
    let with_variables = Command::new(program)
        .arg(BAD)
        .env("NO_COLOR", "0")
        .env("CLICOLOR_FORCE", "1")
        .env("http_proxy", "http://127.0.0.1:1")
        .output()
        .unwrap();
    assert_eq!(plain.stdout, with_variables.stdout);
}

#[test]
fn p_6_10_a_bad_document_makes_the_tool_check_the_form_of_the_grants_only() {
    let result = run(&[
        "--grants",
        "tests/fixtures/grants/5.2_undeclared_action/fail.json",
        BAD,
    ]);
    assert_eq!(result.code, 1);
    assert!(result.stdout.contains("budget with"), "{}", result.stdout);
    assert!(
        result.stdout.ends_with("fail.json: no finding\n"),
        "{}",
        result.stdout
    );
}

#[test]
fn p_5_8_an_options_file_with_a_bad_text_is_a_finding() {
    let file = write("options-bad.json", "[");
    let result = run(&["--options", &file, GOOD]);
    assert_eq!(result.code, 1);
    assert!(result.stdout.contains("rule 5.8"), "{}", result.stdout);
}

#[test]
fn p_3_5_a_duplicate_member_in_the_grants_file_is_a_finding() {
    let file = write("grants-duplicate.json", r#"{"grants": [], "grants": []}"#);
    let result = run(&["--grants", &file, GOOD]);
    assert_eq!(result.code, 1);
    assert!(result.stdout.contains("rule 3.5"), "{}", result.stdout);
}
