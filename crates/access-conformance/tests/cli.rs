//! The command line: usage errors, exit codes, streams, the profile and the secrets.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use serde_json::json;

fn pdp_profile(name: &str, body: &str) -> String {
    write(&temp_dir(name), "profile.json", body)
}

#[test]
fn the_version_gives_the_version_and_the_licence() {
    for flag in ["--version", "-V"] {
        let out = run_cli(&[flag]);
        assert_eq!(out.code, 0);
        assert_eq!(
            out.stdout,
            format!(
                "access-conformance {}\nApache-2.0\n",
                env!("CARGO_PKG_VERSION")
            )
        );
        assert_eq!(out.stderr, "");
    }
}

#[test]
fn the_help_goes_to_stdout_with_no_colour_and_names_the_options_and_the_exit_codes() {
    for flag in ["--help", "-h"] {
        let out = run_cli(&[flag]);
        assert_eq!(out.code, 0);
        assert_eq!(out.stderr, "");
        assert!(!out.stdout.contains('\u{1b}'));
        for text in [
            "Usage: access-conformance",
            "--role <ROLE>",
            "--profile <FILE>",
            "--url <URL>",
            "--cases <ID,ID,...>",
            "--series <SERIES>",
            "--format <FORMAT>",
            "--cases-dir <DIR>",
            "--print-config",
            "Exit codes: 0 each case that ran passed, 1 at least one case failed, 2 usage error",
            "Apache-2.0",
        ] {
            assert!(out.stdout.contains(text), "{text} in {}", out.stdout);
        }
    }
}

#[test]
fn a_run_with_no_argument_is_a_usage_error() {
    let out = run_cli(&[]);
    assert_eq!(out.code, 2);
    assert_eq!(out.stdout, "");
    assert!(!out.stderr.is_empty());
}

#[test]
fn an_unknown_option_a_missing_option_and_a_repeated_option_are_usage_errors() {
    let profile = pdp_profile("cli_usage", r#"{"pdp": {"spawn_fake_pdp": true}}"#);
    for args in [
        vec!["--role", "pdp", "--profile", &profile, "--nothing"],
        vec!["--role", "pdp"],
        vec!["--profile", &profile],
        vec!["--role", "other", "--profile", &profile],
        vec!["--role", "pdp", "--profile", &profile, "--format", "xml"],
        vec![
            "--role",
            "pdp",
            "--profile",
            &profile,
            "--format",
            "text",
            "--format",
            "json",
        ],
        vec!["--role", "pdp", "--role", "pep", "--profile", &profile],
    ] {
        let out = run_cli(&args);
        assert_eq!(out.code, 2, "{args:?}");
        assert_eq!(out.stdout, "", "{args:?}");
        assert!(out.stderr.contains("error"), "{args:?}: {}", out.stderr);
    }
}

#[test]
fn a_profile_that_is_absent_or_not_json_gives_exit_code_2() {
    let dir = temp_dir("cli_profile_file");
    let missing = dir.join("nothing.json").display().to_string();
    let out = run_cli(&["--role", "pdp", "--profile", &missing]);
    assert_eq!(out.code, 2);
    assert!(
        out.stderr
            .contains("Option `--profile`: cannot read the file"),
        "{}",
        out.stderr
    );
    let bad = write(&dir, "bad.json", "{not json");
    let out = run_cli(&["--role", "pdp", "--profile", &bad]);
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("is not valid JSON"), "{}", out.stderr);
}

#[test]
fn an_unknown_member_and_a_duplicate_member_stop_the_program_before_any_request() {
    // The target is not reachable. The profile error comes first, so the message is not about the target.
    let url = format!("http://127.0.0.1:{}", free_port());
    let unknown = pdp_profile(
        "cli_unknown",
        r#"{"pdp": {"spawn_fake_pdp": false, "extra": 1}}"#,
    );
    let out = run_cli(&["--role", "pdp", "--profile", &unknown, "--url", &url]);
    assert_eq!(out.code, 2);
    assert!(
        out.stderr
            .contains("$.pdp.extra: Member `extra` is not known here."),
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains("not reachable"));
    let duplicate = pdp_profile(
        "cli_duplicate",
        r#"{"pdp": {"spawn_fake_pdp": false, "spawn_fake_pdp": true}}"#,
    );
    let out = run_cli(&["--role", "pdp", "--profile", &duplicate, "--url", &url]);
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("duplicate"), "{}", out.stderr);
}

#[test]
fn an_error_of_the_profile_names_the_key_the_expected_type_and_the_value() {
    let profile = pdp_profile(
        "cli_types",
        r#"{"timeouts": {"request_seconds": "ten", "case_seconds": 0, "settle_ms": 1.5}, "pdp": {"spawn_fake_pdp": "yes"}}"#,
    );
    let out = run_cli(&["--role", "pdp", "--profile", &profile]);
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("$.timeouts.request_seconds: Member `request_seconds`: expected a whole number of 0 or more, found a string: \"ten\"."), "{}", out.stderr);
    assert!(out.stderr.contains("$.timeouts.case_seconds: Member `case_seconds`: expected a whole number from 1 to 3600, found 0."), "{}", out.stderr);
    assert!(out.stderr.contains("`settle_ms`"), "{}", out.stderr);
    assert!(out.stderr.contains("$.pdp.spawn_fake_pdp: Member `spawn_fake_pdp`: expected a boolean, found a string: \"yes\"."), "{}", out.stderr);
    // Every error shows, not only the first.
    assert!(out.stderr.matches("error: ").count() >= 4, "{}", out.stderr);
}

#[test]
fn a_profile_with_no_section_for_the_role_gives_exit_code_2() {
    let profile = pdp_profile("cli_no_section", r#"{"pdp": {"spawn_fake_pdp": true}}"#);
    let out = run_cli(&[
        "--role",
        "pep",
        "--profile",
        &profile,
        "--url",
        "http://127.0.0.1:9",
    ]);
    assert_eq!(out.code, 2);
    assert!(
        out.stderr
            .contains("the member `pep` is absent, and the role pep needs it"),
        "{}",
        out.stderr
    );
}

#[test]
fn the_option_url_needs_an_http_url_with_no_path() {
    let profile = pdp_profile("cli_url", r#"{"pdp": {}}"#);
    for (url, word) in [
        ("https://127.0.0.1:9", "https is not supported"),
        ("127.0.0.1:9", "starts with http://"),
        ("http://127.0.0.1:9/mcp", "with no path"),
        ("http://127.0.0.1:0", "port from 1 to 65535"),
    ] {
        let out = run_cli(&["--role", "pdp", "--profile", &profile, "--url", url]);
        assert_eq!(out.code, 2, "{url}");
        assert!(out.stderr.contains(word), "{url}: {}", out.stderr);
    }
}

#[test]
fn a_case_directory_that_is_not_valid_gives_exit_code_2() {
    let profile = pdp_profile("cli_cases_dir", r#"{"pdp": {"spawn_fake_pdp": true}}"#);
    let empty = temp_dir("cli_cases_dir_empty").display().to_string();
    let out = run_cli(&[
        "--role",
        "pdp",
        "--profile",
        &profile,
        "--cases-dir",
        &empty,
    ]);
    assert_eq!(out.code, 2);
    assert!(
        out.stderr.contains("Cannot read the directory"),
        "{}",
        out.stderr
    );
}

#[test]
fn the_effective_configuration_goes_to_stderr_at_start_and_to_stdout_with_the_option() {
    let dir = temp_dir("cli_print_config");
    write(&dir, "credential.txt", "never-print-this-credential\n");
    let profile = write(
        &dir,
        "profile.json",
        &json!({"pdp": {"spawn_fake_pdp": true, "credential_file": "credential.txt"}}).to_string(),
    );
    let out = run_cli(&["--role", "pdp", "--profile", &profile, "--cases", "D01"]);
    assert_eq!(out.code, 0);
    assert!(
        out.stderr
            .contains("config: timeouts.request_seconds = 10 (default)"),
        "{}",
        out.stderr
    );
    assert!(
        out.stderr
            .contains("config: pdp.credential_file = <hidden> (file:"),
        "{}",
        out.stderr
    );
    assert!(!out.stdout.contains("config:"));
    let out = run_cli(&[
        "--role",
        "pdp",
        "--profile",
        &profile,
        "--cases",
        "D01",
        "--print-config",
    ]);
    assert_eq!(out.code, 0);
    assert!(
        out.stdout.contains("pdp.spawn_fake_pdp = true (profile)"),
        "{}",
        out.stdout
    );
    assert!(!out.stdout.contains("D01  "));
}

#[test]
fn the_option_print_config_checks_the_files_and_makes_no_request() {
    let dir = temp_dir("cli_print_config_files");
    let profile = write(
        &dir,
        "profile.json",
        &json!({"pdp": {"spawn_fake_pdp": true, "credential_file": "absent.txt"}}).to_string(),
    );
    let out = run_cli(&["--role", "pdp", "--profile", &profile, "--print-config"]);
    assert_eq!(out.code, 2);
    assert!(
        out.stderr
            .contains("Key `pdp.credential_file`: cannot read the file"),
        "{}",
        out.stderr
    );
    assert_eq!(out.stdout, "");
}

#[test]
fn an_empty_credential_file_stops_the_program_and_no_output_holds_a_secret() {
    let dir = temp_dir("cli_secret");
    write(&dir, "empty.txt", "\n");
    let profile = write(
        &dir,
        "profile.json",
        &json!({"pdp": {"spawn_fake_pdp": true, "credential_file": "empty.txt"}}).to_string(),
    );
    let out = run_cli(&["--role", "pdp", "--profile", &profile]);
    assert_eq!(out.code, 2);
    assert!(
        out.stderr.contains("expected a file that is not empty"),
        "{}",
        out.stderr
    );
    // A secret in clear text is an unknown key: the schema has no such key.
    let clear = write(
        &dir,
        "clear.json",
        &json!({"pdp": {"spawn_fake_pdp": true, "credential": "clear-text-secret"}}).to_string(),
    );
    let out = run_cli(&["--role", "pdp", "--profile", &clear]);
    assert_eq!(out.code, 2);
    assert!(
        out.stderr.contains("`credential` is not known"),
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains("clear-text-secret"));
}

#[test]
fn an_edge_profile_with_a_secret_file_shows_its_path_and_never_its_text() {
    let dir = temp_dir("cli_edge_print");
    let profile = common::mock_edge::profile(1, 2, &dir, "edge-jwks.json", false, false);
    let path = write(&dir, "profile.json", &profile.to_string());
    let out = run_cli(&[
        "--role",
        "edge",
        "--profile",
        &path,
        "--print-config",
        "--url",
        "http://127.0.0.1:9",
    ]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stdout
            .contains("edge.keys.valid.text_file = <hidden> (file:"),
        "{}",
        out.stdout
    );
    assert!(!out.stdout.contains(common::mock_edge::VALID_KEY));
    assert!(!out.stdout.contains(common::mock_edge::CREDENTIAL));
}

#[test]
fn a_pep_profile_with_a_key_file_shows_its_path_and_never_its_text() {
    let dir = temp_dir("cli_pep_print");
    let profile = common::mock_pep::profile(free_port(), None, false);
    let path = write(&dir, "profile.json", &profile.to_string());
    let out = run_cli(&[
        "--role",
        "pep",
        "--profile",
        &path,
        "--print-config",
        "--url",
        "http://127.0.0.1:9",
    ]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stdout
            .contains("pep.token.keys[0].file = <hidden> (file:"),
        "{}",
        out.stdout
    );
    assert!(!out.stdout.contains("BEGIN PRIVATE KEY"));
}
