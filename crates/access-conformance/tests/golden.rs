//! Golden tests: the exact text and JSON output of the tool.
//!
//! A golden file is in `tests/golden/`. When the output changes on purpose,
//! write the new output to the file by hand and read the difference. The
//! output holds the port of a listener and the directory of a test: the test
//! replaces them with fixed words before it compares.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;

use common::mock_pep::{self, CREDENTIAL, Defects, MockPep};
use common::*;

fn golden(name: &str, actual: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join(name);
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read the golden file {}: {e}", path.display()));
    assert_eq!(actual, expected, "the output differs from {name}");
}

/// Replace the port of a loopback URL and the test directory with fixed words.
fn mask(text: &str, dir: &Path) -> String {
    const PREFIX: &str = "http://127.0.0.1:";
    let text = text.replace(&dir.display().to_string(), "<dir>");
    let mut out = String::new();
    let mut rest = text.as_str();
    while let Some(at) = rest.find(PREFIX) {
        out.push_str(&rest[..at + PREFIX.len()]);
        let after = &rest[at + PREFIX.len()..];
        let digits = after.chars().take_while(char::is_ascii_digit).count();
        out.push_str("<port>");
        rest = &after[digits..];
    }
    out.push_str(rest);
    out
}

fn pdp_run(name: &str, extra: &[&str]) -> (Out, std::path::PathBuf) {
    let dir = temp_dir(name);
    let profile = write(&dir, "profile.json", r#"{"pdp": {"spawn_fake_pdp": true}}"#);
    let mut args = vec!["--role", "pdp", "--profile", &profile];
    args.extend_from_slice(extra);
    (run_cli(&args), dir)
}

fn pep_run(name: &str, defects: Defects, extra: &[&str]) -> (Out, std::path::PathBuf) {
    let dir = temp_dir(name);
    let pdp_port = free_port();
    let credential = write(&dir, "credential.txt", &format!("{CREDENTIAL}\n"));
    let mock = MockPep::start(format!("127.0.0.1:{pdp_port}").parse().unwrap(), defects);
    let profile = mock_pep::profile(pdp_port, Some(&credential), false);
    let profile_path = write(&dir, "profile.json", &profile.to_string());
    let url = mock.url();
    let mut args = vec!["--role", "pep", "--profile", &profile_path, "--url", &url];
    args.extend_from_slice(extra);
    let out = run_cli(&args);
    mock.stop();
    (out, dir)
}

#[test]
fn p_4_3_golden_text_of_three_cases_of_a_pdp() {
    let (out, _) = pdp_run("golden_pdp_text", &["--cases", "D01,D05,D41"]);
    assert_eq!(out.code, 0);
    golden("pdp_three_cases.txt", &out.stdout);
}

#[test]
fn p_4_3_golden_json_of_three_cases_of_a_pdp() {
    let (out, _) = pdp_run(
        "golden_pdp_json",
        &["--cases", "D01,D05,D41", "--format", "json"],
    );
    assert_eq!(out.code, 0);
    golden("pdp_three_cases.json", &out.stdout);
}

#[test]
fn p_10_3_golden_text_of_a_failure_a_skip_and_a_warning_of_a_pep() {
    let defects = Defects {
        budget_as_403: true,
        new_connection_each_time: true,
        ..Defects::default()
    };
    let (out, dir) = pep_run("golden_pep_text", defects, &["--cases", "U01,U04,U05,U69"]);
    assert_eq!(out.code, 1);
    golden("pep_mixed.txt", &mask(&out.stdout, &dir));
}

#[test]
fn p_10_3_golden_json_of_a_failure_a_skip_and_a_warning_of_a_pep() {
    let defects = Defects {
        budget_as_403: true,
        new_connection_each_time: true,
        ..Defects::default()
    };
    let (out, dir) = pep_run(
        "golden_pep_json",
        defects,
        &["--cases", "U01,U04,U05,U69", "--format", "json"],
    );
    assert_eq!(out.code, 1);
    golden("pep_mixed.json", &mask(&out.stdout, &dir));
}

#[test]
fn p_4_3_golden_effective_configuration_of_a_pdp() {
    let dir = temp_dir("golden_print_config");
    let credential = write(&dir, "credential.txt", "never-print-this-credential\n");
    let profile = write(
        &dir,
        "profile.json",
        &serde_json::json!({
            "pdp": {"spawn_fake_pdp": true, "credential_file": "credential.txt"},
            "timeouts": {"request_seconds": 5}
        })
        .to_string(),
    );
    let _ = credential;
    let out = run_cli(&[
        "--role",
        "pdp",
        "--profile",
        &profile,
        "--print-config",
        "--cases",
        "D01",
    ]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(!out.stdout.contains("never-print-this-credential"));
    golden("print_config_pdp.txt", &mask(&out.stdout, &dir));
    assert_eq!(out.stderr, "");
}
