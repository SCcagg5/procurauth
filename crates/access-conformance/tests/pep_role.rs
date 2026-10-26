//! The role pep against scripted mock services.
//!
//! The correct mock behaves like a PEP for the cases without MCP and without the
//! options route. Each flag of `Defects` makes it wrong in one way, and the test
//! names the cases that must fail.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::mock_pep::{self, CREDENTIAL, Defects, MockPep};
use common::*;

/// Run the cases of the series U against a mock with the given defects.
fn run_pep_with(name: &str, defects: Defects, enforce_credential: bool, extra: &[&str]) -> Out {
    let dir = temp_dir(name);
    let pdp_port = free_port();
    let credential = write(&dir, "credential.txt", &format!("{CREDENTIAL}\n"));
    let mock = MockPep::start(
        format!("127.0.0.1:{pdp_port}").parse().unwrap(),
        defects.clone(),
    );
    let profile = mock_pep::profile(
        pdp_port,
        enforce_credential.then_some(credential.as_str()),
        defects.cache_true_answers,
    );
    let profile_path = write(&dir, "profile.json", &profile.to_string());
    let url = mock.url();
    let mut args = vec!["--role", "pep", "--profile", &profile_path, "--url", &url];
    args.extend_from_slice(extra);
    let out = run_cli(&args);
    mock.stop();
    out
}

fn run_pep(name: &str, defects: Defects, extra: &[&str]) -> Out {
    run_pep_with(name, defects, true, extra)
}

#[test]
fn a_correct_service_passes_every_case_that_the_runner_can_run() {
    let out = run_pep("pep_correct", Defects::default(), &[]);
    assert_eq!(out.code, 0, "{}\n{}", out.stdout, out.stderr);
    assert_eq!(out.ids_with("fail"), Vec::<String>::new());
    assert_eq!(out.ids_with("warn"), Vec::<String>::new());
    assert_eq!(out.summary(), "99 cases: 58 passed, 0 failed, 41 skipped");
    // The mock has no options route, no MCP endpoint and no use that needs two permissions.
    assert!(out.line("U05").contains("skip"), "{}", out.line("U05"));
    assert!(
        out.line("U05")
            .ends_with("the service has no options route")
    );
    assert!(out.line("U18").ends_with("the service has no MCP endpoint"));
    assert!(
        out.line("U34")
            .ends_with("the service has no use that needs two permissions")
    );
}

#[test]
fn a_correct_service_passes_with_the_credential_checked_by_the_test_pdp() {
    let out = run_pep_with(
        "pep_correct_no_credential",
        Defects::default(),
        false,
        &["--cases", "U56,U01"],
    );
    assert_eq!(out.code, 0, "{}", out.stdout);
}

fn failing(out: &Out) -> Vec<String> {
    out.ids_with("fail")
}

#[test]
fn p_10_3_a_budget_refusal_with_the_status_403_fails_the_cases_of_the_status_429() {
    let out = run_pep(
        "pep_budget_403",
        Defects {
            budget_as_403: true,
            ..Defects::default()
        },
        &[],
    );
    assert_eq!(out.code, 1);
    assert_eq!(failing(&out), vec!["U04", "U58", "U62", "U63"]);
    assert!(
        out.line("U04").contains("status: expected 429, found 403"),
        "{}",
        out.line("U04")
    );
}

#[test]
fn p_10_0_a_service_that_sends_no_credential_fails_the_case_of_the_credential() {
    let out = run_pep_with(
        "pep_no_credential",
        Defects {
            no_credential: true,
            ..Defects::default()
        },
        false,
        &[],
    );
    assert_eq!(out.code, 1);
    assert_eq!(failing(&out), vec!["U56"]);
}

#[test]
fn p_10_0_a_service_that_sends_no_credential_to_a_pdp_that_asks_for_it_fails_every_use() {
    let out = run_pep(
        "pep_no_credential_enforced",
        Defects {
            no_credential: true,
            ..Defects::default()
        },
        &["--cases", "U01,U13,U56"],
    );
    assert_eq!(out.code, 1);
    // The test PDP answers 401, and a correct PEP then gives 503.
    assert_eq!(failing(&out), vec!["U01", "U56"]);
    assert_eq!(out.status_of("U13").as_deref(), Some("pass"));
}

#[test]
fn p_9_4_a_service_that_does_not_check_the_signature_fails_the_case_of_the_bad_signature() {
    let out = run_pep(
        "pep_bad_signature",
        Defects {
            accept_bad_signature: true,
            ..Defects::default()
        },
        &[],
    );
    assert_eq!(out.code, 1);
    assert_eq!(failing(&out), vec!["U03"]);
    assert!(
        out.line("U03").contains("status: expected 401, found "),
        "{}",
        out.line("U03")
    );
}

#[test]
fn p_9_4_a_service_that_reads_the_token_from_authorization_fails_the_case_of_the_header() {
    let out = run_pep(
        "pep_token_authorization",
        Defects {
            token_from_authorization: true,
            ..Defects::default()
        },
        &[],
    );
    assert_eq!(out.code, 1);
    assert_eq!(failing(&out), vec!["U54"]);
}

#[test]
fn p_10_3_a_service_that_fails_open_fails_the_cases_of_the_error_of_the_pdp() {
    let out = run_pep(
        "pep_fail_open",
        Defects {
            fail_open: true,
            ..Defects::default()
        },
        &[],
    );
    assert_eq!(out.code, 1);
    assert_eq!(failing(&out), vec!["U06", "U64", "U65", "U68"]);
}

#[test]
fn p_10_1_a_service_that_keeps_a_true_answer_fails_the_case_of_the_units() {
    let out = run_pep(
        "pep_cache",
        Defects {
            cache_true_answers: true,
            ..Defects::default()
        },
        &[],
    );
    assert_eq!(out.code, 1, "{}", out.stdout);
    assert!(
        failing(&out).contains(&"U22".to_owned()),
        "{:?}",
        failing(&out)
    );
    // The reset request of the profile clears the kept answers between the cases:
    // a case does not fail because of an earlier case.
    assert!(!failing(&out).contains(&"U19".to_owned()));
    assert!(!failing(&out).contains(&"U01".to_owned()));
}

#[test]
fn p_10_3_a_refusal_that_shows_the_reason_fails_the_case_of_the_reason() {
    let out = run_pep(
        "pep_leak_reason",
        Defects {
            leak_reason: true,
            ..Defects::default()
        },
        &[],
    );
    assert_eq!(out.code, 1);
    assert_eq!(failing(&out), vec!["U61"]);
}

#[test]
fn p_10_7_a_service_with_a_new_connection_for_each_question_gets_a_warning_and_the_exit_code_0() {
    let out = run_pep(
        "pep_connections",
        Defects {
            new_connection_each_time: true,
            ..Defects::default()
        },
        &[],
    );
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert_eq!(out.ids_with("warn"), vec!["U69"]);
    assert_eq!(
        out.summary(),
        "99 cases: 57 passed, 0 failed, 41 skipped, 1 warned"
    );
    assert!(
        out.line("U69")
            .contains("connections of the PDP: expected one of [1, 2], found 4"),
        "{}",
        out.line("U69")
    );
}

#[test]
fn the_option_cases_runs_the_cases_in_the_order_of_the_data() {
    let out = run_pep(
        "pep_cases_option",
        Defects::default(),
        &["--cases", "U20,U01,U03"],
    );
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert_eq!(out.ids_with("pass"), vec!["U01", "U03", "U20"]);
    assert_eq!(out.summary(), "3 cases: 3 passed, 0 failed, 0 skipped");
}

#[test]
fn a_case_of_another_role_is_a_usage_error() {
    let out = run_pep("pep_wrong_series", Defects::default(), &["--cases", "D01"]);
    assert_eq!(out.code, 2);
    assert!(
        out.stderr.contains("the case D01 is for the role pdp"),
        "{}",
        out.stderr
    );
    assert_eq!(out.stdout, "");
    let out = run_pep(
        "pep_unknown_case",
        Defects::default(),
        &["--cases", "U01,U9999"],
    );
    assert_eq!(out.code, 2);
    assert!(
        out.stderr
            .contains("expected the id of a case, found \"U9999\""),
        "{}",
        out.stderr
    );
}

#[test]
fn the_json_form_lists_the_failures_and_the_reasons_of_the_skips() {
    let out = run_pep(
        "pep_json",
        Defects {
            budget_as_403: true,
            ..Defects::default()
        },
        &["--format", "json", "--cases", "U01,U04,U05"],
    );
    assert_eq!(out.code, 1);
    let report = out.json();
    assert_eq!(
        report["summary"],
        serde_json::json!({"cases": 3, "passed": 1, "failed": 1, "skipped": 1, "warned": 0})
    );
    let cases = report["cases"].as_array().unwrap();
    assert_eq!(cases[1]["id"], "U04");
    assert_eq!(cases[1]["status"], "fail");
    assert_eq!(
        cases[1]["failures"][0]["step"],
        "Use of an action that lists a budget"
    );
    assert_eq!(
        cases[1]["failures"][0]["message"],
        "status: expected 429, found 403"
    );
    assert_eq!(cases[2]["reason"], "the service has no options route");
    assert_eq!(
        report["target"]
            .as_str()
            .unwrap()
            .starts_with("http://127.0.0.1:"),
        true
    );
}

#[test]
fn a_service_that_gives_no_answer_fails_the_case_with_the_message_of_the_request() {
    // A listener that accepts a connection and never answers.
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", silent.local_addr().unwrap());
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in silent.incoming().flatten() {
            held.push(stream);
        }
    });
    let dir = temp_dir("pep_silent");
    let pdp_port = free_port();
    let credential = write(&dir, "credential.txt", &format!("{CREDENTIAL}\n"));
    let mut profile = mock_pep::profile(pdp_port, Some(&credential), false);
    profile["timeouts"] =
        serde_json::json!({"request_seconds": 1, "case_seconds": 5, "settle_ms": 0});
    let path = write(&dir, "profile.json", &profile.to_string());
    let out = run_cli(&[
        "--role",
        "pep",
        "--profile",
        &path,
        "--url",
        &url,
        "--cases",
        "U01",
    ]);
    assert_eq!(out.code, 1, "{}\n{}", out.stdout, out.stderr);
    assert!(
        out.line("U01").contains("the request failed: "),
        "{}",
        out.line("U01")
    );
}

#[test]
fn a_service_that_is_not_reachable_gives_exit_code_2_before_any_request() {
    let dir = temp_dir("pep_unreachable");
    let pdp_port = free_port();
    let profile = mock_pep::profile(pdp_port, None, false);
    let path = write(&dir, "profile.json", &profile.to_string());
    let port = free_port();
    let out = run_cli(&[
        "--role",
        "pep",
        "--profile",
        &path,
        "--url",
        &format!("http://127.0.0.1:{port}"),
    ]);
    assert_eq!(out.code, 2);
    assert_eq!(out.stdout, "");
    assert!(out.stderr.contains("is not reachable"), "{}", out.stderr);
}
