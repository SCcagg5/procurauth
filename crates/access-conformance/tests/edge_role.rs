//! The role edge against scripted mock edges.
//!
//! The correct mock knows three key texts, asks the PDP for the action `access`,
//! and forwards the accepted requests with an identity token. Each flag of
//! `EdgeDefects` makes it wrong in one way, and the test names the cases that
//! must fail.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::mock_edge::{self, EdgeDefects, MockEdge};
use common::*;

fn run_edge(name: &str, defects: EdgeDefects, jwks: &str, mcp: bool, extra: &[&str]) -> Out {
    let dir = temp_dir(name);
    let pdp_port = free_port();
    let upstream_port = free_port();
    let cache = defects.token_cache;
    let mock = MockEdge::start(
        format!("127.0.0.1:{pdp_port}").parse().unwrap(),
        format!("127.0.0.1:{upstream_port}").parse().unwrap(),
        defects,
    );
    let profile = mock_edge::profile(pdp_port, upstream_port, &dir, jwks, mcp, cache);
    let profile_path = write(&dir, "profile.json", &profile.to_string());
    let url = mock.url();
    let mut args = vec!["--role", "edge", "--profile", &profile_path, "--url", &url];
    args.extend_from_slice(extra);
    run_cli(&args)
}

fn two_keys(name: &str, defects: EdgeDefects) -> Out {
    run_edge(name, defects, "edge-jwks.json", true, &[])
}

#[test]
fn a_correct_edge_passes_every_case_that_the_runner_can_run() {
    let out = two_keys("edge_correct", EdgeDefects::default());
    assert_eq!(out.code, 0, "{}\n{}", out.stdout, out.stderr);
    assert_eq!(out.summary(), "18 cases: 16 passed, 0 failed, 2 skipped");
    assert_eq!(out.ids_with("skip"), vec!["E15", "E16"]);
    assert!(
        out.line("E15")
            .ends_with("the edge keeps no identity token")
    );
}

#[test]
fn a_profile_with_no_mcp_path_skips_the_cases_of_the_mcp_endpoint() {
    let out = run_edge(
        "edge_no_mcp",
        EdgeDefects::default(),
        "edge-jwks.json",
        false,
        &[],
    );
    assert_eq!(out.code, 0, "{}\n{}", out.stdout, out.stderr);
    assert_eq!(
        out.ids_with("skip"),
        vec!["E01", "E15", "E16", "E17", "E18"]
    );
    assert!(out.line("E01").ends_with("the service has no MCP endpoint"));
}

#[test]
fn a_key_set_with_one_key_skips_the_case_of_the_kid() {
    // The key of the set has no kid, so the token has none.
    let defects = EdgeDefects {
        no_kid: true,
        ..EdgeDefects::default()
    };
    let out = run_edge("edge_one_key", defects, "edge-jwks-one.json", true, &[]);
    assert_eq!(out.code, 0, "{}\n{}", out.stdout, out.stderr);
    assert!(out.ids_with("skip").contains(&"E13".to_owned()));
    assert!(
        out.line("E13")
            .ends_with("the key set of the edge holds one key")
    );
}

#[test]
fn p_9_9_an_edge_that_keeps_tokens_passes_the_cases_of_the_cache() {
    let out = two_keys(
        "edge_cache",
        EdgeDefects {
            token_cache: true,
            ..EdgeDefects::default()
        },
    );
    assert_eq!(out.code, 0, "{}\n{}", out.stdout, out.stderr);
    assert_eq!(out.summary(), "18 cases: 18 passed, 0 failed, 0 skipped");
}

#[test]
fn p_9_9_an_edge_that_gives_a_kept_token_to_a_stranger_fails_the_case_of_the_cache() {
    let out = two_keys(
        "edge_cache_leak",
        EdgeDefects {
            token_cache: true,
            cache_leak: true,
            ..EdgeDefects::default()
        },
    );
    assert_eq!(out.code, 1);
    // The cases E11 and E17 send a request with no key, and the edge serves it from its cache.
    assert_eq!(out.ids_with("fail"), vec!["E11", "E15", "E17"]);
}

fn failing(name: &str, defects: EdgeDefects) -> Vec<String> {
    let out = two_keys(name, defects);
    assert_eq!(out.code, 1, "{}", out.stdout);
    out.ids_with("fail")
}

#[test]
fn p_9_1_an_edge_that_forwards_the_key_text_fails_the_case_of_the_header_authorization() {
    let list = failing(
        "edge_keep_authorization",
        EdgeDefects {
            keep_authorization: true,
            ..EdgeDefects::default()
        },
    );
    assert_eq!(list, vec!["E06"]);
}

#[test]
fn p_9_1_an_edge_that_keeps_a_forged_identity_header_fails_the_case_of_the_replacement() {
    let list = failing(
        "edge_forged_header",
        EdgeDefects {
            keep_forged_header: true,
            ..EdgeDefects::default()
        },
    );
    assert_eq!(list, vec!["E05"]);
}

#[test]
fn p_9_8_an_edge_that_redirects_a_refusal_fails_the_cases_of_the_status_401() {
    let list = failing(
        "edge_redirect",
        EdgeDefects {
            redirect_on_refusal: true,
            ..EdgeDefects::default()
        },
    );
    for id in ["E01", "E02", "E03", "E04", "E09", "E10", "E11", "E17"] {
        assert!(list.contains(&id.to_owned()), "{id} in {list:?}");
    }
    assert!(!list.contains(&"E06".to_owned()));
}

#[test]
fn p_9_8_an_edge_that_gives_a_body_with_a_refusal_fails_the_cases_of_the_empty_body() {
    let out = two_keys(
        "edge_body",
        EdgeDefects {
            body_on_refusal: true,
            ..EdgeDefects::default()
        },
    );
    assert_eq!(out.code, 1);
    let list = out.ids_with("fail");
    for id in ["E01", "E02", "E03", "E09", "E10", "E17"] {
        assert!(list.contains(&id.to_owned()), "{id} in {list:?}");
    }
    assert!(
        out.line("E02").contains("body: expected \"\", found "),
        "{}",
        out.line("E02")
    );
}

#[test]
fn p_9_8_an_edge_that_adds_an_error_to_a_missing_key_fails_the_cases_of_the_bare_challenge() {
    let list = failing(
        "edge_error_on_missing",
        EdgeDefects {
            error_on_missing: true,
            ..EdgeDefects::default()
        },
    );
    assert_eq!(list, vec!["E03", "E11", "E17"]);
}

#[test]
fn p_8_3_an_edge_that_does_not_ask_for_access_fails_the_case_of_the_subject_with_no_access() {
    let list = failing(
        "edge_no_access_check",
        EdgeDefects {
            skip_access_check: true,
            ..EdgeDefects::default()
        },
    );
    assert_eq!(list, vec!["E10"]);
}

#[test]
fn p_9_3_an_edge_that_puts_the_key_text_in_the_token_fails_the_cases_of_the_claims() {
    let out = two_keys(
        "edge_leak_key",
        EdgeDefects {
            leak_key: true,
            ..EdgeDefects::default()
        },
    );
    assert_eq!(out.code, 1);
    let list = out.ids_with("fail");
    for id in ["E05", "E07", "E14"] {
        assert!(list.contains(&id.to_owned()), "{id} in {list:?}");
    }
    assert!(
        out.line("E14").contains("token claims /sub"),
        "{}",
        out.line("E14")
    );
}

#[test]
fn p_9_4_an_edge_that_gives_no_kid_to_a_set_of_two_keys_fails_the_cases_of_the_token() {
    let out = two_keys(
        "edge_no_kid",
        EdgeDefects {
            no_kid: true,
            ..EdgeDefects::default()
        },
    );
    assert_eq!(out.code, 1);
    let list = out.ids_with("fail");
    assert!(list.contains(&"E13".to_owned()), "{list:?}");
    assert!(list.contains(&"E12".to_owned()), "{list:?}");
    assert!(
        out.line("E13").contains("is not good"),
        "{}",
        out.line("E13")
    );
}

#[test]
fn the_json_form_of_an_edge_run_names_the_role_and_the_target() {
    let out = run_edge(
        "edge_json",
        EdgeDefects::default(),
        "edge-jwks.json",
        true,
        &["--format", "json", "--cases", "E02,E15"],
    );
    assert_eq!(out.code, 0, "{}\n{}", out.stdout, out.stderr);
    let report = out.json();
    assert_eq!(report["role"], "edge");
    assert_eq!(report["cases"][1]["status"], "skip");
    assert_eq!(
        report["cases"][1]["reason"],
        "the edge keeps no identity token"
    );
}

#[test]
fn an_edge_that_is_not_reachable_gives_exit_code_2() {
    let dir = temp_dir("edge_unreachable");
    let profile = mock_edge::profile(
        free_port(),
        free_port(),
        &dir,
        "edge-jwks.json",
        false,
        false,
    );
    let path = write(&dir, "profile.json", &profile.to_string());
    let out = run_cli(&[
        "--role",
        "edge",
        "--profile",
        &path,
        "--url",
        &format!("http://127.0.0.1:{}", free_port()),
    ]);
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("is not reachable"), "{}", out.stderr);
}

#[test]
fn a_missing_key_file_stops_the_program_before_any_request() {
    let dir = temp_dir("edge_missing_key");
    let mut profile = mock_edge::profile(
        free_port(),
        free_port(),
        &dir,
        "edge-jwks.json",
        false,
        false,
    );
    profile["edge"]["keys"]["valid"]["text_file"] =
        serde_json::json!(dir.join("nothing.txt").display().to_string());
    let path = write(&dir, "profile.json", &profile.to_string());
    let out = run_cli(&[
        "--role",
        "edge",
        "--profile",
        &path,
        "--url",
        "http://127.0.0.1:9",
    ]);
    assert_eq!(out.code, 2);
    assert!(
        out.stderr
            .contains("Key `edge.keys.valid.text_file`: cannot read the file"),
        "{}",
        out.stderr
    );
}
