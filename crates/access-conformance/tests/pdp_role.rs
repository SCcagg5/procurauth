//! The role pdp: the runner against `fake-pdp`, in the process and as a target.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::loadable_pdp::LoadablePdp;
use common::*;
use fake_pdp::{Options, Server};
use serde_json::{Value, json};

fn spawn_profile(dir: &Path) -> String {
    write(dir, "profile.json", r#"{"pdp": {"spawn_fake_pdp": true}}"#)
}

fn case_files(series: &str) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(repository().join("conformance/cases").join(series))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    files
}

fn read_case(id: &str) -> Value {
    let path = repository().join(format!("conformance/cases/D/{id}.json"));
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

/// A copy of the data of the cases, with changes to some cases of the series D.
type Change<'a> = &'a dyn Fn(&mut Value);

fn changed_data(name: &str, changes: &[(&str, Change<'_>)]) -> PathBuf {
    let root = temp_dir(name).join("conformance");
    let _ = fs::remove_dir_all(&root);
    for series in ["U", "D", "E"] {
        fs::create_dir_all(root.join("cases").join(series)).unwrap();
    }
    fs::create_dir_all(root.join("directories")).unwrap();
    for file in case_files("D") {
        fs::copy(&file, root.join("cases/D").join(file.file_name().unwrap())).unwrap();
    }
    for entry in fs::read_dir(repository().join("conformance/directories")).unwrap() {
        let path = entry.unwrap().path();
        fs::copy(
            &path,
            root.join("directories").join(path.file_name().unwrap()),
        )
        .unwrap();
    }
    for (id, change) in changes {
        let path = root.join(format!("cases/D/{id}.json"));
        let mut case: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        change(&mut case);
        fs::write(&path, case.to_string()).unwrap();
    }
    root
}

#[test]
fn all_74_cases_of_the_series_d_pass_against_fake_pdp_in_the_process() {
    let dir = temp_dir("pdp_spawn_all");
    let profile = spawn_profile(&dir);
    let out = run_cli(&["--role", "pdp", "--profile", &profile]);
    assert_eq!(out.code, 0, "{}\n{}", out.stdout, out.stderr);
    assert_eq!(out.summary(), "74 cases: 74 passed, 0 failed, 0 skipped");
    assert_eq!(out.stdout.lines().count(), 75);
    assert!(
        out.line("D01").starts_with("D01  pass  4.3,7.3"),
        "{}",
        out.line("D01")
    );
}

#[test]
fn the_json_form_has_74_passed_cases_and_no_target() {
    let dir = temp_dir("pdp_spawn_json");
    let profile = spawn_profile(&dir);
    let out = run_cli(&["--role", "pdp", "--profile", &profile, "--format", "json"]);
    assert_eq!(out.code, 0);
    let report = out.json();
    assert_eq!(report["role"], "pdp");
    assert_eq!(report["target"], Value::Null);
    assert_eq!(report["summary"]["passed"], 74);
    assert_eq!(report["cases"].as_array().unwrap().len(), 74);
}

#[test]
fn the_option_cases_runs_only_these_cases_and_the_series_must_fit_the_role() {
    let dir = temp_dir("pdp_cases_option");
    let profile = spawn_profile(&dir);
    let out = run_cli(&["--role", "pdp", "--profile", &profile, "--cases", "D05,D01"]);
    assert_eq!(out.code, 0);
    assert_eq!(out.ids_with("pass"), vec!["D01", "D05"]);
    assert_eq!(out.summary(), "2 cases: 2 passed, 0 failed, 0 skipped");
    let out = run_cli(&[
        "--role",
        "pdp",
        "--profile",
        &profile,
        "--series",
        "D",
        "--cases",
        "D01",
    ]);
    assert_eq!(out.code, 0);
    let out = run_cli(&["--role", "pdp", "--profile", &profile, "--series", "U"]);
    assert_eq!(out.code, 2);
    assert!(
        out.stderr.contains("`--series` and `--role` contradict"),
        "{}",
        out.stderr
    );
    assert_eq!(out.stdout, "");
}

fn flip_first_equals(case: &mut Value) {
    for step in case["steps"].as_array_mut().unwrap() {
        let Some(json) = step["expect"]["json"].as_object_mut() else {
            continue;
        };
        for matcher in json.values_mut() {
            if let Some(value) = matcher.get_mut("equals") {
                let changed = match &*value {
                    Value::Bool(b) => json!(!*b),
                    Value::Number(n) => json!(n.as_i64().unwrap() + 1),
                    Value::String(s) => json!(format!("{s}x")),
                    other => other.clone(),
                };
                *value = changed;
                return;
            }
        }
    }
    panic!("the case has no equals matcher");
}

#[test]
fn a_changed_expectation_makes_exactly_that_case_fail() {
    let dir = temp_dir("pdp_mutation");
    let profile = spawn_profile(&dir);
    let root = changed_data(
        "pdp_mutation_data",
        &[
            ("D05", &flip_first_equals),
            ("D35", &|case| {
                case["steps"][0]["expect"]["status"] = json!({"equals": 200})
            }),
            ("D50", &|case| {
                case["steps"][0]["expect"]["json"]["/context/reason"] = json!({"present": true});
            }),
        ],
    );
    let root_text = root.display().to_string();
    let out = run_cli(&[
        "--role",
        "pdp",
        "--profile",
        &profile,
        "--cases-dir",
        &root_text,
        "--cases",
        "D04,D05,D06,D34,D35,D36,D49,D50,D51",
    ]);
    assert_eq!(out.code, 1, "{}", out.stdout);
    assert_eq!(out.ids_with("fail"), vec!["D05", "D35", "D50"]);
    assert_eq!(
        out.ids_with("pass"),
        vec!["D04", "D06", "D34", "D36", "D49", "D51"]
    );
    assert!(
        out.line("D35").contains("status: expected 200, found 400"),
        "{}",
        out.line("D35")
    );
    assert!(
        out.line("D50")
            .contains("/context/reason: expected a value, found no value"),
        "{}",
        out.line("D50")
    );
    assert_eq!(out.summary(), "9 cases: 6 passed, 3 failed, 0 skipped");
}

#[test]
fn a_changed_matcher_of_each_form_is_checked() {
    // The matchers equals, absent, present, regex and one_of, each in a copy of D05.
    let dir = temp_dir("pdp_matchers");
    let profile = spawn_profile(&dir);
    let base = |case: &mut Value, matcher: Value| {
        case["steps"][0]["expect"] =
            json!({"status": {"equals": 200}, "json": {"/decision": matcher}});
    };
    let good = [
        json!({"equals": true}),
        json!({"present": true}),
        json!({"regex": "^true$"}),
        json!({"one_of": [false, true]}),
        json!({"not_regex": "^false$"}),
    ];
    let bad = [
        json!({"equals": false}),
        json!({"absent": true}),
        json!({"regex": "^false$"}),
        json!({"one_of": [false, 3]}),
        json!({"not_regex": "^true$"}),
    ];
    for (round, matchers) in [("good", &good), ("bad", &bad)] {
        for (index, matcher) in matchers.iter().enumerate() {
            let matcher = matcher.clone();
            let root = changed_data(
                &format!("pdp_matchers_{round}_{index}"),
                &[("D01", &|case| {
                    let steps = case["steps"].as_array().unwrap().len();
                    case["steps"].as_array_mut().unwrap().truncate(1);
                    let _ = steps;
                    base(case, matcher.clone());
                    case["steps"][0]["request"] = read_case("D01")["steps"][0]["request"].clone();
                })],
            );
            let root_text = root.display().to_string();
            let out = run_cli(&[
                "--role",
                "pdp",
                "--profile",
                &profile,
                "--cases-dir",
                &root_text,
                "--cases",
                "D01",
            ]);
            let expected = if round == "good" { "pass" } else { "fail" };
            assert_eq!(
                out.status_of("D01").as_deref(),
                Some(expected),
                "{round} {matcher}: {}",
                out.stdout
            );
        }
    }
}

fn external_profile(dir: &Path, extra: Value) -> String {
    let mut pdp = json!({"spawn_fake_pdp": false});
    for (k, v) in extra.as_object().unwrap() {
        pdp[k] = v.clone();
    }
    write(dir, "profile.json", &json!({"pdp": pdp}).to_string())
}

fn datastore_data() -> Value {
    serde_json::from_str(
        &fs::read_to_string(repository().join("conformance/directories/datastore.json")).unwrap(),
    )
    .unwrap()
}

fn admin_server(data: &Value) -> fake_pdp::RunningServer {
    Server::from_value(
        data,
        Options {
            admin: true,
            ..Options::default()
        },
    )
    .unwrap()
    .start("127.0.0.1:0")
    .unwrap()
}

#[test]
fn a_pdp_under_test_with_the_directory_passes_the_cases_that_need_no_clock() {
    let dir = temp_dir("pdp_external_ok");
    let server = admin_server(&datastore_data());
    let profile = external_profile(&dir, json!({}));
    let out = run_cli(&[
        "--role",
        "pdp",
        "--profile",
        &profile,
        "--url",
        &server.url(),
        "--cases",
        "D01,D02,D03,D04,D07,D08,D09,D13,D16,D17,D18,D19,D20,D34,D35,D36,D37",
    ]);
    assert_eq!(out.code, 0, "{}\n{}", out.stdout, out.stderr);
    assert_eq!(out.summary(), "17 cases: 17 passed, 0 failed, 0 skipped");
    server.shutdown();
}

#[test]
fn a_pdp_that_does_not_hold_the_directory_stops_the_run_with_exit_code_2_and_a_list() {
    let dir = temp_dir("pdp_external_wrong_directory");
    let other: Value = serde_json::from_str(
        &fs::read_to_string(repository().join("conformance/directories/access.json")).unwrap(),
    )
    .unwrap();
    let server = admin_server(&other);
    let profile = external_profile(&dir, json!({}));
    let out = run_cli(&[
        "--role",
        "pdp",
        "--profile",
        &profile,
        "--url",
        &server.url(),
        "--cases",
        "D01,D02,D03",
    ]);
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert_eq!(out.stdout, "");
    assert!(
        out.stderr
            .contains("does not hold the directory `datastore.json`"),
        "{}",
        out.stderr
    );
    assert!(out.stderr.contains("cases D01, D02, D03"), "{}", out.stderr);
    assert!(
        out.stderr.contains("control questions have another answer"),
        "{}",
        out.stderr
    );
    server.shutdown();
}

#[test]
fn the_directory_check_can_be_switched_off() {
    let dir = temp_dir("pdp_external_check_off");
    let other: Value = serde_json::from_str(
        &fs::read_to_string(repository().join("conformance/directories/access.json")).unwrap(),
    )
    .unwrap();
    let server = admin_server(&other);
    let profile = external_profile(&dir, json!({"directory_check": {"mode": "none"}}));
    let out = run_cli(&[
        "--role",
        "pdp",
        "--profile",
        &profile,
        "--url",
        &server.url(),
        "--cases",
        "D01",
    ]);
    // The cases run, and the answers show that the data is not the data of the case.
    assert_eq!(out.code, 1, "{}", out.stdout);
    assert_eq!(out.status_of("D01").as_deref(), Some("fail"));
    server.shutdown();
}

#[test]
fn without_the_control_of_the_clock_the_cases_that_need_it_are_skipped_with_the_reason() {
    let dir = temp_dir("pdp_external_skip");
    let mut budgets: Value = serde_json::from_str(
        &fs::read_to_string(repository().join("conformance/directories/budgets.json")).unwrap(),
    )
    .unwrap();
    budgets["clock"] = json!({"now": 1_792_569_648});
    let server = admin_server(&budgets);
    let profile = external_profile(&dir, json!({}));
    let out = run_cli(&[
        "--role",
        "pdp",
        "--profile",
        &profile,
        "--url",
        &server.url(),
        "--cases",
        "D41,D49,D63",
    ]);
    assert_eq!(out.code, 0, "{}\n{}", out.stdout, out.stderr);
    assert_eq!(out.ids_with("skip"), vec!["D41", "D49", "D63"]);
    assert!(
        out.line("D41")
            .contains("the profile has no load request, and the case sets counters"),
        "{}",
        out.line("D41")
    );
    assert!(
        out.line("D49")
            .contains("the profile gives no control of the clock of the PDP"),
        "{}",
        out.line("D49")
    );
    server.shutdown();
}

#[test]
fn with_a_reset_and_a_clock_url_the_usage_cases_that_set_no_counter_pass() {
    let dir = temp_dir("pdp_external_reset");
    let mut budgets: Value = serde_json::from_str(
        &fs::read_to_string(repository().join("conformance/directories/budgets.json")).unwrap(),
    )
    .unwrap();
    budgets["clock"] = json!({"now": 1_792_569_648});
    let server = admin_server(&budgets);
    let base = server.url();
    let profile = external_profile(
        &dir,
        json!({"reset_url": format!("{base}/__fake/reset"), "clock_admin_url": format!("{base}/__fake/clock")}),
    );
    let out = run_cli(&[
        "--role",
        "pdp",
        "--profile",
        &profile,
        "--url",
        &base,
        "--cases",
        "D49,D50,D51,D52,D53,D54,D55,D56,D62,D63",
    ]);
    assert_eq!(out.code, 0, "{}\n{}", out.stdout, out.stderr);
    assert_eq!(
        out.summary(),
        "10 cases: 10 passed, 0 failed, 0 skipped",
        "{}",
        out.stdout
    );
    server.shutdown();
}

#[test]
fn a_pdp_with_a_load_request_passes_all_74_cases() {
    let dir = temp_dir("pdp_external_load");
    let pdp = LoadablePdp::start();
    let base = pdp.url();
    let profile = external_profile(
        &dir,
        json!({"load": {"url": format!("{base}/__load"), "method": "PUT"},
               "clock_admin_url": format!("{base}/__fake/clock")}),
    );
    let out = run_cli(&["--role", "pdp", "--profile", &profile, "--url", &base]);
    assert_eq!(out.code, 0, "{}\n{}", out.stdout, out.stderr);
    assert_eq!(out.summary(), "74 cases: 74 passed, 0 failed, 0 skipped");
    // Each case loaded its own data, with the counters and the clock of the case.
    let loads = pdp.loads.lock().unwrap();
    assert_eq!(loads.len(), 74);
    assert!(loads.iter().any(|data| data["counters"].is_array()));
}

#[test]
fn a_pdp_that_asks_for_a_credential_gets_it_in_each_request() {
    let dir = temp_dir("pdp_credential");
    let credential = write(&dir, "credential.txt", "pdp-secret-credential-value\n");
    let profile = write(
        &dir,
        "profile.json",
        &json!({"pdp": {"spawn_fake_pdp": true, "credential_file": credential}}).to_string(),
    );
    let out = run_cli(&["--role", "pdp", "--profile", &profile, "--cases", "D01,D41"]);
    assert_eq!(out.code, 0, "{}\n{}", out.stdout, out.stderr);
    assert!(!out.stdout.contains("pdp-secret-credential-value"));
    assert!(!out.stderr.contains("pdp-secret-credential-value"));
    assert!(
        out.stderr.contains("pdp.credential_file = <hidden> (file:"),
        "{}",
        out.stderr
    );
}

#[test]
fn a_target_that_is_not_reachable_gives_exit_code_2() {
    let dir = temp_dir("pdp_unreachable");
    let profile = external_profile(&dir, json!({}));
    let port = free_port();
    let out = run_cli(&[
        "--role",
        "pdp",
        "--profile",
        &profile,
        "--url",
        &format!("http://127.0.0.1:{port}"),
    ]);
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("is not reachable"), "{}", out.stderr);
    assert_eq!(out.stdout, "");
}

#[test]
fn a_url_and_a_started_fake_pdp_contradict_each_other() {
    let dir = temp_dir("pdp_contradiction");
    let profile = spawn_profile(&dir);
    let out = run_cli(&[
        "--role",
        "pdp",
        "--profile",
        &profile,
        "--url",
        "http://127.0.0.1:9",
    ]);
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("contradict"), "{}", out.stderr);
    let none = external_profile(&dir, json!({}));
    let out = run_cli(&["--role", "pdp", "--profile", &none]);
    assert_eq!(out.code, 2);
    assert!(
        out.stderr.contains("Option `--url` is absent"),
        "{}",
        out.stderr
    );
}

#[test]
fn the_cases_that_the_program_holds_are_the_cases_of_the_directory() {
    let dir = temp_dir("pdp_embedded_vs_dir");
    let profile = spawn_profile(&dir);
    let root = repository().join("conformance").display().to_string();
    let a = run_cli(&["--role", "pdp", "--profile", &profile, "--format", "json"]);
    let b = run_cli(&[
        "--role",
        "pdp",
        "--profile",
        &profile,
        "--format",
        "json",
        "--cases-dir",
        &root,
    ]);
    assert_eq!(a.stdout, b.stdout);
}
