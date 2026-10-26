//! The schemas of the profile and of the report, and their agreement with the program.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;

use access_conformance::check_profile;
use common::mock_pep::{self, CREDENTIAL, Defects, MockPep};
use common::*;
use procurauth_schema_check::Schemas;
use serde_json::{Value, json};

fn example(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(examples().join(name)).unwrap()).unwrap()
}

#[test]
fn each_example_profile_is_valid_against_the_schema_and_is_read_by_the_program() {
    let schemas = Schemas::load().unwrap();
    for (name, role) in [
        ("pep.json", "pep"),
        ("edge.json", "edge"),
        ("pdp-fake.json", "pdp"),
        ("pdp-external.json", "pdp"),
    ] {
        let value = example(name);
        let errors = schemas.validate("conformance-profile", &value).unwrap();
        assert!(errors.is_empty(), "{name}: {errors:?}");
        check_profile(&value.to_string(), &examples()).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        // The program reads the files of the example too.
        let path = examples().join(name).display().to_string();
        let mut args = vec!["--role", role, "--profile", &path, "--print-config"];
        if name != "pdp-fake.json" {
            args.extend(["--url", "http://127.0.0.1:9"]);
        }
        let out = run_cli(&args);
        assert_eq!(out.code, 0, "{name}: {}", out.stderr);
    }
}

fn base(role: &str) -> Value {
    match role {
        "pep" => example("pep.json"),
        "edge" => example("edge.json"),
        _ => example("pdp-external.json"),
    }
}

/// A document, and the verdicts of the schema and of the program. A row where they differ names a rule that a schema cannot state.
struct Row {
    name: &'static str,
    document: Value,
    schema_ok: bool,
    program_ok: bool,
}

fn row(name: &'static str, document: Value, schema_ok: bool, program_ok: bool) -> Row {
    Row {
        name,
        document,
        schema_ok,
        program_ok,
    }
}

fn changed(role: &str, change: impl FnOnce(&mut Value)) -> Value {
    let mut value = base(role);
    change(&mut value);
    value
}

#[test]
fn the_schema_and_the_program_agree_on_a_table_of_documents() {
    let rows = vec![
        row("a good pep profile", base("pep"), true, true),
        row("a good edge profile", base("edge"), true, true),
        row("a good pdp profile", base("pdp"), true, true),
        row("an empty profile", json!({}), true, true),
        row(
            "an unknown member at the root",
            json!({"other": 1}),
            false,
            false,
        ),
        row(
            "an unknown member in a section",
            changed("pep", |v| v["pep"]["x"] = json!(1)),
            false,
            false,
        ),
        row(
            "a timeout of 0",
            json!({"timeouts": {"request_seconds": 0}}),
            false,
            false,
        ),
        row(
            "a timeout that is a text",
            json!({"timeouts": {"case_seconds": "5"}}),
            false,
            false,
        ),
        row(
            "a pep with no token",
            changed("pep", |v| {
                v["pep"].as_object_mut().unwrap().remove("token");
            }),
            false,
            false,
        ),
        row(
            "an operation with no action",
            changed("pep", |v| {
                v["pep"]["operations"]["use_budget"]
                    .as_object_mut()
                    .unwrap()
                    .remove("action");
            }),
            false,
            false,
        ),
        row(
            "an MCP operation and no MCP endpoint",
            changed("pep", |v| {
                v["pep"].as_object_mut().unwrap().remove("mcp");
            }),
            false,
            false,
        ),
        row(
            "a list_options operation and no options type",
            changed("pep", |v| {
                v["pep"]["operations"]["list_options"] = json!({});
                v["pep"].as_object_mut().unwrap().remove("options_type");
            }),
            false,
            false,
        ),
        row(
            "a body and a body_text",
            changed("pep", |v| {
                v["pep"]["operations"]["mcp_approve"]["body_text"] = json!("x");
            }),
            false,
            false,
        ),
        row(
            "an unknown operation",
            changed("pep", |v| v["pep"]["operations"]["use_other"] = json!({})),
            false,
            false,
        ),
        row(
            "a secret in clear text",
            changed("pep", |v| v["pep"]["pdp"]["credential"] = json!("s")),
            false,
            false,
        ),
        row(
            "a started fake-pdp with a load request",
            json!({"pdp": {"spawn_fake_pdp": true, "load": {"url": "http://127.0.0.1:1/x"}}}),
            false,
            false,
        ),
        row(
            "a directory check with a bad mode",
            json!({"pdp": {"directory_check": {"mode": "maybe"}}}),
            false,
            false,
        ),
        row(
            "an edge with no public key",
            changed("edge", |v| {
                v["edge"]["trust"]
                    .as_object_mut()
                    .unwrap()
                    .remove("jwks_file");
            }),
            false,
            false,
        ),
        row(
            "an edge with two sources of the directory",
            changed("edge", |v| {
                v["edge"]["pdp"]["directory_file"] = json!("d.json")
            }),
            false,
            false,
        ),
        row(
            "an edge with no source of the directory",
            changed("edge", |v| {
                v["edge"]["pdp"]
                    .as_object_mut()
                    .unwrap()
                    .remove("directory");
            }),
            false,
            false,
        ),
        row(
            "an empty service id",
            changed("edge", |v| v["edge"]["service"] = json!("")),
            false,
            false,
        ),
        row(
            "an address with a name",
            changed("pep", |v| v["pep"]["pdp"]["listen"] = json!("localhost:80")),
            false,
            false,
        ),
        // The schema cannot state these rules. The program checks them.
        row(
            "a port above 65535",
            changed("pep", |v| {
                v["pep"]["pdp"]["listen"] = json!("127.0.0.1:99999")
            }),
            true,
            false,
        ),
        row(
            "the port 0 in a URL",
            json!({"pdp": {"reset_url": "http://127.0.0.1:0/r"}}),
            true,
            false,
        ),
        row(
            "the header Authorization for the token",
            changed("edge", |v| {
                v["edge"]["token_header"] = json!("Authorization")
            }),
            true,
            false,
        ),
        row(
            "two keys for one algorithm",
            changed("pep", |v| {
                v["pep"]["token"]["keys"][1]["alg"] = json!("Ed25519")
            }),
            true,
            false,
        ),
    ];
    let schemas = Schemas::load().unwrap();
    for row in rows {
        let schema_ok = schemas
            .is_valid("conformance-profile", &row.document)
            .unwrap();
        let program_ok = check_profile(&row.document.to_string(), Path::new("/base")).is_ok();
        assert_eq!(schema_ok, row.schema_ok, "{}: the schema", row.name);
        assert_eq!(program_ok, row.program_ok, "{}: the program", row.name);
    }
}

#[test]
fn the_json_report_of_a_run_is_valid_against_the_schema() {
    let schemas = Schemas::load().unwrap();
    // A PDP run.
    let dir = temp_dir("schema_report_pdp");
    let profile = write(&dir, "profile.json", r#"{"pdp": {"spawn_fake_pdp": true}}"#);
    let out = run_cli(&[
        "--role",
        "pdp",
        "--profile",
        &profile,
        "--format",
        "json",
        "--cases",
        "D01,D02,D41",
    ]);
    let errors = schemas.validate("conformance-report", &out.json()).unwrap();
    assert!(errors.is_empty(), "{errors:?}");
    // A PEP run with a pass, a failure, a skip and a warning.
    let dir = temp_dir("schema_report_pep");
    let pdp_port = free_port();
    let credential = write(&dir, "credential.txt", &format!("{CREDENTIAL}\n"));
    let mock = MockPep::start(
        format!("127.0.0.1:{pdp_port}").parse().unwrap(),
        Defects {
            budget_as_403: true,
            new_connection_each_time: true,
            ..Defects::default()
        },
    );
    let profile = write(
        &dir,
        "profile.json",
        &mock_pep::profile(pdp_port, Some(&credential), false).to_string(),
    );
    let url = mock.url();
    let out = run_cli(&[
        "--role",
        "pep",
        "--profile",
        &profile,
        "--url",
        &url,
        "--format",
        "json",
        "--cases",
        "U01,U04,U05,U69",
    ]);
    let report = out.json();
    let errors = schemas.validate("conformance-report", &report).unwrap();
    assert!(errors.is_empty(), "{errors:?}");
    let statuses: Vec<&str> = report["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["status"].as_str().unwrap())
        .collect();
    assert_eq!(statuses, vec!["pass", "fail", "skip", "warn"]);
    mock.stop();
}

#[test]
fn a_report_with_a_wrong_member_is_not_valid() {
    let schemas = Schemas::load().unwrap();
    let mut report = schemas.examples("conformance-report")[0].clone();
    report["cases"][0]["status"] = json!("maybe");
    assert!(!schemas.is_valid("conformance-report", &report).unwrap());
    let mut report = schemas.examples("conformance-report")[0].clone();
    report["extra"] = json!(1);
    assert!(!schemas.is_valid("conformance-report", &report).unwrap());
}
