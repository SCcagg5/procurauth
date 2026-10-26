//! The configuration rules: a closed schema, errors that name the key, no coercion,
//! the forms `_env` and `_file`, secrets, contradictions and the effective values.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::Path;

use reference_service::config::{KEYS, Loaded, Source, Sources, load, reference_table};
use serde_json::{Value, json};

const JWKS: &str = r#"{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"P7xgCMzIVQtPtGQyW22ST5y0a6o2maegbk8O2wk1BjY"}]}"#;

#[derive(Default)]
struct World {
    env: BTreeMap<&'static str, &'static str>,
    files: BTreeMap<&'static str, &'static str>,
}

fn run(text: &str, world: &World) -> Result<Loaded, Vec<String>> {
    let env = |name: &str| world.env.get(name).map(|v| (*v).to_owned());
    let file = |path: &Path| {
        world
            .files
            .get(path.to_str().unwrap())
            .map(|v| (*v).to_owned())
            .ok_or_else(|| "No such file or directory".to_owned())
    };
    load(
        text,
        &Sources {
            env: &env,
            file: &file,
        },
    )
}

fn base() -> Value {
    json!({
        "issuer": "https://edge.example",
        "jwks": serde_json::from_str::<Value>(JWKS).unwrap(),
        "pdp": {"url": "http://127.0.0.1:8181", "credential_env": "CRED", "allow_insecure_pdp_link": true}
    })
}

fn world() -> World {
    World {
        env: BTreeMap::from([("CRED", "the-credential")]),
        ..World::default()
    }
}

fn load_value(value: &Value) -> Result<Loaded, Vec<String>> {
    run(&value.to_string(), &world())
}

fn errors(value: &Value) -> Vec<String> {
    load_value(value).unwrap_err()
}

fn has(errors: &[String], parts: &[&str]) -> bool {
    errors.iter().any(|e| parts.iter().all(|p| e.contains(p)))
}

#[test]
fn a_minimal_file_gives_the_documented_defaults() {
    let loaded = load_value(&base()).unwrap();
    let s = &loaded.settings;
    assert_eq!(s.listen.to_string(), "127.0.0.1:8080");
    assert_eq!(s.workers, 8);
    assert_eq!(s.limits.max_body, 1_048_576);
    assert_eq!(s.pep.service_id, "datastore");
    assert_eq!(s.pep.token_header, "X-Identity-Token");
    assert_eq!(s.pep.max_token_age_seconds, 300);
    assert_eq!(s.pep.clock_skew_seconds, 30);
    assert_eq!(s.pep.cache_ttl.as_secs(), 0);
    assert_eq!(s.pep.cache_max_entries, 10_000);
    assert_eq!(s.pep.display_max_questions, 50);
    assert_eq!(s.pep.pdp.request_timeout.as_millis(), 5000);
    assert_eq!(s.pep.pdp.max_connections, 4);
    assert!(s.mcp_path.is_none());
    // Each default in the table is the value that applies.
    for line in &loaded.lines {
        let key = KEYS.iter().find(|k| k.name() == line.key).unwrap();
        if line.source == Source::Default {
            assert_eq!(line.value, key.default, "{}", line.key);
        }
    }
}

#[test]
fn the_effective_configuration_has_each_key_in_the_order_of_the_table() {
    let loaded = load_value(&base()).unwrap();
    let names: Vec<_> = loaded.lines.iter().map(|l| l.key.clone()).collect();
    let table: Vec<_> = KEYS.iter().map(|k| k.name()).collect();
    assert_eq!(names, table);
}

#[test]
fn an_unknown_member_stops_the_program() {
    let mut value = base();
    value["unknown_key"] = json!(1);
    assert!(has(&errors(&value), &["unknown_key", "not known"]));
    let mut value = base();
    value["pdp"]["unknown_key"] = json!(1);
    assert!(has(&errors(&value), &["pdp.unknown_key"]));
    // A form that the key does not accept is an unknown member.
    let mut value = base();
    value["workers_env"] = json!("N");
    assert!(has(&errors(&value), &["workers_env"]));
    let mut value = base();
    value["pdp"]["request_timeout_ms_file"] = json!("/x");
    assert!(has(&errors(&value), &["request_timeout_ms_file"]));
}

#[test]
fn a_duplicate_member_stops_the_program() {
    let text = r#"{"issuer": "a", "issuer": "b"}"#;
    let e = run(text, &world()).unwrap_err();
    assert!(has(&e, &["issuer"]), "{e:?}");
    let text = format!(
        r#"{{"issuer": "a", "jwks": {JWKS}, "pdp": {{"url": "http://h", "url": "http://i", "credential_env": "CRED"}}}}"#
    );
    assert!(run(&text, &world()).is_err());
}

#[test]
fn a_text_that_is_not_json_or_not_an_object_stops_the_program() {
    for text in ["", "{not json", "[]", "5"] {
        assert!(run(text, &world()).is_err(), "{text:?}");
    }
}

#[test]
fn each_error_names_the_key_the_expected_value_and_the_value_found() {
    let mut value = base();
    value["workers"] = json!(300);
    value["max_token_age_seconds"] = json!(0);
    value["clock_skew_seconds"] = json!("30");
    let e = errors(&value);
    assert!(
        e.contains(&"Key `workers`: expected a whole number from 1 to 256, found 300.".to_owned()),
        "{e:?}"
    );
    assert!(
        e.contains(
            &"Key `max_token_age_seconds`: expected a whole number from 1 to 86400, found 0."
                .to_owned()
        ),
        "{e:?}"
    );
    assert!(
        e.contains(
            &"Key `clock_skew_seconds`: expected a whole number from 0 to 3600, found \"30\"."
                .to_owned()
        ),
        "{e:?}"
    );
}

#[test]
fn the_program_never_changes_a_value_to_make_it_fit() {
    for (key, bad) in [
        ("workers", json!(0)),
        ("workers", json!(257)),
        ("workers", json!(1.0)),
        ("workers", json!(-1)),
        ("workers", json!("8")),
        ("workers", json!(true)),
        ("max_body_bytes", json!(0)),
        ("cache_ttl_seconds", json!(3601)),
        ("display_max_questions", json!(0)),
        ("read_timeout_seconds", json!(null)),
    ] {
        let mut value = base();
        value[key] = bad.clone();
        let e = errors(&value);
        assert!(
            has(&e, &[&format!("`{key}`"), "expected a whole number"]),
            "{key} {bad}: {e:?}"
        );
    }
    let mut value = base();
    value["pdp"]["max_connections"] = json!(0);
    value["pdp"]["plain_retries"] = json!(6);
    value["pdp"]["request_timeout_ms"] = json!(600_001);
    let e = errors(&value);
    for key in [
        "pdp.max_connections",
        "pdp.plain_retries",
        "pdp.request_timeout_ms",
    ] {
        assert!(has(&e, &[key]), "{key}: {e:?}");
    }
    let mut value = base();
    value["pdp"]["allow_insecure_pdp_link"] = json!("true");
    assert!(has(
        &errors(&value),
        &["allow_insecure_pdp_link", "boolean"]
    ));
}

#[test]
fn the_program_reports_each_error_and_not_only_the_first() {
    let mut value = base();
    value["workers"] = json!(0);
    value["listen"] = json!("not an address");
    value["extra"] = json!(1);
    value["pdp"]["max_connections"] = json!(0);
    assert!(errors(&value).len() >= 4);
}

#[test]
fn the_listen_address_has_an_ip_address_and_a_port() {
    for bad in ["localhost:8080", "127.0.0.1", "127.0.0.1:99999", ":80", ""] {
        let mut value = base();
        value["listen"] = json!(bad);
        assert!(has(&errors(&value), &["`listen`", "ADDRESS:PORT"]), "{bad}");
    }
    let mut value = base();
    value["listen"] = json!("[::1]:9000");
    assert_eq!(load_value(&value).unwrap().settings.listen.port(), 9000);
}

// ---- The forms _env and _file --------------------------------------------------------------------------

#[test]
fn a_key_takes_its_value_from_an_environment_variable_that_the_file_names() {
    let mut value = base();
    value.as_object_mut().unwrap().remove("issuer");
    value["issuer_env"] = json!("ISSUER");
    let mut w = world();
    w.env.insert("ISSUER", "https://edge.from.env");
    let loaded = run(&value.to_string(), &w).unwrap();
    assert_eq!(loaded.settings.pep.issuer, "https://edge.from.env");
    let line = loaded.lines.iter().find(|l| l.key == "issuer").unwrap();
    assert_eq!(line.source, Source::Env("ISSUER".into()));
    assert_eq!(line.source.text(), "env:ISSUER");
}

#[test]
fn an_environment_variable_that_the_file_does_not_name_is_never_read() {
    // The sources panic on a name that the file does not give.
    let env = |name: &str| -> Option<String> {
        match name {
            "CRED" => Some("the-credential".to_owned()),
            other => panic!("the program read the variable {other}"),
        }
    };
    let file = |_: &Path| -> Result<String, String> { panic!("the program read a file") };
    let loaded = load(
        &base().to_string(),
        &Sources {
            env: &env,
            file: &file,
        },
    )
    .unwrap();
    assert_eq!(
        loaded.settings.pep.pdp.credential.expose(),
        "the-credential"
    );
}

#[test]
fn a_variable_that_does_not_exist_or_is_empty_stops_the_program() {
    let mut value = base();
    value["pdp"]["credential_env"] = json!("MISSING");
    let e = errors(&value);
    assert!(
        has(&e, &["pdp.credential_env", "MISSING", "does not exist"]),
        "{e:?}"
    );
    let mut w = world();
    w.env.insert("EMPTY", "");
    value["pdp"]["credential_env"] = json!("EMPTY");
    let e = run(&value.to_string(), &w).unwrap_err();
    assert!(has(&e, &["pdp.credential_env", "EMPTY", "empty"]), "{e:?}");
    value["pdp"]["credential_env"] = json!("not a name!");
    assert!(has(
        &run(&value.to_string(), &w).unwrap_err(),
        &["pdp.credential_env", "environment variable"]
    ));
    value["pdp"]["credential_env"] = json!(5);
    assert!(run(&value.to_string(), &w).is_err());
}

#[test]
fn a_value_comes_from_a_file_without_its_last_line_end() {
    let mut value = base();
    value.as_object_mut().unwrap().remove("issuer");
    value["issuer_file"] = json!("/run/issuer");
    for (content, expected) in [
        ("https://i\n", "https://i"),
        ("https://i\r\n", "https://i"),
        ("https://i", "https://i"),
        ("https://i\n\n", "https://i\n"),
    ] {
        let mut w = world();
        w.files.insert("/run/issuer", content);
        let loaded = run(&value.to_string(), &w).unwrap();
        assert_eq!(loaded.settings.pep.issuer, expected);
        let line = loaded.lines.iter().find(|l| l.key == "issuer").unwrap();
        assert_eq!(line.source.text(), "file:/run/issuer");
    }
}

#[test]
fn a_file_that_the_program_cannot_read_or_that_is_empty_stops_the_program() {
    let mut value = base();
    value.as_object_mut().unwrap().remove("issuer");
    value["issuer_file"] = json!("/run/none");
    let e = errors(&value);
    assert!(
        has(&e, &["issuer_file", "/run/none", "No such file"]),
        "{e:?}"
    );
    let mut w = world();
    w.files.insert("/run/none", "\n");
    let e = run(&value.to_string(), &w).unwrap_err();
    assert!(has(&e, &["issuer_file", "/run/none", "empty"]), "{e:?}");
}

#[test]
fn two_forms_of_one_key_or_no_form_for_a_mandatory_key_stop_the_program() {
    let mut value = base();
    value["issuer_env"] = json!("ISSUER");
    let e = errors(&value);
    assert!(
        has(
            &e,
            &[
                "`issuer`",
                "exactly one",
                "2 members",
                "`issuer`",
                "`issuer_env`"
            ]
        ),
        "{e:?}"
    );
    let mut value = base();
    value.as_object_mut().unwrap().remove("issuer");
    assert!(has(&errors(&value), &["`issuer`", "one of", "no member"]));
    let mut value = base();
    value["pdp"].as_object_mut().unwrap().remove("url");
    assert!(has(&errors(&value), &["`pdp.url`", "no member"]));
    let mut value = base();
    value.as_object_mut().unwrap().remove("pdp");
    assert!(has(&errors(&value), &["pdp"]));
    let mut value = base();
    value.as_object_mut().unwrap().remove("jwks");
    assert!(has(&errors(&value), &["`jwks`", "no member"]));
}

#[test]
fn the_public_keys_come_from_the_file_from_a_variable_or_from_a_file() {
    let mut value = base();
    value.as_object_mut().unwrap().remove("jwks");
    value["jwks_file"] = json!("/run/jwks.json");
    let mut w = world();
    w.files.insert("/run/jwks.json", JWKS);
    let loaded = run(&value.to_string(), &w).unwrap();
    assert_eq!(loaded.settings.pep.trusted_keys.len(), 1);
    let line = loaded.lines.iter().find(|l| l.key == "jwks").unwrap();
    assert!(
        line.value.starts_with("1 key (Ed25519 kid=k1)"),
        "{}",
        line.value
    );
    assert_eq!(line.source.text(), "file:/run/jwks.json");
    value.as_object_mut().unwrap().remove("jwks_file");
    value["jwks_env"] = json!("JWKS");
    w.env.insert("JWKS", JWKS);
    assert!(run(&value.to_string(), &w).is_ok());
    // A bad key set stops the program, and the error names the key.
    w.env.insert(
        "JWKS",
        r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"AAAA","d":"BBBB"}]}"#,
    );
    assert!(has(&run(&value.to_string(), &w).unwrap_err(), &["jwks"]));
    // A direct value that has the wrong type.
    let mut value = base();
    value["jwks"] = json!("text");
    assert!(has(&errors(&value), &["jwks"]));
}

// ---- Secrets ----------------------------------------------------------------------------------------------

#[test]
fn a_secret_in_clear_text_stops_the_program_and_the_error_hides_it() {
    let mut value = base();
    value["pdp"]
        .as_object_mut()
        .unwrap()
        .remove("credential_env");
    value["pdp"]["credential"] = json!("my-clear-secret");
    let e = errors(&value);
    assert!(has(&e, &["pdp.credential", "clear text"]), "{e:?}");
    assert!(!e.join(" ").contains("my-clear-secret"));
}

#[test]
fn a_secret_takes_one_form_of_env_and_file() {
    let mut value = base();
    value["pdp"]["credential_file"] = json!("/run/cred");
    let mut w = world();
    w.files.insert("/run/cred", "x");
    assert!(has(
        &run(&value.to_string(), &w).unwrap_err(),
        &["pdp.credential", "one of"]
    ));
    value["pdp"]
        .as_object_mut()
        .unwrap()
        .remove("credential_env");
    let loaded = run(&value.to_string(), &w).unwrap();
    assert_eq!(loaded.settings.pep.pdp.credential.expose(), "x");
    value["pdp"]
        .as_object_mut()
        .unwrap()
        .remove("credential_file");
    assert!(has(
        &run(&value.to_string(), &w).unwrap_err(),
        &[
            "pdp.credential",
            "`pdp.credential_env`",
            "`pdp.credential_file`"
        ]
    ));
}

#[test]
fn the_effective_configuration_hides_the_secret_and_shows_its_source() {
    let loaded = load_value(&base()).unwrap();
    let text = loaded.render();
    assert!(
        text.contains("pdp.credential = <hidden>  (env:CRED)"),
        "{text}"
    );
    assert!(!text.contains("the-credential"));
    let debug = format!("{loaded:?}");
    assert!(!debug.contains("the-credential"), "{debug}");
    assert!(text.contains("issuer = https://edge.example  (file)"));
    assert!(text.contains("workers = 8  (default)"));
}

// ---- Contradictions ----------------------------------------------------------------------------------------

#[test]
fn an_http_url_without_the_flag_stops_the_program() {
    let mut value = base();
    value["pdp"]
        .as_object_mut()
        .unwrap()
        .remove("allow_insecure_pdp_link");
    let e = errors(&value);
    assert!(has(&e, &["pdp.url", "https", "secured"]), "{e:?}");
}

#[test]
fn two_keys_that_contradict_each_other_stop_the_program() {
    let mut value = base();
    value["cache_ttl_seconds"] = json!(5);
    value["cache_max_entries"] = json!(0);
    assert!(has(
        &errors(&value),
        &["cache_max_entries", "contradiction"]
    ));
    for path in [
        "/copy",
        "/hosts",
        "/hosts/x",
        "/.well-known/procurauth/actions",
        "/.well-known/procurauth/resources",
    ] {
        let mut value = base();
        value["mcp_path"] = json!(path);
        assert!(has(&errors(&value), &["mcp_path"]), "{path}");
    }
    for path in ["mcp", "/a b", "/a?x=1", ""] {
        let mut value = base();
        value["mcp_path"] = json!(path);
        assert!(has(&errors(&value), &["mcp_path"]), "{path:?}");
    }
    let mut value = base();
    value["token_header"] = json!("Authorization");
    assert!(has(&errors(&value), &["token_header"]));
    let mut value = base();
    value["service_id"] = json!("");
    assert!(has(&errors(&value), &["service_id"]));
}

#[test]
fn the_library_rules_apply_to_the_values_of_the_file() {
    let mut value = base();
    value["pdp"]["url"] = json!("ftp://x");
    assert!(has(&errors(&value), &["pdp.url"]));
    let mut value = base();
    value["pdp"]["url"] = json!("http://user:secret@host");
    let e = errors(&value);
    assert!(has(&e, &["pdp.url"]));
    assert!(!e.join(" ").contains("secret"));
}

// ---- The reference ---------------------------------------------------------------------------------------------

#[test]
fn the_names_of_the_table_are_unique_and_the_forms_follow_the_kind() {
    let mut seen = std::collections::BTreeSet::new();
    for key in KEYS {
        assert!(seen.insert(key.name()), "{}", key.name());
        assert_eq!(key.env.is_some(), key.file.is_some());
        if key.secret {
            assert!(key.env.is_some(), "a secret needs the forms _env and _file");
        }
    }
}

#[test]
fn the_readme_has_the_table_of_the_code() {
    let readme =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md")).unwrap();
    assert!(
        readme.contains(&reference_table()),
        "the table of the README differs from the table of the code"
    );
}

#[cfg(feature = "mcp")]
#[test]
fn the_examples_are_good_files() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    for name in ["config.json", "conformance.json"] {
        let text = std::fs::read_to_string(dir.join(name)).unwrap();
        let mut w = world();
        w.env.insert("PROCURAUTH_PDP_CREDENTIAL", "x");
        w.files.insert(
            "crates/fake-pdp/examples/pep-credential.txt",
            "example-credential-for-tests-only\n",
        );
        let loaded = run(&text, &w).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(loaded.settings.mcp_path.as_deref(), Some("/mcp"));
    }
}

#[test]
fn the_program_reads_the_environment_only_in_the_function_real_sources() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in std::fs::read_dir(src).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        for pattern in ["env::var", "var_os", "env::vars"] {
            let count = text.matches(pattern).count();
            // The one place: `real_sources` in config.rs, and the comment lines that name the rule.
            let allowed = usize::from(name == "config.rs" && pattern == "env::var");
            let in_comments = text
                .lines()
                .filter(|l| l.trim_start().starts_with("//") && l.contains(pattern))
                .count();
            assert!(
                count - in_comments <= allowed,
                "{name} reads the environment with {pattern}"
            );
        }
    }
}

#[test]
fn the_data_file_of_the_test_pdp_follows_its_schema_and_is_read_by_the_core() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/pdp-data.json");
    let value: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let schemas = procurauth_schema_check::Schemas::load().unwrap();
    let problems = schemas.validate("fake-pdp-data", &value).unwrap();
    assert!(problems.is_empty(), "{problems:?}");
    let (directory, report) = procurauth_core::directory::analyze_value(&value);
    assert!(directory.is_some(), "{:?}", report.findings());
    assert!(report.findings().is_empty(), "{:?}", report.findings());
}
