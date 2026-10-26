//! The configuration rules: a closed schema, errors that name the key, no coercion,
//! the forms `_env` and `_file`, secrets, contradictions and the effective values.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;

use reference_edge::config::{KEYS, Loaded, Source, Sources, load, reference_table};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const PEM: &str = include_str!("../../access-token/examples/test-edge-ed25519.pem");
const PEM_ES256: &str = include_str!("../../access-token/examples/test-edge-es256.pem");

#[derive(Default)]
struct World {
    env: BTreeMap<&'static str, String>,
    files: BTreeMap<&'static str, String>,
    asked: RefCell<Vec<String>>,
}

fn run(text: &str, world: &World) -> Result<Loaded, Vec<String>> {
    let env = |name: &str| {
        world.asked.borrow_mut().push(name.to_owned());
        world.env.get(name).cloned()
    };
    let file = |path: &Path| {
        world
            .files
            .get(path.to_str().unwrap())
            .cloned()
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

fn keys() -> Value {
    json!({"keys": [{"sha256": hex::encode(Sha256::digest(b"pk_live_x")), "subject": "key:ann-k1", "owner": "ann"}]})
}

fn base() -> Value {
    json!({
        "service_id": "datastore",
        "issuer": "https://edge.example",
        "key_format": {"prefix": "pk_live_", "length": 51, "alphabet": "0-9"},
        "keys": keys(),
        "upstream": {"url": "http://127.0.0.1:9000"},
        "signing": {"key_env": "KEY"},
        "pdp": {"url": "http://127.0.0.1:8181", "credential_env": "CRED", "allow_insecure_pdp_link": true}
    })
}

fn world() -> World {
    World {
        env: BTreeMap::from([
            ("KEY", PEM.to_owned()),
            ("CRED", "the-credential".to_owned()),
        ]),
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
    assert_eq!(s.listen.to_string(), "127.0.0.1:8090");
    assert_eq!(s.workers, 16);
    assert_eq!(s.limits.max_body, 1_048_576);
    assert_eq!(s.limits.read_timeout.as_secs(), 10);
    assert_eq!(s.limits.idle_timeout.as_secs(), 30);
    assert_eq!(s.token_header, "X-Identity-Token");
    assert_eq!(s.token_life_seconds, 60);
    assert_eq!(s.token_cache_max_entries, 0);
    assert_eq!(s.signing_kid, None);
    assert_eq!(s.upstream.connect_timeout.as_millis(), 2000);
    assert_eq!(s.upstream.response_timeout.as_secs(), 30);
    assert_eq!(s.pdp.request_timeout.as_millis(), 5000);
    assert_eq!(s.pdp.max_connections, 4);
    assert_eq!(s.pdp.plain_retries, 1);
    assert_eq!(s.pdp.metadata_max_age.as_secs(), 3600);
    assert_eq!(s.pdp.max_response_bytes, 1_048_576);
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
fn the_effective_configuration_shows_the_source_and_hides_the_secrets() {
    let mut value = base();
    value["workers"] = json!(4);
    let loaded = load_value(&value).unwrap();
    let source_of = |key: &str| {
        loaded
            .lines
            .iter()
            .find(|l| l.key == key)
            .unwrap()
            .source
            .text()
    };
    assert_eq!(source_of("workers"), "file");
    assert_eq!(source_of("max_body_bytes"), "default");
    assert_eq!(source_of("signing.key"), "env:KEY");
    assert_eq!(source_of("pdp.credential"), "env:CRED");
    assert_eq!(source_of("keys"), "file");
    let text = loaded.render();
    assert!(
        text.contains("pdp.credential = <hidden>  (env:CRED)"),
        "{text}"
    );
    assert!(
        text.contains("signing.key = <hidden> (Ed25519)  (env:KEY)"),
        "{text}"
    );
    for secret in ["the-credential", "BEGIN PRIVATE KEY", "pk_live_x"] {
        assert!(!text.contains(secret), "{secret}");
    }
    assert!(!format!("{loaded:?}").contains("the-credential"));
}

#[test]
fn an_unknown_member_stops_the_program() {
    let mut value = base();
    value["unknown_key"] = json!(1);
    assert!(has(&errors(&value), &["unknown_key", "not known"]));
    for section in ["upstream", "signing", "pdp"] {
        let mut value = base();
        value[section]["unknown_key"] = json!(1);
        assert!(
            has(&errors(&value), &[&format!("{section}.unknown_key")]),
            "{section}"
        );
    }
    // A form that the key does not accept is an unknown member.
    let mut value = base();
    value["workers_env"] = json!("N");
    assert!(has(&errors(&value), &["workers_env"]));
    let mut value = base();
    value["pdp"]["allow_insecure_pdp_link_file"] = json!("/x");
    assert!(has(&errors(&value), &["allow_insecure_pdp_link_file"]));
}

#[test]
fn a_duplicate_member_stops_the_program() {
    let text = r#"{"issuer": "a", "issuer": "b"}"#;
    assert!(has(&run(text, &world()).unwrap_err(), &["issuer"]));
    let mut text = base().to_string();
    text = text.replace(
        r#""upstream":{"url":"http://127.0.0.1:9000"}"#,
        r#""upstream":{"url":"http://a:1","url":"http://b:2"}"#,
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
    value["token_life_seconds"] = json!(0);
    value["max_body_bytes"] = json!("big");
    value["pdp"]["max_connections"] = json!(-1);
    let e = errors(&value);
    assert!(
        has(
            &e,
            &["Key `workers`", "a whole number from 1 to 256", "300"]
        ),
        "{e:?}"
    );
    assert!(
        has(&e, &["Key `token_life_seconds`", "from 1 to 86400", "0"]),
        "{e:?}"
    );
    assert!(
        has(&e, &["Key `max_body_bytes`", "a whole number", "\"big\""]),
        "{e:?}"
    );
    assert!(
        has(&e, &["Key `pdp.max_connections`", "from 1 to 256", "-1"]),
        "{e:?}"
    );
}

#[test]
fn the_program_never_changes_a_value_to_make_it_fit() {
    for (key, value) in [
        ("workers", json!(0)),
        ("workers", json!(257)),
        ("workers", json!(1.5)),
        ("workers", json!("8")),
        ("token_cache_max_entries", json!(10_000_001)),
        ("read_timeout_seconds", json!(true)),
    ] {
        let mut config = base();
        config[key] = value.clone();
        assert!(
            has(&errors(&config), &[&format!("Key `{key}`")]),
            "{key} {value}"
        );
    }
}

#[test]
fn all_the_errors_come_together() {
    let mut value = base();
    value["workers"] = json!(0);
    value["token_header"] = json!("Cookie");
    value["service_id"] = json!("");
    value["upstream"]["url"] = json!("https://service.example");
    assert!(errors(&value).len() >= 4);
}

// ---- The forms _env and _file --------------------------------------------------------------------------------

#[test]
fn a_key_takes_exactly_one_of_its_forms() {
    let mut value = base();
    value["issuer_env"] = json!("ISS");
    let mut w = world();
    w.env.insert("ISS", "x".to_owned());
    let e = run(&value.to_string(), &w).unwrap_err();
    assert!(
        has(
            &e,
            &[
                "issuer",
                "exactly one of the forms",
                "`issuer`",
                "`issuer_env`"
            ]
        ),
        "{e:?}"
    );
    let mut value = base();
    value.as_object_mut().unwrap().remove("issuer");
    assert!(has(
        &errors(&value),
        &[
            "Key `issuer`",
            "one of `issuer`, `issuer_env` and `issuer_file`",
            "no member"
        ]
    ));
}

#[test]
fn the_forms_env_and_file_give_the_value_and_the_source() {
    let mut value = base();
    value.as_object_mut().unwrap().remove("issuer");
    value["issuer_env"] = json!("ISS");
    value["listen_file"] = json!("/run/listen");
    value["upstream"].as_object_mut().unwrap().remove("url");
    value["upstream"]["url_file"] = json!("/run/upstream");
    let mut w = world();
    w.env.insert("ISS", "https://edge.example".to_owned());
    w.files.insert("/run/listen", "127.0.0.1:9999\n".to_owned());
    w.files
        .insert("/run/upstream", "http://127.0.0.1:7000\r\n".to_owned());
    let loaded = run(&value.to_string(), &w).unwrap();
    assert_eq!(loaded.settings.issuer, "https://edge.example");
    assert_eq!(loaded.settings.listen.port(), 9999);
    assert_eq!(loaded.settings.upstream.port, 7000);
    let text = loaded.render();
    assert!(
        text.contains("issuer = https://edge.example  (env:ISS)"),
        "{text}"
    );
    assert!(
        text.contains("listen = 127.0.0.1:9999  (file:/run/listen)"),
        "{text}"
    );
    assert!(
        text.contains("upstream.url = http://127.0.0.1:7000  (file:/run/upstream)"),
        "{text}"
    );
}

#[test]
fn a_variable_that_does_not_exist_an_empty_value_and_a_bad_file_stop_the_program() {
    let mut value = base();
    value["pdp"]
        .as_object_mut()
        .unwrap()
        .remove("credential_env");
    value["pdp"]["credential_env"] = json!("NOPE");
    let e = errors(&value);
    assert!(
        has(&e, &["pdp.credential_env", "\"NOPE\"", "does not exist"]),
        "{e:?}"
    );
    let mut w = world();
    w.env.insert("EMPTY", String::new());
    value["pdp"]["credential_env"] = json!("EMPTY");
    let e = run(&value.to_string(), &w).unwrap_err();
    assert!(
        has(&e, &["pdp.credential_env", "\"EMPTY\"", "empty"]),
        "{e:?}"
    );
    value["pdp"]["credential_env"] = json!("1 BAD");
    assert!(has(
        &run(&value.to_string(), &w).unwrap_err(),
        &["pdp.credential_env", "environment variable"]
    ));
    let mut value = base();
    value["pdp"]
        .as_object_mut()
        .unwrap()
        .remove("credential_env");
    value["pdp"]["credential_file"] = json!("/missing");
    let e = errors(&value);
    assert!(
        has(&e, &["pdp.credential_file", "\"/missing\"", "No such file"]),
        "{e:?}"
    );
    let mut w = world();
    w.files.insert("/empty", "\n".to_owned());
    value["pdp"]["credential_file"] = json!("/empty");
    assert!(has(
        &run(&value.to_string(), &w).unwrap_err(),
        &["pdp.credential_file", "content is empty"]
    ));
}

#[test]
fn a_secret_in_clear_text_stops_the_program_and_the_error_hides_it() {
    let mut value = base();
    value["pdp"]
        .as_object_mut()
        .unwrap()
        .remove("credential_env");
    value["pdp"]["credential"] = json!("clear-secret-value");
    let e = errors(&value);
    assert!(
        has(
            &e,
            &[
                "pdp.credential",
                "never is in clear text",
                "pdp.credential_env",
                "pdp.credential_file"
            ]
        ),
        "{e:?}"
    );
    assert!(!e.join(" ").contains("clear-secret-value"));
    let mut value = base();
    value["signing"].as_object_mut().unwrap().remove("key_env");
    value["signing"]["key"] = json!(PEM);
    let e = errors(&value);
    assert!(has(&e, &["signing.key", "clear text"]), "{e:?}");
    assert!(!e.join(" ").contains("PRIVATE KEY"));
}

#[test]
fn a_secret_needs_one_of_its_two_forms() {
    let mut value = base();
    value["signing"].as_object_mut().unwrap().remove("key_env");
    assert!(has(
        &errors(&value),
        &[
            "signing.key",
            "one of `signing.key_env` and `signing.key_file`",
            "no member"
        ]
    ));
    let mut value = base();
    value["signing"]["key_file"] = json!("/k");
    let mut w = world();
    w.files.insert("/k", PEM.to_owned());
    assert!(has(
        &run(&value.to_string(), &w).unwrap_err(),
        &["signing.key", "one of"]
    ));
}

#[test]
fn the_program_reads_only_the_variables_that_the_file_names() {
    let w = world();
    let _ = run(&base().to_string(), &w).unwrap();
    let mut asked = w.asked.borrow().clone();
    asked.sort();
    assert_eq!(asked, ["CRED", "KEY"]);
}

// ---- The values ------------------------------------------------------------------------------------------------

#[test]
fn the_signing_key_is_a_pem_key_of_ed25519_or_p256() {
    let mut w = world();
    w.env.insert("KEY", PEM_ES256.to_owned());
    let loaded = run(&base().to_string(), &w).unwrap();
    assert!(loaded.render().contains("<hidden> (ES256)"));
    w.env.insert("KEY", "not a key".to_owned());
    let e = run(&base().to_string(), &w).unwrap_err();
    assert!(
        has(&e, &["signing.key", "PKCS#8 PEM", "value stays hidden"]),
        "{e:?}"
    );
    assert!(!e.join(" ").contains("not a key"));
}

#[test]
fn the_key_format_and_the_keys_file_are_read_strictly() {
    let mut value = base();
    value["key_format"]["extra"] = json!(1);
    assert!(has(&errors(&value), &["Key `key_format`"]));
    let mut value = base();
    value["key_format"]["length"] = json!(2);
    assert!(
        has(&errors(&value), &["Key `key_format`"]),
        "a prefix longer than the length"
    );
    let mut value = base();
    value["keys"]["keys"][0]["owner"] = json!("key:other");
    assert!(has(&errors(&value), &["Key `keys`", "$.keys[0].owner"]));
    let mut value = base();
    value["keys"] = json!([]);
    assert!(has(&errors(&value), &["Key `keys`", "a JSON object"]));
    // The file forms give the JSON text.
    let mut value = base();
    value.as_object_mut().unwrap().remove("keys");
    value["keys_file"] = json!("/keys.json");
    let mut w = world();
    w.files.insert("/keys.json", keys().to_string());
    let loaded = run(&value.to_string(), &w).unwrap();
    assert_eq!(loaded.settings.keys.len(), 1);
    w.files
        .insert("/keys.json", r#"{"keys": [], "keys": []}"#.to_owned());
    assert!(has(
        &run(&value.to_string(), &w).unwrap_err(),
        &["Key `keys`"]
    ));
    w.files.insert("/keys.json", "{not json".to_owned());
    assert!(has(
        &run(&value.to_string(), &w).unwrap_err(),
        &["Key `keys`", "not valid"]
    ));
}

#[test]
fn the_upstream_is_an_http_url_with_a_host_and_no_path() {
    for (url, part) in [
        ("https://service.example", "no TLS client"),
        ("ftp://x", "absolute `http` URL"),
        ("http://service.example/base", "no path"),
        ("service.example", "absolute `http` URL"),
        ("http://u:p@service.example", "absolute `http` URL"),
    ] {
        let mut value = base();
        value["upstream"]["url"] = json!(url);
        let e = errors(&value);
        assert!(has(&e, &["Key `upstream.url`", part]), "{url}: {e:?}");
        assert!(!e.join(" ").contains("u:p"), "{e:?}");
    }
    let mut value = base();
    value["upstream"]["url"] = json!("http://service.example:8080/");
    assert!(load_value(&value).is_ok());
}

#[test]
fn the_token_header_and_the_other_texts_follow_the_rules() {
    for name in [
        "Authorization",
        "cookie",
        "Proxy-Authorization",
        "",
        "X Bad",
    ] {
        let mut value = base();
        value["token_header"] = json!(name);
        assert!(has(&errors(&value), &["Key `token_header`"]), "{name:?}");
    }
    let mut value = base();
    value["service_id"] = json!("");
    assert!(has(&errors(&value), &["Key `service_id`"]));
    value.as_object_mut().unwrap().remove("service_id");
    assert!(has(
        &errors(&value),
        &["Key `service_id`", "the member `service_id`", "no member"]
    ));
    for kid in ["", "has space"] {
        let mut value = base();
        value["signing"]["kid"] = json!(kid);
        assert!(has(&errors(&value), &["Key `signing.kid`"]), "{kid:?}");
    }
}

// ---- The contradictions ----------------------------------------------------------------------------------------

#[test]
fn a_life_above_the_maximum_age_stops_the_program() {
    let mut value = base();
    value["token_life_seconds"] = json!(301);
    let e = errors(&value);
    assert!(
        has(
            &e,
            &["token_life_seconds", "max_token_age_seconds", "300", "301"]
        ),
        "{e:?}"
    );
    value["max_token_age_seconds"] = json!(301);
    assert!(load_value(&value).is_ok());
}

#[test]
fn an_upstream_at_the_address_of_the_listener_stops_the_program() {
    let mut value = base();
    value["listen"] = json!("127.0.0.1:9000");
    let e = errors(&value);
    assert!(has(&e, &["upstream.url", "listen", "itself"]), "{e:?}");
}

#[test]
fn an_http_link_to_the_pdp_needs_the_explicit_flag() {
    let mut value = base();
    value["pdp"]
        .as_object_mut()
        .unwrap()
        .remove("allow_insecure_pdp_link");
    let e = errors(&value);
    assert!(
        has(&e, &["pdp.url", "secured", "allow_insecure_pdp_link"]),
        "{e:?}"
    );
    value["pdp"]["allow_insecure_pdp_link"] = json!(true);
    assert!(load_value(&value).is_ok());
}

#[test]
fn a_section_that_is_absent_is_an_error_that_names_it() {
    for section in ["upstream", "signing", "pdp"] {
        let mut value = base();
        value.as_object_mut().unwrap().remove(section);
        assert!(
            has(&errors(&value), &[&format!("Key `{section}`"), "no member"]),
            "{section}"
        );
    }
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

#[test]
fn the_examples_are_good_files() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = dir.join("../..");
    for name in ["config.json", "conformance.json"] {
        let text = std::fs::read_to_string(dir.join("examples").join(name)).unwrap();
        // The examples name their files from the root of the repository.
        let mut value: Value = serde_json::from_str(&text).unwrap();
        for (pointer, member) in [
            ("", "key_format_file"),
            ("", "keys_file"),
            ("/signing", "key_file"),
            ("/pdp", "credential_file"),
        ] {
            if let Some(path) = value
                .pointer(&format!("{pointer}/{member}"))
                .and_then(Value::as_str)
            {
                let absolute = root.join(path).display().to_string();
                *value.pointer_mut(&format!("{pointer}/{member}")).unwrap() = json!(absolute);
            }
        }
        let mut w = World::default();
        w.env.insert("PROCURAUTH_PDP_CREDENTIAL", "x".to_owned());
        let env = |n: &str| w.env.get(n).cloned();
        let file = |p: &Path| std::fs::read_to_string(p).map_err(|e| e.to_string());
        let loaded = load(
            &value.to_string(),
            &Sources {
                env: &env,
                file: &file,
            },
        )
        .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(loaded.settings.service_id, "datastore");
        assert_eq!(loaded.settings.keys.len(), 2);
    }
}

#[test]
fn the_keys_file_of_the_examples_matches_the_test_key_texts_of_the_runner() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../access-conformance/examples");
    let keys = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/keys.test-only.json"),
    )
    .unwrap();
    let store = reference_edge::keys::KeyStore::parse(&keys).unwrap();
    let read = |name: &str| {
        std::fs::read_to_string(dir.join(name))
            .unwrap()
            .trim_end()
            .to_owned()
    };
    assert_eq!(
        store.find(&read("edge-valid-key.txt")).unwrap().subject,
        "key:ann-k1"
    );
    assert_eq!(
        store.find(&read("edge-no-access-key.txt")).unwrap().subject,
        "key:ann-k2"
    );
    assert!(store.find(&read("edge-unknown-key.txt")).is_none());
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
fn the_key_format_of_the_examples_follows_its_schema() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/key-format.test-only.json");
    let value: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let schemas = procurauth_schema_check::Schemas::load().unwrap();
    let problems = schemas.validate("key-format", &value).unwrap();
    assert!(problems.is_empty(), "{problems:?}");
}
