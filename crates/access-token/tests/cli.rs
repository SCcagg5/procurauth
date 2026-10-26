//! The command line: usage errors, exit codes, streams and secrets.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use serde_json::{Value, json};

#[test]
fn p_9_cli_version_gives_the_version_and_the_licence() {
    for flag in ["--version", "-V"] {
        let out = run_cli(&[flag], "");
        assert_eq!(out.code, 0);
        assert_eq!(
            out.stdout,
            format!("access-token {}\nApache-2.0\n", env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(out.stderr, "");
    }
}

#[test]
fn p_9_cli_help_goes_to_stdout_with_no_colour() {
    for args in [
        vec!["--help"],
        vec!["make", "--help"],
        vec!["check", "--help"],
        vec!["-h"],
    ] {
        let out = run_cli(&args, "");
        assert_eq!(out.code, 0, "{args:?}");
        assert!(out.stdout.contains("Usage: access-token"), "{args:?}");
        assert!(!out.all().contains('\u{1b}'), "{args:?}");
        assert_eq!(out.stderr, "");
    }
    let out = run_cli(&["make", "--help"], "");
    for text in [
        "--key <FILE>",
        "--alg <ALG>",
        "--typ <TYPE>",
        "--format <FORMAT>",
        "<CLAIMS>",
    ] {
        assert!(out.stdout.contains(text), "{text}");
    }
    let out = run_cli(&["check", "--help"], "");
    for text in [
        "--config <FILE>",
        "--format <FORMAT>",
        "--now <UNIX_SECONDS>",
        "[TOKEN]",
    ] {
        assert!(out.stdout.contains(text), "{text}");
    }
    let out = run_cli(&["--help"], "");
    assert!(
        out.stdout
            .contains("Exit codes: 0 no finding, 1 at least one finding, 2 usage error")
    );
}

#[test]
fn p_9_cli_a_usage_error_gives_the_exit_code_2_and_nothing_on_stdout() {
    let key = example("test-edge-ed25519.pem");
    let config = example("service.json");
    let cases: Vec<Vec<&str>> = vec![
        vec![],
        vec!["unknown"],
        vec!["make"],
        vec!["make", "claims.json"],
        vec!["make", "--key", &key],
        vec!["make", "--key", &key, "--unknown", "-"],
        vec!["make", "--key", &key, "--alg", "ed25519", "-"],
        vec![
            "make", "--key", &key, "--alg", "Ed25519", "--alg", "ES256", "-",
        ],
        vec!["make", "--key", &key, "--format", "xml", "-"],
        vec![
            "make", "--key", &key, "--format", "json", "--format", "json", "-",
        ],
        vec!["make", "--key", &key, "-", "-"],
        vec!["check"],
        vec!["check", "--config", &config],
        vec!["check", "-"],
        vec!["check", "--config", &config, "--now", "abc", "-"],
        vec!["check", "--config", &config, "--now", "-5", "-"],
        vec!["check", "--config", &config, "--now", "1.5", "-"],
        vec![
            "check", "--config", &config, "--now", "1", "--now", "2", "-",
        ],
        vec!["check", "--config", &config, "--print-config", "-"],
        vec!["check", "--config", &config, "--config", &config, "-"],
    ];
    for args in cases {
        let out = run_cli(&args, "");
        assert_eq!(out.code, 2, "{args:?}: {}", out.stderr);
        assert_eq!(out.stdout, "", "{args:?}");
        assert!(
            out.stderr.contains("error") || out.stderr.contains("Usage"),
            "{args:?}"
        );
        assert!(!out.stderr.contains('\u{1b}'));
    }
}

#[test]
fn p_9_cli_a_bad_value_names_the_flag_and_the_value() {
    let key = example("test-edge-ed25519.pem");
    let out = run_cli(&["make", "--key", &key, "--alg", "ed25519", "-"], "");
    assert!(out.stderr.contains("--alg"));
    assert!(out.stderr.contains("ed25519"));
    assert!(out.stderr.contains("Ed25519"));
    let config = example("service.json");
    let out = run_cli(&["check", "--config", &config, "--now", "abc", "-"], "");
    assert!(out.stderr.contains("--now"));
    assert!(out.stderr.contains("abc"));
}

#[test]
fn p_9_cli_an_unreadable_input_gives_the_exit_code_2() {
    let key = example("test-edge-ed25519.pem");
    let claims = example("claims.json");
    let config = example("service.json");
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (
            vec!["make", "--key", "/nonexistent/key.pem", &claims],
            "/nonexistent/key.pem",
        ),
        (
            vec!["make", "--key", &key, "/nonexistent/claims.json"],
            "/nonexistent/claims.json",
        ),
        (
            vec![
                "check",
                "--config",
                "/nonexistent/service.json",
                "--now",
                "1",
                "-",
            ],
            "/nonexistent/service.json",
        ),
        (
            vec![
                "check",
                "--config",
                &config,
                "--now",
                "1",
                "/nonexistent/token.jwt",
            ],
            "/nonexistent/token.jwt",
        ),
        (
            vec!["make", "--key", &config, &claims],
            "is not a private key",
        ),
    ];
    for (args, fragment) in cases {
        let out = run_cli(&args, "");
        assert_eq!(out.code, 2, "{args:?}");
        assert_eq!(out.stdout, "");
        assert!(out.stderr.starts_with("error: "), "{}", out.stderr);
        assert!(out.stderr.contains(fragment), "{args:?}: {}", out.stderr);
    }
}

#[test]
fn p_9_cli_the_claims_must_be_one_strict_json_object() {
    let key = example("test-edge-ed25519.pem");
    for (text, fragment) in [
        ("", "not valid JSON"),
        ("{", "not valid JSON"),
        ("[]", "expected one JSON object"),
        ("5", "expected one JSON object"),
        ("{\"iss\": \"a\", \"iss\": \"b\"}", "duplicate member `iss`"),
        ("{} {}", "not valid JSON"),
    ] {
        let out = run_cli(&["make", "--key", &key, "-"], text);
        assert_eq!(out.code, 2, "{text}");
        assert!(out.stderr.contains(fragment), "{text}: {}", out.stderr);
    }
}

#[test]
fn p_9_cli_the_options_of_the_header_are_not_empty_and_do_not_contradict() {
    let key = example("test-edge-ed25519.pem");
    let claims = person_claims().to_string();
    for option in ["--typ", "--kid", "--crit"] {
        let out = run_cli(&["make", "--key", &key, option, "", "-"], &claims);
        assert_eq!(out.code, 2, "{option}");
        assert!(out.stderr.contains(option), "{option}");
        assert!(out.stderr.contains("not empty"), "{option}");
    }
    let out = run_cli(
        &[
            "make",
            "--key",
            &key,
            "--alg",
            "none",
            "--bad-signature",
            "-",
        ],
        &claims,
    );
    assert_eq!(out.code, 2);
    assert!(
        out.stderr
            .contains("`--bad-signature` cannot go with `--alg none`")
    );
}

#[test]
fn p_9_cli_the_standard_input_is_never_a_private_key() {
    let pem = example_text("test-edge-ed25519.pem");
    let claims = example("claims.json");
    let out = run_cli(&["make", "--key", "-", &claims], &pem);
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("Cannot open the file `-`"));
    assert_no_secret(&out.all(), "test-edge-ed25519.pem");
}

#[test]
fn p_9_cli_make_json_gives_the_token_the_header_and_the_claims() {
    let out = make_out(
        "test-edge-es256.pem",
        &key_claims(),
        &["--format", "json", "--kid", "k"],
    );
    assert_eq!(out.code, 0);
    let document: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(
        document["header"],
        json!({"alg": "ES256", "kid": "k", "typ": "JWT"})
    );
    assert_eq!(document["claims"], key_claims());
    assert_eq!(document["findings"], json!([]));
    let token = document["token"].as_str().unwrap();
    assert_eq!(token.split('.').count(), 3);
    assert_eq!(out.stderr, "");
}

#[test]
fn p_9_cli_make_json_gives_the_findings_when_it_refuses() {
    let mut claims = person_claims();
    claims.as_object_mut().unwrap().remove("aud");
    let out = make_out("test-edge-ed25519.pem", &claims, &["--format", "json"]);
    assert_eq!(out.code, 1);
    let document: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(document["token"], Value::Null);
    assert_eq!(document["findings"][0]["rule"], "9.3");
    assert_eq!(document["findings"][0]["severity"], "error");
    assert_eq!(out.stderr, "");
}

#[test]
fn p_9_cli_make_writes_the_token_alone_on_the_standard_output() {
    let out = make_out("test-edge-ed25519.pem", &person_claims(), &[]);
    assert_eq!(out.code, 0);
    assert_eq!(out.stdout.lines().count(), 1);
    assert!(out.stdout.ends_with('\n'));
    assert_eq!(out.stderr, "");
}

#[test]
fn p_9_cli_check_json_and_text_agree_on_the_exit_code() {
    let token = make(
        "test-edge-ed25519.pem",
        &person_claims(),
        &["--bad-signature"],
    );
    let text = check("service.json", &token, &[]);
    let json = check("service.json", &token, &["--format", "json"]);
    assert_eq!(text.code, 1);
    assert_eq!(json.code, 1);
    assert_eq!(text.stderr, "");
    assert_eq!(json.stderr, "");
}

#[test]
fn p_9_cli_print_config_checks_the_file_and_writes_the_values() {
    let config = example("service-two-keys.json");
    let out = run_cli(&["check", "--config", &config, "--print-config"], "");
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.contains("max_age_seconds 300"));
    assert!(
        out.stdout
            .contains("kid edge-es256, alg ES256  (file:jwks.keys[0])")
    );
    let out = run_cli(
        &[
            "check",
            "--config",
            &config,
            "--print-config",
            "--format",
            "json",
        ],
        "",
    );
    let document: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(document["service_id"], "datastore");
    let bad = temp_file("cli_bad_config.json", "{}");
    let out = run_cli(&["check", "--config", &bad, "--print-config"], "");
    assert_eq!(out.code, 2);
}

#[test]
fn p_9_cli_no_output_holds_a_private_key() {
    let claims = person_claims();
    for key in ["test-edge-ed25519.pem", "test-edge-es256.pem"] {
        let mut all = String::new();
        for extra in [
            vec![],
            vec!["--format", "json"],
            vec!["--bad-signature"],
            vec!["--alg", "none"],
            vec!["--typ", "at+jwt", "--kid", "k"],
        ] {
            let out = make_out(key, &claims, &extra);
            all.push_str(&out.all());
        }
        let mut bad = claims.clone();
        bad.as_object_mut().unwrap().remove("iss");
        all.push_str(&make_out(key, &bad, &[]).all());
        all.push_str(&make_out(key, &bad, &["--format", "json"]).all());
        // A key file that is not a key: the program never shows its text.
        let junk = temp_file("cli_junk_key.pem", "SECRETMARKER-1234567890\n");
        let claims_file = example("claims.json");
        let out = run_cli(&["make", "--key", &junk, &claims_file], "");
        assert!(!out.all().contains("SECRETMARKER"));
        // A public key in place of a private key.
        let public = example(&key.replace(".pem", ".pub.pem"));
        let out = run_cli(&["make", "--key", &public, &claims_file], "");
        assert_eq!(out.code, 2);
        all.push_str(&out.all());
        assert_no_secret(&all, key);
    }
}

#[test]
fn p_9_cli_a_token_is_not_a_private_key() {
    // A token and its JSON result hold no private key, and the debug text of a key is hidden.
    let token = make("test-edge-es256.pem", &person_claims(), &[]);
    let out = check("service-two-keys.json", &token, &["--format", "json"]);
    assert_no_secret(&out.all(), "test-edge-es256.pem");
}

#[test]
fn p_9_cli_the_code_reads_no_environment_variable() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in std::fs::read_dir(src).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        for forbidden in [
            "env::var",
            "var_os",
            "env::vars",
            "option_env!",
            "#[arg(env",
        ] {
            assert!(!text.contains(forbidden), "{name} has `{forbidden}`");
        }
        let uses_env_macro = text.matches("env!(").count();
        let version_uses = text.matches("env!(\"CARGO_PKG_VERSION\")").count();
        assert_eq!(
            uses_env_macro, version_uses,
            "{name}: an env! macro other than the version"
        );
        if name != "main.rs" {
            assert!(!text.contains("env::args"), "{name} reads the arguments");
        }
    }
}

#[test]
fn p_9_cli_the_code_has_no_unsafe_block_and_no_network() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in std::fs::read_dir(src).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("unsafe "), "{}", path.display());
        assert!(!text.contains("std::net"), "{}", path.display());
    }
}
