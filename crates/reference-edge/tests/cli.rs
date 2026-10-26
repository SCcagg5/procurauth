//! The program: the options, the exit codes, `--print-config`, and a start and a stop.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::{ED25519_PEM, KEY_OK, KEY_UNKNOWN, send};
use serde_json::{Value, json};

fn program() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_reference-edge"));
    // The examples name their files from the root of the repository.
    command.current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."));
    command
}

fn example(name: &str) -> String {
    format!("{}/examples/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn scratch(name: &str, text: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("reference-edge-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path
}

/// A good configuration. The port is free, the PDP is absent, and the secrets come from variables.
fn config(listen: &str) -> Value {
    json!({
        "listen": listen, "service_id": "datastore", "issuer": "https://edge.example",
        "key_format": {"prefix": "pk_live_", "length": 51, "alphabet": "0-9"},
        "keys": common::keys_file(),
        "upstream": {"url": "http://127.0.0.1:1"},
        "signing": {"key_env": "SIGNING_KEY"},
        "pdp": {"url": "http://127.0.0.1:2", "credential_env": "PDP_CRED", "allow_insecure_pdp_link": true,
                "request_timeout_ms": 500, "plain_retries": 0}
    })
}

#[test]
fn the_help_and_the_version_exit_with_0() {
    let out = program().arg("--help").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("--print-config"), "{text}");
    assert!(text.contains("identity token"));
    let out = program().arg("--version").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(
        String::from_utf8(out.stdout)
            .unwrap()
            .starts_with("reference-edge ")
    );
}

#[test]
fn a_bad_command_line_exits_with_2() {
    assert_eq!(program().output().unwrap().status.code(), Some(2));
    assert_eq!(
        program()
            .arg("--unknown")
            .arg("x")
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
    let out = program().arg("/nonexistent/config.json").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("Cannot read the configuration file")
    );
}

#[test]
fn print_config_shows_each_key_with_its_source_and_hides_the_secret() {
    let out = program()
        .arg("--print-config")
        .arg(example("config.json"))
        .env("PROCURAUTH_PDP_CREDENTIAL", "secret-from-the-environment")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.contains("listen = 127.0.0.1:8090  (file)")
            || text.contains("listen = 127.0.0.1:8090  (default)"),
        "{text}"
    );
    assert!(text.contains("workers = 16  (default)"), "{text}");
    assert!(
        text.contains("pdp.credential = <hidden>  (env:PROCURAUTH_PDP_CREDENTIAL)"),
        "{text}"
    );
    assert!(
        text.contains(
            "signing.key = <hidden> (Ed25519)  (file:crates/access-token/examples/test-edge-ed25519.pem)"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "keys = 2 entries  (file:crates/reference-edge/examples/keys.test-only.json)"
        ),
        "{text}"
    );
    for secret in ["secret-from-the-environment", "BEGIN PRIVATE KEY", KEY_OK] {
        assert!(!text.contains(secret), "{secret}");
    }
    assert_eq!(text.lines().count(), reference_edge::config::KEYS.len());
}

#[test]
fn print_config_reads_only_the_variable_that_the_file_names() {
    let out = program()
        .arg("--print-config")
        .arg(example("config.json"))
        .env("PROCURAUTH_PDP_CREDENTIAL", "x")
        .env("OTEL_SERVICE_NAME", "ignored")
        .env("LISTEN", "0.0.0.0:1")
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(text.contains("127.0.0.1:8090"), "{text}");
    assert!(!text.contains("0.0.0.0:1"));
    // Without the variable, the program stops before it serves.
    let out = program()
        .arg("--print-config")
        .arg(example("config.json"))
        .env_remove("PROCURAUTH_PDP_CREDENTIAL")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(
        err.contains("pdp.credential_env") && err.contains("PROCURAUTH_PDP_CREDENTIAL"),
        "{err}"
    );
}

#[test]
fn a_configuration_error_stops_the_program_before_it_opens_the_port() {
    let mut value = config("127.0.0.1:0");
    value["workers"] = json!(0);
    value["unknown"] = json!(1);
    value["token_life_seconds"] = json!(400);
    let path = scratch("bad.json", &value.to_string());
    let out = program()
        .arg(&path)
        .env("SIGNING_KEY", ED25519_PEM)
        .env("PDP_CRED", "x")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty(), "the program printed no address");
    let err = String::from_utf8(out.stderr).unwrap();
    for part in ["`workers`", "unknown", "token_life_seconds"] {
        assert!(err.contains(part), "{part} in {err}");
    }
    assert!(!err.contains("PRIVATE KEY"));
}

#[test]
fn the_program_serves_and_stops_on_sigterm() {
    let path = scratch("serve.json", &config("127.0.0.1:0").to_string());
    let mut child = program()
        .arg(&path)
        .env("SIGNING_KEY", ED25519_PEM)
        .env("PDP_CRED", "x")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut first = String::new();
    BufReader::new(child.stdout.as_mut().unwrap())
        .read_line(&mut first)
        .unwrap();
    let addr = first
        .trim()
        .rsplit_once("http://")
        .unwrap()
        .1
        .parse()
        .unwrap();
    let none = send(addr, "GET", "/hosts", &[], None);
    assert_eq!(none.status, 401);
    assert_eq!(none.header("www-authenticate"), Some("Bearer"));
    let unknown = format!("Bearer {KEY_UNKNOWN}");
    let bad = send(addr, "GET", "/hosts", &[("Authorization", &unknown)], None);
    assert_eq!(
        bad.header("www-authenticate"),
        Some("Bearer error=\"invalid_token\"")
    );
    // The PDP is absent. A good key gets 503, and the edge never contacts the service.
    let good = format!("Bearer {KEY_OK}");
    assert_eq!(
        send(addr, "GET", "/hosts", &[("Authorization", &good)], None).status,
        503
    );
    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let started = Instant::now();
    let code = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code();
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the program does not stop"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(code, Some(0));
    let mut err = String::new();
    child
        .stderr
        .as_mut()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    // The program logs the effective configuration at start, with the secrets hidden.
    assert!(err.contains("effective configuration:"), "{err}");
    assert!(
        err.contains("pdp.credential = <hidden>  (env:PDP_CRED)"),
        "{err}"
    );
    for secret in ["PRIVATE KEY", KEY_OK, KEY_UNKNOWN] {
        assert!(!err.contains(secret), "{secret}");
    }
    assert!(err.contains("GET /hosts 401 (unknown_key)"), "{err}");
    assert!(err.contains("GET /hosts 401 (no_authorization)"), "{err}");
    assert!(err.contains("GET /hosts 503 (pdp_unavailable"), "{err}");
}

#[test]
fn a_port_that_is_in_use_exits_with_1() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let path = scratch(
        "busy.json",
        &config(&listener.local_addr().unwrap().to_string()).to_string(),
    );
    let out = program()
        .arg(&path)
        .env("SIGNING_KEY", ED25519_PEM)
        .env("PDP_CRED", "x")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("Cannot open the port")
    );
}
