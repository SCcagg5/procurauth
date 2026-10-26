//! The program: the options, the exit codes, `--print-config`, and a start and a stop.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::{Edge, send};
use serde_json::json;

fn program() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_reference-service"));
    // The examples name their files from the root of the repository.
    command.current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."));
    command
}

#[cfg(feature = "mcp")]
fn example(name: &str) -> String {
    format!("{}/examples/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn scratch(name: &str, text: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("reference-service-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path
}

#[test]
fn the_help_and_the_version_exit_with_0() {
    let out = program().arg("--help").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("--print-config"), "{text}");
    assert!(text.contains("procurauth-pep"));
    let out = program().arg("--version").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(
        String::from_utf8(out.stdout)
            .unwrap()
            .starts_with("reference-service ")
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

#[cfg(feature = "mcp")]
#[test]
fn print_config_shows_each_key_with_its_source_and_hides_the_secret() {
    let out = program()
        .arg("--print-config")
        .arg(example("config.json"))
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("listen = 127.0.0.1:8080  (file)"), "{text}");
    assert!(text.contains("workers = 8  (default)"), "{text}");
    assert!(
        text.contains(
            "pdp.credential = <hidden>  (file:crates/fake-pdp/examples/pep-credential.txt)"
        ),
        "{text}"
    );
    assert!(!text.contains("example-credential-for-tests-only"));
    assert!(
        text.contains("jwks = 1 key (Ed25519 kid=edge-ed25519)  (file)"),
        "{text}"
    );
    assert_eq!(text.lines().count(), reference_service::config::KEYS.len());
}

#[cfg(feature = "mcp")]
#[test]
fn print_config_reads_only_the_variable_that_the_file_names() {
    let out = program()
        .arg("--print-config")
        .arg(example("conformance.json"))
        .env("PROCURAUTH_PDP_CREDENTIAL", "secret-from-the-environment")
        .env("OTEL_SERVICE_NAME", "ignored")
        .env("LISTEN", "0.0.0.0:1")
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("pdp.credential = <hidden>  (env:PROCURAUTH_PDP_CREDENTIAL)"),
        "{text}"
    );
    assert!(text.contains("listen = 127.0.0.1:8080  (file)"), "{text}");
    assert!(!text.contains("secret-from-the-environment"));
    // Without the variable, the program stops before it serves.
    let out = program()
        .arg("--print-config")
        .arg(example("conformance.json"))
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
    let path = scratch(
        "bad.json",
        r#"{"listen": "127.0.0.1:0", "workers": 0, "unknown": 1, "issuer": "x",
            "jwks": {"keys": []}, "pdp": {"url": "http://127.0.0.1:1", "credential_env": "NOPE"}}"#,
    );
    let out = program().arg(&path).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty(), "the program printed no address");
    let err = String::from_utf8(out.stderr).unwrap();
    for part in ["`workers`", "unknown", "jwks", "NOPE"] {
        assert!(err.contains(part), "{part} in {err}");
    }
}

#[test]
fn the_program_serves_and_stops_on_sigterm() {
    let edge = Edge::new();
    let config = json!({
        "listen": "127.0.0.1:0", "issuer": "https://edge.example", "jwks": edge.jwks(),
        "pdp": {"url": "http://127.0.0.1:1", "credential_env": "PDP_CRED", "allow_insecure_pdp_link": true}
    });
    let path = scratch("serve.json", &config.to_string());
    let mut child = program()
        .arg(&path)
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
    let reply = send(addr, "GET", "/.well-known/procurauth/actions", &[], None);
    assert_eq!(reply.status, 200);
    assert_eq!(send(addr, "GET", "/hosts", &[], None).status, 401);
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
    std::io::Read::read_to_string(child.stderr.as_mut().unwrap(), &mut err).unwrap();
    // The program logs the effective configuration at start, with the secret hidden.
    assert!(err.contains("effective configuration:"), "{err}");
    assert!(
        err.contains("pdp.credential = <hidden>  (env:PDP_CRED)"),
        "{err}"
    );
}

#[test]
fn a_port_that_is_in_use_exits_with_1() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let edge = Edge::new();
    let config = json!({
        "listen": listener.local_addr().unwrap().to_string(), "issuer": "https://edge.example", "jwks": edge.jwks(),
        "pdp": {"url": "http://127.0.0.1:1", "credential_env": "PDP_CRED", "allow_insecure_pdp_link": true}
    });
    let path = scratch("busy.json", &config.to_string());
    let out = program().arg(&path).env("PDP_CRED", "x").output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("Cannot open the port")
    );
}
