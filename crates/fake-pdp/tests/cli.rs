//! The program: usage, exit codes, fail-fast checks, the effective configuration and the stop signals.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// The tests send signals with the program `kill`, so they run on Unix only.
#![cfg(unix)]

mod common;

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use common::*;
use serde_json::json;

const BIN: &str = env!("CARGO_BIN_EXE_fake-pdp");

fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("fake-pdp-cli-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn example(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(name)
}

fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A program that runs, with its output lines on a channel.
struct Program {
    child: Child,
    lines: Receiver<String>,
    errors: Receiver<String>,
}

fn lines_of(reader: impl std::io::Read + Send + 'static) -> Receiver<String> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    receiver
}

fn spawn(args: &[&str]) -> Program {
    let mut child = Command::new(BIN)
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let lines = lines_of(child.stdout.take().unwrap());
    let errors = lines_of(child.stderr.take().unwrap());
    Program {
        child,
        lines,
        errors,
    }
}

impl Program {
    fn line(&self) -> String {
        self.lines
            .recv_timeout(Duration::from_secs(20))
            .expect("a line on stdout")
    }

    fn address(&self) -> SocketAddr {
        let banner = self.line();
        let url = banner.rsplit(" on http://").next().unwrap().to_owned();
        assert!(
            banner.starts_with(&format!(
                "fake-pdp {} on http://",
                env!("CARGO_PKG_VERSION")
            )),
            "{banner}"
        );
        url.parse().unwrap()
    }

    fn signal(&self, name: &str) {
        let status = Command::new("kill")
            .args([format!("-{name}"), self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn wait(&mut self) -> std::process::ExitStatus {
        for _ in 0..200 {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            thread::sleep(Duration::from_millis(50));
        }
        self.child.kill().unwrap();
        panic!("the program did not stop");
    }
}

impl Drop for Program {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn help_shows_the_usage_and_exits_with_0() {
    let output = run(&["--help"]);
    assert_eq!(output.status.code(), Some(0));
    let out = text(&output.stdout);
    for expected in [
        "Usage:",
        "fake-pdp",
        "--listen",
        "--clock-start",
        "--admin",
        "--credential-file",
        "--failures",
        "--print-config",
        "DATA_FILE",
    ] {
        assert!(out.contains(expected), "{expected} in {out}");
    }
    assert!(!out.contains('\u{1b}'), "no colour");
    assert!(!out.contains("--format"), "the tool has no output format");
}

#[test]
fn version_shows_the_version_and_the_licence() {
    for flag in ["--version", "-V"] {
        let output = run(&[flag]);
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(
            text(&output.stdout),
            format!("fake-pdp {}\nApache-2.0\n", env!("CARGO_PKG_VERSION"))
        );
    }
}

#[test]
fn a_usage_error_exits_with_2_and_writes_to_stderr() {
    let data = example("datastore.json");
    let data = data.to_str().unwrap();
    let cases: Vec<Vec<&str>> = vec![
        vec![],
        vec!["--bogus", data],
        vec![data, data],
        vec!["--listen", "127.0.0.1:1", "--listen", "127.0.0.1:2", data],
        vec!["--listen", data],
        vec!["--workers", data],
        vec!["--clock-start", "-5", data],
        vec!["--listen"],
    ];
    for args in cases {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(!output.stderr.is_empty(), "{args:?}");
        assert!(!text(&output.stderr).contains('\u{1b}'), "no colour");
    }
}

#[test]
fn a_bad_flag_value_names_the_key_the_expected_value_and_the_value() {
    let data = example("datastore.json");
    let data = data.to_str().unwrap();
    let cases: [(&[&str], &[&str]); 4] = [
        (
            &["--listen", "localhost:80"],
            &["--listen", "ADDRESS:PORT", "localhost:80"],
        ),
        (
            &["--clock-start", "1.5"],
            &["--clock-start", "whole number", "1.5"],
        ),
        (&["--workers", "0"], &["--workers", "1 to 256", "\"0\""]),
        (&["--workers", "999"], &["--workers", "1 to 256", "999"]),
    ];
    for (flags, expected) in cases {
        let mut args = flags.to_vec();
        args.push(data);
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "{flags:?}");
        let err = text(&output.stderr);
        for word in expected {
            assert!(err.contains(word), "{word} in {err}");
        }
    }
}

#[test]
fn a_missing_data_file_exits_with_2_and_names_the_path() {
    let output = run(&["/nonexistent/directory.json"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(text(&output.stderr).contains("/nonexistent/directory.json"));
}

#[test]
fn a_bad_data_file_exits_with_2_and_prints_every_finding_with_its_path() {
    let dir = scratch("bad-data");
    let path = write(
        &dir,
        "bad.json",
        &json!({
            "services": [],
            "subjects": [
                {"id": "alice", "owner": "bob"},
                {"id": "key:abc"},
                {"id": "bad:id", "grants": [{"action": "data.read", "resource": "service:nope"}]}
            ],
            "counters": [{"subject": "ghost", "limit": "requests", "window": "week", "used": -1}],
            "extra": true
        })
        .to_string(),
    );
    let output = run(&[path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let err = text(&output.stderr);
    for expected in [
        "$.extra",
        "$.subjects[0].owner",
        "$.subjects[1]",
        "$.subjects[2].id",
        "$.counters[0]",
    ] {
        assert!(err.contains(expected), "{expected} in {err}");
    }
    let findings = err.lines().filter(|l| l.contains("error:")).count();
    assert!(findings >= 5, "{err}");
    assert!(err.contains("bad.json"), "each finding names the file");
}

#[test]
fn a_data_file_with_a_duplicate_member_or_bad_json_exits_with_2() {
    let dir = scratch("dup");
    for (name, body) in [
        (
            "dup.json",
            r#"{"services": [], "subjects": [], "subjects": []}"#,
        ),
        ("junk.json", "{"),
        ("array.json", "[]"),
        ("empty.json", ""),
    ] {
        let path = write(&dir, name, body);
        let output = run(&[path.to_str().unwrap()]);
        assert_eq!(output.status.code(), Some(2), "{name}");
        assert!(text(&output.stderr).contains(name), "{name}");
    }
}

#[test]
fn two_clock_settings_contradict_each_other() {
    let output = run(&[
        "--clock-start",
        "5",
        example("datastore.json").to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(2));
    let err = text(&output.stderr);
    assert!(
        err.contains("--clock-start") && err.contains("clock.now"),
        "{err}"
    );
}

#[test]
fn a_bad_credential_file_or_failure_file_exits_with_2_before_the_port_opens() {
    let dir = scratch("files");
    let data = example("datastore.json");
    let data = data.to_str().unwrap();
    let empty = write(&dir, "empty.txt", "\n");
    let output = run(&["--credential-file", empty.to_str().unwrap(), data]);
    assert_eq!(output.status.code(), Some(2));
    let err = text(&output.stderr);
    assert!(
        err.contains("--credential-file") && err.contains("empty.txt"),
        "{err}"
    );
    let output = run(&["--credential-file", "/nonexistent/token", data]);
    assert_eq!(output.status.code(), Some(2));
    assert!(text(&output.stderr).contains("/nonexistent/token"));
    let bad = write(
        &dir,
        "failures.json",
        r#"{"failures": [{"kind": "explode"}], "more": 1}"#,
    );
    let output = run(&["--failures", bad.to_str().unwrap(), data]);
    assert_eq!(output.status.code(), Some(2));
    let err = text(&output.stderr);
    assert!(
        err.contains("$.failures[0].kind") && err.contains("$.more"),
        "{err}"
    );
}

#[test]
fn print_config_shows_each_value_and_its_source_and_hides_the_secret() {
    let output = run(&[
        "--print-config",
        "--workers",
        "4",
        "--credential-file",
        example("pep-credential.txt").to_str().unwrap(),
        example("datastore-with-counters.json").to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(0));
    let out = text(&output.stdout);
    for expected in [
        "--listen = 127.0.0.1:8181  (default)",
        "--workers = 4  (flag)",
        "--admin = off  (default)",
        "clock.now = 1792569648  (data file)",
        "metadata.usage_max_seconds = 5  (data file)",
        "metadata.evaluations_max_items = 50  (data file)",
        "(value hidden)  (flag)",
        "directory = 1 services, 4 subjects, 3 counters  (data file)",
    ] {
        assert!(out.contains(expected), "{expected} in {out}");
    }
    assert!(!out.contains("example-credential-for-tests-only"));
    assert!(text(&output.stderr).is_empty());
}

#[test]
fn print_config_shows_the_defaults_for_a_file_without_metadata() {
    let output = run(&[
        "--print-config",
        example("datastore.json").to_str().unwrap(),
    ]);
    let out = text(&output.stdout);
    assert!(
        out.contains("metadata.idle_max_seconds = 30  (default)"),
        "{out}"
    );
    assert!(
        out.contains("metadata.evaluations_max_bytes = 1048576  (default)"),
        "{out}"
    );
    assert!(out.contains("clock.now = 1792569648  (data file)"), "{out}");
    let output = run(&[
        "--print-config",
        "--clock-start",
        "5",
        example("datastore-with-counters.json").to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(2), "the file has a clock");
}

#[test]
fn the_program_serves_logs_and_stops_on_sigterm_with_exit_code_0() {
    let mut program = spawn(&[
        "--listen",
        "127.0.0.1:0",
        example("datastore.json").to_str().unwrap(),
    ]);
    let addr = program.address();
    assert_eq!(
        program.line(),
        "metadata /.well-known/authzen-configuration"
    );
    let reply =
        Client::connect(addr).post_json(EVALUATION, &question("alice", "data.read", TEST1, true));
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json()["context"]["usage"]["units"], 1);
    assert_eq!(
        program.line(),
        "q1  alice  data.read  host:prod/database:test1"
    );
    assert_eq!(
        program.line(),
        "    true  limits {\"max_rows\":1000}  units 1"
    );
    assert_eq!(
        program.line(),
        "    counters  alice/second 1  alice/minute 1"
    );
    program.signal("TERM");
    assert_eq!(program.wait().code(), Some(0));
    // The configuration is on stderr, and the secrets are not.
    let mut config = Vec::new();
    while let Ok(line) = program.errors.try_recv() {
        config.push(line);
    }
    assert!(
        config
            .iter()
            .any(|l| l.starts_with("config --listen = 127.0.0.1:0  (flag)")),
        "{config:?}"
    );
}

#[test]
fn the_program_stops_on_sigint_with_exit_code_0() {
    let mut program = spawn(&[
        "--listen",
        "127.0.0.1:0",
        example("datastore.json").to_str().unwrap(),
    ]);
    let addr = program.address();
    assert_eq!(
        Client::connect(addr)
            .get("/.well-known/authzen-configuration")
            .status,
        200
    );
    program.signal("INT");
    assert_eq!(program.wait().code(), Some(0));
    assert!(std::net::TcpStream::connect(addr).is_err());
}

#[test]
fn the_port_does_not_open_when_the_data_is_bad() {
    // Find a free port, then give it to a program that must fail before it binds.
    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = free.local_addr().unwrap().port();
    drop(free);
    let dir = scratch("no-port");
    let bad = write(&dir, "bad.json", r#"{"services": []}"#);
    let output = run(&[
        "--listen",
        &format!("127.0.0.1:{port}"),
        bad.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
}

#[test]
fn a_port_that_is_in_use_exits_with_1() {
    let mut first = spawn(&[
        "--listen",
        "127.0.0.1:0",
        example("datastore.json").to_str().unwrap(),
    ]);
    let addr = first.address();
    let output = run(&[
        "--listen",
        &addr.to_string(),
        example("datastore.json").to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).contains(&addr.to_string()));
    first.signal("TERM");
    assert_eq!(first.wait().code(), Some(0));
}

#[test]
fn the_clock_start_flag_and_the_admin_flag_work_together() {
    let dir = scratch("clock");
    let mut data = datastore();
    data.as_object_mut().unwrap().remove("clock");
    let path = write(&dir, "no-clock.json", &data.to_string());
    let mut program = spawn(&[
        "--listen",
        "127.0.0.1:0",
        "--clock-start",
        "1792569648",
        "--admin",
        path.to_str().unwrap(),
    ]);
    let addr = program.address();
    let mut client = Client::connect(addr);
    assert_eq!(client.get("/__fake/clock").json()["now"], NOW);
    let reply = client.send("POST", "/__fake/clock", &[], Some(br#"{"advance": 30}"#));
    assert_eq!(reply.json()["now"], NOW + 30);
    program.signal("TERM");
    assert_eq!(program.wait().code(), Some(0));
}

#[test]
fn the_credential_and_failure_files_work_and_the_program_reads_no_environment_variable() {
    let credential = example("pep-credential.txt");
    let mut program = spawn(&[
        "--listen",
        "127.0.0.1:0",
        "--credential-file",
        credential.to_str().unwrap(),
        "--failures",
        example("failures.json").to_str().unwrap(),
        example("datastore.json").to_str().unwrap(),
    ]);
    let addr = program.address();
    let q = question("alice", "data.read", TEST1, false);
    assert_eq!(Client::connect(addr).post_json(EVALUATION, &q).status, 401);
    let token = std::fs::read_to_string(&credential).unwrap();
    let header = format!("Bearer {}", token.trim_end());
    let reply = Client::connect(addr).post_json_with(EVALUATION, &[("Authorization", &header)], &q);
    assert_eq!(reply.status, 200);
    program.signal("TERM");
    assert_eq!(program.wait().code(), Some(0));
    // No output holds the credential.
    let mut all = String::new();
    while let Ok(line) = program.lines.try_recv() {
        all.push_str(&line);
    }
    while let Ok(line) = program.errors.try_recv() {
        all.push_str(&line);
    }
    assert!(!all.contains(token.trim_end()), "{all}");
}

#[test]
fn an_environment_variable_changes_nothing() {
    let output = Command::new(BIN)
        .args([
            "--print-config",
            example("datastore.json").to_str().unwrap(),
        ])
        .env_clear()
        .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
        .env("FAKE_PDP_LISTEN", "127.0.0.1:1")
        .env("RUST_LOG", "trace")
        .env("NO_COLOR", "")
        .output()
        .unwrap();
    let plain = run(&[
        "--print-config",
        example("datastore.json").to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, plain.stdout);
}
