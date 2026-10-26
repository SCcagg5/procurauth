//! Helpers for the tests of `access-token`. They call `run` with no process.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use access_token::{Io, run};
use base64::Engine as _;
use serde_json::{Value, json};

/// The time of the tests: 100 seconds after the issue of the example claims.
pub(crate) const NOW: u64 = 1_792_569_700;

/// The result of one run.
pub(crate) struct Out {
    pub(crate) code: u8,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

impl Out {
    /// The stdout and the stderr together.
    pub(crate) fn all(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

/// The path of a file of `examples/`, as text.
pub(crate) fn example(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(name)
        .display()
        .to_string()
}

/// The text of a file of `examples/`.
pub(crate) fn example_text(name: &str) -> String {
    std::fs::read_to_string(example(name)).unwrap()
}

/// A file for a test, in the target directory. The name must be unique in the tests.
pub(crate) fn temp_file(name: &str, content: &str) -> String {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("access-token-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path.display().to_string()
}

/// Run the program. The clock gives an error: a test must give `--now`.
pub(crate) fn run_cli(args: &[&str], stdin: &str) -> Out {
    run_with_clock(args, stdin, &|| {
        Err("The test did not give a clock.".to_owned())
    })
}

/// Run the program with a clock.
pub(crate) fn run_with_clock(
    args: &[&str],
    stdin: &str,
    clock: &dyn Fn() -> Result<u64, String>,
) -> Out {
    let mut input = stdin.as_bytes();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut full = vec!["access-token"];
    full.extend_from_slice(args);
    let code = run(
        full,
        &mut Io {
            stdin: &mut input,
            stdout: &mut stdout,
            stderr: &mut stderr,
            clock,
        },
    );
    Out {
        code,
        stdout: String::from_utf8(stdout).unwrap(),
        stderr: String::from_utf8(stderr).unwrap(),
    }
}

/// The claims of a good token for a person, as the examples give them.
pub(crate) fn person_claims() -> Value {
    json!({
        "iss": "https://edge.example",
        "sub": "alice",
        "aud": "datastore",
        "iat": 1_792_569_600_u64,
        "exp": 1_792_569_900_u64
    })
}

/// The claims of a good token for a key.
pub(crate) fn key_claims() -> Value {
    let mut claims = person_claims();
    claims["sub"] = json!("key:9b1c04e2aa71f0c3");
    claims["owner"] = json!("alice");
    claims
}

/// Make a token with the test key. `extra` holds more arguments for `make`.
pub(crate) fn make(key: &str, claims: &Value, extra: &[&str]) -> String {
    let out = make_out(key, claims, extra);
    assert_eq!(out.code, 0, "make failed: {}", out.stderr);
    out.stdout.trim_end().to_owned()
}

/// Run `make` and give the whole result.
pub(crate) fn make_out(key: &str, claims: &Value, extra: &[&str]) -> Out {
    let key_path = example(key);
    let mut args = vec!["make", "--key", key_path.as_str()];
    args.extend_from_slice(extra);
    args.push("-");
    run_cli(&args, &claims.to_string())
}

/// Run `check` on a token with a configuration of `examples/`.
pub(crate) fn check(config: &str, token: &str, extra: &[&str]) -> Out {
    let config_path = example(config);
    let now = NOW.to_string();
    let mut args = vec![
        "check",
        "--config",
        config_path.as_str(),
        "--now",
        now.as_str(),
    ];
    args.extend_from_slice(extra);
    args.push("-");
    run_cli(&args, token)
}

/// The names of the checks that fail, in the JSON result.
pub(crate) fn failing(out: &Out) -> Vec<String> {
    let document: Value = serde_json::from_str(&out.stdout).unwrap();
    document["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|check| check["outcome"] == "fail")
        .map(|check| check["name"].as_str().unwrap().to_owned())
        .collect()
}

/// The result of one check in the JSON result.
pub(crate) fn check_entry(out: &Out, name: &str) -> Value {
    let document: Value = serde_json::from_str(&out.stdout).unwrap();
    document["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["name"] == name)
        .unwrap()
        .clone()
}

/// The texts that a private key makes, and that no output may hold.
pub(crate) fn secrets_of(pem_name: &str) -> Vec<String> {
    let pem = example_text(pem_name);
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(&body)
        .unwrap();
    // The seed or the scalar has 32 bytes. Ed25519 has it at 16. P-256 has it after `02 01 01 04 20`.
    let start = if der.len() == 48 {
        16
    } else {
        der.windows(5)
            .position(|w| w == [0x02, 0x01, 0x01, 0x04, 0x20])
            .unwrap()
            + 5
    };
    let secret = &der[start..start + 32];
    let mut texts = vec![body.clone()];
    texts.push(base64::engine::general_purpose::STANDARD.encode(secret));
    texts.push(base64::engine::general_purpose::STANDARD_NO_PAD.encode(secret));
    texts.push(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret));
    texts.push(hex_of(secret));
    texts
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Assert that the output holds no text of the private key.
pub(crate) fn assert_no_secret(output: &str, pem_name: &str) {
    for secret in secrets_of(pem_name) {
        assert!(
            !output.contains(&secret),
            "the output holds a text of the private key {pem_name}"
        );
    }
}
