//! Helpers for the tests of `keycheck`: a run without a process, and keys from fixed seeds.

#![allow(dead_code, unreachable_pub, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use keycheck::Exit;
use procurauth_core::key_format::KeyFormat;

/// The example format file of the crate.
pub const FORMAT_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/format.json");

/// The random part of the key of the golden tests.
pub const GOLDEN_RANDOM: &str = "aB3dE5gH7jK9mN1pQ2rS4tU6vW8xY0zA1bC3dE5fG7h";
/// The key of the golden tests: `mcp_`, 43 random characters and the checksum.
pub const GOLDEN_KEY: &str = "mcp_aB3dE5gH7jK9mN1pQ2rS4tU6vW8xY0zA1bC3dE5fG7h0bRv4o";
/// The SHA-256 digest of the golden key. `printf %s KEY | sha256sum` gives it.
pub const GOLDEN_DIGEST: &str = "a9985ef98e018b4c34f4e5cedd1e19cb5b31e533f30a18fc12834f378919b99f";

/// The result of one run.
pub struct Run {
    pub exit: Exit,
    pub stdout: String,
    pub stderr: String,
}

/// Run the program with the arguments and the bytes of the standard input.
pub fn go(args: &[&str], stdin: &[u8]) -> Run {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = keycheck::run(
        std::iter::once("keycheck").chain(args.iter().copied()),
        stdin,
        &mut stdout,
        &mut stderr,
    );
    Run {
        exit,
        stdout: String::from_utf8(stdout).unwrap(),
        stderr: String::from_utf8(stderr).unwrap(),
    }
}

/// Run with the example format file.
pub fn check(stdin: &[u8]) -> Run {
    go(&[FORMAT_PATH], stdin)
}

/// The portal format.
pub fn format() -> KeyFormat {
    KeyFormat::parse_str(&fs::read_to_string(FORMAT_PATH).unwrap()).unwrap()
}

/// A random part of 43 base62 characters from a seed (a simple generator, for tests only).
pub fn random_part(seed: u64) -> String {
    const DIGITS: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut state = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    (0..43)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            char::from(DIGITS[usize::try_from((state >> 33) % 62).unwrap()])
        })
        .collect()
}

/// A good key of the portal format from a seed. The result has the random part too.
pub fn key_from_seed(seed: u64) -> (String, String) {
    let random = random_part(seed);
    let checksum = format().checksum_for(&random).unwrap();
    (format!("mcp_{random}{checksum}"), random)
}

/// A path for a file of a test, in the target directory of the tests.
pub fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("keycheck");
    fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

/// Write a file of a test and give its path as text.
pub fn scratch_file(name: &str, content: &[u8]) -> String {
    let path = scratch(name);
    fs::write(&path, content).unwrap();
    path.to_str().unwrap().to_owned()
}
