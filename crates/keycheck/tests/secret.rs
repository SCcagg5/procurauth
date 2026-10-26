//! The text of a key never appears in an output or in an error.
//!
//! The tests make keys from fixed seeds and feed bad variants through each
//! failure mode. They search every output for the random part and the whole text.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{FORMAT_PATH, go, key_from_seed, scratch_file};

/// Run the program in both forms, and assert that no output holds the secret.
fn assert_no_leak(
    args: &[&str],
    stdin: &[u8],
    secrets: &[&str],
    what: &str,
) -> Vec<(String, String, u8)> {
    let mut seen = Vec::new();
    for form in ["text", "json"] {
        let mut all: Vec<&str> = vec!["--format", form];
        all.extend_from_slice(args);
        let run = go(&all, stdin);
        for secret in secrets {
            assert!(
                !run.stdout.contains(secret),
                "{what} ({form}): stdout holds the secret"
            );
            assert!(
                !run.stderr.contains(secret),
                "{what} ({form}): stderr holds the secret"
            );
        }
        seen.push((run.stdout, run.stderr, run.exit.code()));
    }
    seen
}

fn variants(key: &str) -> Vec<(&'static str, Vec<u8>)> {
    let mut bad_alphabet = key.to_owned();
    bad_alphabet.replace_range(15..16, "!");
    let mut bad_checksum = key.to_owned();
    let last = bad_checksum.pop().unwrap();
    bad_checksum.push(if last == 'x' { 'y' } else { 'x' });
    let mut not_utf8 = key.as_bytes().to_vec();
    not_utf8[20] = 0xFF;
    let mut not_ascii = key.to_owned();
    not_ascii.replace_range(30..31, "\u{e9}");
    vec![
        ("good", key.as_bytes().to_vec()),
        ("good with line end", format!("{key}\n").into_bytes()),
        ("good with CRLF", format!("{key}\r\n").into_bytes()),
        ("bad prefix", key.replacen("mcp_", "dlg_", 1).into_bytes()),
        ("no prefix", key.as_bytes()[4..].to_vec()),
        ("too short", key.as_bytes()[..47].to_vec()),
        ("too long", format!("{key}Z").into_bytes()),
        ("bad alphabet", bad_alphabet.into_bytes()),
        ("bad checksum", bad_checksum.into_bytes()),
        ("not ascii", not_ascii.into_bytes()),
        ("not utf8", not_utf8),
        (
            "space",
            format!("{} {}", &key[..20], &key[20..]).into_bytes(),
        ),
        ("trailing space", format!("{key} \n").into_bytes()),
        ("second line", format!("{key}\n{key}\n").into_bytes()),
        (
            "second line other key",
            format!("{key}\nmcp_other\n").into_bytes(),
        ),
        ("very long", key.repeat(100).into_bytes()),
        ("endless line", key.repeat(2000).into_bytes()),
        ("quoted", format!("\"{key}\"\n").into_bytes()),
        (
            "json string",
            format!("{{\"key\": \"{key}\"}}\n").into_bytes(),
        ),
    ]
}

#[test]
fn p_2_the_text_of_a_key_is_in_no_output_for_any_variant() {
    for seed in 1..=20 {
        let (key, random) = key_from_seed(seed);
        assert_eq!(key.len(), 53);
        let secrets = [key.as_str(), random.as_str(), &key[4..]];
        for (name, input) in variants(&key) {
            assert_no_leak(&[FORMAT_PATH], &input, &secrets, name);
        }
    }
}

#[test]
fn p_2_a_good_key_shows_only_the_digest_and_four_characters() {
    let (key, random) = key_from_seed(7);
    let run = go(&[FORMAT_PATH], key.as_bytes());
    assert!(run.stdout.contains(&format!("hint: {}\n", &random[..4])));
    assert!(!run.stdout.contains(&random[..5]));
    assert_eq!(run.stdout.lines().count(), 3);
}

#[test]
fn p_2_a_key_given_as_an_argument_is_not_echoed() {
    let (key, random) = key_from_seed(3);
    let secrets = [key.as_str(), random.as_str()];
    let cases: [Vec<&str>; 6] = [
        vec![FORMAT_PATH, &key],
        vec![&key],
        vec![&key, FORMAT_PATH],
        vec!["--format", &key, FORMAT_PATH],
        vec![&key, &key],
        vec![FORMAT_PATH, "--", &key],
    ];
    for args in cases {
        let run = go(&args, key.as_bytes());
        assert_ne!(run.exit.code(), 0, "{args:?}");
        for secret in secrets {
            assert!(
                !run.stdout.contains(secret) && !run.stderr.contains(secret),
                "{args:?}"
            );
        }
    }
    let flag = format!("--{key}");
    let eq = format!("--format={key}");
    for arg in [flag, eq] {
        let run = go(&[arg.as_str(), FORMAT_PATH], key.as_bytes());
        assert_eq!(run.exit.code(), 2);
        assert!(!run.stderr.contains(&random));
    }
}

#[test]
fn p_2_a_key_in_the_place_of_the_format_file_is_not_echoed() {
    let (key, random) = key_from_seed(4);
    // As a path that does not exist.
    let run = go(&[&key], key.as_bytes());
    assert_eq!(run.exit.code(), 2);
    assert!(!run.stderr.contains(&random) && !run.stdout.contains(&random));
    // As the content of the format file, in several shapes.
    for (name, content) in [
        ("key_plain.json", key.clone()),
        ("key_string.json", format!("\"{key}\"")),
        ("key_member.json", format!("{{\"{key}\": 1}}")),
        (
            "key_duplicate.json",
            format!("{{\"{key}\": 1, \"{key}\": 2}}"),
        ),
        (
            "key_prefix.json",
            format!("{{\"prefix\": \"{key}\", \"length\": 53, \"alphabet\": \"a-z\"}}"),
        ),
    ] {
        let path = scratch_file(name, content.as_bytes());
        let run = go(&[&path], key.as_bytes());
        assert_eq!(run.exit.code(), 2, "{name}");
        // A finding repeats the value that it found, but it hides a long token.
        let combined = format!("{}{}", run.stdout, run.stderr);
        assert!(!combined.contains(&random), "{name}: {combined}");
    }
}

#[test]
fn p_2_the_format_file_path_is_not_echoed() {
    let (key, random) = key_from_seed(5);
    // A file whose name is the key.
    let path = scratch_file(&format!("{key}.json"), b"{}");
    let run = go(&[&path], key.as_bytes());
    assert_eq!(run.exit.code(), 2);
    assert!(!run.stderr.contains(&random), "{}", run.stderr);
    let missing = common::scratch(&format!("{key}.absent"));
    let run = go(&[missing.to_str().unwrap()], key.as_bytes());
    assert!(!run.stderr.contains(&random), "{}", run.stderr);
}

#[test]
fn p_2_no_output_holds_the_key_when_the_format_is_unusual() {
    // The prefix is the start of the key, and the alphabet has few characters.
    let (key, random) = key_from_seed(9);
    let path = scratch_file(
        "short_alphabet.json",
        br#"{"prefix": "mcp_", "length": 53, "alphabet": "a-z"}"#,
    );
    let run = go(&[&path], key.as_bytes());
    assert_eq!(run.exit.code(), 1);
    assert!(!run.stdout.contains(&random) && !run.stderr.contains(&random));
}
