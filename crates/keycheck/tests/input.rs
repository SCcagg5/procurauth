//! The standard input: line ends, empty input, spaces, a second line, a long input, bad bytes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{GOLDEN_DIGEST, GOLDEN_KEY, check};
use keycheck::{Exit, MAX_INPUT_BYTES};

#[test]
fn p_3_8_the_final_line_end_is_not_part_of_the_key() {
    for suffix in ["", "\n", "\r\n"] {
        let run = check(format!("{GOLDEN_KEY}{suffix}").as_bytes());
        assert_eq!(run.exit, Exit::Clean, "suffix {suffix:?}");
        assert!(run.stdout.contains(GOLDEN_DIGEST));
    }
}

#[test]
fn p_3_8_the_program_removes_exactly_one_line_end() {
    for suffix in ["\n\n", "\r\n\r\n", "\n\r\n", " \n", "\r"] {
        let run = check(format!("{GOLDEN_KEY}{suffix}").as_bytes());
        assert_eq!(run.exit, Exit::Findings, "suffix {suffix:?}");
        assert!(run.stdout.starts_with("bad: "), "suffix {suffix:?}");
    }
}

#[test]
fn p_3_8_a_text_with_a_space_is_bad() {
    let mut key = GOLDEN_KEY.to_owned();
    key.replace_range(20..21, " ");
    let run = check(key.as_bytes());
    assert_eq!(run.exit, Exit::Findings);
    assert!(
        run.stdout
            .starts_with("bad: alphabet (the character at position 21")
    );
    let leading = check(format!(" {GOLDEN_KEY}\n").as_bytes());
    assert!(leading.stdout.starts_with("bad: prefix"));
}

#[test]
fn p_3_8_a_second_line_makes_the_text_bad() {
    let run = check(format!("{GOLDEN_KEY}\n{GOLDEN_KEY}\n").as_bytes());
    assert_eq!(run.exit, Exit::Findings);
    assert!(
        run.stdout
            .starts_with("bad: length (expected 53 characters, found 107)")
    );
}

#[test]
fn empty_input_is_an_input_error() {
    for input in [&b""[..], &b"\n"[..], &b"\r\n"[..]] {
        let run = check(input);
        assert_eq!(run.exit, Exit::Usage);
        assert_eq!(run.stdout, "");
        assert!(
            run.stderr
                .starts_with("keycheck: The standard input has no text.")
        );
    }
}

#[test]
fn a_very_long_input_is_refused_without_a_read_of_all_of_it() {
    let long = vec![b'a'; MAX_INPUT_BYTES + 1];
    let run = check(&long);
    assert_eq!(run.exit, Exit::Usage);
    assert_eq!(run.stdout, "");
    assert!(run.stderr.contains("more than 4096 bytes"));
    // An endless stream stops at the bound.
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = keycheck::run(
        ["keycheck", common::FORMAT_PATH],
        std::io::repeat(b'a'),
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(exit, Exit::Usage);
}

#[test]
fn an_input_of_the_largest_size_is_checked() {
    let exact = vec![b'a'; MAX_INPUT_BYTES];
    let run = check(&exact);
    assert_eq!(run.exit, Exit::Findings);
    assert!(run.stdout.starts_with("bad: prefix"));
}

#[test]
fn a_text_that_is_not_utf8_is_an_input_error() {
    let mut bytes = GOLDEN_KEY.as_bytes().to_vec();
    bytes[12] = 0xFF;
    let run = check(&bytes);
    assert_eq!(run.exit, Exit::Usage);
    assert_eq!(run.stdout, "");
    assert_eq!(
        run.stderr,
        "keycheck: The standard input is not UTF-8 text.\n"
    );
}

#[test]
fn a_text_with_a_character_that_is_not_ascii_is_bad() {
    let key = GOLDEN_KEY.replacen('a', "\u{e9}", 1);
    let run = check(key.as_bytes());
    assert_eq!(run.exit, Exit::Findings);
    assert!(run.stdout.starts_with("bad: "));
}

#[test]
fn a_nul_byte_is_a_bad_character() {
    let mut bytes = GOLDEN_KEY.as_bytes().to_vec();
    bytes[30] = 0;
    let run = check(&bytes);
    assert_eq!(run.exit, Exit::Findings);
    assert!(
        run.stdout
            .starts_with("bad: alphabet (the character at position 31")
    );
}

struct BrokenInput;

impl std::io::Read for BrokenInput {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("broken"))
    }
}

#[test]
fn an_input_that_fails_to_read_is_an_input_error() {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = keycheck::run(
        ["keycheck", common::FORMAT_PATH],
        BrokenInput,
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(exit, Exit::Usage);
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("Cannot read the standard input")
    );
}

struct BrokenOutput;

impl std::io::Write for BrokenOutput {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("closed"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn an_output_that_fails_to_write_is_an_error() {
    let mut stderr = Vec::new();
    let exit = keycheck::run(
        ["keycheck", common::FORMAT_PATH],
        GOLDEN_KEY.as_bytes(),
        &mut BrokenOutput,
        &mut stderr,
    );
    assert_eq!(exit, Exit::Usage);
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("Cannot write to the standard output.")
    );
}
