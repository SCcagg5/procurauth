//! The text format of a key, as data (protocol 3.8 and 2, Key).
//!
//! The protocol defines no format for the text of a key: the system that
//! makes keys chooses it. A [`KeyFormat`] describes one format: a prefix, a
//! total length, an alphabet and an optional checksum. The default format is
//! `mcp_`, 43 random characters and 6 characters of CRC-32 in base62:
//! 53 characters in total. The checker never writes the text of a key in an
//! error, in a log or in a message.

use std::fmt;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::finding::{Finding, JsonPath, Report, show};
use crate::json::parse_str;
use crate::read::{Obj, Unknown};

/// The most characters of the random part that the hint shows.
pub const HINT_CHARACTERS: usize = 4;
/// The longest total length that a format can give.
pub const MAX_LENGTH: u64 = 1024;
/// The longest prefix that a format can give.
pub const MAX_PREFIX: usize = 32;

const BASE62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const HEX: &[u8; 16] = b"0123456789abcdef";

/// The algorithm of the checksum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumAlgorithm {
    /// CRC-32 as in zlib and in Ethernet (the polynomial 0xEDB88320, reflected).
    Crc32,
}

/// The encoding of the checksum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumEncoding {
    /// The digits `0-9`, `A-Z`, `a-z`, with the most significant digit first.
    Base62,
    /// The digits `0-9`, `a-f`, with the most significant digit first.
    Hex,
}

impl ChecksumEncoding {
    fn digits(self) -> &'static [u8] {
        match self {
            Self::Base62 => BASE62,
            Self::Hex => HEX,
        }
    }

    /// The fewest characters that a 32-bit value needs.
    fn minimum_characters(self) -> usize {
        match self {
            Self::Base62 => 6,
            Self::Hex => 8,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Base62 => "base62",
            Self::Hex => "hex",
        }
    }
}

/// The text that the checksum covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Covers {
    /// The random part only. This is the default, and it is the default format.
    Random,
    /// The prefix and the random part.
    PrefixAndRandom,
}

/// The checksum at the end of a key text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checksum {
    /// The algorithm.
    pub algorithm: ChecksumAlgorithm,
    /// The encoding.
    pub encoding: ChecksumEncoding,
    /// The number of characters. The encoder adds `0` on the left up to this number.
    pub characters: usize,
    /// The text that the checksum covers.
    pub covers: Covers,
}

/// A set of characters, written as ranges: `A-Za-z0-9`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alphabet {
    spec: String,
    members: Vec<char>,
}

impl Alphabet {
    /// Read an alphabet. A range is `x-y`. A `-` that is first or last is a character.
    /// Each character is a printable ASCII character, and no character repeats.
    ///
    /// # Errors
    /// Returns the reason when the text is not an alphabet.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let chars: Vec<char> = spec.chars().collect();
        if chars.is_empty() {
            return Err("the alphabet is empty".to_owned());
        }
        let mut members = Vec::new();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if !(c.is_ascii_graphic()) {
                return Err("the alphabet has a character that is not printable ASCII".to_owned());
            }
            let is_range = i + 2 < chars.len() && chars[i + 1] == '-';
            if is_range {
                let end = chars[i + 2];
                if !end.is_ascii_graphic() || end < c {
                    return Err(format!("the range {c}-{end} is not valid"));
                }
                members.extend(c..=end);
                i += 3;
            } else {
                members.push(c);
                i += 1;
            }
        }
        let mut sorted = members.clone();
        sorted.sort_unstable();
        if let Some(pair) = sorted.windows(2).find(|w| w[0] == w[1]) {
            return Err(format!(
                "the character {} occurs more than one time",
                pair[0]
            ));
        }
        Ok(Self {
            spec: spec.to_owned(),
            members,
        })
    }

    /// True when the alphabet has the character.
    pub fn contains(&self, c: char) -> bool {
        self.members.contains(&c)
    }

    /// The text that the format gave.
    pub fn spec(&self) -> &str {
        &self.spec
    }
}

/// A key format (the document `key-format`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyFormat {
    /// The text at the start of each key.
    pub prefix: String,
    /// The length of the whole text, in characters.
    pub length: usize,
    /// The characters that can follow the prefix, the checksum included.
    pub alphabet: Alphabet,
    /// The checksum, when the format has one.
    pub checksum: Option<Checksum>,
}

/// Why a text is not a key of the format. The error never holds the text.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum KeyFormatError {
    /// The text does not start with the prefix.
    #[error("prefix (expected the prefix {expected})")]
    Prefix {
        /// The prefix of the format.
        expected: String,
    },
    /// The text has another length.
    #[error("length (expected {expected} characters, found {found})")]
    Length {
        /// The length of the format.
        expected: usize,
        /// The length of the text.
        found: usize,
    },
    /// A character is not in the alphabet.
    #[error("alphabet (the character at position {position} is not in the alphabet {alphabet})")]
    Alphabet {
        /// The position of the first bad character, from 1, in the text.
        position: usize,
        /// The alphabet of the format.
        alphabet: String,
    },
    /// The checksum does not match.
    #[error("checksum (the checksum characters do not match the text)")]
    Checksum,
}

impl KeyFormatError {
    /// The name of the cause: `prefix`, `length`, `alphabet` or `checksum`.
    pub fn cause(&self) -> &'static str {
        match self {
            Self::Prefix { .. } => "prefix",
            Self::Length { .. } => "length",
            Self::Alphabet { .. } => "alphabet",
            Self::Checksum => "checksum",
        }
    }
}

/// The result for a text that has the format.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyInfo {
    /// The SHA-256 digest of the whole text, in lower-case hexadecimal.
    pub digest_hex: String,
    /// At most 4 of the first characters of the random part.
    pub hint: String,
}

impl fmt::Debug for KeyInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyInfo")
            .field("digest_hex", &self.digest_hex)
            .field("hint", &self.hint)
            .finish()
    }
}

impl KeyFormat {
    /// Read a format from JSON text. The reader is strict.
    ///
    /// # Errors
    /// Returns a finding for each problem.
    pub fn parse_str(text: &str) -> Result<Self, Vec<Finding>> {
        match parse_str(text) {
            Ok(value) => Self::from_value(&value),
            Err(error) => {
                let mut report = Report::new();
                report.error(
                    &error.path,
                    "3.8",
                    "bad_json",
                    format!("The text is not valid JSON: {error}."),
                );
                Err(report.into_findings())
            }
        }
    }

    /// Read a format from a JSON value.
    ///
    /// # Errors
    /// Returns a finding for each problem.
    pub fn from_value(value: &Value) -> Result<Self, Vec<Finding>> {
        let mut report = Report::new();
        let format = read_format(value, &mut report);
        match format {
            Some(format) if !report.has_errors() => Ok(format),
            _ => Err(report.into_findings()),
        }
    }

    /// The format as JSON.
    pub fn to_value(&self) -> Value {
        let mut v = json!({
            "prefix": self.prefix,
            "length": self.length,
            "alphabet": self.alphabet.spec(),
        });
        if let Some(c) = &self.checksum {
            v["checksum"] = json!({
                "algorithm": "crc32",
                "encoding": c.encoding.as_str(),
                "characters": c.characters,
                "covers": match c.covers { Covers::Random => "random", Covers::PrefixAndRandom => "prefix_and_random" },
            });
        }
        v
    }

    /// The number of characters of the random part.
    pub fn random_length(&self) -> usize {
        let checksum = self.checksum.as_ref().map_or(0, |c| c.characters);
        self.length - self.prefix.chars().count() - checksum
    }

    /// Check a text. The checks run in this order: prefix, length, alphabet,
    /// checksum. The function stops at the first failure. The text is exact:
    /// the caller removes the line end of a line that it read.
    ///
    /// # Errors
    /// Returns the first cause of failure. The error does not hold the text.
    pub fn check(&self, text: &str) -> Result<KeyInfo, KeyFormatError> {
        let Some(rest) = text.strip_prefix(&self.prefix) else {
            return Err(KeyFormatError::Prefix {
                expected: self.prefix.clone(),
            });
        };
        let found = text.chars().count();
        if found != self.length {
            return Err(KeyFormatError::Length {
                expected: self.length,
                found,
            });
        }
        let prefix_len = self.prefix.chars().count();
        if let Some(offset) = rest.chars().position(|c| !self.alphabet.contains(c)) {
            return Err(KeyFormatError::Alphabet {
                position: prefix_len + offset + 1,
                alphabet: self.alphabet.spec().to_owned(),
            });
        }
        let random_len = self.random_length();
        let random: String = rest.chars().take(random_len).collect();
        if let Some(checksum) = &self.checksum {
            let given: String = rest.chars().skip(random_len).collect();
            if self.checksum_text(checksum, &random).as_deref() != Some(given.as_str()) {
                return Err(KeyFormatError::Checksum);
            }
        }
        Ok(KeyInfo {
            digest_hex: hex::encode(Sha256::digest(text.as_bytes())),
            hint: random.chars().take(HINT_CHARACTERS).collect(),
        })
    }

    /// The checksum characters for a random part. It is `None` when the
    /// format has no checksum. Use it to make a key text for a test.
    pub fn checksum_for(&self, random: &str) -> Option<String> {
        self.checksum
            .as_ref()
            .and_then(|c| self.checksum_text(c, random))
    }

    fn checksum_text(&self, checksum: &Checksum, random: &str) -> Option<String> {
        let covered = match checksum.covers {
            Covers::Random => random.to_owned(),
            Covers::PrefixAndRandom => format!("{}{random}", self.prefix),
        };
        let ChecksumAlgorithm::Crc32 = checksum.algorithm;
        Some(encode(
            crc32(covered.as_bytes()),
            checksum.encoding,
            checksum.characters,
        ))
    }
}

fn read_format(value: &Value, report: &mut Report) -> Option<KeyFormat> {
    let root = JsonPath::root();
    let mut obj = Obj::new(value, &root, "3.8", Unknown::Error, report)?;
    let prefix = obj.string("prefix", report);
    let length = obj.whole("length", report);
    let alphabet = obj.string("alphabet", report);
    let checksum_obj = obj.object_opt("checksum", "3.8", Unknown::Error, report);
    obj.finish(report);

    if let Some(prefix) = prefix
        && (prefix.is_empty()
            || prefix.chars().count() > MAX_PREFIX
            || !prefix.chars().all(|c| c.is_ascii_graphic()))
    {
        report.error(
            &root.key("prefix"),
            "3.8",
            "bad_prefix",
            format!(
                "Member `prefix`: expected 1 to {MAX_PREFIX} printable ASCII characters, found {}.",
                show(&json!(prefix))
            ),
        );
    }
    if let Some(length) = length
        && !(1..=MAX_LENGTH).contains(&length)
    {
        report.error(
            &root.key("length"),
            "3.8",
            "bad_length",
            format!(
                "Member `length`: expected a whole number from 1 to {MAX_LENGTH}, found {length}."
            ),
        );
    }
    let alphabet_value = alphabet.and_then(|spec| match Alphabet::parse(spec) {
        Ok(a) => Some(a),
        Err(reason) => {
            report.error(
                &root.key("alphabet"),
                "3.8",
                "bad_alphabet",
                format!("Member `alphabet` {}: {reason}.", show(&json!(spec))),
            );
            None
        }
    });
    let checksum = checksum_obj.and_then(|c| read_checksum(c, report));

    let (prefix, length, alphabet_value) =
        (prefix?, usize::try_from(length?).ok()?, alphabet_value?);
    let prefix_len = prefix.chars().count();
    if let Some(checksum) = &checksum {
        let path = root.key("checksum");
        if let Some(min) = Some(checksum.encoding.minimum_characters())
            && checksum.characters < min
        {
            report.error(
                &path.key("characters"),
                "3.8",
                "checksum_too_short",
                format!(
                    "Member `characters`: expected at least {min} for the encoding `{}`, found {}.",
                    checksum.encoding.as_str(),
                    checksum.characters
                ),
            );
        }
        if let Some(missing) = checksum
            .encoding
            .digits()
            .iter()
            .map(|b| char::from(*b))
            .find(|c| !alphabet_value.contains(*c))
        {
            report.error(
                &root.key("alphabet"),
                "3.8",
                "alphabet_lacks_digit",
                format!("The alphabet must have each digit of the encoding `{}`, and it lacks `{missing}`.", checksum.encoding.as_str()),
            );
        }
        if prefix_len + checksum.characters >= length {
            report.error(
                &root.key("length"),
                "3.8",
                "no_random_part",
                format!("Member `length` is {length}, and the prefix and the checksum use {} characters. The random part needs at least 1.", prefix_len + checksum.characters),
            );
        }
    } else if prefix_len >= length {
        report.error(
            &root.key("length"),
            "3.8",
            "no_random_part",
            format!("Member `length` is {length}, and the prefix has {prefix_len} characters. The random part needs at least 1."),
        );
    }
    Some(KeyFormat {
        prefix: prefix.to_owned(),
        length,
        alphabet: alphabet_value,
        checksum,
    })
}

fn read_checksum(mut obj: Obj<'_>, report: &mut Report) -> Option<Checksum> {
    let algorithm = obj.string("algorithm", report);
    let encoding = obj.string("encoding", report);
    let characters = obj.whole("characters", report);
    let covers = obj.string_opt("covers", report);
    obj.finish(report);
    let algorithm = match algorithm? {
        "crc32" => ChecksumAlgorithm::Crc32,
        other => {
            report.error(
                &obj.member_path("algorithm"),
                "3.8",
                "bad_algorithm",
                format!(
                    "Member `algorithm`: expected `crc32`, found {}.",
                    show(&json!(other))
                ),
            );
            return None;
        }
    };
    let encoding = match encoding? {
        "base62" => ChecksumEncoding::Base62,
        "hex" => ChecksumEncoding::Hex,
        other => {
            report.error(
                &obj.member_path("encoding"),
                "3.8",
                "bad_encoding",
                format!(
                    "Member `encoding`: expected `base62` or `hex`, found {}.",
                    show(&json!(other))
                ),
            );
            return None;
        }
    };
    let covers = match covers {
        None | Some("random") => Covers::Random,
        Some("prefix_and_random") => Covers::PrefixAndRandom,
        Some(other) => {
            report.error(
                &obj.member_path("covers"),
                "3.8",
                "bad_covers",
                format!(
                    "Member `covers`: expected `random` or `prefix_and_random`, found {}.",
                    show(&json!(other))
                ),
            );
            return None;
        }
    };
    let characters = characters?;
    if !(1..=64).contains(&characters) {
        report.error(
            &obj.member_path("characters"),
            "3.8",
            "bad_characters",
            format!(
                "Member `characters`: expected a whole number from 1 to 64, found {characters}."
            ),
        );
        return None;
    }
    Some(Checksum {
        algorithm,
        encoding,
        characters: usize::try_from(characters).ok()?,
        covers,
    })
}

/// The CRC-32 of zlib (polynomial 0xEDB88320, reflected, initial and final value 0xFFFFFFFF).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn encode(mut value: u32, encoding: ChecksumEncoding, characters: usize) -> String {
    let digits = encoding.digits();
    let base = u32::try_from(digits.len()).unwrap_or(62);
    let mut out = Vec::new();
    while value > 0 {
        out.push(digits[(value % base) as usize]);
        value /= base;
    }
    while out.len() < characters {
        out.push(digits[0]);
    }
    out.reverse();
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_format() -> KeyFormat {
        KeyFormat::from_value(&json!({
            "prefix": "mcp_", "length": 53, "alphabet": "A-Za-z0-9",
            "checksum": {"algorithm": "crc32", "encoding": "base62", "characters": 6}
        }))
        .unwrap()
    }

    const RANDOM: &str = "aB3dE5gH7jK9mN1pQ2rS4tU6vW8xY0zA1bC3dE5fG7h";

    fn default_key() -> String {
        let format = default_format();
        format!("mcp_{RANDOM}{}", format.checksum_for(RANDOM).unwrap())
    }

    #[test]
    fn p_3_8_the_random_part_of_the_test_key_has_43_characters() {
        assert_eq!(RANDOM.len(), 43);
        assert_eq!(default_key().len(), 53);
        assert_eq!(default_format().random_length(), 43);
    }

    #[test]
    fn p_3_8_crc32_of_zlib() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
    }

    #[test]
    fn p_3_8_base62_checksum_is_padded_on_the_left() {
        assert_eq!(encode(0, ChecksumEncoding::Base62, 6), "000000");
        assert_eq!(encode(61, ChecksumEncoding::Base62, 6), "00000z");
        assert_eq!(encode(62, ChecksumEncoding::Base62, 6), "000010");
        assert_eq!(encode(u32::MAX, ChecksumEncoding::Base62, 6), "4gfFC3");
        assert_eq!(encode(255, ChecksumEncoding::Hex, 8), "000000ff");
    }

    #[test]
    fn p_3_8_a_good_key_has_a_digest_and_a_hint() {
        let key = default_key();
        let info = default_format().check(&key).unwrap();
        assert_eq!(info.digest_hex.len(), 64);
        assert_eq!(info.digest_hex, hex::encode(Sha256::digest(key.as_bytes())));
        assert_eq!(info.hint, "aB3d");
        assert!(!format!("{info:?}").contains(&key));
    }

    #[test]
    fn p_3_8_the_checker_gives_the_cause_prefix() {
        let key = default_key().replacen("mcp_", "dlg_", 1);
        let error = default_format().check(&key).unwrap_err();
        assert_eq!(error.cause(), "prefix");
        assert_eq!(error.to_string(), "prefix (expected the prefix mcp_)");
    }

    #[test]
    fn p_3_8_the_checker_gives_the_cause_length() {
        // A standalone key of the binding has 47 characters: mcp_ and 43 base64url characters.
        let standalone = format!("mcp_{RANDOM}");
        let error = default_format().check(&standalone).unwrap_err();
        assert_eq!(error.cause(), "length");
        assert_eq!(
            error.to_string(),
            "length (expected 53 characters, found 47)"
        );
        assert_eq!(
            default_format().check("mcp_").unwrap_err().cause(),
            "length"
        );
        assert_eq!(default_format().check("").unwrap_err().cause(), "prefix");
    }

    #[test]
    fn p_3_8_the_checker_gives_the_cause_alphabet() {
        let mut key = default_key();
        key.replace_range(10..11, "-");
        let error = default_format().check(&key).unwrap_err();
        assert_eq!(error.cause(), "alphabet");
        assert!(matches!(
            error,
            KeyFormatError::Alphabet { position: 11, .. }
        ));
        assert!(!error.to_string().contains('-') || error.to_string().contains("A-Za-z0-9"));
        // The text has 53 characters, and one is not ASCII.
        let non_ascii = format!("mcp_{}{}", "\u{e9}".repeat(43), "000000");
        assert_eq!(
            default_format().check(&non_ascii).unwrap_err().cause(),
            "alphabet"
        );
    }

    #[test]
    fn p_3_8_the_checker_gives_the_cause_checksum() {
        let mut key = default_key();
        let last = key.pop().unwrap();
        key.push(if last == 'a' { 'b' } else { 'a' });
        assert_eq!(
            default_format().check(&key).unwrap_err(),
            KeyFormatError::Checksum
        );
        // A change in the random part also fails the checksum.
        let key = default_key().replacen("aB3d", "aB3e", 1);
        assert_eq!(
            default_format().check(&key).unwrap_err(),
            KeyFormatError::Checksum
        );
    }

    #[test]
    fn p_3_8_the_error_never_holds_the_text() {
        let key = default_key();
        for bad in [
            key.replacen("mcp_", "dlg_", 1),
            key[..47].to_owned(),
            format!("{}-", &key[..52]),
            format!("{}aaaaaa", &key[..47]),
        ] {
            let error = default_format().check(&bad).unwrap_err().to_string();
            assert!(!error.contains(RANDOM), "{error}");
            assert!(!error.contains(&bad), "{error}");
        }
    }

    #[test]
    fn p_3_8_a_format_without_a_checksum() {
        let format =
            KeyFormat::from_value(&json!({"prefix": "k_", "length": 10, "alphabet": "a-z"}))
                .unwrap();
        assert_eq!(format.random_length(), 8);
        let info = format.check("k_abcdefgh").unwrap();
        assert_eq!(info.hint, "abcd");
        assert!(format.checksum_for("abc").is_none());
        assert_eq!(format.check("k_abcdefg1").unwrap_err().cause(), "alphabet");
    }

    #[test]
    fn p_3_8_a_checksum_over_the_prefix_and_the_random_part() {
        let format = KeyFormat::from_value(&json!({
            "prefix": "k_", "length": 16, "alphabet": "0-9A-Za-z_",
            "checksum": {"algorithm": "crc32", "encoding": "base62", "characters": 6, "covers": "prefix_and_random"}
        }))
        .unwrap();
        let random = "abcdefgh";
        let text = format!("k_{random}{}", format.checksum_for(random).unwrap());
        assert!(format.check(&text).is_ok());
        let other = KeyFormat {
            checksum: Some(Checksum {
                covers: Covers::Random,
                ..format.checksum.clone().unwrap()
            }),
            ..format.clone()
        };
        assert_eq!(other.check(&text).unwrap_err(), KeyFormatError::Checksum);
    }

    #[test]
    fn p_3_8_the_hint_has_at_most_four_characters() {
        let format =
            KeyFormat::from_value(&json!({"prefix": "k_", "length": 4, "alphabet": "a-z"}))
                .unwrap();
        assert_eq!(format.check("k_ab").unwrap().hint, "ab");
    }

    #[test]
    fn p_3_8_the_format_document_is_closed() {
        let good = json!({"prefix": "mcp_", "length": 53, "alphabet": "A-Za-z0-9",
            "checksum": {"algorithm": "crc32", "encoding": "base62", "characters": 6}});
        let with = |f: &dyn Fn(&mut Value)| {
            let mut v = good.clone();
            f(&mut v);
            KeyFormat::from_value(&v).unwrap_err()[0].code
        };
        assert_eq!(with(&|v| v["extra"] = json!(1)), "unknown_member");
        assert_eq!(
            with(&|v| v["checksum"]["extra"] = json!(1)),
            "unknown_member"
        );
        assert_eq!(
            with(&|v| {
                v.as_object_mut().unwrap().remove("prefix");
            }),
            "missing_member"
        );
        assert_eq!(with(&|v| v["length"] = json!("53")), "wrong_type");
        assert_eq!(with(&|v| v["length"] = json!(53.0)), "wrong_type");
        assert_eq!(with(&|v| v["length"] = json!(0)), "bad_length");
        assert_eq!(with(&|v| v["prefix"] = json!("")), "bad_prefix");
        assert_eq!(with(&|v| v["prefix"] = json!("m c")), "bad_prefix");
        assert_eq!(
            with(&|v| v["checksum"]["algorithm"] = json!("md5")),
            "bad_algorithm"
        );
        assert_eq!(
            with(&|v| v["checksum"]["encoding"] = json!("base64")),
            "bad_encoding"
        );
        assert_eq!(
            with(&|v| v["checksum"]["covers"] = json!("all")),
            "bad_covers"
        );
        assert_eq!(
            with(&|v| v["checksum"]["characters"] = json!(0)),
            "bad_characters"
        );
        assert_eq!(with(&|v| v["alphabet"] = json!("z-a")), "bad_alphabet");
        assert_eq!(with(&|v| v["alphabet"] = json!("aa")), "bad_alphabet");
        assert_eq!(with(&|v| v["alphabet"] = json!("")), "bad_alphabet");
    }

    #[test]
    fn p_3_8_two_members_that_contradict_each_other_are_refused() {
        let base = json!({"prefix": "mcp_", "length": 53, "alphabet": "A-Za-z0-9",
            "checksum": {"algorithm": "crc32", "encoding": "base62", "characters": 6}});
        let code = |v: &Value| KeyFormat::from_value(v).unwrap_err()[0].code;
        let mut v = base.clone();
        v["alphabet"] = json!("a-z0-9");
        assert_eq!(code(&v), "alphabet_lacks_digit");
        let mut v = base.clone();
        v["checksum"]["characters"] = json!(5);
        assert_eq!(code(&v), "checksum_too_short");
        let mut v = base.clone();
        v["length"] = json!(10);
        assert_eq!(code(&v), "no_random_part");
        let mut v = base;
        v["checksum"]["encoding"] = json!("hex");
        v["checksum"]["characters"] = json!(8);
        assert!(KeyFormat::from_value(&v).is_ok());
    }

    #[test]
    fn p_3_8_a_duplicate_member_in_the_format_text_is_refused() {
        let text = r#"{"prefix": "a", "prefix": "b", "length": 5, "alphabet": "a-z"}"#;
        assert_eq!(KeyFormat::parse_str(text).unwrap_err()[0].code, "bad_json");
    }

    #[test]
    fn p_3_8_the_format_round_trip() {
        let format = default_format();
        assert_eq!(KeyFormat::from_value(&format.to_value()).unwrap(), format);
    }

    #[test]
    fn p_3_8_alphabet_ranges() {
        let a = Alphabet::parse("a-cX-").unwrap();
        assert!(a.contains('b') && a.contains('X') && a.contains('-') && !a.contains('d'));
        let a = Alphabet::parse("-a").unwrap();
        assert!(a.contains('-') && a.contains('a'));
        assert!(Alphabet::parse("a-").unwrap().contains('-'));
        assert!(Alphabet::parse("a b").is_err());
    }
}
