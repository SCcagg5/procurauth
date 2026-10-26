//! A strict JSON reader.
//!
//! `serde_json` accepts a duplicate member and keeps the last value. A
//! protocol document must not have this ambiguity. This reader follows
//! RFC 8259 and stops at the first problem. It rejects a duplicate member,
//! a lone surrogate, a number out of range and any byte after the value.
//! It also rejects a depth above [`MAX_DEPTH`]. The error names the JSON path.

use std::fmt;
use std::str::FromStr;

use serde_json::{Map, Number, Value};

use crate::finding::JsonPath;

/// The greatest depth of arrays and objects that the reader accepts.
pub const MAX_DEPTH: usize = 64;

/// What is wrong in a JSON text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JsonErrorKind {
    /// The bytes are not UTF-8.
    InvalidUtf8,
    /// The text ends too early.
    UnexpectedEnd,
    /// A byte is not valid here. The field names what the reader expected.
    Unexpected(&'static str),
    /// An object has the same member two times.
    DuplicateMember(String),
    /// A number does not follow the JSON grammar, or it is out of range.
    BadNumber,
    /// A string has a bad escape, a lone surrogate or a control character.
    BadString(&'static str),
    /// The depth is above [`MAX_DEPTH`].
    TooDeep,
    /// Bytes follow the value.
    TrailingData,
}

impl fmt::Display for JsonErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8 => f.write_str("the text is not valid UTF-8"),
            Self::UnexpectedEnd => f.write_str("the text ends before the value ends"),
            Self::Unexpected(expected) => write!(f, "expected {expected}"),
            Self::DuplicateMember(name) => write!(f, "duplicate member `{name}`"),
            Self::BadNumber => f.write_str("the number is not valid JSON, or it is out of range"),
            Self::BadString(why) => write!(f, "bad string: {why}"),
            Self::TooDeep => write!(f, "depth above {MAX_DEPTH} levels"),
            Self::TrailingData => f.write_str("data follows the end of the value"),
        }
    }
}

/// An error of the strict reader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonError {
    /// What is wrong.
    pub kind: JsonErrorKind,
    /// The JSON path of the value or member where the error occurs.
    pub path: JsonPath,
    /// The byte offset in the text.
    pub offset: usize,
    /// The line, from 1.
    pub line: usize,
    /// The column in characters, from 1.
    pub column: usize,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "JSON error at {} (line {}, column {}): {}",
            self.path, self.line, self.column, self.kind
        )
    }
}

impl std::error::Error for JsonError {}

/// Read a JSON text and reject each duplicate member.
///
/// # Errors
/// Returns the first problem of the text, with its JSON path.
pub fn parse_str(text: &str) -> Result<Value, JsonError> {
    let mut parser = Parser {
        text,
        bytes: text.as_bytes(),
        pos: 0,
        path: Vec::new(),
    };
    parser.skip_ws();
    let value = parser.value(0)?;
    parser.skip_ws();
    if parser.pos < parser.bytes.len() {
        return Err(parser.error(JsonErrorKind::TrailingData));
    }
    Ok(value)
}

/// Read JSON bytes. The bytes must be UTF-8.
///
/// # Errors
/// Returns the first problem of the bytes, with its JSON path.
pub fn parse_slice(bytes: &[u8]) -> Result<Value, JsonError> {
    match std::str::from_utf8(bytes) {
        Ok(text) => parse_str(text),
        Err(error) => Err(position_error(
            std::str::from_utf8(&bytes[..error.valid_up_to()]).unwrap_or(""),
            error.valid_up_to(),
            JsonErrorKind::InvalidUtf8,
            JsonPath::root(),
        )),
    }
}

fn position_error(before: &str, offset: usize, kind: JsonErrorKind, path: JsonPath) -> JsonError {
    let line = before.matches('\n').count() + 1;
    let column = before
        .rsplit('\n')
        .next()
        .map_or(0, |last| last.chars().count())
        + 1;
    JsonError {
        kind,
        path,
        offset,
        line,
        column,
    }
}

enum Segment {
    Key(String),
    Index(usize),
}

struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
    path: Vec<Segment>,
}

impl Parser<'_> {
    fn current_path(&self) -> JsonPath {
        self.path
            .iter()
            .fold(JsonPath::root(), |path, segment| match segment {
                Segment::Key(name) => path.key(name),
                Segment::Index(index) => path.index(*index),
            })
    }

    fn error(&self, kind: JsonErrorKind) -> JsonError {
        let before = self.text.get(..self.pos).unwrap_or("");
        position_error(before, self.pos, kind, self.current_path())
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, byte: u8, what: &'static str) -> Result<(), JsonError> {
        match self.peek() {
            Some(found) if found == byte => {
                self.pos += 1;
                Ok(())
            }
            Some(_) => Err(self.error(JsonErrorKind::Unexpected(what))),
            None => Err(self.error(JsonErrorKind::UnexpectedEnd)),
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, JsonError> {
        match self.peek() {
            None => Err(self.error(JsonErrorKind::UnexpectedEnd)),
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Value::String),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.error(JsonErrorKind::Unexpected("a JSON value"))),
        }
    }

    fn literal(&mut self, word: &'static str, value: Value) -> Result<Value, JsonError> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(value)
        } else {
            Err(self.error(JsonErrorKind::Unexpected("a JSON value")))
        }
    }

    fn number(&mut self) -> Result<Value, JsonError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(self.error(JsonErrorKind::BadNumber)),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.error(JsonErrorKind::BadNumber));
            }
            self.digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.error(JsonErrorKind::BadNumber));
            }
            self.digits();
        }
        let lexeme = &self.text[start..self.pos];
        match Number::from_str(lexeme) {
            Ok(number) => Ok(Value::Number(number)),
            Err(_) => {
                self.pos = start;
                Err(self.error(JsonErrorKind::BadNumber))
            }
        }
    }

    fn digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"', "a string")?;
        let mut out = String::new();
        loop {
            let run_start = self.pos;
            while let Some(byte) = self.peek() {
                if byte == b'"' || byte == b'\\' || byte < 0x20 {
                    break;
                }
                self.pos += 1;
            }
            out.push_str(&self.text[run_start..self.pos]);
            match self.peek() {
                None => return Err(self.error(JsonErrorKind::UnexpectedEnd)),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    self.escape(&mut out)?;
                }
                Some(_) => {
                    return Err(self.error(JsonErrorKind::BadString("control character")));
                }
            }
        }
    }

    fn escape(&mut self, out: &mut String) -> Result<(), JsonError> {
        let Some(byte) = self.peek() else {
            return Err(self.error(JsonErrorKind::UnexpectedEnd));
        };
        self.pos += 1;
        match byte {
            b'"' => out.push('"'),
            b'\\' => out.push('\\'),
            b'/' => out.push('/'),
            b'b' => out.push('\u{0008}'),
            b'f' => out.push('\u{000C}'),
            b'n' => out.push('\n'),
            b'r' => out.push('\r'),
            b't' => out.push('\t'),
            b'u' => {
                let first = self.hex4()?;
                let code = if (0xD800..0xDC00).contains(&first) {
                    if self.bytes[self.pos..].starts_with(b"\\u") {
                        self.pos += 2;
                        let second = self.hex4()?;
                        if !(0xDC00..0xE000).contains(&second) {
                            return Err(self.error(JsonErrorKind::BadString("lone surrogate")));
                        }
                        0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
                    } else {
                        return Err(self.error(JsonErrorKind::BadString("lone surrogate")));
                    }
                } else if (0xDC00..0xE000).contains(&first) {
                    return Err(self.error(JsonErrorKind::BadString("lone surrogate")));
                } else {
                    first
                };
                match char::from_u32(code) {
                    Some(c) => out.push(c),
                    None => return Err(self.error(JsonErrorKind::BadString("bad code point"))),
                }
            }
            _ => {
                self.pos -= 1;
                return Err(self.error(JsonErrorKind::BadString("unknown escape")));
            }
        }
        Ok(())
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let end = self.pos + 4;
        let Some(digits) = self.text.get(self.pos..end) else {
            return Err(self.error(JsonErrorKind::BadString("bad \\u escape")));
        };
        if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(self.error(JsonErrorKind::BadString("bad \\u escape")));
        }
        self.pos = end;
        u32::from_str_radix(digits, 16)
            .map_err(|_| self.error(JsonErrorKind::BadString("bad \\u escape")))
    }

    fn array(&mut self, depth: usize) -> Result<Value, JsonError> {
        if depth >= MAX_DEPTH {
            return Err(self.error(JsonErrorKind::TooDeep));
        }
        self.expect(b'[', "an array")?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            self.path.push(Segment::Index(items.len()));
            let item = self.value(depth + 1)?;
            self.path.pop();
            items.push(item);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                Some(_) => return Err(self.error(JsonErrorKind::Unexpected("`,` or `]`"))),
                None => return Err(self.error(JsonErrorKind::UnexpectedEnd)),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, JsonError> {
        if depth >= MAX_DEPTH {
            return Err(self.error(JsonErrorKind::TooDeep));
        }
        self.expect(b'{', "an object")?;
        let mut members = Map::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(members));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.error(JsonErrorKind::Unexpected("a member name")));
            }
            let key_start = self.pos;
            let key = self.string()?;
            if members.contains_key(&key) {
                self.pos = key_start;
                self.path.push(Segment::Key(key.clone()));
                let error = self.error(JsonErrorKind::DuplicateMember(key));
                self.path.pop();
                return Err(error);
            }
            self.skip_ws();
            self.expect(b':', "`:`")?;
            self.skip_ws();
            self.path.push(Segment::Key(key.clone()));
            let value = self.value(depth + 1)?;
            self.path.pop();
            members.insert(key, value);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(members));
                }
                Some(_) => return Err(self.error(JsonErrorKind::Unexpected("`,` or `}`"))),
                None => return Err(self.error(JsonErrorKind::UnexpectedEnd)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_reads_a_good_document() {
        let value =
            parse_str(r#" {"a": [1, 2.5, "x\u00e9\ud83d\ude00", null, true], "b": {}} "#).unwrap();
        assert_eq!(
            value,
            json!({"a": [1, 2.5, "x\u{e9}\u{1F600}", null, true], "b": {}})
        );
    }

    #[test]
    fn json_duplicate_member_is_rejected_with_its_path() {
        let error = parse_str(r#"{"a": {"b": 1, "c": 2, "b": 3}}"#).unwrap_err();
        assert_eq!(error.kind, JsonErrorKind::DuplicateMember("b".into()));
        assert_eq!(error.path.as_str(), "$.a.b");
        assert_eq!((error.line, error.column), (1, 24));
    }

    #[test]
    fn json_duplicate_member_with_an_escape_is_rejected() {
        let error = parse_str(r#"{"a": 1, "\u0061": 2}"#).unwrap_err();
        assert!(matches!(error.kind, JsonErrorKind::DuplicateMember(_)));
    }

    #[test]
    fn json_same_member_in_two_objects_is_good() {
        assert!(parse_str(r#"[{"a": 1}, {"a": 2}]"#).is_ok());
    }

    #[test]
    fn json_path_of_an_error_in_an_array() {
        let error = parse_str(r#"{"items": [1, 2, tru]}"#).unwrap_err();
        assert_eq!(error.path.as_str(), "$.items[2]");
    }

    #[test]
    fn json_rejects_bad_syntax() {
        for text in [
            "",
            "{",
            "[1,]",
            "{\"a\":1,}",
            "{'a':1}",
            "01",
            "1.",
            ".5",
            "+1",
            "1e",
            "NaN",
            "\"abc",
            "\"a\nb\"",
            "\"\\x\"",
            "\"\\ud800\"",
            "\"\\udc00\"",
            "\"\\ud800\\u0041\"",
            "[1] 2",
            "{\"a\" 1}",
            "\u{feff}{}",
            "1e999",
        ] {
            assert!(parse_str(text).is_err(), "must reject: {text:?}");
        }
    }

    #[test]
    fn json_rejects_a_nesting_that_is_too_deep() {
        let deep = format!("{}{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
        assert_eq!(parse_str(&deep).unwrap_err().kind, JsonErrorKind::TooDeep);
        let ok = format!("{}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        assert!(parse_str(&ok).is_ok());
    }

    #[test]
    fn json_rejects_bytes_that_are_not_utf8() {
        let error = parse_slice(b"{\"a\": \"\xff\"}").unwrap_err();
        assert_eq!(error.kind, JsonErrorKind::InvalidUtf8);
        assert_eq!(error.offset, 7);
    }

    #[test]
    fn json_keeps_the_difference_between_integer_and_float() {
        let value = parse_str("[1, 1.0, -0, 18446744073709551615]").unwrap();
        assert!(value[0].is_u64());
        assert!(value[1].is_f64());
        assert!(value[3].is_u64());
    }
}
