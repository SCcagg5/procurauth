//! The keys file: the keys that the edge knows, by the SHA-256 digest of their text.
//!
//! The edge never keeps the text of a key. The file has the digest of each text,
//! the subject id of the key (3.2) and the id of its owner (3.1). A person can also
//! have a text: its subject id has no colon, and it has no owner.
//!
//! The file is one JSON object with the member `keys`. The schema is closed: an
//! unknown member and a duplicate member stop the program.
//!
//! ```json
//! { "keys": [ { "sha256": "<64 hexadecimal digits>", "subject": "key:ann-k1", "owner": "ann" } ] }
//! ```

use std::collections::HashMap;

use procurauth_core::finding::{JsonPath, Report};
use procurauth_core::json::parse_str;
use procurauth_core::names::validate_id;
use procurauth_core::read::{Obj, Unknown};
use procurauth_core::subject::{SubjectKind, classify};
use serde_json::Value;

/// The most entries that the file can have.
pub const MAX_ENTRIES: usize = 1_000_000;

/// What the edge knows about one text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The subject id: `key:<local>` for a key, and an id with no colon for a person.
    pub subject: String,
    /// The id of the owner of a key. A person has none.
    pub owner: Option<String>,
}

/// The entries, by the digest of the text.
#[derive(Clone, Debug, Default)]
pub struct KeyStore {
    entries: HashMap<[u8; 32], Entry>,
}

impl KeyStore {
    /// The number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the store has no entry.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Find the entry of a text. The function hashes the text, and it compares digests only.
    pub fn find(&self, text: &str) -> Option<&Entry> {
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] = Sha256::digest(text.as_bytes()).into();
        self.entries.get(&digest)
    }

    /// Read the keys file from its JSON text. The reader returns every error.
    ///
    /// # Errors
    /// Returns one message for each problem. Each message names the JSON path, the
    /// expected value and the value found. No message holds a digest.
    pub fn parse(text: &str) -> Result<Self, Vec<String>> {
        let value =
            parse_str(text).map_err(|e| vec![format!("The keys file is not valid JSON: {e}.")])?;
        Self::from_value(&value)
    }

    /// Read the keys file from a JSON value.
    ///
    /// # Errors
    /// Returns one message for each problem.
    pub fn from_value(value: &Value) -> Result<Self, Vec<String>> {
        let mut report = Report::new();
        let root = JsonPath::root();
        let mut store = Self::default();
        if let Some(mut obj) = Obj::new(value, &root, "keys", Unknown::Error, &mut report) {
            let items = obj.array("keys", &mut report);
            obj.finish(&mut report);
            if let Some(items) = items {
                if items.len() > MAX_ENTRIES {
                    report.error(
                        &root.key("keys"),
                        "keys",
                        "too_many",
                        format!(
                            "Expected at most {MAX_ENTRIES} entries, found {}.",
                            items.len()
                        ),
                    );
                }
                for (index, item) in items.iter().enumerate().take(MAX_ENTRIES) {
                    store.read_entry(item, &root.key("keys").index(index), &mut report);
                }
            }
        }
        if report.has_errors() {
            Err(report.findings().iter().map(ToString::to_string).collect())
        } else {
            Ok(store)
        }
    }

    fn read_entry(&mut self, item: &Value, path: &JsonPath, report: &mut Report) {
        let Some(mut obj) = Obj::new(item, path, "keys", Unknown::Error, report) else {
            return;
        };
        let digest = obj.string("sha256", report);
        let subject = obj.string("subject", report);
        let owner = obj.string_opt("owner", report);
        obj.finish(report);
        let mut bad = |member: &str, code: &'static str, message: String| {
            report.error(&path.key(member), "keys", code, message);
        };
        let digest_bytes = digest.and_then(|text| {
            let good = text.len() == 64
                && text
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            if good {
                let mut out = [0_u8; 32];
                hex::decode_to_slice(text, &mut out).ok().map(|()| out)
            } else {
                bad(
                    "sha256",
                    "bad_digest",
                    "Expected 64 lower-case hexadecimal digits, found a text of another form (the value stays hidden)."
                        .to_owned(),
                );
                None
            }
        });
        let mut entry_subject = None;
        if let Some(subject) = subject {
            match classify(subject) {
                SubjectKind::Key { .. } => {
                    match owner {
                        None => bad(
                            "owner",
                            "owner_missing",
                            format!(
                                "Expected the id of the owner, because the subject {subject:?} is a key (3.2), found no member."
                            ),
                        ),
                        Some(owner) => {
                            if let Err(error) = validate_id(owner) {
                                bad(
                                    "owner",
                                    "bad_owner",
                                    format!(
                                        "Expected an id of 1 to 256 bytes with no control character ({error}), found {owner:?}."
                                    ),
                                );
                            } else if !matches!(classify(owner), SubjectKind::Person) {
                                bad(
                                    "owner",
                                    "bad_owner",
                                    format!(
                                        "Expected the id of a person, with no colon (3.1), found {owner:?}."
                                    ),
                                );
                            }
                        }
                    }
                    entry_subject = Some(subject.to_owned());
                }
                SubjectKind::Person => {
                    if owner.is_some() {
                        bad(
                            "owner",
                            "owner_for_person",
                            format!(
                                "Expected no member, because the subject {subject:?} is a person (3.1), found an owner."
                            ),
                        );
                    }
                    if let Err(error) = validate_id(subject) {
                        bad(
                            "subject",
                            "bad_subject",
                            format!(
                                "Expected an id of 1 to 256 bytes with no control character ({error}), found {subject:?}."
                            ),
                        );
                    } else {
                        entry_subject = Some(subject.to_owned());
                    }
                }
                SubjectKind::Unknown => bad(
                    "subject",
                    "bad_subject",
                    format!(
                        "Expected a person id with no colon, or a key id `key:<local>` (3.1, 3.2), found {subject:?}."
                    ),
                ),
            }
        }
        if let (Some(digest), Some(subject)) = (digest_bytes, entry_subject) {
            let entry = Entry {
                subject,
                owner: owner.map(str::to_owned),
            };
            if self.entries.insert(digest, entry).is_some() {
                report.error(
                    &path.key("sha256"),
                    "keys",
                    "duplicate_digest",
                    "Expected a digest that no other entry has, found a duplicate (the value stays hidden).".to_owned(),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    fn digest(text: &str) -> String {
        hex::encode(Sha256::digest(text.as_bytes()))
    }

    fn file(entries: &Value) -> String {
        json!({"keys": entries}).to_string()
    }

    #[test]
    fn p_9_1_a_text_is_found_by_its_digest_and_a_person_has_no_owner() {
        let text = file(&json!([
            {"sha256": digest("pk_a"), "subject": "key:ann-k1", "owner": "ann"},
            {"sha256": digest("session-b"), "subject": "ben"},
        ]));
        let store = KeyStore::parse(&text).unwrap();
        assert_eq!(store.len(), 2);
        assert_eq!(
            store.find("pk_a"),
            Some(&Entry {
                subject: "key:ann-k1".into(),
                owner: Some("ann".into())
            })
        );
        assert_eq!(store.find("session-b").unwrap().owner, None);
        assert_eq!(store.find("pk_c"), None);
    }

    #[test]
    fn the_reader_refuses_an_unknown_member_and_a_duplicate_member() {
        let unknown = file(&json!([
            {"sha256": digest("a"), "subject": "key:a", "owner": "o", "state": "active"}
        ]));
        let errors = KeyStore::parse(&unknown).unwrap_err();
        assert!(errors.iter().any(|e| e.contains("state")), "{errors:?}");
        let top = r#"{"keys": [], "extra": 1}"#;
        assert!(KeyStore::parse(top).is_err());
        let duplicate = format!(
            r#"{{"keys": [{{"sha256": "{0}", "sha256": "{0}", "subject": "key:a", "owner": "o"}}]}}"#,
            digest("a")
        );
        assert!(KeyStore::parse(&duplicate).is_err());
        assert!(KeyStore::parse("{not json").is_err());
    }

    #[test]
    fn the_reader_names_the_path_and_the_rule_of_each_bad_value() {
        let text = file(&json!([
            {"sha256": "ABC", "subject": "key:a", "owner": "o"},
            {"sha256": digest("b"), "subject": "key:b"},
            {"sha256": digest("c"), "subject": "key:c", "owner": "key:d"},
            {"sha256": digest("d"), "subject": "ben", "owner": "o"},
            {"sha256": digest("e"), "subject": "other:e", "owner": "o"},
            {"sha256": digest("f"), "subject": "key:UPPER", "owner": "o"},
        ]));
        let errors = KeyStore::parse(&text).unwrap_err();
        let all = errors.join("\n");
        for path in [
            "$.keys[0].sha256",
            "$.keys[1].owner",
            "$.keys[2].owner",
            "$.keys[3].owner",
            "$.keys[4].subject",
            "$.keys[5].subject",
        ] {
            assert!(all.contains(path), "{path} in {all}");
        }
        assert!(!all.contains("ABC"), "a digest never shows: {all}");
    }

    #[test]
    fn two_entries_with_the_same_digest_are_an_error_and_the_message_hides_it() {
        let d = digest("same");
        let text = file(&json!([
            {"sha256": d, "subject": "key:a", "owner": "o"},
            {"sha256": d, "subject": "key:b", "owner": "o"},
        ]));
        let errors = KeyStore::parse(&text).unwrap_err();
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(!errors[0].contains(&d));
    }

    #[test]
    fn an_empty_list_is_good_and_a_missing_member_is_not() {
        assert!(KeyStore::parse(r#"{"keys": []}"#).unwrap().is_empty());
        assert!(KeyStore::parse("{}").is_err());
        assert!(KeyStore::parse("[]").is_err());
    }
}
