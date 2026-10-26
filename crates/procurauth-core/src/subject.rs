//! The subject ids of section 3.
//!
//! A PDP and an edge read the form of an id: a person has no colon (3.1), and
//! a key has `<prefix>:<local>` (3.2). A PEP never calls [`classify`]. The PEP
//! treats the id as opaque text (3.3).

/// The prefix of a key (3.2).
pub const KEY_PREFIX: &str = "key";
/// The longest local part of a key id (3.2).
pub const MAX_LOCAL_PART: usize = 64;

/// What the form of a subject id says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubjectKind<'a> {
    /// An id with no colon (3.1).
    Person,
    /// An id `key:<local>` with a good local part (3.2).
    Key {
        /// The local part: the id of the key in the system that makes it.
        local: &'a str,
    },
    /// An id with a colon and an unknown prefix or a bad local part (3.7), or an empty id.
    Unknown,
}

/// True when `local` is a good local part: 1 to 64 characters from a to z, 0 to 9, underscore and hyphen (3.2).
pub fn is_local_part(local: &str) -> bool {
    (1..=MAX_LOCAL_PART).contains(&local.len())
        && local
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// Read the form of a subject id (3.1, 3.2, 3.7).
pub fn classify(id: &str) -> SubjectKind<'_> {
    if id.is_empty() {
        return SubjectKind::Unknown;
    }
    match id.split_once(':') {
        None => SubjectKind::Person,
        Some((KEY_PREFIX, local)) if is_local_part(local) => SubjectKind::Key { local },
        Some(_) => SubjectKind::Unknown,
    }
}

/// The subject id of a key with this local part.
pub fn key_id(local: &str) -> String {
    format!("{KEY_PREFIX}:{local}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_3_1_a_person_has_no_colon() {
        assert_eq!(classify("alice"), SubjectKind::Person);
        assert_eq!(classify("Alice Smith"), SubjectKind::Person);
    }

    #[test]
    fn p_3_2_a_key_has_a_prefix_and_a_local_part() {
        assert_eq!(
            classify("key:9b1c04e2aa71f0c3"),
            SubjectKind::Key {
                local: "9b1c04e2aa71f0c3"
            }
        );
        assert_eq!(classify("key:a_b-c"), SubjectKind::Key { local: "a_b-c" });
        let longest = format!("key:{}", "a".repeat(64));
        assert!(matches!(classify(&longest), SubjectKind::Key { .. }));
        assert_eq!(key_id("abc"), "key:abc");
    }

    #[test]
    fn p_3_7_an_unknown_prefix_or_a_bad_local_part_is_unknown() {
        for id in [
            "svc:abc",
            "key:",
            "key:ABC",
            "key:a b",
            "key:a:b",
            ":abc",
            "",
            &format!("key:{}", "a".repeat(65)),
        ] {
            assert_eq!(classify(id), SubjectKind::Unknown, "{id}");
        }
    }
}
