//! The ceilings of an answer, and the way to apply them (7).
//!
//! A ceiling is the maximum of one use. A lower value is stricter (7.1). The
//! PEP applies each ceiling of `context.limits` to the use (7.4, 7.5). The
//! values are whole numbers. A function here never rounds a value and never
//! changes a type. It returns the lower of two values, or it refuses.
//!
//! ```
//! use procurauth_pep::ceilings::Ceilings;
//!
//! let ceilings = Ceilings::from_pairs([("max_rows", 100)]);
//! assert_eq!(ceilings.cap("max_rows", 5000).value, 100);
//! assert!(ceilings.check("max_rows", 5000).is_err());
//! assert_eq!(ceilings.cap("max_duration", 7).value, 7);
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

/// A value after a ceiling applied to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capped {
    /// The value to use: the lower of the request and the ceiling.
    pub value: u64,
    /// True when the ceiling made the value lower than the request.
    pub capped: bool,
}

/// A request above its ceiling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CeilingExceeded {
    /// The name of the ceiling.
    pub name: String,
    /// The value that the ceiling gives.
    pub ceiling: u64,
    /// The value that the client asked for.
    pub requested: u64,
}

impl fmt::Display for CeilingExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "The ceiling `{}` is {}, and the request asks for {}.",
            self.name, self.ceiling, self.requested
        )
    }
}

impl std::error::Error for CeilingExceeded {}

/// The ceilings that apply to one use, by name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ceilings(BTreeMap<String, u64>);

impl Ceilings {
    /// Ceilings from pairs of a name and a value.
    pub fn from_pairs<'a>(pairs: impl IntoIterator<Item = (&'a str, u64)>) -> Self {
        Self(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    }

    pub(crate) fn from_map(map: BTreeMap<String, u64>) -> Self {
        Self(map)
    }

    /// True when no ceiling applies.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The value of a ceiling, when the answer gives it.
    pub fn get(&self, name: &str) -> Option<u64> {
        self.0.get(name).copied()
    }

    /// Each ceiling, in the order of the names.
    pub fn iter(&self) -> impl Iterator<Item = (&str, u64)> {
        self.0.iter().map(|(k, v)| (k.as_str(), *v))
    }

    /// Apply a ceiling to a requested amount. The result is the lower value.
    /// Without a ceiling of this name, the request stays as it is.
    pub fn cap(&self, name: &str, requested: u64) -> Capped {
        match self.get(name) {
            Some(ceiling) if ceiling < requested => Capped {
                value: ceiling,
                capped: true,
            },
            _ => Capped {
                value: requested,
                capped: false,
            },
        }
    }

    /// Apply a ceiling to an amount that the client may leave out. Without a
    /// request, the ceiling itself applies. Without a ceiling and without a
    /// request, the result is `None`: the service uses its own default.
    pub fn cap_or_ceiling(&self, name: &str, requested: Option<u64>) -> Option<u64> {
        match (requested, self.get(name)) {
            (Some(r), Some(c)) => Some(r.min(c)),
            (Some(r), None) => Some(r),
            (None, c) => c,
        }
    }

    /// Check a requested amount against a ceiling, and refuse it when it is
    /// above. Use it when the service must not run a smaller use than the
    /// client asked for.
    ///
    /// # Errors
    /// Returns [`CeilingExceeded`] when the request is above the ceiling.
    pub fn check(&self, name: &str, requested: u64) -> Result<u64, CeilingExceeded> {
        match self.get(name) {
            Some(ceiling) if requested > ceiling => Err(CeilingExceeded {
                name: name.to_owned(),
                ceiling,
                requested,
            }),
            _ => Ok(requested),
        }
    }

    /// Apply a ceiling that counts whole seconds to a duration. A part of a
    /// second above the ceiling is cut: the result never exceeds the ceiling.
    pub fn cap_duration(&self, name: &str, requested: Duration) -> Duration {
        match self.get(name) {
            Some(seconds) => requested.min(Duration::from_secs(seconds)),
            None => requested,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_7_4_a_ceiling_makes_a_larger_request_lower() {
        let c = Ceilings::from_pairs([("max_rows", 100)]);
        assert_eq!(
            c.cap("max_rows", 5000),
            Capped {
                value: 100,
                capped: true
            }
        );
        assert_eq!(
            c.cap("max_rows", 100),
            Capped {
                value: 100,
                capped: false
            }
        );
        assert_eq!(
            c.cap("max_rows", 7),
            Capped {
                value: 7,
                capped: false
            }
        );
    }

    #[test]
    fn p_7_4_a_name_with_no_ceiling_leaves_the_request() {
        let c = Ceilings::from_pairs([("max_rows", 100)]);
        assert_eq!(c.cap("max_duration", 99).value, 99);
        assert_eq!(c.cap_or_ceiling("max_duration", None), None);
        assert_eq!(c.cap_or_ceiling("max_duration", Some(3)), Some(3));
    }

    #[test]
    fn p_7_4_a_missing_request_takes_the_ceiling() {
        let c = Ceilings::from_pairs([("max_rows", 100)]);
        assert_eq!(c.cap_or_ceiling("max_rows", None), Some(100));
        assert_eq!(c.cap_or_ceiling("max_rows", Some(500)), Some(100));
        assert_eq!(c.cap_or_ceiling("max_rows", Some(5)), Some(5));
    }

    #[test]
    fn p_7_4_a_check_refuses_a_request_above_the_ceiling() {
        let c = Ceilings::from_pairs([("max_rows", 100)]);
        assert_eq!(c.check("max_rows", 100), Ok(100));
        let error = c.check("max_rows", 101).unwrap_err();
        assert_eq!(error.ceiling, 100);
        assert_eq!(error.requested, 101);
        assert!(error.to_string().contains("max_rows"));
    }

    #[test]
    fn p_7_1_a_duration_ceiling_counts_seconds() {
        let c = Ceilings::from_pairs([("max_duration", 30)]);
        assert_eq!(
            c.cap_duration("max_duration", Duration::from_millis(30_500)),
            Duration::from_secs(30)
        );
        assert_eq!(
            c.cap_duration("max_duration", Duration::from_secs(2)),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn the_ceilings_list_in_the_order_of_the_names() {
        let c = Ceilings::from_pairs([("max_rows", 1), ("max_duration", 2)]);
        let names: Vec<_> = c.iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["max_duration", "max_rows"]);
        assert!(!c.is_empty());
        assert!(Ceilings::default().is_empty());
    }
}
