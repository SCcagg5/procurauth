//! The identity of the subject that the PEP gets from the identity token (9.3, 9.4).

use procurauth_core::authzen::Subject;

/// The subject of a request, after the PEP checked the identity token (9.4).
///
/// The PEP sends the subject to the PDP with the type `user`, and with the
/// `sub` of the token as the id (3.3). The PEP treats the id as opaque text. It
/// reads no meaning from its characters. The PEP sends no other claim to the PDP (9.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    sub: String,
    owner: Option<String>,
    issued_at: u64,
    expires_at: u64,
}

impl Identity {
    pub(crate) fn new(sub: String, owner: Option<String>, issued_at: u64, expires_at: u64) -> Self {
        Self {
            sub,
            owner,
            issued_at,
            expires_at,
        }
    }

    /// The `sub` of the token: the id of the subject.
    pub fn sub(&self) -> &str {
        &self.sub
    }

    /// The subject as the PEP sends it in a question (3.3).
    pub fn subject(&self) -> Subject {
        Subject::user(self.sub.clone())
    }

    /// The claim `owner`. It is for logs and for approvals only. Never use it
    /// in a decision (9.5). A token for a person has no owner.
    pub fn owner(&self) -> Option<&str> {
        self.owner.as_deref()
    }

    /// The claim `iat`, in seconds since the Unix epoch.
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// The claim `exp`, in seconds since the Unix epoch.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_3_3_the_subject_has_the_type_user_and_the_sub_as_its_id() {
        let who = Identity::new("key:abc".into(), Some("alice".into()), 1, 2);
        let subject = who.subject();
        assert_eq!(subject.subject_type, "user");
        assert_eq!(subject.id, "key:abc");
        assert!(subject.properties.is_none());
        assert_eq!(who.owner(), Some("alice"));
    }
}
