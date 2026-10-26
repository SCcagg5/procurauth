//! The kept answers (10.1, 10.1b).
//!
//! The PEP can keep an answer for at most `cache_ttl`. An answer applies only
//! to the same subject, action, resource with its chain, and `context.match`.
//! The PEP keeps the answers to questions with `context.usage` apart from the
//! other answers. It never keeps a `true` answer with `units` above 0. The
//! table has a fixed bound that the clients cannot change.

use std::collections::HashMap;

use procurauth_core::authzen::{Decision, MatchMode};
use procurauth_core::path::NodePath;

/// What a kept answer applies to.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Key {
    subject: String,
    action: String,
    nodes: Vec<(String, String)>,
    subtree: bool,
    usage_side: bool,
}

impl Key {
    pub(crate) fn new(
        subject: &str,
        action: &str,
        node: &NodePath,
        mode: MatchMode,
        usage_side: bool,
    ) -> Self {
        Self {
            subject: subject.to_owned(),
            action: action.to_owned(),
            nodes: node
                .nodes()
                .iter()
                .map(|n| (n.node_type.clone(), n.id.clone()))
                .collect(),
            subtree: mode == MatchMode::Subtree,
            usage_side,
        }
    }

    /// The same subject and the same resource with its chain, for any action.
    fn same_subject_and_resource(&self, other: &Self) -> bool {
        self.subject == other.subject && self.nodes == other.nodes
    }
}

struct Entry {
    decision: Decision,
    expires_ms: u64,
    /// For `budget_exceeded`: the time when the window of the budget ends.
    retry_at_ms: u64,
}

/// A kept answer that the cache found.
pub(crate) struct Kept {
    pub(crate) decision: Decision,
    /// For `budget_exceeded`: the whole seconds to the end of the window, at least 1.
    pub(crate) retry_after: Option<u64>,
}

pub(crate) struct AnswerCache {
    ttl_ms: u64,
    max_entries: usize,
    map: HashMap<Key, Entry>,
}

impl AnswerCache {
    pub(crate) fn new(ttl_ms: u64, max_entries: usize) -> Self {
        Self {
            ttl_ms,
            max_entries,
            map: HashMap::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn enabled(&self) -> bool {
        self.ttl_ms > 0
    }

    pub(crate) fn ttl_ms(&self) -> u64 {
        self.ttl_ms
    }

    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    pub(crate) fn get(&mut self, key: &Key, now_ms: u64) -> Option<Kept> {
        let entry = self.map.get(key)?;
        if now_ms >= entry.expires_ms {
            self.map.remove(key);
            return None;
        }
        let retry_after = entry.decision.context.retry_after.map(|_| {
            (entry.retry_at_ms.saturating_sub(now_ms))
                .div_ceil(1000)
                .max(1)
        });
        Some(Kept {
            decision: entry.decision.clone(),
            retry_after,
        })
    }

    /// Keep an answer for `lifetime_ms`, but not longer than `cache_ttl`.
    /// When the table is full, the cache drops the old entries first. When it
    /// is still full, it keeps no new answer (10.1b).
    pub(crate) fn put(&mut self, key: Key, decision: Decision, now_ms: u64, lifetime_ms: u64) {
        if self.ttl_ms == 0 {
            return;
        }
        let life = lifetime_ms.min(self.ttl_ms);
        if life == 0 {
            return;
        }
        if self.map.len() >= self.max_entries && !self.map.contains_key(&key) {
            self.map.retain(|_, e| e.expires_ms > now_ms);
            if self.map.len() >= self.max_entries {
                return;
            }
        }
        let retry_at_ms = decision
            .context
            .retry_after
            .map_or(0, |s| now_ms.saturating_add(s.saturating_mul(1000)));
        self.map.insert(
            key,
            Entry {
                decision,
                expires_ms: now_ms.saturating_add(life),
                retry_at_ms,
            },
        );
    }

    /// Delete the answers for one subject and one resource, for any action (10.1).
    pub(crate) fn forget_subject_and_resource(&mut self, like: &Key) {
        self.map
            .retain(|key, _| !key.same_subject_and_resource(like));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use procurauth_core::path::NodeRef;

    fn node(id: &str) -> NodePath {
        NodePath::from_nodes(vec![NodeRef::service("s"), NodeRef::new("host", id)]).unwrap()
    }

    fn key(subject: &str, action: &str, host: &str) -> Key {
        Key::new(subject, action, &node(host), MatchMode::Node, false)
    }

    fn yes() -> Decision {
        Decision::allow(Default::default(), None)
    }

    #[test]
    fn p_10_1_an_answer_applies_to_the_same_subject_action_resource_and_match_only() {
        let mut cache = AnswerCache::new(5000, 10);
        cache.put(key("alice", "a.read", "x"), yes(), 0, 5000);
        assert!(cache.get(&key("alice", "a.read", "x"), 1).is_some());
        assert!(cache.get(&key("bob", "a.read", "x"), 1).is_none());
        assert!(cache.get(&key("alice", "a.write", "x"), 1).is_none());
        assert!(cache.get(&key("alice", "a.read", "y"), 1).is_none());
        let subtree = Key::new("alice", "a.read", &node("x"), MatchMode::Subtree, false);
        assert!(cache.get(&subtree, 1).is_none());
        let usage = Key::new("alice", "a.read", &node("x"), MatchMode::Node, true);
        assert!(cache.get(&usage, 1).is_none());
    }

    #[test]
    fn p_10_1_the_chain_is_part_of_the_key() {
        let mut cache = AnswerCache::new(5000, 10);
        let a = NodePath::from_nodes(vec![
            NodeRef::service("s"),
            NodeRef::new("host", "h1"),
            NodeRef::new("database", "d"),
        ])
        .unwrap();
        let b = NodePath::from_nodes(vec![
            NodeRef::service("s"),
            NodeRef::new("host", "h2"),
            NodeRef::new("database", "d"),
        ])
        .unwrap();
        cache.put(
            Key::new("u", "x", &a, MatchMode::Node, false),
            yes(),
            0,
            5000,
        );
        assert!(
            cache
                .get(&Key::new("u", "x", &b, MatchMode::Node, false), 1)
                .is_none()
        );
    }

    #[test]
    fn p_10_1_an_answer_does_not_live_longer_than_cache_ttl() {
        let mut cache = AnswerCache::new(5000, 10);
        cache.put(key("a", "x", "h"), yes(), 1000, 60_000);
        assert!(cache.get(&key("a", "x", "h"), 5999).is_some());
        assert!(cache.get(&key("a", "x", "h"), 6000).is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn p_10_1_a_ttl_of_zero_keeps_nothing() {
        let mut cache = AnswerCache::new(0, 10);
        assert!(!cache.enabled());
        cache.put(key("a", "x", "h"), yes(), 0, 1000);
        assert!(cache.get(&key("a", "x", "h"), 0).is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn p_10_1_a_budget_answer_keeps_the_seconds_to_the_end_of_its_window() {
        let mut cache = AnswerCache::new(5000, 10);
        cache.put(key("a", "x", "h"), Decision::budget_exceeded(12), 0, 12_000);
        let kept = cache.get(&key("a", "x", "h"), 0).unwrap();
        assert_eq!(kept.retry_after, Some(12));
        let kept = cache.get(&key("a", "x", "h"), 3_400).unwrap();
        assert_eq!(kept.retry_after, Some(9));
        let kept = cache.get(&key("a", "x", "h"), 4_999).unwrap();
        assert_eq!(kept.retry_after, Some(8));
    }

    #[test]
    fn p_10_1b_a_full_table_keeps_no_new_answer() {
        let mut cache = AnswerCache::new(5000, 2);
        cache.put(key("a", "x", "1"), yes(), 0, 5000);
        cache.put(key("a", "x", "2"), yes(), 0, 5000);
        cache.put(key("a", "x", "3"), yes(), 0, 5000);
        assert_eq!(cache.len(), 2);
        assert!(cache.get(&key("a", "x", "3"), 1).is_none());
        // An old entry leaves room.
        cache.put(key("a", "x", "3"), yes(), 6000, 5000);
        assert!(cache.get(&key("a", "x", "3"), 6001).is_some());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn p_10_1_the_cache_forgets_one_subject_and_one_resource_for_any_action() {
        let mut cache = AnswerCache::new(5000, 10);
        cache.put(key("a", "x", "h"), yes(), 0, 5000);
        cache.put(key("a", "y", "h"), yes(), 0, 5000);
        cache.put(key("a", "x", "other"), yes(), 0, 5000);
        cache.put(key("b", "x", "h"), yes(), 0, 5000);
        cache.forget_subject_and_resource(&key("a", "z", "h"));
        assert!(cache.get(&key("a", "x", "h"), 1).is_none());
        assert!(cache.get(&key("a", "y", "h"), 1).is_none());
        assert!(cache.get(&key("a", "x", "other"), 1).is_some());
        assert!(cache.get(&key("b", "x", "h"), 1).is_some());
    }
}
