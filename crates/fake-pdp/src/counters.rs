//! The counters of the budgets (6.3, 6.5, 6.7).
//!
//! A counter holds the units that one subject spent for one budget of one
//! service in one window. The windows are fixed: a window starts at a multiple of its length
//! since the Unix epoch. A counter that belongs to an older window counts
//! as zero. The counters live in memory, in one process.

use std::collections::BTreeMap;

use procurauth_core::directory::CounterPreset;
use procurauth_core::limits::{Window, window_start};

/// The name of one counter: the service, the subject, the budget and the window.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CounterKey {
    /// The id of the service that declares the budget.
    pub service: String,
    /// The subject id.
    pub subject: String,
    /// The name of the budget.
    pub limit: String,
    /// The window.
    pub window: Window,
}

impl CounterKey {
    /// A name for a counter.
    pub fn new(service: &str, subject: &str, limit: &str, window: Window) -> Self {
        Self {
            service: service.to_owned(),
            subject: subject.to_owned(),
            limit: limit.to_owned(),
            window,
        }
    }
}

/// The value of one counter, as a test sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CounterView {
    /// The id of the service that declares the budget.
    pub service: String,
    /// The subject id.
    pub subject: String,
    /// The name of the budget.
    pub limit: String,
    /// The window.
    pub window: Window,
    /// The units that the subject spent in the current window.
    pub used: u64,
    /// The start of the current window, in seconds since the Unix epoch.
    pub window_start: u64,
}

#[derive(Clone, Copy, Debug)]
struct Slot {
    start: u64,
    used: u64,
}

/// All the counters of the PDP.
#[derive(Clone, Debug)]
pub struct Counters {
    slots: BTreeMap<CounterKey, Slot>,
    presets: Vec<(String, CounterPreset)>,
}

impl Counters {
    /// The counters at the start. Each preset names a service. It applies to the
    /// window that holds `now_seconds`.
    pub fn new(presets: Vec<(String, CounterPreset)>, now_seconds: u64) -> Self {
        let mut counters = Self {
            slots: BTreeMap::new(),
            presets,
        };
        counters.reset(now_seconds);
        counters
    }

    /// Put each counter back to the first value of the data file. A counter
    /// without a preset starts again at zero.
    pub fn reset(&mut self, now_seconds: u64) {
        self.slots.clear();
        for (service, preset) in &self.presets {
            self.slots.insert(
                CounterKey::new(service, &preset.subject, &preset.limit, preset.window),
                Slot {
                    start: window_start(now_seconds, preset.window),
                    used: preset.used,
                },
            );
        }
    }

    /// The units spent in the current window.
    pub fn used(&self, key: &CounterKey, now_seconds: u64) -> u64 {
        match self.slots.get(key) {
            Some(slot) if slot.start == window_start(now_seconds, key.window) => slot.used,
            _ => 0,
        }
    }

    /// Take one unit from a counter. The caller checked the amount first.
    pub fn take(&mut self, key: &CounterKey, now_seconds: u64) {
        let start = window_start(now_seconds, key.window);
        let slot = self
            .slots
            .entry(key.clone())
            .or_insert(Slot { start, used: 0 });
        if slot.start != start {
            *slot = Slot { start, used: 0 };
        }
        slot.used = slot.used.saturating_add(1);
    }

    /// The counters of the current windows, in the order of subject, budget and window.
    /// A counter of an older window is not in the list.
    pub fn view(&self, now_seconds: u64) -> Vec<CounterView> {
        self.slots
            .iter()
            .filter(|(key, slot)| slot.start == window_start(now_seconds, key.window))
            .map(|(key, slot)| CounterView {
                service: key.service.clone(),
                subject: key.subject.clone(),
                limit: key.limit.clone(),
                window: key.window,
                used: slot.used,
                window_start: slot.start,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preset(subject: &str, window: Window, used: u64) -> (String, CounterPreset) {
        (
            "datastore".to_owned(),
            CounterPreset {
                subject: subject.to_owned(),
                limit: "requests".to_owned(),
                window,
                used,
            },
        )
    }

    fn key_of(subject: &str, window: Window) -> CounterKey {
        CounterKey::new("datastore", subject, "requests", window)
    }

    #[test]
    fn p_6_3_a_window_starts_at_a_multiple_of_its_length() {
        let key = key_of("alice", Window::Minute);
        let mut counters = Counters::new(Vec::new(), 1_792_569_648);
        counters.take(&key, 1_792_569_648);
        assert_eq!(counters.used(&key, 1_792_569_659), 1);
        // 1792569648 is 48 seconds into a minute: the window ends 12 seconds later.
        assert_eq!(counters.used(&key, 1_792_569_660), 0);
    }

    #[test]
    fn p_6_3_a_new_window_starts_again_at_zero() {
        let key = key_of("alice", Window::Second);
        let mut counters = Counters::new(Vec::new(), 100);
        counters.take(&key, 100);
        counters.take(&key, 100);
        counters.take(&key, 101);
        assert_eq!(counters.used(&key, 101), 1);
        assert_eq!(counters.view(101)[0].used, 1);
    }

    #[test]
    fn p_6_7_the_presets_apply_to_the_window_of_the_start() {
        let counters = Counters::new(vec![preset("alice", Window::Minute, 300)], 1_792_569_648);
        let key = key_of("alice", Window::Minute);
        assert_eq!(counters.used(&key, 1_792_569_659), 300);
        assert_eq!(counters.used(&key, 1_792_569_660), 0);
    }

    #[test]
    fn a_reset_puts_each_counter_back_to_its_preset() {
        let mut counters = Counters::new(vec![preset("alice", Window::Second, 9)], 50);
        let alice = key_of("alice", Window::Second);
        let bob = key_of("bob", Window::Second);
        counters.take(&alice, 50);
        counters.take(&bob, 50);
        counters.reset(50);
        assert_eq!(counters.used(&alice, 50), 9);
        assert_eq!(counters.used(&bob, 50), 0);
        assert_eq!(counters.view(50).len(), 1);
    }

    #[test]
    fn p_6_7_two_services_do_not_share_a_counter() {
        let mut counters = Counters::new(Vec::new(), 10);
        let a = CounterKey::new("one", "alice", "requests", Window::Second);
        let b = CounterKey::new("two", "alice", "requests", Window::Second);
        counters.take(&a, 10);
        assert_eq!(counters.used(&a, 10), 1);
        assert_eq!(counters.used(&b, 10), 0);
        assert_eq!(counters.view(10)[0].service, "one");
    }

    #[test]
    fn the_view_is_sorted_by_subject_budget_and_window() {
        let mut counters = Counters::new(Vec::new(), 10);
        counters.take(&key_of("bob", Window::Second), 10);
        counters.take(&key_of("alice", Window::Minute), 10);
        counters.take(&key_of("alice", Window::Second), 10);
        let names: Vec<_> = counters
            .view(10)
            .iter()
            .map(|c| format!("{}/{}", c.subject, c.window.as_str()))
            .collect();
        assert_eq!(names, ["alice/second", "alice/minute", "bob/second"]);
    }
}
