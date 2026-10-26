//! The clock of the PEP.
//!
//! The PEP needs the time for two jobs. It checks the identity token (9.4).
//! It gives a life to a kept answer (10.1). Both jobs read one [`Clock`].
//! A test uses a [`ManualClock`] and moves it by hand.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of time, in milliseconds since the Unix epoch.
pub trait Clock: Send + Sync + fmt::Debug {
    /// The time now, in milliseconds since the Unix epoch.
    fn now_millis(&self) -> u64;

    /// The time now, in whole seconds since the Unix epoch.
    fn now_seconds(&self) -> u64 {
        self.now_millis() / 1000
    }
}

/// The clock of the system. This is the only place where the library reads
/// the system time.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_millis(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }
}

/// A clock that stands still until the caller moves it. A copy of the clock
/// shares the same time.
#[derive(Clone, Debug)]
pub struct ManualClock {
    millis: Arc<AtomicU64>,
}

impl ManualClock {
    /// A clock that shows this time, in whole seconds since the Unix epoch.
    pub fn at_seconds(seconds: u64) -> Self {
        Self {
            millis: Arc::new(AtomicU64::new(seconds.saturating_mul(1000))),
        }
    }

    /// Set the time, in whole seconds since the Unix epoch.
    pub fn set_seconds(&self, seconds: u64) {
        self.millis
            .store(seconds.saturating_mul(1000), Ordering::SeqCst);
    }

    /// Move the time forward, in milliseconds.
    pub fn advance_millis(&self, millis: u64) {
        self.millis.fetch_add(millis, Ordering::SeqCst);
    }

    /// Move the time forward, in whole seconds.
    pub fn advance_seconds(&self, seconds: u64) {
        self.advance_millis(seconds.saturating_mul(1000));
    }
}

impl Clock for ManualClock {
    fn now_millis(&self) -> u64 {
        self.millis.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manual_clock_stands_still_and_copies_share_the_time() {
        let a = ManualClock::at_seconds(100);
        let b = a.clone();
        assert_eq!(a.now_seconds(), 100);
        b.advance_millis(1500);
        assert_eq!(a.now_millis(), 101_500);
        assert_eq!(a.now_seconds(), 101);
        a.set_seconds(5);
        assert_eq!(b.now_seconds(), 5);
    }

    #[test]
    fn the_system_clock_is_after_2020() {
        assert!(SystemClock.now_seconds() > 1_577_836_800);
    }
}
