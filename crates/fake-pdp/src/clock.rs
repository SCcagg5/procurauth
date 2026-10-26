//! The clock of the test PDP.
//!
//! The clock is either the system clock or a fixed clock. A fixed clock
//! stops at a time that the test chooses. A test moves it with [`Clock::advance`]
//! and [`Clock::set`]. The windows of the counters follow this clock (6.3).
//! All the threads of the server share one clock.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::ClockError;

/// The largest time that the clock accepts, in whole seconds since the Unix epoch.
/// The clock keeps milliseconds, so a larger value would overflow.
pub const MAX_SECONDS: u64 = u64::MAX / 1000;

/// A clock that all threads share. A copy of a clock is a handle to the same clock.
#[derive(Clone, Debug)]
pub struct Clock {
    fixed_millis: Arc<Mutex<Option<u64>>>,
}

impl Clock {
    /// A clock that follows the system time until a test fixes it.
    pub fn system() -> Self {
        Self {
            fixed_millis: Arc::new(Mutex::new(None)),
        }
    }

    /// A fixed clock that starts at `seconds`.
    ///
    /// # Errors
    /// Returns an error when `seconds` is above [`MAX_SECONDS`].
    pub fn fixed(seconds: u64) -> Result<Self, ClockError> {
        let clock = Self::system();
        clock.set(seconds)?;
        Ok(clock)
    }

    /// The time in milliseconds since the Unix epoch.
    pub fn now_millis(&self) -> u64 {
        let guard = self
            .fixed_millis
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match *guard {
            Some(millis) => millis,
            None => system_millis(),
        }
    }

    /// The time in whole seconds since the Unix epoch.
    pub fn now_seconds(&self) -> u64 {
        self.now_millis() / 1000
    }

    /// True when the clock is fixed.
    pub fn is_fixed(&self) -> bool {
        self.fixed_millis
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// Fix the clock at `seconds`. A test can move the clock back.
    ///
    /// # Errors
    /// Returns an error when `seconds` is above [`MAX_SECONDS`].
    pub fn set(&self, seconds: u64) -> Result<(), ClockError> {
        let millis = seconds
            .checked_mul(1000)
            .ok_or(ClockError::OutOfRange { seconds })?;
        *self
            .fixed_millis
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(millis);
        Ok(())
    }

    /// Move the clock forward by `seconds`. A system clock becomes a fixed clock
    /// at the current time plus `seconds`. The function returns the new time in seconds.
    ///
    /// # Errors
    /// Returns an error when the new time is above [`MAX_SECONDS`].
    pub fn advance(&self, seconds: u64) -> Result<u64, ClockError> {
        let mut guard = self
            .fixed_millis
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let now = guard.unwrap_or_else(system_millis);
        let delta = seconds
            .checked_mul(1000)
            .ok_or(ClockError::OutOfRange { seconds })?;
        let next = now
            .checked_add(delta)
            .ok_or(ClockError::OutOfRange { seconds })?;
        *guard = Some(next);
        Ok(next / 1000)
    }
}

fn system_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fixed_clock_does_not_move_until_a_test_moves_it() {
        let clock = Clock::fixed(1_792_569_648).unwrap();
        assert!(clock.is_fixed());
        assert_eq!(clock.now_seconds(), 1_792_569_648);
        assert_eq!(clock.advance(12).unwrap(), 1_792_569_660);
        assert_eq!(clock.now_millis(), 1_792_569_660_000);
        clock.set(5).unwrap();
        assert_eq!(clock.now_seconds(), 5);
    }

    #[test]
    fn a_copy_of_a_clock_is_a_handle_to_the_same_clock() {
        let clock = Clock::fixed(100).unwrap();
        let other = clock.clone();
        other.advance(1).unwrap();
        assert_eq!(clock.now_seconds(), 101);
    }

    #[test]
    fn a_system_clock_becomes_fixed_when_a_test_moves_it() {
        let clock = Clock::system();
        assert!(!clock.is_fixed());
        let before = clock.now_seconds();
        let after = clock.advance(10).unwrap();
        assert!(clock.is_fixed());
        assert!(after >= before + 10);
    }

    #[test]
    fn a_time_that_overflows_is_an_error_and_the_clock_stays() {
        let clock = Clock::fixed(7).unwrap();
        assert!(clock.set(MAX_SECONDS + 1).is_err());
        assert!(clock.advance(u64::MAX).is_err());
        assert_eq!(clock.now_seconds(), 7);
        assert!(Clock::fixed(u64::MAX).is_err());
    }
}
