// Copyright (C) 2026 Amaan Qureshi <contact@amaanq.com>
// SPDX-License-Identifier: Apache-2.0

use core::time::Duration;
use std::{
   collections::HashMap,
   sync::Mutex,
   time::Instant,
};

const WINDOW: Duration = Duration::from_secs(10);

/// libsu opens several shells back to back while probing, so the ceiling has to
/// clear a burst rather than a steady rate.
const MAX_PER_WINDOW: u32 = 32;
const MAX_TRACKED_UIDS: usize = 1024;

pub struct RateLimiter {
   counts: Mutex<HashMap<u32, (Instant, u32)>>,
}

impl Default for RateLimiter {
   #[inline]
   fn default() -> Self {
      Self::new()
   }
}

impl RateLimiter {
   #[must_use]
   #[inline]
   pub fn new() -> Self {
      Self {
         counts: Mutex::new(HashMap::new()),
      }
   }

   #[inline]
   pub fn allow(&self, uid: u32) -> bool {
      self.allow_at(uid, Instant::now())
   }

   fn allow_at(&self, uid: u32, now: Instant) -> bool {
      let mut counts = match self.counts.lock() {
         Ok(guard) => guard,
         Err(poisoned) => poisoned.into_inner(),
      };
      if !counts.contains_key(&uid) && counts.len() >= MAX_TRACKED_UIDS {
         counts.retain(|_uid, state| now.saturating_duration_since(state.0) < WINDOW);
         if counts.len() >= MAX_TRACKED_UIDS {
            return false;
         }
      }
      let entry = counts.entry(uid).or_insert((now, 0));
      if now.duration_since(entry.0) >= WINDOW {
         *entry = (now, 0);
      }
      let allowed = if entry.1 >= MAX_PER_WINDOW {
         false
      } else {
         entry.1 += 1;
         true
      };
      drop(counts);
      allowed
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn budgets_are_per_uid_and_reset_at_the_window_boundary() {
      let rl = RateLimiter::new();
      let t0 = Instant::now();
      for _ in 0..MAX_PER_WINDOW {
         assert!(rl.allow_at(10123, t0));
      }
      assert!(!rl.allow_at(10123, t0));
      assert!(rl.allow_at(10456, t0));
      assert!(rl.allow_at(10123, t0 + WINDOW));
   }
}
