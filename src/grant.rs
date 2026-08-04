// Copyright (C) 2026 Amaan Qureshi <contact@amaanq.com>
// SPDX-License-Identifier: Apache-2.0

use app_benzeneos_benzened::aidl::app::benzeneos::benzened::IBenzenedGrants::{
   TIER_NONE as AIDL_TIER_NONE,
   TIER_STANDARD as AIDL_TIER_STANDARD,
   TIER_UNRESTRICTED as AIDL_TIER_UNRESTRICTED,
};

pub const TIER_NONE: i32 = AIDL_TIER_NONE;
pub const TIER_STANDARD: i32 = AIDL_TIER_STANDARD;
pub const TIER_UNRESTRICTED: i32 = AIDL_TIER_UNRESTRICTED;

pub const UNRESTRICTED_CONTEXT: &str = "u:r:benzened_shell_unrestricted:s0";

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decision {
   Allow(Tier),
   DenyNotGranted,
   DenyUnknownCaller,
}

/// Ordered so a drop from Unrestricted to Standard reads as a downgrade.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[non_exhaustive]
pub enum Tier {
   Standard,
   Unrestricted,
}

impl Tier {
   #[must_use]
   #[inline]
   pub const fn exec_context(self) -> Option<&'static str> {
      match self {
         Self::Standard => None,
         Self::Unrestricted => Some(UNRESTRICTED_CONTEXT),
      }
   }
}

pub trait Source {
   fn tier(&self, uid: u32) -> Option<i32>;
}

#[inline]
pub fn decide<S>(source: &S, caller_uid: u32) -> Decision
where
   S: Source,
{
   match source.tier(caller_uid) {
      Some(TIER_STANDARD) => Decision::Allow(Tier::Standard),
      Some(TIER_UNRESTRICTED) => Decision::Allow(Tier::Unrestricted),
      // An unrecognised tier is never treated as permissive.
      Some(TIER_NONE | _) => Decision::DenyNotGranted,
      None => Decision::DenyUnknownCaller,
   }
}
