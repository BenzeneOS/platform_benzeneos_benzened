// Copyright (C) 2026 Amaan Qureshi <contact@amaanq.com>
// SPDX-License-Identifier: Apache-2.0

//! Benzene privileged access service.

// Soong builds with `-D warnings`, so these deny rather than warn.
#![warn(clippy::nursery, clippy::pedantic, clippy::restriction)]
#![allow(clippy::blanket_clippy_restriction_lints, reason = "opt-outs below")]
#![allow(
   // unidiomatic, or against this repo's comment policy
   clippy::implicit_return,
   clippy::missing_docs_in_private_items,
   clippy::missing_trait_methods,
   clippy::pattern_type_mismatch,
   clippy::question_mark_used,
   clippy::single_call_fn,
   // inherent to byte parsing and libc
   clippy::arithmetic_side_effects,
   clippy::as_conversions,
   clippy::indexing_slicing,
   clippy::integer_division_remainder_used,
   clippy::little_endian_bytes,
   // the group enables the opposite half of each pair
   clippy::semicolon_outside_block,
   clippy::separated_literal_suffix,
   // would need `extern crate alloc` in a std binary
   clippy::std_instead_of_alloc,
   // no payoff in a binary crate
   clippy::arbitrary_source_item_ordering,
   clippy::print_stderr,
   reason = "see grouping comments"
)]
#![allow(
   clippy::cast_possible_truncation,
   clippy::cast_possible_wrap,
   clippy::cast_sign_loss,
   reason = "these narrow at a kernel or libc boundary, each bounded by a clamp, a modulo, or a \
             checked length"
)]

mod children;
mod grant;
mod pty;
mod ratelimit;
mod service;

use std::{
   process,
   thread,
};

use android_logger::Config;
use binder::ProcessState;
use log::{
   LevelFilter,
   error,
   info,
};

fn main() {
   android_logger::init_once(
      Config::default()
         .with_tag("benzened")
         .with_max_level(LevelFilter::Info),
   );

   info!("Starting benzened");

   ProcessState::start_thread_pool();

   let registry = match service::register() {
      Ok(registry) => registry,
      Err(err) => {
         error!("Failed to register: {err:?}");
         process::exit(1);
      },
   };

   thread::spawn(move || service::watch_grants(&registry));

   ProcessState::join_thread_pool();
}
