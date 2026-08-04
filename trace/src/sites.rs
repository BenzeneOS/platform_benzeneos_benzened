// Copyright (C) 2026 Amaan Qureshi <contact@amaanq.com>
// SPDX-License-Identifier: Apache-2.0

use std::{
   fs,
   io,
};

use crate::{
   command::{
      Location,
      ProbeSet,
      ProcessTrap,
   },
   perf,
};

pub enum SiteLocation {
   Selected(Location),
   Named(String),
}

pub struct Site {
   pub library:  String,
   pub location: SiteLocation,
   pub label:    Option<String>,
}

fn parse(text: &str) -> io::Result<Vec<Site>> {
   let mut sites = Vec::new();
   for (index, raw) in text.lines().enumerate() {
      let line = raw.split('#').next().unwrap_or_default().trim();
      if line.is_empty() {
         continue;
      }
      let mut parts = line.split_whitespace();
      let Some((lib, at)) = parts.next().zip(parts.next()) else {
         return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("probe line {} needs a library and site", index + 1),
         ));
      };
      if parts.next().is_some() {
         return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("probe line {} has unexpected fields", index + 1),
         ));
      }
      sites.push(Site {
         library:  lib.to_owned(),
         location: SiteLocation::Named(at.to_owned()),
         label:    Some(format!("{lib}!{at}")),
      });
   }
   Ok(sites)
}

pub fn load(probes: &ProbeSet, trap: ProcessTrap) -> io::Result<Vec<Site>> {
   let sites = match probes {
      ProbeSet::File(file) => parse(&fs::read_to_string(file)?)?,
      ProbeSet::Single { library, location } => {
         vec![Site {
            library:  library.clone(),
            label:    match location {
               Location::Symbol(symbol) => Some(symbol.clone()),
               Location::VirtualAddress(_) | Location::FileOffset(_) => None,
            },
            location: SiteLocation::Selected(location.clone()),
         }]
      },
   };
   if sites.is_empty() {
      return Err(io::Error::new(
         io::ErrorKind::InvalidInput,
         "the probe set has no usable lines",
      ));
   }
   let slots = match trap {
      ProcessTrap::Breakpoint => Some(("--hw", perf::HW_BREAKPOINT_SLOTS)),
      ProcessTrap::Uprobe { .. } => None,
   };
   if let Some((flag, budget)) = slots
      && sites.len() > budget
   {
      return Err(io::Error::new(
         io::ErrorKind::InvalidInput,
         format!(
            "{flag} allows at most {budget} sites, and {} were given",
            sites.len()
         ),
      ));
   }
   Ok(sites)
}

pub fn ring_pages(events: usize, sample: usize) -> usize {
   const PAGE: usize = 4096;
   const WANT: usize = 8;

   let budget = match events {
      0..=64 => 8,
      65..=512 => 2,
      _ => 1,
   };
   // A ring too small for one sample arms cleanly, reports success and delivers
   // nothing. An 8K stack capture across 156 tasks did exactly that.
   let needed = sample
      .saturating_mul(WANT)
      .div_ceil(PAGE)
      .max(1)
      .next_power_of_two();
   budget.max(needed)
}

#[cfg(test)]
mod tests {
   use super::*;
   use crate::perf::sample_size;

   /// An 8K stack capture across 156 tasks armed all of them, reported success
   /// and delivered nothing, because the ring stayed at two pages.
   #[test]
   fn a_ring_always_holds_at_least_one_sample() {
      let big = sample_size(8192);
      let pages = ring_pages(156, big);
      assert!(
         pages * 4096 >= big,
         "{pages} pages cannot hold a {big} byte sample"
      );
      assert!(pages.is_power_of_two());
      // A plain probe keeps its generous ring.
      assert_eq!(ring_pages(1, sample_size(0)), 8);
   }
}
