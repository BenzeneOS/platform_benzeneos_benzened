// Copyright (C) 2026 Amaan Qureshi <contact@amaanq.com>
// SPDX-License-Identifier: Apache-2.0

use std::{
   fs,
   io::{
      self,
      Write as _,
   },
};

use serde::Serialize;

use crate::{
   elf,
   session::Group,
};

#[derive(Serialize)]
struct Artifact<'group> {
   pid:     Option<i32>,
   modules: Vec<Module<'group>>,
}

#[derive(Serialize)]
struct Module<'group> {
   path:      &'group str,
   build_id:  Option<String>,
   functions: Vec<u64>,
   sites:     Vec<Site<'group>>,
}

#[derive(Serialize)]
struct Site<'group> {
   label:   &'group str,
   offset:  u64,
   hits:    u64,
   callers: Vec<Caller<'group>>,
}

#[derive(Serialize)]
struct Caller<'group> {
   module: &'group str,
   vaddr:  u64,
   count:  u64,
}

fn module_paths(groups: &[Group]) -> io::Result<Vec<&str>> {
   let mut paths = Vec::new();
   for group in groups {
      let path = group.path().ok_or_else(|| {
         io::Error::new(
            io::ErrorKind::InvalidInput,
            "a runtime address has no ASLR-stable artifact location",
         )
      })?;
      if !paths.contains(&path) {
         paths.push(path);
      }
   }
   if paths.is_empty() {
      return Err(io::Error::other(
         "cannot write an artifact without a probe group",
      ));
   }
   Ok(paths)
}

fn load_module<'group>(path: &'group str, groups: &'group [Group]) -> io::Result<Module<'group>> {
   let image = fs::read(path)?;
   let parsed = elf::Elf::parse(&image)?;
   let segments = parsed.segments()?;
   let functions = match parsed.function_entries() {
      Ok(vaddrs) => {
         vaddrs
            .into_iter()
            .map(|vaddr| {
               elf::vaddr_to_file_offset(&segments, vaddr).ok_or_else(|| {
                  io::Error::new(
                     io::ErrorKind::InvalidData,
                     format!("function {vaddr:#x} in {path} is outside every load segment"),
                  )
               })
            })
            .collect::<io::Result<_>>()?
      },
      Err(err) => {
         eprintln!("  warning: functions unavailable for {path} ({err})");
         Vec::new()
      },
   };
   let sites = groups
      .iter()
      .filter(|group| group.path() == Some(path))
      .map(|group| {
         Site {
            label:   group.label(),
            offset:  group.offset(),
            hits:    group.hits(),
            callers: group
               .callers()
               .iter()
               .map(|edge| {
                  Caller {
                     module: &edge.module,
                     vaddr:  edge.vaddr,
                     count:  edge.count,
                  }
               })
               .collect(),
         }
      })
      .collect();
   Ok(Module {
      path,
      build_id: parsed.build_id(),
      functions,
      sites,
   })
}

/// Everything observed in one run, grouped by the exact image each file
/// offset belongs to.
pub fn write(path: &str, pid: Option<i32>, groups: &[Group]) -> io::Result<()> {
   let modules = module_paths(groups)?
      .into_iter()
      .map(|module| load_module(module, groups))
      .collect::<io::Result<_>>()?;
   let artifact = Artifact { pid, modules };
   let mut output = io::BufWriter::new(fs::File::create(path)?);
   serde_json::to_writer_pretty(&mut output, &artifact).map_err(io::Error::other)?;
   writeln!(output)
}
