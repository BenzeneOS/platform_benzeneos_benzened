// Copyright (C) 2026 Amaan Qureshi <contact@amaanq.com>
// SPDX-License-Identifier: Apache-2.0

use core::time::Duration;
use std::{
   fs,
   time::Instant,
};

use crate::{
   elf,
   maps,
   perf,
   ring,
   target,
};

const LIBRARY_HEAD: usize = 64 * 1024;

#[derive(Clone)]
pub struct CodeSite {
   pub module: String,
   pub vaddr:  u64,
}

pub struct Caller {
   name: String,
   site: Option<CodeSite>,
}

impl Caller {
   #[must_use]
   pub fn name(&self) -> &str {
      &self.name
   }

   #[must_use]
   pub const fn site(&self) -> Option<&CodeSite> {
      self.site.as_ref()
   }
}

struct Process {
   pid:          i32,
   mappings:     Vec<maps::Mapping>,
   last_refresh: Instant,
   snapshot:     bool,
}

struct Library {
   path:     String,
   segments: Option<Vec<elf::Segment>>,
   entries:  Option<Vec<u64>>,
}

pub struct Symbolizer {
   processes:    Vec<Process>,
   libraries:    Vec<Library>,
   with_entries: bool,
}

impl Symbolizer {
   #[must_use]
   pub const fn new(with_entries: bool) -> Self {
      Self {
         processes: Vec::new(),
         libraries: Vec::new(),
         with_entries,
      }
   }

   pub fn remember_process(&mut self, pid: i32, mappings: &[maps::Mapping]) {
      if let Some(process) = self.processes.iter_mut().find(|process| process.pid == pid) {
         if process.mappings != mappings {
            process.mappings = mappings.to_vec();
         }
         process.last_refresh = Instant::now();
         process.snapshot = true;
         return;
      }
      self.processes.push(Process {
         pid,
         mappings: mappings.to_vec(),
         last_refresh: Instant::now(),
         snapshot: true,
      });
   }

   pub fn caller(&mut self, sample: &ring::Sample) -> Option<Caller> {
      let addr = caller_address(sample)?;
      let site = self.code_site(sample.pid as i32, addr);
      let name = site.as_ref().map_or_else(
         || format!("{addr:#x}"),
         |location| format!("{}@{:#x}", module_name(&location.module), location.vaddr),
      );
      Some(Caller { name, site })
   }

   pub fn frames(&mut self, sample: &ring::Sample, limit: usize) -> Vec<String> {
      frame_addresses(sample, limit)
         .into_iter()
         .map(|addr| self.name_code_address(sample.pid as i32, addr))
         .collect()
   }

   fn code_site(&mut self, pid: i32, addr: u64) -> Option<CodeSite> {
      let process = self.process(pid);
      let maps::CodeLocation::File { path, offset } =
         maps::describe_code(&self.processes[process].mappings, addr)?
      else {
         return None;
      };
      let module = path.to_owned();
      let library = self.library(&module);
      let segments = self.libraries[library].segments.as_deref()?;
      let vaddr = elf::file_offset_to_vaddr(segments, offset)?;
      Some(CodeSite { module, vaddr })
   }

   fn process(&mut self, pid: i32) -> usize {
      if let Some(index) = self.processes.iter().position(|process| process.pid == pid) {
         self.refresh(index);
         return index;
      }
      let mappings = maps::read_for_pid(pid).unwrap_or_default();
      self.processes.push(Process {
         pid,
         mappings,
         last_refresh: Instant::now(),
         snapshot: false,
      });
      self.processes.len() - 1
   }

   fn refresh(&mut self, index: usize) {
      const INTERVAL: Duration = Duration::from_millis(200);

      if self.processes[index].snapshot || self.processes[index].last_refresh.elapsed() < INTERVAL {
         return;
      }
      self.processes[index].last_refresh = Instant::now();
      let Ok(mappings) = maps::read_for_pid(self.processes[index].pid) else {
         return;
      };
      if mappings == self.processes[index].mappings {
         return;
      }
      self.processes[index].mappings = mappings;
   }

   fn library(&mut self, path: &str) -> usize {
      if let Some(index) = self
         .libraries
         .iter()
         .position(|library| library.path == path)
      {
         return index;
      }

      let loaded = if self.with_entries {
         fs::read(path)
      } else {
         target::read_head(path, LIBRARY_HEAD)
      };
      let (segments, entries) = match loaded {
         Err(error) => {
            eprintln!("trace warning, could not read {path}, {error}");
            (None, None)
         },
         Ok(image) if self.with_entries => {
            match elf::Elf::parse(&image) {
               Err(error) => {
                  eprintln!("trace warning, could not parse {path}, {error}");
                  (None, None)
               },
               Ok(object) => {
                  match object.segments() {
                     Err(error) => {
                        eprintln!("trace warning, could not read segments from {path}, {error}");
                        (None, None)
                     },
                     Ok(segments) => {
                        let entries = match object.function_entries() {
                           Ok(entries) => Some(entries),
                           Err(error) => {
                              eprintln!(
                                 "trace warning, unwind entries are unavailable for {path}, \
                                  {error}"
                              );
                              None
                           },
                        };
                        (Some(segments), entries)
                     },
                  }
               },
            }
         },
         Ok(image) => {
            elf::segments_from_head(&image).map_or_else(
               || {
                  eprintln!("trace warning, could not read segments from {path}");
                  (None, None)
               },
               |segments| (Some(segments), None),
            )
         },
      };
      self.libraries.push(Library {
         path: path.to_owned(),
         segments,
         entries,
      });
      self.libraries.len() - 1
   }

   fn name_code_address(&mut self, pid: i32, addr: u64) -> String {
      let process = self.process(pid);
      let (path, offset) = match maps::describe_code(&self.processes[process].mappings, addr) {
         Some(maps::CodeLocation::File { path, offset }) => (path, offset),
         Some(maps::CodeLocation::Anonymous) => return format!("{addr:#x}"),
         None => return format!("{addr:#x}?"),
      };
      let owned_path = path.to_owned();
      let name = module_name(&owned_path);
      let library = self.library(&owned_path);
      let Some(segments) = self.libraries[library].segments.as_deref() else {
         return format!("{name}+{offset:#x}");
      };
      let Some(vaddr) = elf::file_offset_to_vaddr(segments, offset) else {
         return format!("{name}+{offset:#x}?");
      };
      let contradicted = self.libraries[library]
         .entries
         .as_ref()
         .is_some_and(|entries| {
            !entries.is_empty() && entries.binary_search(&vaddr).is_err_and(|index| index == 0)
         });
      let mark = if contradicted { "?" } else { "" };
      format!("{name}@{vaddr:#x}{mark}")
   }
}

fn caller_address(sample: &ring::Sample) -> Option<u64> {
   let slot = perf::caller_slot(&sample.regs)?;
   let addr = if perf::CALLER_IS_LINK_REGISTER {
      slot
   } else {
      u64::from_le_bytes(sample.stack.get(..8)?.try_into().ok()?)
   };
   (addr != 0).then_some(addr)
}

fn frame_addresses(sample: &ring::Sample, limit: usize) -> Vec<u64> {
   let Some(base) = perf::stack_pointer(&sample.regs) else {
      return Vec::new();
   };
   let read = |addr: u64| -> Option<u64> {
      let at = usize::try_from(addr.checked_sub(base)?).ok()?;
      let bytes = sample.stack.get(at..at.checked_add(8)?)?;
      Some(u64::from_le_bytes(bytes.try_into().ok()?))
   };

   let mut frames = Vec::new();
   let mut fp = perf::frame_pointer(&sample.regs).unwrap_or_default();
   while frames.len() < limit && fp > base {
      let Some(next) = read(fp) else { break };
      let Some(ret_at) = fp.checked_add(8) else {
         break;
      };
      let Some(ret) = read(ret_at) else { break };
      if ret == 0 {
         break;
      }
      frames.push(ret);
      if next <= fp {
         break;
      }
      fp = next;
   }
   frames
}

fn module_name(path: &str) -> &str {
   path.rsplit('/').next().unwrap_or(path)
}
