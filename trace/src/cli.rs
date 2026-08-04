// Copyright (C) 2026 Amaan Qureshi <contact@amaanq.com>
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)] use pound::Parse as _;

use crate::{
   command::{
      Capture,
      Command,
      DumpRequest,
      ListRequest,
      Location,
      ProbeSet,
      Process,
      ProcessTrace,
      ProcessTrap,
      Report,
      SystemTrace,
      TraceRequest,
      WatchAccess,
      WatchLocation,
      WatchTrace,
   },
   perf,
   target,
};

#[derive(pound::Parse)]
#[pound(name = "process-probe", version = "1")]
pub enum ProcessProbe {
   /// Probe an exported symbol in a mapped library.
   Symbol { library: String, symbol: String },
   /// Probe a virtual address shown by a disassembler.
   Vaddr {
      library: String,
      #[pound(parse = "parse_address")]
      address: u64,
   },
   /// Probe a file offset in a mapped library.
   Offset {
      library: String,
      #[pound(parse = "parse_address")]
      address: u64,
   },
   /// Probe every site named in a file, one per line.
   Probes { file: String },
}

impl ProcessProbe {
   fn into_probe_set(self) -> ProbeSet {
      match self {
         Self::Symbol { library, symbol } => {
            ProbeSet::Single {
               library,
               location: Location::Symbol(symbol),
            }
         },
         Self::Vaddr { library, address } => {
            ProbeSet::Single {
               library,
               location: Location::VirtualAddress(address),
            }
         },
         Self::Offset { library, address } => {
            ProbeSet::Single {
               library,
               location: Location::FileOffset(address),
            }
         },
         Self::Probes { file } => ProbeSet::File(file),
      }
   }
}

#[derive(pound::Parse)]
#[pound(name = "system-location", version = "1")]
pub enum SystemLocation {
   /// Probe an exported symbol in a library.
   Symbol { symbol: String },
   /// Probe a virtual address shown by a disassembler.
   Vaddr {
      #[pound(parse = "parse_address")]
      address: u64,
   },
   /// Probe a file offset in a library.
   Offset {
      #[pound(parse = "parse_address")]
      address: u64,
   },
}

impl SystemLocation {
   fn into_location(self) -> Location {
      match self {
         Self::Symbol { symbol } => Location::Symbol(symbol),
         Self::Vaddr { address } => Location::VirtualAddress(address),
         Self::Offset { address } => Location::FileOffset(address),
      }
   }
}

#[derive(pound::Parse)]
#[pound(name = "watch-location", version = "1")]
pub enum WatchSite {
   /// Watch an address in the target process.
   Runtime {
      #[pound(parse = "parse_address")]
      address: u64,
   },
   /// Watch a virtual address in a mapped library.
   Vaddr {
      library: String,
      #[pound(parse = "parse_address")]
      address: u64,
   },
   /// Watch a file offset in a mapped library.
   Offset {
      library: String,
      #[pound(parse = "parse_address")]
      address: u64,
   },
}

impl WatchSite {
   fn into_location(self) -> WatchLocation {
      match self {
         Self::Runtime { address } => WatchLocation::Runtime(address),
         Self::Vaddr { library, address } => WatchLocation::VirtualAddress { library, address },
         Self::Offset { library, address } => {
            WatchLocation::FileOffset {
               library,
               offset: address,
            }
         },
      }
   }
}

#[derive(pound::Parse)]
#[pound(name = "function-source", version = "1")]
pub enum FunctionSource {
   /// Read unwind entries from an absolute library path.
   File {
      #[pound(validate = "absolute_library")]
      library: String,
   },
   /// Read unwind entries from a library mapped into one process.
   Process { process: Process, library: String },
}

/// Trace code, watch data, or inspect one mapped library.
#[derive(pound::Parse)]
#[pound(name = "benzened_trace", version = "1")]
pub enum Cli {
   /// Trace code in one process.
   Trace {
      process:  Process,
      /// Read bytes from one argument on every hit.
      #[pound(long, global, parse = "parse_dump_value", conflicts_with = "threads")]
      dump:     Option<(usize, usize)>,
      /// Read bytes through a pointer stored inside an argument.
      #[pound(long, global, parse = "parse_deref_value", conflicts_with = "threads")]
      deref:    Option<(usize, u64, usize)>,
      /// Print every sampled register.
      #[pound(long, global, conflicts_with = "threads")]
      regs:     bool,
      /// Capture bytes of user stack per hit.
      #[pound(long, global, parse = "parse_stack", conflicts_with = "threads")]
      stack:    Option<u32>,
      /// Rank threads by hit count instead of printing samples.
      #[pound(long, global)]
      threads:  bool,
      /// Report at the return site.
      #[pound(long, global)]
      retprobe: bool,
      /// Trap through debug registers without changing target text.
      #[pound(long, global, conflicts_with = "retprobe")]
      hw:       bool,
      /// Write observed sites to a JSON artifact.
      #[pound(long, global)]
      emit:     Option<String>,
      /// Arm only these comma-separated thread IDs.
      #[pound(long, global, parse = "parse_tid_list")]
      tid:      Option<Vec<i32>>,
      /// Keep arming threads and forked children as they appear.
      #[pound(long, global)]
      follow:   bool,
      /// Wait for the process to start and map the library, then arm.
      #[pound(long, global)]
      wait:     bool,
      #[pound(subcommand)]
      probe:    ProcessProbe,
   },
   /// Trace code system-wide.
   System {
      #[pound(validate = "absolute_library")]
      library:  String,
      /// Read bytes from one argument on every hit.
      #[pound(long, global, parse = "parse_dump_value")]
      dump:     Option<(usize, usize)>,
      /// Read bytes through a pointer stored inside an argument.
      #[pound(long, global, parse = "parse_deref_value")]
      deref:    Option<(usize, u64, usize)>,
      /// Print every sampled register.
      #[pound(long, global)]
      regs:     bool,
      /// Capture bytes of user stack per hit.
      #[pound(long, global, parse = "parse_stack")]
      stack:    Option<u32>,
      /// Report at the return site.
      #[pound(long, global)]
      retprobe: bool,
      /// Write observed sites to a JSON artifact.
      #[pound(long, global)]
      emit:     Option<String>,
      #[pound(subcommand)]
      location: SystemLocation,
   },
   /// Watch memory through a process's debug registers.
   Watch {
      process: Process,
      access:  WatchAccess,
      #[pound(validate = "watch_length")]
      length:  u64,
      /// Read bytes from one argument on every hit.
      #[pound(long, global, parse = "parse_dump_value", conflicts_with = "threads")]
      dump:    Option<(usize, usize)>,
      /// Read bytes through a pointer stored inside an argument.
      #[pound(long, global, parse = "parse_deref_value", conflicts_with = "threads")]
      deref:   Option<(usize, u64, usize)>,
      /// Print every sampled register.
      #[pound(long, global, conflicts_with = "threads")]
      regs:    bool,
      /// Capture bytes of user stack per hit.
      #[pound(long, global, parse = "parse_stack", conflicts_with = "threads")]
      stack:   Option<u32>,
      /// Rank threads by hit count instead of printing samples.
      #[pound(long, global)]
      threads: bool,
      /// Write observed sites to a JSON artifact.
      #[pound(long, global)]
      emit:    Option<String>,
      /// Arm only these comma-separated thread IDs.
      #[pound(long, global, parse = "parse_tid_list")]
      tid:     Option<Vec<i32>>,
      /// Keep arming threads and forked children as they appear.
      #[pound(long, global)]
      follow:  bool,
      #[pound(subcommand)]
      site:    WatchSite,
   },
   /// Write a mapped library to disk as it exists in memory.
   DumpLibrary {
      process: Process,
      library: String,
      output:  String,
   },
   /// List function entry points recovered from unwind data.
   ListFunctions {
      #[pound(subcommand)]
      source: FunctionSource,
   },
}

impl Cli {
   #[must_use]
   pub fn into_command(self) -> Command {
      match self {
         Self::Trace {
            process,
            dump,
            deref,
            regs,
            stack,
            threads,
            retprobe,
            hw,
            emit,
            tid,
            follow,
            wait,
            probe,
         } => {
            Command::Trace(TraceRequest::Process(ProcessTrace {
               process,
               probes: probe.into_probe_set(),
               trap: if hw {
                  ProcessTrap::Breakpoint
               } else {
                  ProcessTrap::Uprobe { retprobe }
               },
               report: report(threads, dump, deref, stack, regs),
               emit,
               tids: tid.unwrap_or_default(),
               follow,
               wait,
            }))
         },
         Self::System {
            library,
            dump,
            deref,
            regs,
            stack,
            retprobe,
            emit,
            location,
         } => {
            Command::Trace(TraceRequest::System(SystemTrace {
               library,
               location: location.into_location(),
               retprobe,
               report: report(false, dump, deref, stack, regs),
               emit,
            }))
         },
         Self::Watch {
            process,
            access,
            length,
            dump,
            deref,
            regs,
            stack,
            threads,
            emit,
            tid,
            follow,
            site,
         } => {
            Command::Trace(TraceRequest::Watch(WatchTrace {
               process,
               location: site.into_location(),
               access,
               length,
               report: report(threads, dump, deref, stack, regs),
               emit,
               tids: tid.unwrap_or_default(),
               follow,
            }))
         },
         Self::DumpLibrary {
            process,
            library,
            output,
         } => {
            Command::DumpLibrary(DumpRequest {
               library,
               output,
               process,
            })
         },
         Self::ListFunctions { source } => {
            let (library, process) = match source {
               FunctionSource::File { library } => (library, None),
               FunctionSource::Process { process, library } => (library, Some(process)),
            };
            Command::ListFunctions(ListRequest { library, process })
         },
      }
   }
}

fn report(
   threads: bool,
   dump: Option<(usize, usize)>,
   deref: Option<(usize, u64, usize)>,
   stack: Option<u32>,
   regs: bool,
) -> Report {
   if threads {
      Report::Threads
   } else {
      Report::Samples(Capture {
         dump,
         deref,
         stack: stack.unwrap_or(0),
         all_regs: regs,
      })
   }
}

impl pound::FromArg for Process {
   fn from_arg(s: &str) -> Result<Self, pound::ValueError> {
      match s.parse::<i32>() {
         Ok(pid) if pid > 0 => Ok(Self::Pid(pid)),
         Ok(_ignored) => Err(pound::ValueError::new(s, "PID must be positive")),
         Err(_ignored) if s.is_empty() => {
            Err(pound::ValueError::new(s, "package must not be empty"))
         },
         Err(_ignored) => Ok(Self::Package(s.to_owned())),
      }
   }

   fn possible_values() -> Option<&'static [&'static str]> {
      Self::POSSIBLE
   }
}

fn parse_address(text: &str) -> Result<u64, &'static str> {
   target::parse_address(text).ok_or("expected an address")
}

fn absolute_library(library: &str) -> Result<(), &'static str> {
   if library.starts_with('/') {
      Ok(())
   } else {
      Err("system and file lookups need an absolute library path")
   }
}

fn parse_dump_value(spec: &str) -> Result<(usize, usize), &'static str> {
   let (which, size) = spec.split_once(':').ok_or("expected <arg>:<len>")?;
   let arg = which
      .parse::<usize>()
      .map_err(|_ignored| "invalid argument index")?;
   let len = size
      .parse::<usize>()
      .map_err(|_ignored| "invalid byte length")?;
   if perf::is_dumpable(arg) && len > 0 && len <= 4 * 1024 * 1024 {
      Ok((arg, len))
   } else {
      Err("argument index or byte length is out of range")
   }
}

fn parse_deref_value(spec: &str) -> Result<(usize, u64, usize), &'static str> {
   let mut parts = spec.split(':');
   let arg = parts
      .next()
      .ok_or("expected <arg>:<off>:<len>")?
      .parse::<usize>()
      .map_err(|_ignored| "invalid argument index")?;
   let off = parts
      .next()
      .and_then(target::parse_address)
      .ok_or("invalid pointer offset")?;
   let len = parts
      .next()
      .ok_or("expected <arg>:<off>:<len>")?
      .parse::<usize>()
      .map_err(|_ignored| "invalid byte length")?;
   if parts.next().is_none() && perf::is_dumpable(arg) && len > 0 && len <= 4 * 1024 * 1024 && off <= 4096
   {
      Ok((arg, off, len))
   } else {
      Err("argument index, pointer offset, or byte length is out of range")
   }
}

fn parse_stack(text: &str) -> Result<u32, &'static str> {
   let bytes = text
      .parse::<u32>()
      .map_err(|_ignored| "invalid stack size")?;
   if bytes != 0 && bytes.is_multiple_of(8) && bytes <= 64 * 1024 {
      Ok(bytes)
   } else {
      Err("stack size must be aligned and between 8 and 65536")
   }
}

fn parse_tid_list(list: &str) -> Result<Vec<i32>, &'static str> {
   let mut tids = list
      .split(',')
      .map(|one| {
         one.trim()
            .parse::<i32>()
            .ok()
            .filter(|tid| *tid > 0_i32)
            .ok_or("thread IDs must be positive integers")
      })
      .collect::<Result<Vec<_>, _>>()?;
   if tids.is_empty() {
      return Err("give at least one thread ID");
   }
   tids.sort_unstable();
   tids.dedup();
   Ok(tids)
}

#[expect(
   clippy::trivially_copy_pass_by_ref,
   reason = "Pound validator hooks receive fields by reference"
)]
const fn watch_length(length: &u64) -> Result<(), &'static str> {
   if perf::watch_len_is_valid(*length) {
      Ok(())
   } else {
      Err("watch length is not supported by the debug registers")
   }
}

#[cfg(test)]
fn parse_args(argv: &[String]) -> Option<Command> {
   Cli::try_parse_from(argv.iter().map(String::as_str))
      .ok()
      .map(Cli::into_command)
}

#[cfg(test)]
mod tests {
   use super::*;

   fn argv(args: &[&str]) -> Vec<String> {
      args.iter().copied().map(str::to_owned).collect()
   }

   #[test]
   fn a_raw_watch_is_distinct_from_a_library_probe() {
      assert!(parse_args(&argv(&["watch", "1", "rw", "8", "runtime", "0x8"])).is_some());
      assert!(parse_args(&argv(&["watch", "1", "rw", "8", "offset", "8"])).is_none());
      assert!(parse_args(&argv(&["watch", "1", "rw", "8", "symbol", "a", "b"])).is_none());
      assert!(parse_args(&argv(&["system", "/lib/libg.so", "runtime", "0x8"])).is_none());
   }

   #[test]
   fn offline_actions_reject_options_they_would_ignore() {
      assert!(parse_args(&argv(&["list-functions", "file", "/lib/libg.so"])).is_some());
      assert!(
         parse_args(&argv(&[
            "list-functions",
            "file",
            "/lib/libg.so",
            "--pid",
            "1"
         ]))
         .is_none()
      );
      assert!(parse_args(&argv(&["dump-library", "com.x", "libg.so", "/tmp/g.so"])).is_some());
      assert!(
         parse_args(&argv(&[
            "dump-library",
            "1",
            "libg.so",
            "/tmp/g.so",
            "extra"
         ]))
         .is_none()
      );
   }

   #[test]
   fn process_and_site_selectors_are_unambiguous() {
      assert!(parse_args(&argv(&["trace", "0", "symbol", "a", "b"])).is_none());
      assert!(parse_args(&argv(&["trace", "1", "symbol", "a", "b", "vaddr"])).is_none());
      assert!(
         parse_args(&argv(&[
            "trace",
            "1",
            "symbol",
            "a",
            "b",
            "--hw",
            "--retprobe"
         ]))
         .is_none()
      );
      assert!(
         parse_args(&argv(&["trace", "1", "symbol", "a", "b", "--tid", "2,2,3"])).is_some_and(
            |command| {
               matches!(
                  command,
                  Command::Trace(TraceRequest::Process(ProcessTrace { tids, .. }))
                     if tids == [2_i32, 3_i32]
               )
            }
         )
      );
   }
}
