// Copyright (C) 2026 Amaan Qureshi <contact@amaanq.com>
// SPDX-License-Identifier: Apache-2.0

pub enum Process {
   Pid(i32),
   Package(String),
}

pub struct ListRequest {
   pub library: String,
   pub process: Option<Process>,
}

pub struct DumpRequest {
   pub library: String,
   pub output:  String,
   pub process: Process,
}

#[derive(Clone)]
pub enum Location {
   Symbol(String),
   VirtualAddress(u64),
   FileOffset(u64),
}

pub enum ProbeSet {
   Single {
      library:  String,
      location: Location,
   },
   File(String),
}

#[derive(Clone, Copy, pound::ValueEnum)]
pub enum WatchAccess {
   Read,
   Write,
   Rw,
}

pub enum WatchLocation {
   Runtime(u64),
   VirtualAddress { library: String, address: u64 },
   FileOffset { library: String, offset: u64 },
}

#[derive(Clone, Copy)]
pub enum ProcessTrap {
   Uprobe { retprobe: bool },
   Breakpoint,
}

#[derive(Clone, Copy)]
pub struct Capture {
   pub dump:     Option<(usize, usize)>,
   pub deref:    Option<(usize, u64, usize)>,
   pub stack:    u32,
   pub all_regs: bool,
}

#[derive(Clone, Copy)]
pub enum Report {
   Samples(Capture),
   Threads,
}

impl Report {
   #[must_use]
   pub const fn stack(&self) -> u32 {
      match *self {
         Self::Samples(capture) => capture.stack,
         Self::Threads => 0,
      }
   }
}

pub struct ProcessTrace {
   pub process: Process,
   pub probes:  ProbeSet,
   pub trap:    ProcessTrap,
   pub report:  Report,
   pub emit:    Option<String>,
   pub tids:    Vec<i32>,
   pub follow:  bool,
   pub wait:    bool,
}

pub struct SystemTrace {
   pub library:  String,
   pub location: Location,
   pub retprobe: bool,
   pub report:   Report,
   pub emit:     Option<String>,
}

pub struct WatchTrace {
   pub process:  Process,
   pub location: WatchLocation,
   pub access:   WatchAccess,
   pub length:   u64,
   pub report:   Report,
   pub emit:     Option<String>,
   pub tids:     Vec<i32>,
   pub follow:   bool,
}

pub enum TraceRequest {
   Process(ProcessTrace),
   System(SystemTrace),
   Watch(WatchTrace),
}

impl TraceRequest {
   #[must_use]
   pub const fn report(&self) -> &Report {
      match self {
         Self::Process(request) => &request.report,
         Self::System(request) => &request.report,
         Self::Watch(request) => &request.report,
      }
   }

   #[must_use]
   pub fn emit(&self) -> Option<&str> {
      match self {
         Self::Process(request) => request.emit.as_deref(),
         Self::System(request) => request.emit.as_deref(),
         Self::Watch(request) => request.emit.as_deref(),
      }
   }
}

pub enum Command {
   Trace(TraceRequest),
   DumpLibrary(DumpRequest),
   ListFunctions(ListRequest),
}
