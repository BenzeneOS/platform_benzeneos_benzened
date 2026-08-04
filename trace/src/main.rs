// Copyright (C) 2026 Amaan Qureshi <contact@amaanq.com>
// SPDX-License-Identifier: Apache-2.0

//! Attaches a uprobe to a symbol and streams hits, optionally dumping a buffer
//! one of the arguments points at.

#![warn(clippy::nursery, clippy::pedantic, clippy::restriction)]
#![allow(clippy::blanket_clippy_restriction_lints, reason = "opt-outs below")]
#![allow(
   // unidiomatic, or against this repo's comment policy
   clippy::implicit_return,
   clippy::missing_docs_in_private_items,
   clippy::pattern_type_mismatch,
   clippy::question_mark_used,
   clippy::single_call_fn,
   // inherent to byte parsing and libc
   clippy::arithmetic_side_effects,
   clippy::as_conversions,
   clippy::indexing_slicing,
   clippy::integer_division_remainder_used,
   clippy::little_endian_bytes,
   // generated Pound parsers validate their match shape before indexing
   clippy::missing_asserts_for_indexing,
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

mod artifact;
mod cli;
mod command;
mod elf;
mod maps;
mod output;
mod perf;
mod report;
mod ring;
mod session;
mod sites;
mod symbolizer;
mod target;

use core::{
   sync::atomic::{
      AtomicBool,
      Ordering,
   },
   time::Duration,
};
use std::{
   io::{
      self,
      Write as _,
   },
   process::ExitCode,
   thread,
   time::Instant,
};

use cli::Cli;
use command::{
   Command,
   Process,
   Report,
   TraceRequest,
};
use pound::Parse as _;
use session::Session;
use symbolizer::Symbolizer;

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn request_stop(_signal: libc::c_int) {
   STOP.store(true, Ordering::Relaxed);
}

#[expect(
   clippy::fn_to_numeric_cast_any,
   reason = "sighandler_t is the libc ABI for a handler"
)]
fn install_stop_handlers() {
   let handler = request_stop as extern "C" fn(libc::c_int) as libc::sighandler_t;
   // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
   unsafe {
      libc::signal(libc::SIGINT, handler);
   }
   // SAFETY: as above.
   unsafe {
      libc::signal(libc::SIGTERM, handler);
   }
}

fn process_pid(process: &Process) -> io::Result<i32> {
   match process {
      Process::Pid(pid) => Ok(*pid),
      Process::Package(package) => target::pid_for_package(package),
   }
}

const AWAIT_LIMIT: Duration = Duration::from_secs(180);
const AWAIT_POLL: Duration = Duration::from_millis(2);

/// Startup-only code has already run by the time a process is nameable, so poll
/// until both the process and its library exist and arm on the first success.
fn await_process(request: &command::ProcessTrace) -> io::Result<(i32, Session)> {
   let deadline = Instant::now() + AWAIT_LIMIT;
   let mut last = None;
   while !STOP.load(Ordering::Relaxed) {
      match process_pid(&request.process).and_then(|pid| {
         Session::process(request, pid).map(|session| (pid, session))
      }) {
         Ok(found) => return Ok(found),
         Err(err) => last = Some(err),
      }
      if Instant::now() >= deadline {
         break;
      }
      thread::sleep(AWAIT_POLL);
   }
   Err(last.unwrap_or_else(|| {
      io::Error::new(io::ErrorKind::TimedOut, "gave up waiting for the process")
   }))
}

fn run_trace(request: &TraceRequest) -> io::Result<()> {
   let (pid, mut session) = match request {
      TraceRequest::Process(process) => {
         let (pid, session) = if process.wait {
            await_process(process)?
         } else {
            let pid = process_pid(&process.process)?;
            (pid, Session::process(process, pid)?)
         };
         (Some(pid), session)
      },
      TraceRequest::System(system) => (None, Session::system(system)?),
      TraceRequest::Watch(watch) => {
         let pid = process_pid(&watch.process)?;
         (Some(pid), Session::watch(watch, pid)?)
      },
   };
   let mut symbolizer = Symbolizer::new(request.report().stack() > 0);
   let stdout = io::stdout();

   loop {
      for (process, mappings) in session.mappings() {
         symbolizer.remember_process(process, mappings);
      }
      let batch = if STOP.load(Ordering::Relaxed) {
         session.finish()
      } else {
         match session.wait() {
            Ok(batch) => batch,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {
               if STOP.load(Ordering::Relaxed) {
                  session.finish()
               } else {
                  continue;
               }
            },
            Err(err) => return Err(err),
         }
      };
      let mut out = stdout.lock();
      for drain in batch.drains {
         if drain.lost > 0 {
            writeln!(out, "  <lost {} samples>", drain.lost)?;
         }
         if drain.malformed > 0 {
            writeln!(
               out,
               "  <discarded {} malformed perf records>",
               drain.malformed
            )?;
         }
         let label = session.label(drain.group).to_owned();
         for sample in drain.samples {
            let caller = symbolizer.caller(&sample);
            let site = caller
               .as_ref()
               .and_then(symbolizer::Caller::site)
               .map(|site| (site.module.as_str(), site.vaddr));
            session.record(drain.group, sample.pid, sample.tid, site);
            let Report::Samples(capture) = request.report() else {
               continue;
            };
            let from = caller.as_ref().map_or("?", symbolizer::Caller::name);
            report::sample(&mut out, &label, capture, &sample, from, &mut symbolizer)?;
         }
      }
      out.flush()?;
      if batch.finished {
         break;
      }
   }

   if matches!(request.report(), Report::Threads) {
      report::threads(session.groups())?;
   }
   if let Some(path) = request.emit() {
      artifact::write(path, pid, session.groups())?;
      eprintln!("artifact -> {path}");
   }
   Ok(())
}

fn run(command: &Command) -> io::Result<()> {
   match command {
      Command::Trace(request) => run_trace(request),
      Command::DumpLibrary(request) => {
         let pid = process_pid(&request.process)?;
         target::dump_library(pid, &request.library, &request.output)
      },
      Command::ListFunctions(request) => {
         let pid = request.process.as_ref().map(process_pid).transpose()?;
         target::list_functions(&request.library, pid)
      },
   }
}

fn main() -> ExitCode {
   // SAFETY: restoring a signal to its default disposition touches no memory.
   unsafe {
      libc::signal(libc::SIGPIPE, libc::SIG_DFL);
   }
   install_stop_handlers();

   let command = Cli::parse().into_command();
   match run(&command) {
      Ok(()) => ExitCode::SUCCESS,
      Err(err) => {
         eprintln!("benzened_trace: {err}");
         ExitCode::from(1)
      },
   }
}
