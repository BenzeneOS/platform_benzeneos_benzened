// Copyright (C) 2026 Amaan Qureshi <contact@amaanq.com>
// SPDX-License-Identifier: Apache-2.0

//! Non-setuid su client. All privilege comes from benzened over binder.

// Soong builds with `-D warnings`, so these deny rather than warn.
#![warn(clippy::nursery, clippy::pedantic, clippy::restriction)]
#![allow(clippy::blanket_clippy_restriction_lints, reason = "opt-outs below")]
#![allow(
   // unidiomatic, or against this repo's comment policy
   clippy::implicit_return,
   clippy::missing_docs_in_private_items,
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

use core::mem;
use std::{
   env,
   fs::File,
   io::{
      self,
      Read as _,
      Write as _,
   },
   os::fd::{
      AsRawFd as _,
      OwnedFd,
   },
   process::ExitCode,
   thread,
};

use app_benzeneos_benzened::aidl::app::benzeneos::benzened::{
   IBenzened::{
      IBenzened,
      SERVICE_NAME,
   },
   ShellRequest::ShellRequest,
   ShellSession::ShellSession,
};

struct RawGuard {
   fd:    i32,
   saved: libc::termios,
}

impl RawGuard {
   fn enter(fd: i32) -> Option<Self> {
      // SAFETY: isatty only inspects the given fd.
      if unsafe { libc::isatty(fd) } != 1_i32 {
         return None;
      }
      // SAFETY: termios is a plain C struct with no invalid bit patterns.
      let mut saved = unsafe { mem::zeroed::<libc::termios>() };
      // SAFETY: saved is a live termios and fd is owned by the caller.
      if unsafe { libc::tcgetattr(fd, &raw mut saved) } != 0_i32 {
         return None;
      }
      let mut raw_mode = saved;
      // SAFETY: raw_mode is a live initialised termios.
      unsafe {
         libc::cfmakeraw(&raw mut raw_mode);
      }
      // SAFETY: raw_mode is a live termios and fd is owned by the caller.
      if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw const raw_mode) } != 0_i32 {
         return None;
      }
      Some(Self { fd, saved })
   }
}

impl Drop for RawGuard {
   fn drop(&mut self) {
      // SAFETY: self.saved outlives the call and self.fd is still open.
      unsafe {
         libc::tcsetattr(self.fd, libc::TCSAFLUSH, &raw const self.saved);
      }
   }
}

fn stdin_is_tty() -> bool {
   // SAFETY: isatty only inspects the given fd.
   unsafe { libc::isatty(libc::STDIN_FILENO) == 1_i32 }
}

fn window_size() -> (i32, i32) {
   if !stdin_is_tty() {
      return (80, 24);
   }
   // SAFETY: winsize is a plain C struct with no invalid bit patterns.
   let mut ws = unsafe { mem::zeroed::<libc::winsize>() };
   // SAFETY: ws is a live winsize and stdin is always a valid fd number.
   if unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &raw mut ws) } == 0_i32 {
      (i32::from(ws.ws_col), i32::from(ws.ws_row))
   } else {
      (80, 24)
   }
}

fn shell_quote(arg: &str) -> String {
   format!("'{}'", arg.replace('\'', r"'\''"))
}

/// Builds the script for `sh -c`. As in su(1), the first argument after -c is
/// the command and any further ones become its positional parameters rather
/// than being concatenated into it.
fn build_command(command: String, arguments: impl IntoIterator<Item = String>) -> String {
   let quoted = arguments
      .into_iter()
      .map(|arg| shell_quote(&arg))
      .collect::<Vec<_>>();
   if quoted.is_empty() {
      command
   } else {
      format!("set -- {}\n{command}", quoted.join(" "))
   }
}

fn command_from_args(mut args: impl Iterator<Item = String>) -> Result<String, &'static str> {
   match args.next().as_deref() {
      None => Ok(String::new()),
      Some("-c") => {
         let command = args.next().ok_or("-c requires a command")?;
         Ok(build_command(command, args))
      },
      Some(_unexpected) => Err("expected -c followed by a command"),
   }
}

fn relay(ptmx: &File) -> io::Result<()> {
   let ptmx_fd = ptmx.as_raw_fd();
   let mut ptmx_r = ptmx;
   let mut ptmx_w = ptmx;
   let mut buf = [0_u8; 4096];
   let mut stdin_open = true;

   loop {
      let mut fds = [
         libc::pollfd {
            fd:      if stdin_open {
               libc::STDIN_FILENO
            } else {
               -1_i32
            },
            events:  libc::POLLIN,
            revents: 0_i16,
         },
         libc::pollfd {
            fd:      ptmx_fd,
            events:  libc::POLLIN,
            revents: 0_i16,
         },
      ];

      // SAFETY: fds is a live array of exactly the length passed.
      if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) }.is_negative() {
         let err = io::Error::last_os_error();
         if err.kind() == io::ErrorKind::Interrupted {
            continue;
         }
         return Err(err);
      }

      if fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0_i16 {
         match ptmx_r.read(&mut buf) {
            Ok(0) => {
               return Ok(());
            },
            Ok(n) => io::stdout().write_all(&buf[..n])?,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {},
            Err(_) => return Ok(()),
         }
         io::stdout().flush()?;
      }

      if fds[1].revents & libc::POLLNVAL != 0_i16 {
         return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "benzened returned an invalid I/O descriptor",
         ));
      }

      if fds[0].revents & libc::POLLIN != 0_i16 {
         match io::stdin().read(&mut buf) {
            Ok(0) => {
               stdin_open = false;
               // SAFETY: ptmx_fd is still open and owned by the caller. On a
               // socketpair this propagates EOF to the child, but on a pty it
               // is a harmless no-op.
               unsafe {
                  libc::shutdown(ptmx_fd, libc::SHUT_WR);
               }
            },
            Ok(n) => ptmx_w.write_all(&buf[..n])?,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {},
            Err(err) => return Err(err),
         }
      }
      if fds[0].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0_i16 {
         stdin_open = false;
      }
   }
}

fn copy_standard_error(mut error: File) -> io::Result<()> {
   let mut stderr = io::stderr().lock();
   io::copy(&mut error, &mut stderr)?;
   stderr.flush()
}

fn read_exit_status(mut status: File) -> io::Result<u8> {
   let mut code = [0_u8];
   status.read_exact(&mut code).map_err(|err| {
      if err.kind() == io::ErrorKind::UnexpectedEof {
         io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "shell exited without reporting its status",
         )
      } else {
         err
      }
   })?;
   Ok(code[0])
}

fn main() -> ExitCode {
   let command = match command_from_args(env::args().skip(1)) {
      Ok(command) => command,
      Err(err) => {
         eprintln!("su: {err}");
         return ExitCode::from(1);
      },
   };

   let Ok(service) = binder::get_interface::<dyn IBenzened>(SERVICE_NAME) else {
      eprintln!("su: benzened is not available");
      return ExitCode::from(1);
   };

   let (cols, rows) = window_size();
   let want_pty = stdin_is_tty();
   // A real su keeps the caller's cwd and environment.
   let cwd = env::current_dir()
      .ok()
      .and_then(|dir| dir.to_str().map(str::to_owned));
   let environment = env::vars()
      .map(|(key, value)| format!("{key}={value}"))
      .collect::<Vec<String>>();
   let request = ShellRequest {
      command,
      terminal: want_pty,
      columns: cols,
      rows,
      workingDirectory: cwd,
      environment,
   };
   let session = match service.openShell(&request) {
      Ok(session) => session,
      Err(err) => {
         eprintln!("su: permission denied ({err})");
         return ExitCode::from(1);
      },
   };
   let ShellSession {
      inputOutput,
      standardError,
      exitStatus,
   } = session;
   if want_pty == standardError.is_some() {
      eprintln!("su: benzened returned an invalid standard error channel");
      return ExitCode::from(1);
   }
   let Some(input_output) = inputOutput else {
      eprintln!("su: benzened returned no input and output channel");
      return ExitCode::from(1);
   };
   let Some(exit_status_channel) = exitStatus else {
      eprintln!("su: benzened returned no exit status channel");
      return ExitCode::from(1);
   };
   let ptmx = File::from(OwnedFd::from(input_output));
   let stderr_thread = standardError.map(|fd| {
      let error = File::from(OwnedFd::from(fd));
      thread::spawn(move || copy_standard_error(error))
   });
   let status = File::from(OwnedFd::from(exit_status_channel));

   let _guard = RawGuard::enter(libc::STDIN_FILENO);

   let relayed = relay(&ptmx);
   drop(ptmx);
   let copied_stderr = stderr_thread.map(|handle| {
      handle
         .join()
         .unwrap_or_else(|_panic| Err(io::Error::other("stderr relay panicked")))
   });

   let exit_status = read_exit_status(status);

   match (relayed, copied_stderr, exit_status) {
      (Err(err), ..) | (_, Some(Err(err)), _) | (_, _, Err(err)) => {
         eprintln!("su: {err}");
         ExitCode::from(1)
      },
      (Ok(()), _, Ok(code)) => ExitCode::from(code),
   }
}

#[cfg(test)]
mod command_tests {
   use super::*;

   #[test]
   fn extra_args_become_positionals_not_concatenated() {
      let args = ["a  b".to_owned()];
      let script = build_command("echo \"$1\"".to_owned(), args);
      assert!(script.starts_with("set -- 'a  b'\n"), "{script}");
      assert!(script.ends_with("echo \"$1\""), "{script}");
   }
}
