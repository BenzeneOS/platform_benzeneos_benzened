// Copyright (C) 2026 Amaan Qureshi <contact@amaanq.com>
// SPDX-License-Identifier: Apache-2.0

#![expect(
   clippy::multiple_unsafe_ops_per_block,
   reason = "a post-clone child, and the fd cleanup after it, are each one async-signal-safe unit"
)]

use core::{
   ffi::CStr,
   mem::size_of,
   ptr,
};
use std::{
   ffi::{
      CString,
      NulError,
   },
   io,
   os::{
      fd::{
         AsRawFd as _,
         FromRawFd as _,
         OwnedFd,
      },
      unix::net::UnixStream,
   },
};

const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;

#[repr(C)]
#[derive(Default)]
struct CloneArgs {
   flags:        u64,
   pidfd:        u64,
   child_tid:    u64,
   parent_tid:   u64,
   exit_signal:  u64,
   stack:        u64,
   stack_size:   u64,
   tls:          u64,
   set_tid:      u64,
   set_tid_size: u64,
   cgroup:       u64,
}

pub struct ChildHandle {
   pid:   libc::pid_t,
   pidfd: OwnedFd,
}

impl ChildHandle {
   #[must_use]
   pub const fn pid(&self) -> libc::pid_t {
      self.pid
   }

   fn terminate(&self) {
      // SAFETY: pidfd names this exact child and the remaining arguments are
      // the signal number, a null siginfo pointer, and zero flags.
      unsafe {
         libc::syscall(
            libc::SYS_pidfd_send_signal,
            self.pidfd.as_raw_fd(),
            libc::SIGKILL,
            ptr::null::<libc::siginfo_t>(),
            0_u32,
         );
      }
      // SAFETY: the child may already have completed setsid. Signalling both
      // identities covers either side of that transition.
      unsafe {
         libc::killpg(self.pid, libc::SIGKILL);
      }
   }

   pub fn terminate_and_wait(&self) {
      self.terminate();
      let mut status = 0_i32;
      loop {
         // SAFETY: pid names our direct child and status is a live output int.
         let waited = unsafe { libc::waitpid(self.pid, &raw mut status, 0_i32) };
         if waited == self.pid
            || waited.is_negative()
               && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
         {
            return;
         }
         if waited.is_negative() && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
         {
            return;
         }
      }
   }
}

enum Cloned {
   Child,
   Parent(ChildHandle),
}

fn clone_with_pidfd() -> io::Result<Cloned> {
   let mut pidfd = -1_i32;
   let args = CloneArgs {
      flags: u64::try_from(libc::CLONE_PIDFD).unwrap_or_default(),
      pidfd: ptr::from_mut(&mut pidfd) as u64,
      exit_signal: u64::try_from(libc::SIGCHLD).unwrap_or_default(),
      ..Default::default()
   };
   // SAFETY: args is the kernel clone_args layout and remains live for the
   // syscall. No sharing flags are used, so the result has fork semantics.
   let result = unsafe {
      libc::syscall(
         libc::SYS_clone3,
         ptr::from_ref(&args),
         size_of::<CloneArgs>(),
      )
   };
   if result.is_negative() {
      return Err(io::Error::last_os_error());
   }
   if result == 0 {
      return Ok(Cloned::Child);
   }
   let pid = libc::pid_t::try_from(result).map_err(io::Error::other)?;
   if pidfd.is_negative() {
      return Err(io::Error::other("clone3 did not return a pidfd"));
   }
   // SAFETY: CLONE_PIDFD wrote a fresh descriptor into pidfd for the parent.
   let owned_pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
   Ok(Cloned::Parent(ChildHandle {
      pid,
      pidfd: owned_pidfd,
   }))
}

const CHILD_SESSION_FAILED: u8 = 1;
const CHILD_TERMINAL_FAILED: u8 = 2;
const CHILD_IO_FAILED: u8 = 3;
const CHILD_CONTEXT_FAILED: u8 = 4;
const CHILD_EXEC_FAILED: u8 = 5;

/// # Safety
///
/// Must only run in the post-clone child with `notify` open.
unsafe fn child_failed(notify: i32, failure: u8, exit_code: i32) -> ! {
   // SAFETY: notify is the child end of the handshake pipe and failure is live
   // for the one-byte write.
   unsafe {
      libc::write(notify, ptr::from_ref(&failure).cast::<libc::c_void>(), 1);
      libc::_exit(exit_code);
   }
}

fn handshake_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
   let (reader, writer) = io::pipe()?;
   Ok((reader.into(), writer.into()))
}

fn await_exec(pipe: &OwnedFd) -> io::Result<()> {
   let mut failure = 0_u8;
   loop {
      // SAFETY: pipe is live and failure is a one-byte output buffer.
      let read = unsafe {
         libc::read(
            pipe.as_raw_fd(),
            ptr::from_mut(&mut failure).cast::<libc::c_void>(),
            1,
         )
      };
      if read == 0 {
         return Ok(());
      }
      if read == 1 {
         let message = match failure {
            CHILD_SESSION_FAILED => "child could not create its session",
            CHILD_TERMINAL_FAILED => "child could not open its terminal",
            CHILD_IO_FAILED => "child could not connect standard I/O",
            CHILD_CONTEXT_FAILED => "child could not select its SELinux exec context",
            CHILD_EXEC_FAILED => "child could not execute the shell",
            _ => "child setup failed",
         };
         return Err(io::Error::other(message));
      }
      let error = io::Error::last_os_error();
      if error.kind() != io::ErrorKind::Interrupted {
         return Err(error);
      }
   }
}

/// # Safety
///
/// Must only run in the post-clone child.
unsafe fn close_descriptors_on_exec() -> bool {
   // SAFETY: close_range touches only the child descriptor table.
   unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, CLOSE_RANGE_CLOEXEC) >= 0 }
}

/// # Safety
///
/// Must only run in the post-clone child with both descriptors open.
unsafe fn redirect_standard_io(input_output: i32, error: i32) -> bool {
   // SAFETY: The caller owns both descriptors in the post-clone child.
   unsafe {
      libc::dup2(input_output, libc::STDIN_FILENO) >= 0
         && libc::dup2(input_output, libc::STDOUT_FILENO) >= 0
         && libc::dup2(error, libc::STDERR_FILENO) >= 0
         && libc::fcntl(libc::STDIN_FILENO, libc::F_SETFD, 0_i32) >= 0
         && libc::fcntl(libc::STDOUT_FILENO, libc::F_SETFD, 0_i32) >= 0
         && libc::fcntl(libc::STDERR_FILENO, libc::F_SETFD, 0_i32) >= 0
   }
}

pub struct Spawned {
   pub master: OwnedFd,
   pub stderr: Option<OwnedFd>,
   pub child:  ChildHandle,
}

pub struct SpawnOpts<'req> {
   pub argv:         &'req [&'req str],
   pub exec_context: Option<&'req str>,
   pub env:          &'req [String],
}

/// Everything the child needs, allocated before the fork so the child branch
/// stays async-signal-safe.
struct Prepared {
   args:     Vec<CString>,
   env:      Vec<CString>,
   exec_ctx: Option<CString>,
}

enum ChildStdio {
   Terminal {
      name:   [libc::c_char; 128],
      master: i32,
   },
   Socket {
      input_output: OwnedFd,
      error:        OwnedFd,
   },
}

fn invalid(error: NulError) -> io::Error {
   io::Error::new(io::ErrorKind::InvalidInput, error)
}

impl Prepared {
   fn new(opts: &SpawnOpts) -> io::Result<Self> {
      if opts.argv.is_empty() {
         return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "argv must not be empty",
         ));
      }
      Ok(Self {
         args:     opts
            .argv
            .iter()
            .map(|arg| CString::new(*arg).map_err(invalid))
            .collect::<io::Result<Vec<CString>>>()?,
         env:      opts
            .env
            .iter()
            .map(|entry| CString::new(entry.as_str()).map_err(invalid))
            .collect::<io::Result<Vec<CString>>>()?,
         exec_ctx: opts
            .exec_context
            .map(|ctx| CString::new(ctx).map_err(invalid))
            .transpose()?,
      })
   }

   fn raw(list: &[CString]) -> Vec<*const libc::c_char> {
      let mut raw = list
         .iter()
         .map(|item| item.as_ptr())
         .collect::<Vec<*const libc::c_char>>();
      raw.push(ptr::null());
      raw
   }
}

/// # Safety
///
/// Must only be called between clone and exec, with `prep` still live.
unsafe fn exec_child(
   prep: &Prepared,
   raw_args: &[*const libc::c_char],
   raw_env: &[*const libc::c_char],
   notify: i32,
) -> ! {
   // SAFETY: post-clone child. write and execve are async-signal-safe and every
   // pointer was built before the fork.
   unsafe {
      if let Some(ctx) = prep.exec_ctx.as_ref()
         && !set_exec_context(ctx)
      {
         child_failed(notify, CHILD_CONTEXT_FAILED, 126);
      }
      libc::execve(raw_args[0], raw_args.as_ptr(), raw_env.as_ptr());
      child_failed(notify, CHILD_EXEC_FAILED, 127);
   }
}

const ATTR_EXEC: &[u8] = b"/proc/self/attr/exec\0";

/// Selects the `SELinux` domain the following exec transitions into. Called in
/// a cloned child of a multithreaded process, so it uses raw syscalls rather
/// than `libselinux`'s `setexeccon`, which is not async-signal-safe.
///
/// # Safety
///
/// Must only be called between clone and exec, with `ctx` still live.
unsafe fn set_exec_context(ctx: &CStr) -> bool {
   // SAFETY: ATTR_EXEC is a NUL-terminated literal and open takes no allocation.
   let fd = unsafe { libc::open(ATTR_EXEC.as_ptr().cast::<libc::c_char>(), libc::O_WRONLY) };
   if fd.is_negative() {
      return false;
   }
   let bytes = ctx.to_bytes();
   // SAFETY: fd is open and bytes points at ctx's live buffer.
   let n = unsafe { libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), bytes.len()) };
   // SAFETY: fd is a live descriptor owned here.
   unsafe {
      libc::close(fd);
   }
   usize::try_from(n).is_ok_and(|written| written == bytes.len())
}

/// The clamp keeps the value inside `u16`, so the conversion cannot fail.
fn window_dimension(value: i32) -> u16 {
   u16::try_from(value.clamp(1, i32::from(u16::MAX))).unwrap_or(1)
}

fn set_window_size(fd: i32, columns: i32, rows: i32) {
   let ws = libc::winsize {
      ws_row:    window_dimension(rows),
      ws_col:    window_dimension(columns),
      ws_xpixel: 0,
      ws_ypixel: 0,
   };
   // SAFETY: ws is a valid initialised winsize and fd is owned by the caller.
   unsafe {
      libc::ioctl(fd, libc::TIOCSWINSZ, &ws);
   }
}

/// # Safety
///
/// Must only run in the post-clone child.
unsafe fn connect_child_io(stdio: &ChildStdio, notify: i32) {
   // SAFETY: every descriptor and pointer was prepared before clone and all
   // operations in this block are async-signal-safe.
   unsafe {
      match stdio {
         ChildStdio::Terminal { name, master } => {
            let slave = libc::open(name.as_ptr(), libc::O_RDWR);
            if slave.is_negative() {
               child_failed(notify, CHILD_TERMINAL_FAILED, 127);
            }
            if libc::ioctl(slave, libc::TIOCSCTTY, 0).is_negative()
               || !redirect_standard_io(slave, slave)
            {
               child_failed(notify, CHILD_IO_FAILED, 126);
            }
            if slave > libc::STDERR_FILENO {
               libc::close(slave);
            }
            libc::close(*master);
         },
         ChildStdio::Socket {
            input_output: child_io,
            error: child_error,
         } => {
            let io_fd = child_io.as_raw_fd();
            let error_fd = child_error.as_raw_fd();
            if !redirect_standard_io(io_fd, error_fd) {
               child_failed(notify, CHILD_IO_FAILED, 126);
            }
            if io_fd > libc::STDERR_FILENO {
               libc::close(io_fd);
            }
            if error_fd > libc::STDERR_FILENO {
               libc::close(error_fd);
            }
         },
      }
   }
}

fn spawn_prepared(
   prep: &Prepared,
   master: OwnedFd,
   stderr: Option<OwnedFd>,
   stdio: ChildStdio,
) -> io::Result<Spawned> {
   let raw_args = Prepared::raw(&prep.args);
   let raw_env = Prepared::raw(&prep.env);
   let (handshake, notify) = handshake_pipe()?;
   match clone_with_pidfd()? {
      Cloned::Child => {
         let notify_fd = notify.as_raw_fd();
         // SAFETY: post-clone child. Every call here is async-signal-safe and
         // every allocation and pointer was prepared before clone.
         unsafe {
            if !close_descriptors_on_exec() || libc::setsid().is_negative() {
               child_failed(notify_fd, CHILD_SESSION_FAILED, 126);
            }
            connect_child_io(&stdio, notify_fd);
            exec_child(prep, &raw_args, &raw_env, notify_fd);
         }
      },
      Cloned::Parent(child) => {
         drop(notify);
         drop(stdio);
         if let Err(error) = await_exec(&handshake) {
            child.terminate_and_wait();
            return Err(error);
         }
         Ok(Spawned {
            master,
            stderr,
            child,
         })
      },
   }
}

/// Spawns `argv` on a new pty. The child keeps the caller's uid, so the caller
/// is responsible for having already dropped or retained privilege as intended.
///
/// # Errors
///
/// Returns an error if `argv` contains an interior NUL, if the pty cannot be
/// allocated or unlocked, or if the fork fails.
#[inline]
pub fn spawn_on_terminal(opts: &SpawnOpts, columns: i32, rows: i32) -> io::Result<Spawned> {
   let prep = Prepared::new(opts)?;
   // SAFETY: posix_openpt takes only flags and returns a new fd or -1.
   let opened = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
   if opened.is_negative() {
      return Err(io::Error::last_os_error());
   }
   // SAFETY: opened is a fresh fd we own and have not registered elsewhere.
   let master = unsafe { OwnedFd::from_raw_fd(opened) };
   let master_raw = master.as_raw_fd();

   // SAFETY: master_raw is a live pty master fd owned by this function.
   if unsafe { libc::grantpt(master_raw) } != 0_i32
      // SAFETY: as above, and only reached when grantpt succeeded.
      || unsafe { libc::unlockpt(master_raw) } != 0_i32
   {
      return Err(io::Error::last_os_error());
   }

   let mut name = [0 as libc::c_char; 128];
   // SAFETY: name is a live buffer and its length is passed alongside it.
   if unsafe { libc::ptsname_r(master_raw, name.as_mut_ptr(), name.len()) } != 0_i32 {
      return Err(io::Error::last_os_error());
   }

   set_window_size(master_raw, columns, rows);
   spawn_prepared(&prep, master, None, ChildStdio::Terminal {
      name,
      master: master_raw,
   })
}

/// Spawns `argv` on a socketpair instead of a pty, for callers whose stdio is
/// not a terminal.
///
/// # Errors
///
/// Returns an error if `argv` contains an interior NUL, if either socketpair
/// cannot be created, or if the fork fails.
#[inline]
pub fn spawn_on_socketpair(opts: &SpawnOpts) -> io::Result<Spawned> {
   let prep = Prepared::new(opts)?;
   let (parent, child_io) = UnixStream::pair()?;
   let (err_read, child_err) = UnixStream::pair()?;
   spawn_prepared(
      &prep,
      parent.into(),
      Some(err_read.into()),
      ChildStdio::Socket {
         input_output: child_io.into(),
         error:        child_err.into(),
      },
   )
}
