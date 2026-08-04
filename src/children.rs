// Copyright (C) 2026 Amaan Qureshi <contact@amaanq.com>
// SPDX-License-Identifier: Apache-2.0

//! Tracks spawned root shells so a revoked tier can be enforced on sessions
//! that are already running.

use core::time::Duration;
use std::{
   fs::File,
   io::{
      self,
      Write as _,
   },
   os::fd::{
      AsRawFd as _,
      OwnedFd,
   },
   sync::{
      Mutex,
      MutexGuard,
      mpsc::{
         self,
         Receiver,
         RecvTimeoutError,
         Sender,
      },
   },
   thread,
};

use log::{
   info,
   warn,
};

use crate::{
   grant::{
      self,
      Decision,
      Source,
      Tier,
   },
   pty::ChildHandle,
};

struct Entry {
   uid:   u32,
   tier:  Tier,
   child: ChildHandle,
}

pub struct Registry {
   entries: Mutex<Vec<Entry>>,
   exits:   Sender<ExitWatch>,
}

struct ExitWatch {
   pid:           libc::pid_t,
   writer:        File,
   client_gone:   bool,
   leader_reaped: bool,
}

const REAP_INTERVAL: Duration = Duration::from_millis(20);

fn status_pipe() -> io::Result<(OwnedFd, File)> {
   let (reader, writer) = io::pipe()?;
   Ok((reader.into(), File::from(OwnedFd::from(writer))))
}

fn exit_code(status: i32) -> Option<u8> {
   let code = if libc::WIFEXITED(status) {
      libc::WEXITSTATUS(status)
   } else if libc::WIFSIGNALED(status) {
      128_i32.saturating_add(libc::WTERMSIG(status))
   } else {
      return None;
   };
   u8::try_from(code.clamp(0_i32, i32::from(u8::MAX))).ok()
}

fn status_reader_closed(writer: &File) -> io::Result<bool> {
   let mut poll = libc::pollfd {
      fd:      writer.as_raw_fd(),
      events:  0_i16,
      revents: 0_i16,
   };
   // SAFETY: poll is a live single pollfd and the zero timeout never blocks.
   let ready = unsafe { libc::poll(&raw mut poll, 1, 0_i32) };
   if ready < 0_i32 {
      return Err(io::Error::last_os_error());
   }
   Ok(ready > 0_i32 && poll.revents & libc::POLLERR != 0_i16)
}

fn reap(watch: &mut ExitWatch) -> bool {
   if !watch.client_gone {
      match status_reader_closed(&watch.writer) {
         Ok(true) => {
            watch.client_gone = true;
            info!("client left pid {}, killing its process group", watch.pid);
         },
         Ok(false) => {},
         Err(err) => {
            warn!("could not inspect pid {} client lease: {err}", watch.pid);
            return true;
         },
      }
   }
   if watch.client_gone {
      let _still_exiting = kill_group(watch.pid);
   }

   if watch.leader_reaped {
      return group_alive(watch.pid);
   }

   let mut status = 0_i32;
   // SAFETY: pid names a registered direct child and status is a live output int.
   let waited = unsafe { libc::waitpid(watch.pid, &raw mut status, libc::WNOHANG) };
   if waited == 0_i32 {
      return true;
   }
   if waited == watch.pid {
      if let Some(code) = exit_code(status) {
         let _ignored = watch.writer.write_all(&[code]);
      }
      watch.leader_reaped = true;
      return group_alive(watch.pid);
   }
   io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
}

fn watch_exits(receiver: &Receiver<ExitWatch>) {
   let mut watches = Vec::new();
   let mut connected = true;
   while connected || !watches.is_empty() {
      if watches.is_empty() {
         match receiver.recv() {
            Ok(watch) => watches.push(watch),
            Err(_disconnected) => break,
         }
      } else if connected {
         match receiver.recv_timeout(REAP_INTERVAL) {
            Ok(watch) => watches.push(watch),
            Err(RecvTimeoutError::Timeout) => {},
            Err(RecvTimeoutError::Disconnected) => connected = false,
         }
      } else {
         thread::sleep(REAP_INTERVAL);
      }
      watches.extend(receiver.try_iter());
      watches.retain_mut(reap);
   }
}

/// Asks about the whole group, not the leader. A leader that forks and exits
/// leaves privileged children behind, and dropping the entry then would strand
/// them permanently. The pidfd is held only to pin the pid against reuse.
fn group_alive(pid: libc::pid_t) -> bool {
   // SAFETY: killpg takes a pgid and a signal, and signal 0 only probes.
   if unsafe { libc::killpg(pid, 0_i32) } == 0_i32 {
      return true;
   }
   // EPERM means the group is out of reach, not gone. Dropping the entry there
   // would silently give up on revoking it.
   io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Kills the whole group. The child called `setsid`, so it leads one, and the
/// pidfd guarantees this pid is still that child.
fn kill_group(pid: libc::pid_t) -> bool {
   // SAFETY: killpg takes a pgid and a signal number.
   if unsafe { libc::killpg(pid, libc::SIGKILL) } == 0_i32 {
      return true;
   }
   // ESRCH means it is already gone. Anything else means it is still out there.
   io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

impl Registry {
   fn entries(&self) -> MutexGuard<'_, Vec<Entry>> {
      match self.entries.lock() {
         Ok(entries) => entries,
         Err(poisoned) => poisoned.into_inner(),
      }
   }

   #[inline]
   pub fn new() -> io::Result<Self> {
      let (exits, receiver) = mpsc::channel();
      thread::Builder::new()
         .name("benzened-reaper".to_owned())
         .spawn(move || watch_exits(&receiver))?;
      Ok(Self {
         entries: Mutex::new(Vec::new()),
         exits,
      })
   }

   #[inline]
   pub fn track(&self, uid: u32, child: ChildHandle, tier: Tier) -> io::Result<OwnedFd> {
      let (status, writer) = match status_pipe() {
         Ok(pipe) => pipe,
         Err(error) => {
            child.terminate_and_wait();
            return Err(error);
         },
      };
      if self
         .exits
         .send(ExitWatch {
            pid: child.pid(),
            writer,
            client_gone: false,
            leader_reaped: false,
         })
         .is_err()
      {
         child.terminate_and_wait();
         return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "the child reaper stopped",
         ));
      }
      self.entries().push(Entry { uid, tier, child });
      Ok(status)
   }

   /// Drops finished shells and kills those whose grant no longer covers them.
   #[inline]
   pub fn sweep<S>(&self, source: &S)
   where
      S: Source,
   {
      let mut holders = {
         let mut entries = self.entries();
         entries.retain(|entry| group_alive(entry.child.pid()));
         entries
            .iter()
            .map(|entry| (entry.uid, entry.tier))
            .collect::<Vec<(u32, Tier)>>()
      };
      holders.sort_unstable();
      holders.dedup();

      // Queried with the lock released. Source::tier is a binder call to
      // system_server, and track() needs this lock to spawn a shell.
      let doomed = holders
         .into_iter()
         .filter(|&(uid, tier)| revoked(source, uid, tier))
         .collect::<Vec<(u32, Tier)>>();
      if doomed.is_empty() {
         return;
      }

      let mut entries = self.entries();
      entries.retain(|entry| {
         if !doomed.contains(&(entry.uid, entry.tier)) {
            return true;
         }
         info!(
            "uid {} lost tier {:?}, killing pid {}",
            entry.uid,
            entry.tier,
            entry.child.pid()
         );
         // Kept on failure so the next sweep tries again rather than forgetting
         // a session that is still running with a revoked grant.
         if kill_group(entry.child.pid()) {
            return false;
         }
         warn!("could not kill pid {}, will retry", entry.child.pid());
         true
      });
   }
}

/// A drop to a lower tier revokes too, since a Standard shell must not keep
/// running with the descriptors an Unrestricted grant handed it.
fn revoked<S>(source: &S, uid: u32, granted: Tier) -> bool
where
   S: Source,
{
   match grant::decide(source, uid) {
      Decision::Allow(current) => current < granted,
      Decision::DenyNotGranted | Decision::DenyUnknownCaller => true,
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   struct Fixed(Option<i32>);

   impl Source for Fixed {
      fn tier(&self, _uid: u32) -> Option<i32> {
         self.0
      }
   }

   #[test]
   fn grant_loss_and_downgrades_revoke_only_overprivileged_shells() {
      assert!(revoked(
         &Fixed(Some(grant::TIER_NONE)),
         10_001,
         Tier::Standard
      ));
      assert!(revoked(&Fixed(None), 10_001, Tier::Standard));
      assert!(revoked(
         &Fixed(Some(grant::TIER_STANDARD)),
         10_001,
         Tier::Unrestricted
      ));
      assert!(!revoked(
         &Fixed(Some(grant::TIER_UNRESTRICTED)),
         10_001,
         Tier::Standard
      ));
      assert!(!revoked(
         &Fixed(Some(grant::TIER_STANDARD)),
         10_001,
         Tier::Standard
      ));
   }
}
