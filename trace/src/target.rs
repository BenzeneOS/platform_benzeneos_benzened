// Copyright (C) 2026 Amaan Qureshi <contact@amaanq.com>
// SPDX-License-Identifier: Apache-2.0

use core::ops::Range;
use std::{
   collections::{
      HashMap,
      HashSet,
   },
   fs,
   io::{
      self,
      Read as _,
      Write as _,
   },
};

use crate::{
   command::Location,
   elf,
   maps,
};

/// `pidof` equivalent, so a caller can name the app instead of hunting the pid.
pub fn pid_for_package(package: &str) -> io::Result<i32> {
   for entry in fs::read_dir("/proc")? {
      let path = entry?.path();
      let Some(pid) = path
         .file_name()
         .and_then(|name| name.to_str())
         .and_then(|name| name.parse::<i32>().ok())
      else {
         continue;
      };
      let cmdline = fs::read(path.join("cmdline")).unwrap_or_default();
      if cmdline.split(|byte| *byte == 0).next() == Some(package.as_bytes()) {
         return Ok(pid);
      }
   }
   Err(io::Error::new(
      io::ErrorKind::NotFound,
      format!("no running process named {package}"),
   ))
}

#[derive(Debug)]
pub struct TaskGroup {
   pub pid:  i32,
   pub tids: Vec<i32>,
}

fn thread_ids(pid: i32) -> io::Result<Vec<i32>> {
   let mut out = Vec::new();
   for entry in fs::read_dir(format!("/proc/{pid}/task"))? {
      if let Some(tid) = entry?
         .file_name()
         .to_str()
         .and_then(|name| name.parse::<i32>().ok())
      {
         out.push(tid);
      }
   }
   Ok(out)
}

pub fn task_group(pid: i32) -> io::Result<TaskGroup> {
   Ok(TaskGroup {
      pid,
      tids: thread_ids(pid)?,
   })
}

/// `/proc/<pid>/stat` names the process in a field that can hold spaces and
/// parentheses, so ppid is taken from after the last `)` rather than by
/// splitting the whole line.
#[must_use]
pub fn ppid_from_stat(stat: &str) -> Option<i32> {
   let (_, tail) = stat.rsplit_once(')')?;
   tail.split_whitespace().nth(1)?.parse().ok()
}

/// Every task under `pid`, walking forked children as well as threads. There is
/// no kernel mechanism that carries a uprobe event into a child for this PMU,
/// so following a fork means finding the child and arming it separately.
///
/// Children come from a ppid scan rather than
/// `/proc/<pid>/task/<tid>/children`, which needs `CONFIG_PROC_CHILDREN` and is
/// absent on these kernels.
pub fn task_tree(pid: i32) -> io::Result<Vec<TaskGroup>> {
   let children = children_by_parent()?;
   let mut pids = vec![pid];
   let mut seen = HashSet::from([pid]);
   let mut idx = 0;
   while let Some(next) = pids.get(idx).copied() {
      idx += 1;
      if let Some(direct) = children.get(&next) {
         for &child in direct {
            if seen.insert(child) {
               pids.push(child);
            }
         }
      }
   }
   let mut out = Vec::new();
   for target in pids {
      match task_group(target) {
         Ok(group) => out.push(group),
         Err(err) if target == pid => return Err(err),
         Err(_ignored) => {},
      }
   }
   Ok(out)
}

fn children_by_parent() -> io::Result<HashMap<i32, Vec<i32>>> {
   let entries = fs::read_dir("/proc")?;
   let mut out = HashMap::<i32, Vec<i32>>::new();
   for entry in entries.flatten() {
      let Some(pid) = entry
         .file_name()
         .to_str()
         .and_then(|name| name.parse::<i32>().ok())
      else {
         continue;
      };
      let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
         continue;
      };
      if let Some(ppid) = ppid_from_stat(&stat) {
         out.entry(ppid).or_default().push(pid);
      }
   }
   Ok(out)
}

/// Reads `len` bytes from another process without ptrace-attaching to it.
pub fn read_remote(pid: i32, addr: u64, len: usize) -> io::Result<Vec<u8>> {
   let mut buf = vec![0_u8; len];
   let local = libc::iovec {
      iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
      iov_len:  len,
   };
   let remote = libc::iovec {
      iov_base: addr as *mut libc::c_void,
      iov_len:  len,
   };
   // SAFETY: both iovecs describe live buffers. The remote one is only read by
   // the kernel and is never dereferenced in this address space.
   let n = unsafe { libc::process_vm_readv(pid, &raw const local, 1, &raw const remote, 1, 0) };
   if n < 0 {
      return Err(io::Error::last_os_error());
   }
   buf.truncate(n as usize);
   Ok(buf)
}

/// An app library's path is an unguessable /data/app/~~hash/ string, so a bare
/// basename is matched against what the target actually has mapped.
pub fn resolve_library(path: &str, mappings: &[maps::Mapping]) -> io::Result<String> {
   if path.starts_with('/') {
      return Ok(path.to_owned());
   }
   let mut matches = mappings
      .iter()
      .filter_map(|mapping| mapping.path.as_deref())
      .filter(|mapped| mapped.rsplit('/').next() == Some(path));
   let first = matches.next().ok_or_else(|| {
      io::Error::new(
         io::ErrorKind::NotFound,
         format!("the target has no mapped library named {path}"),
      )
   })?;
   if let Some(other) = matches.find(|mapped| *mapped != first) {
      return Err(io::Error::new(
         io::ErrorKind::InvalidInput,
         format!("{path} is ambiguous between {first} and {other}"),
      ));
   }
   Ok(first.to_owned())
}

/// Resolves one probe-set entry, which is a symbol unless it looks like an
/// address.
pub fn site_offset(path: &str, site: &str) -> io::Result<u64> {
   let location = parse_address(site)
      .filter(|_| site.starts_with("0x") || site.starts_with("0X"))
      .map_or_else(
         || Location::Symbol(site.to_owned()),
         Location::VirtualAddress,
      );
   probe_site(&location, path)
}

/// Accepts 0x-prefixed hex, since that is how a disassembler shows an address.
pub fn parse_address(text: &str) -> Option<u64> {
   let trimmed = text.trim();
   trimmed
      .strip_prefix("0x")
      .or_else(|| trimmed.strip_prefix("0X"))
      .map_or_else(
         || trimmed.parse::<u64>().ok(),
         |hex| u64::from_str_radix(hex, 16).ok(),
      )
}

pub fn read_head(path: &str, len: usize) -> io::Result<Vec<u8>> {
   let mut buf = Vec::with_capacity(len);
   fs::File::open(path)?
      .take(len as u64)
      .read_to_end(&mut buf)?;
   Ok(buf)
}

/// `process_vm_readv` can come back short on a multi-megabyte request, so the
/// segment is walked in pieces and a partial read is not treated as the end.
fn read_segment(pid: i32, addr: u64, len: usize) -> io::Result<Vec<u8>> {
   const CHUNK: usize = 1 << 20;
   let mut out = Vec::with_capacity(len);
   while out.len() < len {
      let want = CHUNK.min(len - out.len());
      let bytes = read_remote(pid, addr + out.len() as u64, want)?;
      if bytes.is_empty() {
         break;
      }
      out.extend_from_slice(&bytes);
   }
   Ok(out)
}

/// Writes the library out as the process sees it. A packed library decrypts its
/// own text at load, so the mapped bytes are the real code while the file on
/// disk is ciphertext. Runtime bytes are laid back over a copy of the file so
/// the result keeps its headers and still loads in a disassembler.
pub fn dump_library(pid: i32, name: &str, out: &str) -> io::Result<()> {
   let mappings = maps::read_for_pid(pid)?;
   let path = resolve_library(name, &mappings)?;
   let base = load_base(&mappings, &path);
   let mut image = fs::read(&path)?;
   let segments = elf::Elf::parse(&image)?.segments()?;
   let mut recovered = 0_usize;

   for mapping in mappings
      .iter()
      .filter(|mapping| mapping.path.as_deref() == Some(path.as_str()))
   {
      let span = mapping.end.saturating_sub(mapping.start) as usize;
      let at = mapping.pgoff as usize;
      for range in file_extents(&segments, at, span, image.len()) {
         let addr = mapping.start + (range.start - at) as u64;
         match read_segment(pid, addr, range.end - range.start) {
            Ok(bytes) if !bytes.is_empty() => {
               let end = range.start + bytes.len();
               image
                  .get_mut(range.start..end)
                  .ok_or_else(|| {
                     io::Error::new(io::ErrorKind::InvalidData, "segment overruns image")
                  })?
                  .copy_from_slice(&bytes);
               recovered += bytes.len();
               eprintln!("  {addr:#014x} +{:#x} {} bytes", range.start, bytes.len());
            },
            Ok(_) => eprintln!("  {addr:#014x} unreadable"),
            Err(err) => eprintln!("  {addr:#014x} unreadable: {err}"),
         }
      }
   }

   if recovered == 0 {
      return Err(io::Error::new(
         io::ErrorKind::NotFound,
         format!("nothing of {name} is mapped in pid {pid}"),
      ));
   }
   fs::write(out, &image)?;
   if let Some(loaded) = base {
      let sidecar = format!("{out}.json");
      fs::write(
         &sidecar,
         format!("{{\n  \"base\": {loaded},\n  \"path\": \"{path}\",\n  \"pid\": {pid}\n}}\n"),
      )?;
      eprintln!("  load base {loaded:#x} -> {sidecar}");
   }
   eprintln!("{recovered} bytes recovered from memory -> {out}");
   Ok(())
}

/// Every pointer inside a dump is a runtime address, so without the base the dump
/// cannot be followed once the process is gone. Recovering it afterwards is not
/// reliable, since a packed library's relocated slots do not agree on one.
fn load_base(mappings: &[maps::Mapping], path: &str) -> Option<u64> {
   mappings
      .iter()
      .filter(|mapping| mapping.path.as_deref() == Some(path))
      .filter_map(|mapping| mapping.start.checked_sub(mapping.pgoff))
      .min()
}

/// The parts of a mapping that are genuinely segment content, as file ranges. A
/// mapping's offset is page aligned, so it can begin before the segment it
/// carries and its tail can run past it, and in memory those edges hold bss or
/// heap rather than the file's own bytes. Overlaying a whole mapping buries the
/// section table under live data and leaves a dump no disassembler will open.
fn file_extents(
   segments: &[elf::Segment],
   at: usize,
   span: usize,
   limit: usize,
) -> Vec<Range<usize>> {
   let stop = at.saturating_add(span).min(limit);
   segments
      .iter()
      .filter_map(|seg| {
         let start = usize::try_from(seg.offset).ok()?;
         let end = start
            .checked_add(usize::try_from(seg.filesz).ok()?)?
            .min(limit);
         let from = start.max(at);
         let to = end.min(stop);
         (from < to).then_some(from..to)
      })
      .collect()
}

pub fn probe_site(location: &Location, path: &str) -> io::Result<u64> {
   match location {
      Location::FileOffset(offset) => Ok(*offset),
      Location::VirtualAddress(vaddr) => {
         let data = fs::read(path)?;
         let segments = elf::Elf::parse(&data)?.segments()?;
         elf::vaddr_to_file_offset(&segments, *vaddr).ok_or_else(|| {
            io::Error::new(
               io::ErrorKind::InvalidInput,
               format!("{vaddr:#x} is not inside any PT_LOAD segment"),
            )
         })
      },
      Location::Symbol(symbol) => {
         let data = fs::read(path)?;
         elf::Elf::parse(&data)?.probe_offset(symbol)
      },
   }
}

pub fn list_functions(target: &str, pid: Option<i32>) -> io::Result<()> {
   let path = match pid {
      Some(target_pid) => resolve_library(target, &maps::read_for_pid(target_pid)?)?,
      None => target.to_owned(),
   };
   let data = fs::read(&path)?;
   let entries = elf::Elf::parse(&data)?.function_entries()?;
   eprintln!("{} function entries in {path}", entries.len());
   let stdout = io::stdout();
   let mut out = stdout.lock();
   for entry in entries {
      writeln!(out, "{entry:#x}")?;
   }
   out.flush()
}

#[cfg(test)]
mod tests {
   #![expect(clippy::unwrap_used, reason = "a panic is the failure signal in tests")]

   use super::*;

   /// The mechanism this replaces, `/proc/<pid>/task/<tid>/children`, needs
   /// `CONFIG_PROC_CHILDREN` and does not exist on these kernels, so the walk
   /// has to be proven against a real child rather than assumed.
   #[test]
   fn the_task_tree_reaches_a_forked_child() {
      use std::process::{
         Command,
         id,
      };

      let mut child = Command::new("sleep").arg("10").spawn().unwrap();
      let kid = child.id() as i32;
      let own = id() as i32;

      let tree = task_tree(own).unwrap();
      let child_tree = task_tree(kid).unwrap();
      child.kill().unwrap();
      child.wait().unwrap();

      assert!(
         tree.iter().any(|group| group.pid == own),
         "own pid missing from {tree:?}"
      );
      assert!(
         tree.iter().any(|group| group.pid == kid),
         "child {kid} missing from {tree:?}"
      );
      assert!(
         child_tree.iter().all(|group| group.pid != own),
         "the walk went upwards"
      );
   }

   #[test]
   fn a_process_name_cannot_shift_which_field_ppid_is_read_from() {
      assert_eq!(
         ppid_from_stat("7842 (sleep) S 7841 7841 0 0").unwrap(),
         7841_i32
      );
      // A name holding spaces and its own parentheses is legal, and splitting the
      // whole line would read the name as a field and land on the wrong number.
      assert_eq!(
         ppid_from_stat("42 (evil ) 1 2 3) S 99 99 0").unwrap(),
         99_i32
      );
      assert!(ppid_from_stat("no parens here").is_none());
      assert!(ppid_from_stat("42 (x) S").is_none());
   }

   #[test]
   fn memory_overlays_are_clipped_to_file_backed_segment_bytes() {
      let segments = [
         elf::Segment {
            offset: 0,
            vaddr:  0,
            filesz: 0x1500,
         },
         elf::Segment {
            offset: 0x1500,
            vaddr:  0x2500,
            filesz: 0x300,
         },
      ];

      assert_eq!(file_extents(&segments, 0x1000, 0x1000, 0x1600), vec![
         0x1000..0x1500,
         0x1500..0x1600
      ]);
      assert!(file_extents(&segments, 0x1800, 0x1000, 0x4000).is_empty());
   }
}
