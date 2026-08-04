// Copyright (C) 2026 Amaan Qureshi <contact@amaanq.com>
// SPDX-License-Identifier: Apache-2.0

use std::io::{
   self,
   Write as _,
};

use crate::{
   command::Capture,
   output,
   perf,
   ring,
   session::Group,
   symbolizer::Symbolizer,
   target,
};

const STACK_FRAMES: usize = 32;

pub fn sample<Writer>(
   out: &mut Writer,
   label: &str,
   capture: &Capture,
   sample: &ring::Sample,
   caller: &str,
   symbolizer: &mut Symbolizer,
) -> io::Result<()>
where
   Writer: io::Write + ?Sized,
{
   let regs = perf::args_from_regs(&sample.regs).ok_or_else(|| {
      io::Error::new(
         io::ErrorKind::InvalidData,
         "the sample does not contain the complete register set",
      )
   })?;
   let state = perf::state(&sample.regs)
      .map(|[eight, nine, ten]| {
         format!(
            " state=[{:#x},{:#x},{:#x}]",
            eight as u32, nine as u32, ten as u32
         )
      })
      .unwrap_or_default();
   writeln!(
      out,
      "{:>16} {label} pid={} tid={} from={caller}{state} {}",
      sample.time,
      sample.pid,
      sample.tid,
      output::registers(&regs, capture.all_regs)
   )?;

   if capture.stack > 0 {
      let frames = symbolizer.frames(sample, STACK_FRAMES);
      if frames.is_empty() {
         writeln!(out, "  <no frames recovered>")?;
      } else {
         writeln!(out, "  {}", frames.join(" < "))?;
      }
   }
   let slot = |index: usize| {
      if index == perf::SP_SLOT {
         perf::stack_pointer(&sample.regs).unwrap_or_default()
      } else {
         regs[index]
      }
   };
   if let Some((index, len)) = capture.dump {
      match target::read_remote(sample.pid as i32, slot(index), len) {
         Ok(bytes) if !bytes.is_empty() => write!(out, "{}", output::hexdump(&bytes))?,
         Ok(_) => {},
         Err(err) => writeln!(out, "  <unreadable: {err}>")?,
      }
   }
   if let Some((index, offset, len)) = capture.deref {
      match read_through(sample.pid as i32, slot(index), offset, len) {
         Ok(bytes) if !bytes.is_empty() => write!(out, "{}", output::hexdump(&bytes))?,
         Ok(_) => {},
         Err(err) => writeln!(out, "  <unreadable: {err}>")?,
      }
   }
   Ok(())
}

pub fn threads(groups: &[Group]) -> io::Result<()> {
   let stdout = io::stdout();
   let mut out = stdout.lock();
   for group in groups {
      let mut ranked = group
         .threads()
         .iter()
         .map(|entry| (entry.count, entry.pid, entry.tid, entry.name.as_str()))
         .collect::<Vec<_>>();
      ranked.sort_unstable_by(|left, right| right.cmp(left));
      writeln!(out, "{} threads for {}", ranked.len(), group.label())?;
      for (count, _pid, tid, name) in ranked {
         writeln!(out, "  {tid:>7}  {count:>8}  {name}")?;
      }
   }
   out.flush()
}

fn read_through(pid: i32, addr: u64, offset: u64, len: usize) -> io::Result<Vec<u8>> {
   let field = addr.checked_add(offset).ok_or_else(|| {
      io::Error::new(
         io::ErrorKind::InvalidInput,
         "dereference offset overflows the object address",
      )
   })?;
   let handle = target::read_remote(pid, field, 8)?;
   let slot = u64::from_le_bytes(handle.as_slice().try_into().map_err(|_short| {
      io::Error::new(io::ErrorKind::UnexpectedEof, "pointer read was incomplete")
   })?);
   if slot == 0 {
      return Ok(Vec::new());
   }
   target::read_remote(pid, slot, len)
}
