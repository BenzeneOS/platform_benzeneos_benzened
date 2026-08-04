// Copyright (C) 2026 Amaan Qureshi <contact@amaanq.com>
// SPDX-License-Identifier: Apache-2.0

//! `perf_event_open` plumbing for uprobes and hardware breakpoints. bionic's
//! headers are not exposed to Rust here, so the ABI is spelled out and
//! size-asserted against the kernel's `PERF_ATTR_SIZE_VER8`.

use core::{
   ptr,
   sync::atomic::{
      Ordering,
      fence,
   },
};
use std::{
   ffi::CString,
   fs,
   io,
   os::fd::{
      AsRawFd,
      FromRawFd as _,
      OwnedFd,
      RawFd,
   },
   slice,
};

use crate::ring;

/// Most fields exist only for the kernel to read through the pointer.
#[repr(C)]
#[derive(Default)]
pub struct PerfEventAttr {
   pub type_:              u32,
   pub size:               u32,
   pub config:             u64,
   pub sample_period:      u64,
   pub sample_type:        u64,
   pub read_format:        u64,
   pub flags:              u64,
   pub wakeup_events:      u32,
   pub bp_type:            u32,
   pub config1:            u64,
   pub config2:            u64,
   pub branch_sample_type: u64,
   pub sample_regs_user:   u64,
   pub sample_stack_user:  u32,
   pub clockid:            i32,
   pub sample_regs_intr:   u64,
   pub aux_watermark:      u32,
   pub sample_max_stack:   u16,
   pub reserved_2:         u16,
   pub aux_sample_size:    u32,
   pub reserved_3:         u32,
   pub sig_data:           u64,
}

const _: () = assert!(
   size_of::<PerfEventAttr>() == 128,
   "PerfEventAttr must match PERF_ATTR_SIZE_VER8"
);

pub const PERF_SAMPLE_IP: u64 = 1 << 0;
pub const PERF_SAMPLE_TID: u64 = 1 << 1;
pub const PERF_SAMPLE_TIME: u64 = 1 << 2;
pub const PERF_SAMPLE_REGS_USER: u64 = 1 << 12;
pub const PERF_SAMPLE_STACK_USER: u64 = 1 << 13;

const FLAG_DISABLED: u64 = 1 << 0;
const FLAG_EXCLUDE_KERNEL: u64 = 1 << 5;
const FLAG_EXCLUDE_HV: u64 = 1 << 6;

/// `AArch64` exposes a handful of breakpoint registers per task, so a probe set
/// cannot be spread across debug registers the way uprobes can.
pub const HW_BREAKPOINT_SLOTS: usize = 4;

const PERF_EVENT_IOC_ENABLE: libc::Ioctl = 0x2400;

const PERF_TYPE_BREAKPOINT: u32 = 5;
pub const HW_BREAKPOINT_R: u32 = 1;
pub const HW_BREAKPOINT_W: u32 = 2;
pub const HW_BREAKPOINT_RW: u32 = 3;
pub const HW_BREAKPOINT_X: u32 = 4;

/// x86 execution breakpoints must have length 1, arm64 matches an instruction.
#[cfg(target_arch = "x86_64")]
pub const HW_BREAKPOINT_EXEC_LEN: u64 = 1;
#[cfg(target_arch = "aarch64")]
pub const HW_BREAKPOINT_EXEC_LEN: u64 = 4;

/// A watchpoint's length must be a power of two up to eight, and the address
/// has to be aligned to it, or the kernel rejects the event.
#[must_use]
pub const fn watch_len_is_valid(len: u64) -> bool {
   matches!(len, 1 | 2 | 4 | 8)
}

/// The uprobe PMU publishes this as `config:0` in its format directory.
const RETPROBE_BIT: u64 = 1 << 0;

#[cfg(target_arch = "x86_64")]
const SYS_PERF_EVENT_OPEN: libc::c_long = 298;
#[cfg(target_arch = "aarch64")]
const SYS_PERF_EVENT_OPEN: libc::c_long = 241;

/// aarch64 passes arguments in x0-x7 and puts an *indirect result* pointer in
/// x8, which is where a function returning a struct writes its output. A probe
/// that cannot read x8 cannot see that output at all, which is the usual case
/// for anything returning a `std::string`. x30 is the link register.
#[cfg(target_arch = "aarch64")]
pub const ARG_REGS: u64 = 0x7FF | (1 << 29) | (1 << 30) | (1 << 31);
#[cfg(target_arch = "aarch64")]
const ARG_ORDER: [usize; 9] = [0, 1, 2, 3, 4, 5, 6, 7, 8];
/// A flattened dispatcher keeps its block id in one of these. Measured across the
/// packed target: w9 holds it at 42.7% of dispatch sites, w8 at 22.7% and w10 at
/// 9.7%, so sampling x9 and x10 alongside the argument registers covers about three
/// quarters of them.
#[cfg(target_arch = "aarch64")]
pub const STATE_SLOTS: [usize; 3] = [8, 9, 10];
#[cfg(target_arch = "aarch64")]
pub const FP_SLOT: usize = 11;
#[cfg(target_arch = "aarch64")]
pub const CALLER_SLOT: usize = 12;
#[cfg(target_arch = "aarch64")]
pub const SP_SLOT: usize = 13;

/// `x86_64` passes arguments in rdi, rsi, rdx, rcx, r8, r9, returns a large
/// struct through a hidden pointer in rdi rather than a dedicated register, and
/// has no link register, so rsp is sampled and the return address read from the
/// top of the stack.
#[cfg(target_arch = "x86_64")]
pub const ARG_REGS: u64 =
   (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 16) | (1 << 17);
#[cfg(target_arch = "x86_64")]
const ARG_ORDER: [usize; 6] = [3, 2, 1, 0, 6, 7];
#[cfg(target_arch = "x86_64")]
pub const FP_SLOT: usize = 4;
#[cfg(target_arch = "x86_64")]
pub const CALLER_SLOT: usize = 5;
#[cfg(target_arch = "x86_64")]
pub const SP_SLOT: usize = 5;

pub const ARG_COUNT: usize = ARG_ORDER.len();

/// Names the registers in `--regs` output after the architecture's own
/// notation, so a value can be matched against a disassembly listing without
/// translation.
#[cfg(target_arch = "aarch64")]
pub const ARG_PREFIX: &str = "x";
#[cfg(target_arch = "x86_64")]
pub const ARG_PREFIX: &str = "arg";

/// Total sampled registers, which `parse_sample` needs in order to size the
/// array.
pub const SAMPLED_REGS: usize = ARG_REGS.count_ones() as usize;

#[cfg(target_arch = "aarch64")]
const CALLER_STACK: u32 = 0;
#[cfg(target_arch = "x86_64")]
const CALLER_STACK: u32 = 8;

/// `x86_64` has no link register, so naming a caller means reading the return
/// address off the stack and a few bytes are always captured. aarch64 reads
/// `x30` and needs none, which is why this is a no-op there.
const fn captured_stack(stack: u32) -> u32 {
   if stack > CALLER_STACK {
      stack
   } else {
      CALLER_STACK
   }
}

/// x8 is the whole point of the wide mask, since a function returning a struct
/// writes it through that pointer rather than in x0. Asserted at compile time
/// because a `cfg` test for one architecture never runs on the other.
#[cfg(target_arch = "aarch64")]
const _: () = {
   assert!(
      ARG_COUNT == 9,
      "x0 through x8 must be addressable by --dump"
   );
   assert!(STATE_SLOTS[2] == 10, "x10 sorts after x0 through x9");
   assert!(FP_SLOT == 11, "x29 sorts after x10");
   assert!(CALLER_SLOT == 12, "x30 sorts after x29");
   assert!(SP_SLOT == 13, "sp sorts after x30");
   assert!(SAMPLED_REGS == 14, "x0-x10, then x29, x30 and sp");
};

/// The flattening state. A dispatcher compares this against a block constant, so
/// reading it names the block about to run without solving the dispatch statically.
/// Absent on architectures where no such register is sampled.
#[cfg(target_arch = "aarch64")]
#[must_use]
#[inline]
pub fn state(regs: &[u64]) -> Option<[u64; 3]> {
   Some([
      *regs.get(STATE_SLOTS[0])?,
      *regs.get(STATE_SLOTS[1])?,
      *regs.get(STATE_SLOTS[2])?,
   ])
}

#[cfg(not(target_arch = "aarch64"))]
#[must_use]
#[inline]
pub const fn state(_regs: &[u64]) -> Option<[u64; 3]> {
   None
}

/// The frame pointer, which is what a frame walk chains through. Measured at
/// 78.9% of functions in a packed target, so it covers most frames without
/// trusting any unwind table the target supplies.
#[must_use]
#[inline]
pub fn frame_pointer(regs: &[u64]) -> Option<u64> {
   regs.get(FP_SLOT).copied()
}

/// Where the captured stack begins, since `PERF_SAMPLE_STACK_USER` copies
/// upward from the stack pointer and the bytes mean nothing without that base.
#[must_use]
#[inline]
pub fn stack_pointer(regs: &[u64]) -> Option<u64> {
   regs.get(SP_SLOT).copied()
}

/// A callee returning a large object writes it through a caller stack slot rather
/// than a register, so a probe on the site after the call needs `sp` addressable.
#[must_use]
#[inline]
pub const fn is_dumpable(index: usize) -> bool {
   index < ARG_COUNT || index == SP_SLOT
}

/// On aarch64 x30 is the return address at function entry, so a probe hit names
/// its own caller. `x86_64` has no link register, so this is the stack pointer
/// and the caller has to be read from the top of the stack.
#[must_use]
#[inline]
pub fn caller_slot(regs: &[u64]) -> Option<u64> {
   regs.get(CALLER_SLOT).copied()
}

#[cfg(target_arch = "aarch64")]
pub const CALLER_IS_LINK_REGISTER: bool = true;
#[cfg(target_arch = "x86_64")]
pub const CALLER_IS_LINK_REGISTER: bool = false;

/// Reorders sampled slots into argument order. The kernel emits in ascending
/// register index, which is not argument order on `x86_64` (rdi is index 5 but
/// argument 0).
pub fn args_from_regs(regs: &[u64]) -> Option<[u64; ARG_COUNT]> {
   if regs.len() < SAMPLED_REGS {
      return None;
   }
   let mut out = [0_u64; ARG_COUNT];
   for (idx, src) in ARG_ORDER.iter().enumerate() {
      out[idx] = regs[*src];
   }
   Some(out)
}

/// Bytes one sample occupies in the ring, which is what the ring has to be
/// sized against. A ring smaller than a single sample delivers nothing at all.
#[must_use]
pub const fn sample_size(stack: u32) -> usize {
   let captured_stack = captured_stack(stack);
   // header, ip, pid, tid, time, the regs abi, then the registers themselves.
   let fixed = 8 + 8 + 4 + 4 + 8 + 8 + SAMPLED_REGS * 8;
   if captured_stack == 0 {
      fixed
   } else {
      // size, the bytes, then the size the kernel actually copied.
      fixed + 8 + captured_stack as usize + 8
   }
}

/// Shared attr for every probe kind. `stack` bytes of user stack are copied at
/// each hit when non-zero, which is what an offline frame walk needs, since the
/// sampled registers alone only name one frame.
fn probe_attr(type_: u32, retprobe: bool, stack: u32) -> PerfEventAttr {
   let captured_stack = captured_stack(stack);
   let mut sample_type =
      PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_REGS_USER;
   if captured_stack > 0 {
      sample_type |= PERF_SAMPLE_STACK_USER;
   }
   PerfEventAttr {
      type_,
      config: if retprobe { RETPROBE_BIT } else { 0 },
      size: size_of::<PerfEventAttr>() as u32,
      sample_period: 1,
      sample_type,
      flags: FLAG_DISABLED | FLAG_EXCLUDE_KERNEL | FLAG_EXCLUDE_HV,
      wakeup_events: 1,
      sample_regs_user: ARG_REGS,
      sample_stack_user: captured_stack,
      ..Default::default()
   }
}

fn uprobe_pmu_type() -> io::Result<u32> {
   let text = fs::read_to_string("/sys/bus/event_source/devices/uprobe/type")?;
   text.trim().parse::<u32>().map_err(|error| {
      io::Error::new(
         io::ErrorKind::InvalidData,
         format!("bad uprobe PMU type ({error})"),
      )
   })
}

/// `_SC_NPROCESSORS_CONF` and not `_SC_NPROCESSORS_ONLN`, since a cpu that is
/// offline right now can come online while a system-wide probe is armed and
/// would otherwise run untraced.
#[must_use]
pub fn cpu_count() -> usize {
   // SAFETY: sysconf takes an int and returns a long, with no memory involved.
   let count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_CONF) };
   usize::try_from(count).unwrap_or(1).max(1)
}

pub struct Probe {
   ring:        MappedRing,
   fd:          OwnedFd,
   data_offset: usize,
   data_size:   usize,
   tail:        u64,
}

impl AsRawFd for Probe {
   fn as_raw_fd(&self) -> RawFd {
      self.fd.as_raw_fd()
   }
}

enum EventTarget {
   Task(i32),
   Cpu(usize),
}

impl EventTarget {
   /// `cpu` is -1 for a named task, watched wherever it runs. A system-wide
   /// event has no task to name, so it pins a cpu instead.
   fn syscall_args(self) -> io::Result<(i32, i32)> {
      match self {
         Self::Task(pid) => Ok((pid, -1_i32)),
         Self::Cpu(cpu_index) => {
            let cpu = i32::try_from(cpu_index).map_err(|_ignored| {
               io::Error::new(io::ErrorKind::InvalidInput, "cpu index too large")
            })?;
            Ok((-1_i32, cpu))
         },
      }
   }
}

pub struct Records {
   pub samples:   Vec<ring::Sample>,
   pub lost:      u64,
   pub malformed: u64,
}

struct MappedRing {
   base: *mut libc::c_void,
   len:  usize,
}

impl MappedRing {
   fn map(fd: &OwnedFd, len: usize) -> io::Result<Self> {
      // SAFETY: fd is a live perf event and len is a multiple of the page size.
      let base = unsafe {
         libc::mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            0,
         )
      };
      if base == libc::MAP_FAILED {
         return Err(io::Error::last_os_error());
      }
      Ok(Self { base, len })
   }
}

impl Drop for MappedRing {
   fn drop(&mut self) {
      // SAFETY: base and len are exactly what mmap returned.
      unsafe {
         libc::munmap(self.base, self.len);
      }
   }
}

impl Probe {
   /// `path` must be absolute and stay alive across the syscall, since the
   /// kernel reads it out of config1 as a pointer.
   ///
   /// The event cannot carry `inherit`. `perf_uprobe_init` re-reads that
   /// pointer with `strndup_user` every time the event is allocated, and on
   /// a fork that allocation runs in the target's address space where the
   /// pointer means nothing, so the target's `fork` fails rather than the
   /// probe spreading.
   pub fn open(
      path: &str,
      offset: u64,
      pid: i32,
      pages: usize,
      retprobe: bool,
      stack: u32,
   ) -> io::Result<Self> {
      let cpath =
         CString::new(path).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

      let mut attr = probe_attr(uprobe_pmu_type()?, retprobe, stack);
      attr.config1 = cpath.as_ptr() as u64;
      attr.config2 = offset;

      Self::from_attr(&attr, EventTarget::Task(pid), pages)
   }

   /// A breakpoint armed on a cpu rather than a task, so a thread created later
   /// is covered too. Debug registers are a per-cpu bank, so this costs one
   /// register per cpu instead of one per thread, and a target with hundreds
   /// of threads cannot be covered any other way.
   pub fn open_hw_system(
      addr: u64,
      cpu: usize,
      pages: usize,
      bp_type: u32,
      bp_len: u64,
      stack: u32,
   ) -> io::Result<Self> {
      let mut attr = probe_attr(PERF_TYPE_BREAKPOINT, false, stack);
      attr.bp_type = bp_type;
      attr.config1 = addr;
      attr.config2 = bp_len;

      Self::from_attr(&attr, EventTarget::Cpu(cpu), pages)
   }

   /// Watches every process on one cpu rather than one task anywhere. A uprobe
   /// is keyed on inode and offset, so this reports for a process that
   /// starts after the probe is armed, which is the only way to see a
   /// function that runs during process startup.
   pub fn open_system(
      path: &str,
      offset: u64,
      cpu: usize,
      pages: usize,
      retprobe: bool,
      stack: u32,
   ) -> io::Result<Self> {
      let cpath =
         CString::new(path).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

      let mut attr = probe_attr(uprobe_pmu_type()?, retprobe, stack);
      attr.config1 = cpath.as_ptr() as u64;
      attr.config2 = offset;

      Self::from_attr(&attr, EventTarget::Cpu(cpu), pages)
   }

   fn from_attr(attr: &PerfEventAttr, target: EventTarget, pages: usize) -> io::Result<Self> {
      let (pid, cpu) = target.syscall_args()?;
      // SAFETY: attr is live and sized, and cpath outlives the call.
      let raw_fd = unsafe {
         libc::syscall(
            SYS_PERF_EVENT_OPEN,
            ptr::from_ref(attr),
            pid,
            cpu,
            -1_i32,
            0_u64,
         )
      };
      if raw_fd < 0 {
         return Err(io::Error::last_os_error());
      }

      // SAFETY: raw_fd is a fresh descriptor owned here.
      let fd = unsafe { OwnedFd::from_raw_fd(raw_fd as i32) };

      let page = page_size();
      let map_len = pages
         .checked_add(1)
         .and_then(|count| count.checked_mul(page))
         .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "perf ring is too large"))?;
      let ring = MappedRing::map(&fd, map_len)?;

      let data_offset = read_meta(ring.base, 1040) as usize;
      let data_size = read_meta(ring.base, 1048) as usize;
      let tail = read_meta(ring.base, 1032);
      if !data_size.is_power_of_two()
         || data_offset < page
         || data_offset
            .checked_add(data_size)
            .is_none_or(|end| end > map_len)
      {
         return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "perf published an invalid ring layout",
         ));
      }

      // SAFETY: fd is a live perf event descriptor.
      if unsafe { libc::ioctl(fd.as_raw_fd(), PERF_EVENT_IOC_ENABLE, 0_i32) }.is_negative() {
         return Err(io::Error::last_os_error());
      }

      Ok(Self {
         ring,
         fd,
         data_offset,
         data_size,
         tail,
      })
   }

   /// Drains everything published since the last call.
   pub fn drain(&mut self) -> Records {
      let base = self.ring.base;
      let (off, size) = (self.data_offset, self.data_size);
      let head = read_meta(base, 1024);
      fence(Ordering::Acquire);
      let mut out = Vec::new();
      let mut lost = 0_u64;
      let mut malformed = 0_u64;
      // SAFETY: off is the kernel-published data offset, so it lies inside the
      // mapping created in open().
      let start = unsafe { base.cast::<u8>().add(off) };
      // SAFETY: the data area lies inside that same mapping and is not aliased
      // by any live reference to self.
      let data: &[u8] = unsafe { slice::from_raw_parts(start, size) };
      let mut tail = self.tail;
      loop {
         let (rec, next) = match ring::next_record(data, tail, head) {
            Ok(Some(record)) => record,
            Ok(None) => break,
            Err(_error) => {
               malformed += 1;
               break;
            },
         };
         tail = next;
         match rec.kind {
            ring::PERF_RECORD_SAMPLE => {
               if let Some(sample) = ring::parse_sample(&rec.body, SAMPLED_REGS) {
                  out.push(sample);
               } else {
                  malformed += 1;
               }
            },
            ring::PERF_RECORD_LOST => {
               if let Some(bytes) = rec.body.get(8..16) {
                  lost += u64::from_le_bytes(bytes.try_into().unwrap_or_default());
               } else {
                  malformed += 1;
               }
            },
            _ => {},
         }
      }
      self.tail = head;
      fence(Ordering::Release);
      write_meta(base, 1032, head);
      Records {
         samples: out,
         lost,
         malformed,
      }
   }
}

fn page_size() -> usize {
   // SAFETY: sysconf takes only a name and returns a long.
   let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
   if n > 0 { n as usize } else { 4096 }
}

#[expect(
   clippy::cast_ptr_alignment,
   reason = "the perf metadata page keeps these fields 64-bit aligned by ABI"
)]
fn read_meta(base: *mut libc::c_void, off: usize) -> u64 {
   // SAFETY: off is within the first page of the perf mapping.
   let field = unsafe { base.cast::<u8>().add(off) };
   // SAFETY: the kernel updates these fields atomically for aligned 64-bit reads.
   unsafe { ptr::read_volatile(field.cast::<u64>()) }
}

#[expect(
   clippy::cast_ptr_alignment,
   reason = "the perf metadata page keeps these fields 64-bit aligned by ABI"
)]
fn write_meta(base: *mut libc::c_void, off: usize, value: u64) {
   // SAFETY: as in read_meta.
   let field = unsafe { base.cast::<u8>().add(off) };
   // SAFETY: data_tail is the one field userspace owns.
   unsafe {
      ptr::write_volatile(field.cast::<u64>(), value);
   }
}

#[cfg(test)]
mod tests {
   #![expect(clippy::unwrap_used, reason = "a panic is the failure signal in tests")]

   use super::*;

   /// The kernel emits sampled registers in ascending register index, so a slot
   /// is just the count of lower-numbered registers in the mask. Deriving that
   /// here independently is the only thing that catches a mask edit which
   /// silently shifts every slot by one and makes every reported value wrong.
   #[test]
   fn sampled_register_slots_match_the_architecture_abi() {
      let caller_reg = if cfg!(target_arch = "aarch64") {
         30_u32
      } else {
         7_u32
      };
      assert!(
         ARG_REGS & (1_u64 << caller_reg) != 0,
         "the caller register is not in the sample mask"
      );
      let below = ARG_REGS & ((1_u64 << caller_reg) - 1);
      assert_eq!(CALLER_SLOT, below.count_ones() as usize);

      assert_eq!(SAMPLED_REGS, ARG_REGS.count_ones() as usize);
      assert!(
         ARG_ORDER.iter().all(|slot| *slot < SAMPLED_REGS),
         "an argument maps to a slot the kernel never emits"
      );
      assert!(
         !ARG_ORDER.contains(&CALLER_SLOT),
         "an argument aliases the caller slot"
      );
      if cfg!(target_arch = "x86_64") {
         assert_eq!(
            ARG_REGS & ((1_u64 << 16_u32) | (1_u64 << 17_u32)),
            (1_u64 << 16_u32) | (1_u64 << 17_u32),
            "r8 and r9 are not in the sample mask"
         );
      }
      let mut seen = ARG_ORDER.to_vec();
      seen.sort_unstable();
      let mut unique = seen.clone();
      unique.dedup();
      assert_eq!(seen, unique, "two arguments share a slot");

      // Each slot holds its own index, so a misordered mapping is visible as a
      // value that does not match the slot the ABI says it came from.
      let regs = (0..SAMPLED_REGS as u64).collect::<Vec<u64>>();
      let args = args_from_regs(&regs).unwrap();
      // Ascending index on x86_64 is cx, dx, si, di, bp, sp, r8, r9, while
      // argument order is di, si, dx, cx, r8, r9. aarch64 needs no reordering.
      let expected: &[u64] = if cfg!(target_arch = "x86_64") {
         &[3, 2, 1, 0, 6, 7]
      } else {
         &[0, 1, 2, 3, 4, 5, 6, 7, 8]
      };
      assert_eq!(args.as_slice(), expected);

      // One short of the full set still has to be refused, since the caller slot
      // sits at the end and a partial read would index past it.
      let short = (0..SAMPLED_REGS as u64 - 1).collect::<Vec<u64>>();
      assert!(args_from_regs(&short).is_none());
   }
}
