// Copyright (C) 2026 Amaan Qureshi <contact@amaanq.com>
// SPDX-License-Identifier: Apache-2.0

//! Pure decoding of the perf ring buffer. Kept free of syscalls so the wrap and
//! layout handling can be tested without a device.

use core::cmp;

pub const PERF_RECORD_SAMPLE: u32 = 9;
pub const PERF_RECORD_LOST: u32 = 2;

pub const HEADER_SIZE: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub struct Record {
   pub kind: u32,
   pub body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeError;

/// The data area is a power-of-two ring indexed by `tail % len`, and a single
/// record may straddle the end, so this cannot be a plain slice.
fn read_wrapped(data: &[u8], start: u64, len: usize) -> Option<Vec<u8>> {
   if data.is_empty() || len > data.len() {
      return None;
   }
   let begin = (start % data.len() as u64) as usize;
   let mut out = Vec::with_capacity(len);
   let first = cmp::min(len, data.len() - begin);
   out.extend_from_slice(&data[begin..begin + first]);
   if first < len {
      out.extend_from_slice(&data[..len - first]);
   }
   Some(out)
}

/// Returns the record at `tail` and the tail to use next.
pub fn next_record(
   data: &[u8],
   tail: u64,
   head: u64,
) -> Result<Option<(Record, u64)>, DecodeError> {
   if tail >= head {
      return Ok(None);
   }
   if head - tail < HEADER_SIZE as u64 {
      return Err(DecodeError);
   }
   let hdr = read_wrapped(data, tail, HEADER_SIZE).ok_or(DecodeError)?;
   let kind = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
   let size = u16::from_le_bytes([hdr[6], hdr[7]]) as usize;
   if size < HEADER_SIZE || size as u64 > head - tail {
      return Err(DecodeError);
   }
   let body =
      read_wrapped(data, tail + HEADER_SIZE as u64, size - HEADER_SIZE).ok_or(DecodeError)?;
   Ok(Some((Record { kind, body }, tail + size as u64)))
}

/// Fields of a sample recorded with `IP` | `TID` | `TIME` | `REGS_USER`,
/// optionally followed by `STACK_USER`, in the order the kernel emits them.
#[derive(Debug, PartialEq, Eq)]
pub struct Sample {
   pub ip:    u64,
   pub pid:   u32,
   pub tid:   u32,
   pub time:  u64,
   pub regs:  Vec<u64>,
   pub stack: Vec<u8>,
}

pub fn parse_sample(body: &[u8], reg_count: usize) -> Option<Sample> {
   let need = 32_usize.checked_add(reg_count.checked_mul(8)?)?;
   if body.len() < need {
      return None;
   }
   let g64 = |off: usize| {
      body
         .get(off..off.checked_add(8)?)?
         .try_into()
         .ok()
         .map(u64::from_le_bytes)
   };
   let g32 =
      |off: usize| u32::from_le_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]]);

   let regs = (0..reg_count)
      .map(|idx| g64(32 + idx * 8))
      .collect::<Option<Vec<_>>>()?;

   // PERF_SAMPLE_STACK_USER appends a size, the bytes, then the size the kernel
   // actually managed to copy, which is what bounds the walk. A truncated record
   // yields no stack rather than a wrong one.
   let stack = g64(need)
      .and_then(|raw_size| {
         let size = usize::try_from(raw_size).ok()?;
         let bytes_at = need.checked_add(8)?;
         let dyn_at = bytes_at.checked_add(size)?;
         let filled = usize::try_from(g64(dyn_at)?).ok()?.min(size);
         body
            .get(bytes_at..bytes_at.checked_add(filled)?)
            .map(<[u8]>::to_vec)
      })
      .unwrap_or_default();

   Some(Sample {
      ip: g64(0)?,
      pid: g32(8),
      tid: g32(12),
      time: g64(16)?,
      regs,
      stack,
   })
}

#[cfg(test)]
mod tests {
   #![expect(clippy::unwrap_used, reason = "a panic is the failure signal in tests")]

   use super::*;

   fn record(kind: u32, body: &[u8]) -> Vec<u8> {
      let size = (HEADER_SIZE + body.len()) as u16;
      let mut bytes = Vec::new();
      bytes.extend_from_slice(&kind.to_le_bytes());
      bytes.extend_from_slice(&0_u16.to_le_bytes());
      bytes.extend_from_slice(&size.to_le_bytes());
      bytes.extend_from_slice(body);
      bytes
   }

   #[test]
   fn record_straddling_the_end_of_the_ring_is_reassembled() {
      let len = 32_usize;
      let mut data = vec![0_u8; len];
      let rec = record(PERF_RECORD_SAMPLE, &[1, 2, 3, 4, 5, 6, 7, 8]);
      assert_eq!(rec.len(), 16);
      let start = (len - 8) as u64;
      for (idx, byte) in rec.iter().enumerate() {
         data[(start as usize + idx) % len] = *byte;
      }
      let (got, next) = next_record(&data, start, start + rec.len() as u64)
         .unwrap()
         .unwrap();
      assert_eq!(got.kind, PERF_RECORD_SAMPLE);
      assert_eq!(got.body, vec![1, 2, 3, 4, 5, 6, 7, 8]);
      assert_eq!(next, start + 16);
   }

   #[test]
   fn incomplete_and_overstated_records_are_rejected() {
      let partial = [0_u8; 32];
      assert_eq!(next_record(&partial, 10, 10), Ok(None));
      next_record(&partial, 10, 14).unwrap_err();

      let len = 64_usize;
      let mut data = vec![0_u8; len];
      let rec = record(PERF_RECORD_SAMPLE, &[0_u8; 40]);
      assert!(rec.len() <= len, "record must fit the ring under test");
      data[..rec.len()].copy_from_slice(&rec);
      next_record(&data, 0, 16).unwrap_err();
   }

   #[test]
   fn a_stack_payload_is_bounded_by_what_the_kernel_actually_copied() {
      let mut body = Vec::new();
      body.extend_from_slice(&0xDEAD_BEEF_u64.to_le_bytes()); // ip
      body.extend_from_slice(&1_u32.to_le_bytes()); // pid
      body.extend_from_slice(&2_u32.to_le_bytes()); // tid
      body.extend_from_slice(&3_u64.to_le_bytes()); // time
      body.extend_from_slice(&1_u64.to_le_bytes()); // regs abi
      body.extend_from_slice(&0xAAA_u64.to_le_bytes()); // one register
      body.extend_from_slice(&24_u64.to_le_bytes()); // stack size requested
      body.extend_from_slice(&[0xEE; 24]); // stack bytes
      body.extend_from_slice(&16_u64.to_le_bytes()); // dyn_size, kernel copied less

      let sample = parse_sample(&body, 1).unwrap();
      assert_eq!(sample.regs, vec![0xAAA]);
      // Trusting the requested size instead of dyn_size would hand the walk eight
      // bytes of whatever followed in the record.
      assert_eq!(sample.stack.len(), 16);
      assert!(sample.stack.iter().all(|byte| *byte == 0xEE));

      let mut malformed = body;
      let size_at = 40;
      malformed[size_at..size_at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
      assert!(parse_sample(&malformed, 1).is_some_and(|decoded| decoded.stack.is_empty()));
   }
}
