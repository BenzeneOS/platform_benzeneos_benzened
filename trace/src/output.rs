// Copyright (C) 2026 Amaan Qureshi <contact@amaanq.com>
// SPDX-License-Identifier: Apache-2.0

use crate::perf;

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

pub fn registers(regs: &[u64; perf::ARG_COUNT], all: bool) -> String {
   if !all {
      let shown = regs.len().min(4);
      let list = regs
         .get(..shown)
         .unwrap_or_default()
         .iter()
         .map(|value| format!("{value:#x}"))
         .collect::<Vec<_>>()
         .join(", ");
      return format!("args=[{list}]");
   }
   regs
      .iter()
      .enumerate()
      .map(|(idx, value)| format!("{}{idx}={value:#x}", perf::ARG_PREFIX))
      .collect::<Vec<_>>()
      .join(" ")
}

pub fn hexdump(bytes: &[u8]) -> String {
   let mut out = String::new();
   for chunk in bytes.chunks(16) {
      for byte in chunk {
         out.push(HEX_DIGITS[usize::from(byte >> 4_u8)] as char);
         out.push(HEX_DIGITS[usize::from(byte & 0x0F_u8)] as char);
         out.push(' ');
      }
      for _ in chunk.len()..16 {
         out.push_str("   ");
      }
      out.push(' ');
      for byte in chunk {
         out.push(if byte.is_ascii_graphic() || *byte == b' ' {
            *byte as char
         } else {
            '.'
         });
      }
      out.push('\n');
   }
   out
}
