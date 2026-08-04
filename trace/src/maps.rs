// Copyright (C) 2026 Amaan Qureshi <contact@amaanq.com>
// SPDX-License-Identifier: Apache-2.0

//! Resolving a file offset to the address it was mapped at in a live process.

use std::{
   fs,
   io,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
   pub start:      u64,
   pub end:        u64,
   pub pgoff:      u64,
   pub path:       Option<String>,
   pub executable: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CodeLocation<'maps> {
   File { path: &'maps str, offset: u64 },
   Anonymous,
}

/// Parses a /proc/<pid>/maps line. Malformed lines are skipped.
pub fn parse_line(line: &str) -> Option<Mapping> {
   let mut fields = line.split_whitespace();
   let range = fields.next()?;
   let perms = fields.next()?;
   let pgoff = u64::from_str_radix(fields.next()?, 16).ok()?;
   let _dev = fields.next()?;
   let _inode = fields.next()?;
   let path_text = fields.collect::<Vec<_>>().join(" ");
   let path = (!path_text.is_empty()).then_some(path_text);
   let (start, end) = range.split_once('-')?;
   Some(Mapping {
      start: u64::from_str_radix(start, 16).ok()?,
      end: u64::from_str_radix(end, 16).ok()?,
      pgoff,
      path,
      executable: perms.as_bytes().get(2) == Some(&b'x'),
   })
}

/// A shared library is mapped as several segments, each covering a different
/// slice of the file, so the offset has to be matched against the segment that
/// actually contains it rather than against the first mapping of the path.
pub fn runtime_address(maps: &[Mapping], path: &str, file_offset: u64) -> Option<u64> {
   maps
      .iter()
      .filter(|mapping| mapping.path.as_deref() == Some(path))
      .find_map(|mapping| {
         let span = mapping.end.checked_sub(mapping.start)?;
         let rel = file_offset.checked_sub(mapping.pgoff)?;
         (rel < span).then(|| mapping.start + rel)
      })
}

/// The inverse of `runtime_address`. Returns the full path rather than a
/// basename, because turning the offset into a virtual address needs the file's
/// own program headers.
#[must_use]
pub fn describe_code(maps: &[Mapping], addr: u64) -> Option<CodeLocation<'_>> {
   let mapping = maps
      .iter()
      .find(|mapping| mapping.executable && (mapping.start..mapping.end).contains(&addr))?;
   let Some(path) = mapping.path.as_deref() else {
      return Some(CodeLocation::Anonymous);
   };
   let offset = addr
      .checked_sub(mapping.start)?
      .checked_add(mapping.pgoff)?;
   Some(CodeLocation::File { path, offset })
}

pub fn read_for_pid(pid: i32) -> io::Result<Vec<Mapping>> {
   let text = fs::read_to_string(format!("/proc/{pid}/maps"))?;
   Ok(text.lines().filter_map(parse_line).collect())
}

#[cfg(test)]
mod tests {
   use super::*;

   const LIB: &str = "/apex/com.android.runtime/lib64/bionic/libc.so";

   fn sample() -> Vec<Mapping> {
      [
         "77fbdda0d000-77fbdda65000 r--p 00000000 07:70 21    \
          /apex/com.android.runtime/lib64/bionic/libc.so",
         "77fbdda65000-77fbddb0d000 r-xp 00058000 07:70 21    \
          /apex/com.android.runtime/lib64/bionic/libc.so",
      ]
      .iter()
      .filter_map(|line| parse_line(line))
      .collect()
   }

   #[test]
   fn offsets_and_addresses_use_the_mapping_that_actually_contains_them() {
      assert_eq!(
         runtime_address(&sample(), LIB, 0x5_8FC0),
         Some(0x77FB_DDA6_5FC0)
      );
      assert_eq!(
         runtime_address(&sample(), LIB, 0x100),
         Some(0x77FB_DDA0_D100)
      );
      assert_eq!(runtime_address(&sample(), LIB, 0xFFFF_FFFF), None);
      assert_eq!(
         describe_code(&sample(), 0x77FB_DDA6_5FC0),
         Some(CodeLocation::File {
            path:   LIB,
            offset: 0x5_8FC0,
         })
      );
      assert!(describe_code(&sample(), 0x77FB_DDA0_D100).is_none());
      assert!(describe_code(&sample(), 0x1234).is_none());
      assert_eq!(
         runtime_address(&sample(), "/system/lib64/libfoo.so", 0x5_8FC0),
         None
      );
   }
}
