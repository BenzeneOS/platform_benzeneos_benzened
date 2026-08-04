// Copyright (C) 2026 Amaan Qureshi <contact@amaanq.com>
// SPDX-License-Identifier: Apache-2.0

//! Turns a symbol name into the file offset a uprobe needs.

use core::fmt::Write as _;
use std::io;

use elf::{
   ElfBytes,
   abi::{
      PT_LOAD,
      SHN_UNDEF,
      STT_GNU_IFUNC,
   },
   endian::AnyEndian,
};

fn err(msg: &str) -> io::Error {
   io::Error::new(io::ErrorKind::InvalidData, msg.to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
   pub offset: u64,
   pub vaddr:  u64,
   pub filesz: u64,
}

/// A symbol's `st_value` is a virtual address in the object's own address
/// space. uprobes want a file offset, so it has to be walked back through
/// whichever `PT_LOAD` segment maps it.
pub fn vaddr_to_file_offset(segments: &[Segment], vaddr: u64) -> Option<u64> {
   segments.iter().find_map(|seg| {
      let end = seg.vaddr.checked_add(seg.filesz)?;
      let within = (seg.vaddr..end)
         .contains(&vaddr)
         .then(|| vaddr - seg.vaddr)?;
      seg.offset.checked_add(within)
   })
}

/// Reads `PT_LOAD` entries straight out of the ELF header, without the section
/// table. `minimal_parse` reads sections, which sit at the end of the file, so
/// it fails on the truncated head we read for every mapped library and the
/// whole layout ends up empty.
#[must_use]
pub fn segments_from_head(data: &[u8]) -> Option<Vec<Segment>> {
   const ELFCLASS64: u8 = 2;
   const ELFDATA2LSB: u8 = 1;

   let word = |at: usize| -> Option<u64> {
      data
         .get(at..at.checked_add(8)?)
         .and_then(|bytes| bytes.try_into().ok())
         .map(u64::from_le_bytes)
   };
   let half = |at: usize| -> Option<u16> {
      data
         .get(at..at.checked_add(2)?)
         .and_then(|bytes| bytes.try_into().ok())
         .map(u16::from_le_bytes)
   };

   if data.get(..4)? != b"\x7fELF" || *data.get(4)? != ELFCLASS64 || *data.get(5)? != ELFDATA2LSB {
      return None;
   }
   let phoff = usize::try_from(word(0x20)?).ok()?;
   let phentsize = usize::from(half(0x36)?);
   let phnum = usize::from(half(0x38)?);
   if phentsize < 56 {
      return None;
   }

   let mut out = Vec::new();
   for index in 0..phnum {
      let at = phoff.checked_add(index.checked_mul(phentsize)?)?;
      let kind = data
         .get(at..at.checked_add(4)?)
         .and_then(|bytes| bytes.try_into().ok())
         .map(u32::from_le_bytes)?;
      if kind != PT_LOAD {
         continue;
      }
      out.push(Segment {
         offset: word(at.checked_add(8)?)?,
         vaddr:  word(at.checked_add(16)?)?,
         filesz: word(at.checked_add(32)?)?,
      });
   }
   Some(out)
}

/// The inverse of `vaddr_to_file_offset`. A caller is only useful if it can be
/// named as the address a disassembler shows, which is also what `--vaddr`
/// takes. The two coincide whenever the first `PT_LOAD` sits at offset 0 vaddr
/// 0, which is common enough to hide the difference and not a rule.
pub fn file_offset_to_vaddr(segments: &[Segment], offset: u64) -> Option<u64> {
   segments.iter().find_map(|seg| {
      let end = seg.offset.checked_add(seg.filesz)?;
      let within = (seg.offset..end)
         .contains(&offset)
         .then(|| offset - seg.offset)?;
      seg.vaddr.checked_add(within)
   })
}

/// Scans a `PT_NOTE` payload rather than walking it entry by entry. Walking is
/// the documented layout, but these libraries declare 152 bytes of zeros ahead
/// of the real note, and a zero header has no length, so a strict walk advances
/// twelve bytes at a time and steps over the note it is looking for.
fn build_id_from_notes(notes: &[u8]) -> Option<String> {
   const NT_GNU_BUILD_ID: u32 = 3;
   const GNU: &[u8] = b"GNU\0";
   const HEADER: usize = 12;

   let word = |at: usize| -> Option<u32> {
      notes
         .get(at..at + 4)
         .and_then(|bytes| bytes.try_into().ok())
         .map(u32::from_le_bytes)
   };

   for at in (0..notes.len().saturating_sub(HEADER)).step_by(4) {
      if word(at + 8) != Some(NT_GNU_BUILD_ID) {
         continue;
      }
      let namesz = word(at)? as usize;
      let descsz = word(at + 4)? as usize;
      // A build id is a hash, so anything outside this range is a false positive
      // from padding that happens to hold a three.
      if namesz != GNU.len() || !(8..=64).contains(&descsz) {
         continue;
      }
      let name_at = at + HEADER;
      if notes.get(name_at..name_at + namesz) != Some(GNU) {
         continue;
      }
      let desc_at = name_at + namesz.next_multiple_of(4);
      let desc = notes.get(desc_at..desc_at.checked_add(descsz)?)?;
      let mut hex = String::with_capacity(descsz * 2);
      for byte in desc {
         write!(hex, "{byte:02x}").ok()?;
      }
      return Some(hex);
   }
   None
}

pub struct Elf<'data> {
   file: ElfBytes<'data, AnyEndian>,
   data: &'data [u8],
}

impl<'data> Elf<'data> {
   pub fn parse(data: &'data [u8]) -> io::Result<Self> {
      let file = ElfBytes::<AnyEndian>::minimal_parse(data)
         .map_err(|error| err(&format!("not a usable ELF file: {error}")))?;
      Ok(Self { file, data })
   }

   pub fn segments(&self) -> io::Result<Vec<Segment>> {
      let segments = self
         .file
         .segments()
         .ok_or_else(|| err("no program headers"))?;
      Ok(segments
         .iter()
         .filter(|phdr| phdr.p_type == PT_LOAD)
         .map(|phdr| {
            Segment {
               offset: phdr.p_offset,
               vaddr:  phdr.p_vaddr,
               filesz: phdr.p_filesz,
            }
         })
         .collect())
   }

   /// Prefers `.dynsym`, since stripped system libraries only have that one.
   /// Imported symbols are skipped because their `st_value` is not an address
   /// in this object and would resolve to an unrelated instruction.
   pub fn symbol_value(&self, name: &str) -> io::Result<Option<(u64, u8)>> {
      for table in [self.file.dynamic_symbol_table(), self.file.symbol_table()] {
         let Some((symtab, strtab)) =
            table.map_err(|error| err(&format!("bad symbol table: {error}")))?
         else {
            continue;
         };
         for sym in symtab.iter() {
            if sym.st_value == 0 || sym.st_shndx == SHN_UNDEF {
               continue;
            }
            if strtab.get(sym.st_name as usize).unwrap_or_default() == name {
               return Ok(Some((sym.st_value, sym.st_symtype())));
            }
         }
      }
      Ok(None)
   }

   /// Function entry points recovered from `.eh_frame_hdr`. A packed or
   /// stripped library exports almost nothing, but unwind tables survive
   /// both because C++ exceptions need them at runtime, so this is usually
   /// the only way to enumerate what is in a library at all.
   ///
   /// # Errors
   ///
   /// Returns an error if the section is absent or uses an encoding other than
   /// the `pcrel|sdata4` / `udata4` / `datarel|sdata4` triple every toolchain
   /// actually emits.
   pub fn function_entries(&self) -> io::Result<Vec<u64>> {
      const EH_FRAME_PTR_PCREL_SDATA4: u8 = 0x1B;
      const FDE_COUNT_UDATA4: u8 = 0x03;
      const TABLE_DATAREL_SDATA4: u8 = 0x3B;

      let (bytes, table_base) = self.eh_frame_hdr()?;

      let encodings = bytes
         .get(1..4)
         .ok_or_else(|| err(".eh_frame_hdr too short"))?;
      if encodings
         != [
            EH_FRAME_PTR_PCREL_SDATA4,
            FDE_COUNT_UDATA4,
            TABLE_DATAREL_SDATA4,
         ]
      {
         return Err(err("unsupported .eh_frame_hdr encoding"));
      }

      let count_bytes = bytes.get(8..12).ok_or_else(|| err("truncated fde count"))?;
      let count_word = u32::from_le_bytes(
         count_bytes
            .try_into()
            .map_err(|_ignored| err("bad count"))?,
      );
      let count = usize::try_from(count_word).map_err(|_ignored| err("fde count is too large"))?;
      let table_len = count
         .checked_mul(8)
         .ok_or_else(|| err("fde table size overflows"))?;
      let table_end = 12_usize
         .checked_add(table_len)
         .ok_or_else(|| err("fde table size overflows"))?;
      let table = bytes
         .get(12..table_end)
         .ok_or_else(|| err("truncated fde table"))?;

      let mut entries = Vec::with_capacity(count);
      for slot in table.as_chunks::<8>().0 {
         let rel = i32::from_le_bytes(slot[..4].try_into().map_err(|_ignored| err("bad entry"))?);
         // Table entries are relative to the start of the section itself.
         let addr = table_base
            .checked_add_signed(i64::from(rel))
            .ok_or_else(|| err("fde address is out of range"))?;
         entries.push(addr);
      }
      entries.sort_unstable();
      entries.dedup();
      Ok(entries)
   }

   /// The build id from `.note.gnu.build-id`, found through `PT_NOTE` so it
   /// works on a memory dump too. It is what keys an artifact to one exact
   /// build, because every offset in that artifact is meaningless against a
   /// different one.
   pub fn build_id(&self) -> Option<String> {
      const PT_NOTE: u32 = 4;

      let segments = self.file.segments()?;
      for phdr in segments.iter().filter(|phdr| phdr.p_type == PT_NOTE) {
         let start = usize::try_from(phdr.p_offset).ok()?;
         let len = usize::try_from(phdr.p_filesz).ok()?;
         let notes = self.data.get(start..start.checked_add(len)?)?;
         if let Some(id) = build_id_from_notes(notes) {
            return Some(id);
         }
      }
      None
   }

   /// A dump of a process's memory has no section table, because section
   /// headers are not inside any `PT_LOAD`, so the program header is the
   /// only way to find the unwind table in one.
   fn eh_frame_hdr(&self) -> io::Result<(&'data [u8], u64)> {
      const PT_GNU_EH_FRAME: u32 = 0x6474_E550;

      let unwind = self
         .file
         .segments()
         .and_then(|segments| segments.iter().find(|phdr| phdr.p_type == PT_GNU_EH_FRAME));
      if let Some(phdr) = unwind {
         let start =
            usize::try_from(phdr.p_offset).map_err(|_ignored| err("bad segment offset"))?;
         let len = usize::try_from(phdr.p_filesz).map_err(|_ignored| err("bad segment size"))?;
         let bytes = self
            .data
            .get(start..start.saturating_add(len))
            .ok_or_else(|| err("PT_GNU_EH_FRAME lies outside the file"))?;
         return Ok((bytes, phdr.p_vaddr));
      }

      let header = self
         .file
         .section_header_by_name(".eh_frame_hdr")
         .map_err(|error| err(&format!("bad section table: {error}")))?
         .ok_or_else(|| err("no .eh_frame_hdr, so functions cannot be enumerated"))?;
      let (bytes, _) = self
         .file
         .section_data(&header)
         .map_err(|error| err(&format!("unreadable .eh_frame_hdr: {error}")))?;
      Ok((bytes, header.sh_addr))
   }

   pub fn probe_offset(&self, symbol: &str) -> io::Result<u64> {
      let (value, symtype) = self
         .symbol_value(symbol)?
         .ok_or_else(|| err("symbol not found"))?;
      // An ifunc's st_value is a resolver that runs once at relocation, so a
      // probe there would never see a call. Fail loudly rather than sit silent.
      if symtype == STT_GNU_IFUNC {
         return Err(err(
            "symbol is an ifunc, so its address is chosen at relocation time; probe the resolved \
             implementation instead",
         ));
      }
      let segments = self.segments()?;
      vaddr_to_file_offset(&segments, value)
         .ok_or_else(|| err("symbol is not inside any PT_LOAD segment"))
   }
}

#[cfg(test)]
mod tests {
   #![expect(clippy::unwrap_used, reason = "a panic is the failure signal in tests")]

   use super::*;

   /// Every mapped library is read as a truncated head, and a real library
   /// keeps its section table at the end, so a parser that needs sections
   /// finds nothing and the caller of every sample goes unnamed.
   #[test]
   fn program_headers_are_readable_without_the_section_table() {
      let mut head = vec![0_u8; 0x400];
      head[..4].copy_from_slice(b"\x7fELF");
      head[4] = 2; // ELFCLASS64
      head[5] = 1; // little endian
      head[0x20..0x28].copy_from_slice(&0x40_u64.to_le_bytes()); // e_phoff
      head[0x36..0x38].copy_from_slice(&56_u16.to_le_bytes()); // e_phentsize
      head[0x38..0x3A].copy_from_slice(&2_u16.to_le_bytes()); // e_phnum

      let mut put = |at: usize, kind: u32, off: u64, vaddr: u64, filesz: u64| {
         head[at..at + 4].copy_from_slice(&kind.to_le_bytes());
         head[at + 8..at + 16].copy_from_slice(&off.to_le_bytes());
         head[at + 16..at + 24].copy_from_slice(&vaddr.to_le_bytes());
         head[at + 32..at + 40].copy_from_slice(&filesz.to_le_bytes());
      };
      put(0x40, PT_LOAD, 0, 0, 0x7_BA78);
      put(0x78, PT_LOAD, 0x7_BA80, 0x7_FA80, 0x9_4028);

      let segments = segments_from_head(&head).unwrap();
      assert_eq!(segments.len(), 2);
      // The address a real caller landed at, which resolved to nothing before.
      assert_eq!(file_offset_to_vaddr(&segments, 0x10_D1E4), Some(0x11_11E4));
   }

   /// The real `PT_NOTE` payload from the packed target, which leads with 152
   /// zero bytes. A strict entry walk lands on 144 then 156 and misses the
   /// note at 152, so this fixture is the exact shape that broke the first
   /// implementation.
   #[test]
   fn a_build_id_is_found_past_zero_padding() {
      let mut notes = vec![0_u8; 152];
      notes.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]); // namesz
      notes.extend_from_slice(&[0x14, 0x00, 0x00, 0x00]); // descsz
      notes.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]); // NT_GNU_BUILD_ID
      notes.extend_from_slice(b"GNU\0");
      notes.extend_from_slice(&[
         0x1A, 0xE6, 0xB6, 0xD6, 0x03, 0xE8, 0x6A, 0xB8, 0x1F, 0xD2, 0xD7, 0x95, 0x9A, 0xBF, 0x34,
         0x46, 0x1E, 0x7D, 0xBA, 0x9B,
      ]);

      assert_eq!(
         build_id_from_notes(&notes).unwrap(),
         "1ae6b6d603e86ab81fd2d7959abf34461e7dba9b"
      );
      assert!(build_id_from_notes(&[0_u8; 188]).is_none());
   }

   /// Deliberately uses a segment whose offset and vaddr differ. A library with
   /// its first `PT_LOAD` at offset 0 vaddr 0 makes the two interchangeable,
   /// and a fixture like that would pass even with one direction wired to
   /// the other.
   #[test]
   fn an_offset_and_a_virtual_address_round_trip_through_each_other() {
      let segments = [
         Segment {
            offset: 0x0,
            vaddr:  0x0,
            filesz: 0x1000,
         },
         Segment {
            offset: 0x1000,
            vaddr:  0x1_2000,
            filesz: 0x800,
         },
      ];

      let vaddr = 0x1_2400_u64;
      let offset = vaddr_to_file_offset(&segments, vaddr).unwrap();
      assert_eq!(offset, 0x1400_u64);
      assert_ne!(offset, vaddr, "the fixture must not let the two coincide");
      assert_eq!(file_offset_to_vaddr(&segments, offset), Some(vaddr));

      // Past every segment there is nothing to name, so a caller keeps the raw
      // offset rather than being reported as an address that does not exist.
      assert_eq!(file_offset_to_vaddr(&segments, 0x9000), None);
      assert_eq!(vaddr_to_file_offset(&segments, 0x9_0000), None);
   }
}
