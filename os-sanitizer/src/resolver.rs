// Copyright (c) OS-Sanitizer developers, 2024, licensed under the EUPL-1.2-or-later.
//
// See LICENSE at the root of this repository (or a legal translation in LICENSE-translations).

use libc::pid_t;
use std::path::Path;
use std::{
    cmp::Ordering, ffi::OsStr, fs, io, num::ParseIntError, os::unix::ffi::OsStrExt, path::PathBuf,
    str::Utf8Error,
};
use thiserror::Error;

// TODO use the aya api for this when it is merged/made public
// --- copy/pasted, then modified from: https://github.com/aya-rs/aya/pull/719 ---

#[derive(Debug, Error)]
pub enum ProcMapError {
    /// Unable to read /proc/pid/maps.
    #[error(transparent)]
    Read(#[from] io::Error),

    /// Error parsing an integer.
    #[error(transparent)]
    ParseInt(#[from] ParseIntError),

    /// Error parsing a string component from the process map.
    #[error(transparent)]
    ParseStr(#[from] Utf8Error),

    /// Error parsing a line of /proc/pid/maps.
    #[error("proc map entry parse error")]
    Parse,
}

/// The memory maps of a process.
///
/// This is read from /proc/`pid`/maps.
///
/// The information here may be used to resolve addresses to paths.
pub struct ProcMap {
    // This is going to be used by USDT probes to resolve virtual addresses to
    // library paths.
    entries: Vec<ProcMapEntry>,
}

impl ProcMap {
    /// Create a new [`ProcMap`] from a given pid.
    pub fn new(pid: pid_t) -> Result<Self, ProcMapError> {
        let maps_file = format!("/proc/{}/maps", pid);
        let data = fs::read(maps_file).map_err(ProcMapError::Read)?;
        Self::try_from(data.as_slice())
    }

    pub fn entries(&self) -> &[ProcMapEntry] {
        &self.entries
    }

    fn entry_for(&self, addr: u64) -> Option<&ProcMapEntry> {
        let Ok(entry) = self
            .entries()
            .binary_search_by(|entry| match entry.address().cmp(&addr) {
                Ordering::Less => match entry.address_end().cmp(&addr) {
                    Ordering::Greater => Ordering::Equal,
                    Ordering::Less | Ordering::Equal => Ordering::Less,
                },
                o @ (Ordering::Equal | Ordering::Greater) => o,
            })
        else {
            return None;
        };
        Some(&self.entries[entry])
    }
}

impl TryFrom<&[u8]> for ProcMap {
    type Error = ProcMapError;

    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        let mut entries = vec![];
        for line in s.split(|&c| c == b'\n') {
            if !line.is_empty() {
                let entry = ProcMapEntry::try_from(line)?;
                entries.push(entry);
            }
        }
        Ok(ProcMap { entries })
    }
}

/// A entry that has been parsed from /proc/`pid`/maps.
///
/// This contains information about a mapped portion of memory
/// for the process, ranging from address to address_end.
#[derive(Debug)]
pub struct ProcMapEntry {
    address: u64,
    address_end: u64,
    _perms: String,
    offset: u64,
    _dev: String,
    _inode: u32,
    path: Option<PathBuf>,
}

impl ProcMapEntry {
    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn address_end(&self) -> u64 {
        self.address_end
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn path(&self) -> Option<&PathBuf> {
        self.path.as_ref()
    }
}

impl TryFrom<&[u8]> for ProcMapEntry {
    type Error = ProcMapError;

    fn try_from(line: &[u8]) -> Result<Self, Self::Error> {
        let mut parts = line
            .split(|c| c.is_ascii_whitespace())
            .filter(|s| !s.is_empty());
        let mut next = || parts.next().ok_or(ProcMapError::Parse);
        let addresses = next()?;
        let (address, address_end) = addresses
            .iter()
            .enumerate()
            .find_map(|(i, &c)| (c == b'-').then_some(i))
            .ok_or(ProcMapError::Parse)
            .map(|i| addresses.split_at(i))
            .and_then(|(start, end)| {
                let start = u64::from_str_radix(core::str::from_utf8(start)?, 16)?;
                let end = u64::from_str_radix(core::str::from_utf8(&end[1..])?, 16)?;
                Ok((start, end))
            })?;
        let perms = core::str::from_utf8(next()?)?;
        let offset = u64::from_str_radix(core::str::from_utf8(next()?)?, 16)?;
        let dev = core::str::from_utf8(next()?)?;
        let inode = core::str::from_utf8(next()?)?.parse()?;
        let path = parts.next().and_then(|s| {
            s.starts_with(&[b'/'])
                .then(|| PathBuf::from(OsStr::from_bytes(s)))
        });
        Ok(ProcMapEntry {
            address,
            address_end,
            _perms: perms.to_string(),
            offset,
            _dev: dev.to_string(),
            _inode: inode,
            path,
        })
    }
}

// --- end of copy/pasted section

pub struct ProcMapOffsetResolver<'a> {
    procmap: &'a ProcMap,
}

impl<'a> ProcMapOffsetResolver<'a> {
    pub fn resolve_file_offset(&self, addr: u64) -> Option<(&Path, u64)> {
        if let Some(entry) = self.procmap.entry_for(addr) {
            if let Some(path) = entry.path() {
                // offset into the range we found
                let Some(offset_in_range) = addr.checked_sub(entry.address()) else {
                    unreachable!("guaranteed by lookup above")
                };
                // offset into the file
                let Some(raw_offset) = entry.offset().checked_add(offset_in_range) else {
                    unreachable!("unimaginably large offset")
                };

                return Some((path, raw_offset));
            }
        }
        None
    }
}

impl<'a> From<&'a ProcMap> for ProcMapOffsetResolver<'a> {
    fn from(procmap: &'a ProcMap) -> Self {
        Self { procmap }
    }
}
