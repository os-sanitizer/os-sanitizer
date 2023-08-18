use clru::CLruCache;
use libc::pid_t;
use log::warn;
use std::cell::RefCell;
use std::num::NonZeroUsize;
use std::path::Path;
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::{
    cmp::Ordering, ffi::OsStr, fs, io, num::ParseIntError, os::unix::ffi::OsStrExt, path::PathBuf,
    str::Utf8Error,
};
use thiserror::Error;
use tokio::runtime::Handle;
use wholesym::{FrameDebugInfo, FramesLookupResult, SymbolManager, SymbolManagerConfig, SymbolMap};

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

type SymbolMapping = Option<SymbolMap>;
type GlobalSymbolManager = Rc<SymbolManager>;
type GlobalSymbolCache = Rc<RefCell<CLruCache<PathBuf, Rc<SymbolMapping>>>>;

pub struct FileOffsetResolver {
    handle: Handle,
    procmap: ProcMap,
    manager: GlobalSymbolManager,
    global: GlobalSymbolCache,
}

impl FileOffsetResolver {
    fn new(
        handle: Handle,
        procmap: ProcMap,
        manager: GlobalSymbolManager,
        global: GlobalSymbolCache,
    ) -> Self {
        FileOffsetResolver {
            handle,
            procmap,
            manager,
            global,
        }
    }

    pub fn resolve_symbol(&self, addr: u64) -> Option<(PathBuf, Option<Vec<FrameDebugInfo>>)> {
        let Some(entry) = self.procmap.entry_for(addr) else {
            return None;
        };

        let mut wlock = self.global.borrow_mut();
        if let Some(path) = entry.path().and_then(|p| p.canonicalize().ok()) {
            // avoid looking up private directories
            if path.is_absolute() && !path.starts_with("/home") {
                let mapping = {
                    if let Some(mapping) = wlock.get(&path) {
                        mapping
                    } else {
                        let _ = Command::new("debuginfod-find")
                            .arg("debuginfo")
                            .arg(&path)
                            .stdin(Stdio::null())
                            .stderr(Stdio::null())
                            .stdout(Stdio::null())
                            .status();
                        let maybe_map = match self
                            .handle
                            .block_on(self.manager.load_symbol_map_for_binary_at_path(&path, None))
                        {
                            Ok(map) => Some(map),
                            Err(e) => {
                                warn!(
                                    "Encountered error while loading {}: {e}",
                                    path.to_string_lossy()
                                );
                                None
                            }
                        };
                        let maybe_map = Rc::new(maybe_map);

                        let _ = wlock.put(path.clone(), maybe_map);
                        wlock.get(&path).expect("just inserted")
                    }
                };

                if let Some(mapping) = mapping.as_ref() {
                    // offset into the range we found
                    let Some(offset_in_range) = addr.checked_sub(entry.address()) else {
                        unreachable!("guaranteed by lookup above")
                    };
                    // offset into the file
                    let Some(raw_offset) = entry.offset().checked_add(offset_in_range) else {
                        unreachable!("unimaginably large offset")
                    };

                    if let Some(info) = mapping.lookup_offset(raw_offset) {
                        match info.frames {
                            FramesLookupResult::Available(frames) => {
                                return Some((path, Some(frames)))
                            }
                            FramesLookupResult::External(ext) => {
                                return Some((
                                    path,
                                    self.handle.block_on(
                                        self.manager
                                            .lookup_external(&mapping.symbol_file_origin(), &ext),
                                    ),
                                ));
                            }
                            FramesLookupResult::Unavailable => {}
                        }
                    }
                }
                return Some((path, None));
            }
        }
        None
    }
}

#[derive(Clone)]
pub struct FileOffsetResolverFactory {
    handle: Handle,
    manager: GlobalSymbolManager,
    global: GlobalSymbolCache,
}

impl FileOffsetResolverFactory {
    pub fn new(handle: Handle, cache_size: NonZeroUsize) -> Self {
        let mut config = SymbolManagerConfig::default().use_debuginfod(false);

        if let Some(home) = std::env::var_os("HOME") {
            let cache = Path::new(&home).join(".cache/debuginfod_client");
            if cache.exists() {
                config = SymbolManagerConfig::default()
                    .use_debuginfod(true)
                    .debuginfod_cache_dir_if_not_installed(cache)
            }
        }
        Self {
            handle,
            manager: Rc::new(SymbolManager::with_config(config)),
            global: Rc::new(RefCell::new(CLruCache::new(cache_size))),
        }
    }

    pub fn resolver_for(&self, procmap: ProcMap) -> FileOffsetResolver {
        FileOffsetResolver::new(
            self.handle.clone(),
            procmap,
            self.manager.clone(),
            self.global.clone(),
        )
    }
}
