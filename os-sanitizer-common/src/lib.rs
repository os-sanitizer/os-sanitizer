#![cfg_attr(not(feature = "user"), no_std)]

#[cfg(feature = "user")]
use core::mem::size_of;
use core::mem::size_of_val;

pub const EXECUTABLE_LEN: usize = 16;
pub const WRITTEN_LEN: usize = 64;
pub const FILENAME_LEN: usize = 64;
pub const TEMPLATE_LEN: usize = 64;

pub const SERIALIZED_SIZE: usize = 256;

#[repr(u32)]
pub enum OsSanitizerError {
    MissingArg(&'static str, usize) = 1,
    CouldntReadKernel(&'static str, u64, usize),
    CouldntReadUser(&'static str, u64, usize),
    CouldntRecoverStack(&'static str, i64),
    CouldntGetPath(&'static str, i64),
    CouldntGetComm(&'static str, i64),
    CouldntAccessBuffer(&'static str),
    InvalidUtf8(&'static str),
    OutOfSpace(&'static str),
    RacefulAccess(&'static str),
    UnexpectedNull(&'static str),
    SerialisationError(&'static str),
    CouldntFindVma(&'static str, i64, u32, u32),
    ImpossibleFile,
    Unreachable(&'static str),
}

#[derive(Copy, Clone)]
pub enum ToctouVariant {
    Access,
    Stat,
    Statx,
}

#[cfg(feature = "user")]
impl std::fmt::Display for ToctouVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToctouVariant::Access => f.write_str("access"),
            ToctouVariant::Stat => f.write_str("stat"),
            ToctouVariant::Statx => f.write_str("statx"),
        }
    }
}

#[derive(Copy, Clone)]
pub enum OpenViolation {
    Perms,
    Toctou(ToctouVariant),
}

#[derive(Copy, Clone)]
pub enum CopyViolation {
    Strlen,
    Malloc,
}

#[derive(Copy, Clone)]
pub enum FixedMmapViolation {
    HintUsed,
    FixedMmapUnmapped,
    FixedMmapBadProt,
}

#[derive(Copy, Clone, Ord, PartialOrd, PartialEq, Eq)]
pub enum SnprintfViolation {
    PossibleLeak,
    DefiniteLeak,
}

#[derive(Copy, Clone)]
pub enum OsSanitizerReport {
    RwxVma {
        executable: [u8; EXECUTABLE_LEN],
        pid_tgid: u64,
        stack_id: u64,
        start: u64,
        end: u64,
    },
    PrintfMutability {
        executable: [u8; EXECUTABLE_LEN],
        pid_tgid: u64,
        stack_id: u64,
        template_param: u64,
        template: [u8; TEMPLATE_LEN],
    },
    SystemMutability {
        executable: [u8; EXECUTABLE_LEN],
        pid_tgid: u64,
        stack_id: u64,
        command_param: u64,
        command: [u8; TEMPLATE_LEN],
    },
    SystemAbsolute {
        executable: [u8; EXECUTABLE_LEN],
        pid_tgid: u64,
        stack_id: u64,
        command_param: u64,
        command: [u8; TEMPLATE_LEN],
    },
    FilePointerLocking {
        executable: [u8; EXECUTABLE_LEN],
        pid_tgid: u64,
        stack_id: u64,
    },
    Sprintf {
        executable: [u8; EXECUTABLE_LEN],
        pid_tgid: u64,
        stack_id: u64,
        dest: u64,
    },
    Snprintf {
        executable: [u8; EXECUTABLE_LEN],
        pid_tgid: u64,
        stack_id: u64,
        srcptr: u64,
        size: u64,
        computed: u64,
        count: u64,
        kind: SnprintfViolation,
        index: u64,
    },
    Strcpy {
        executable: [u8; EXECUTABLE_LEN],
        pid_tgid: u64,
        stack_id: u64,
        dest: u64,
        src: u64,
        len_checked: bool,
    },
    Strncpy {
        executable: [u8; EXECUTABLE_LEN],
        pid_tgid: u64,
        stack_id: u64,
        len: u64,
        allocated: u64,
        dest: u64,
        src: u64,
        variant: CopyViolation,
    },
    Memcpy {
        executable: [u8; EXECUTABLE_LEN],
        pid_tgid: u64,
        stack_id: u64,
        len: u64,
        allocated: u64,
        dest: u64,
        src: u64,
        variant: CopyViolation,
    },
    Open {
        executable: [u8; EXECUTABLE_LEN],
        pid_tgid: u64,
        stack_id: u64,
        i_mode: u64,
        filename: [u8; FILENAME_LEN],
        variant: OpenViolation,
    },
    Access {
        executable: [u8; EXECUTABLE_LEN],
        pid_tgid: u64,
        stack_id: u64,
    },
    Gets {
        executable: [u8; EXECUTABLE_LEN],
        pid_tgid: u64,
        stack_id: u64,
    },
    FixedMmap {
        executable: [u8; EXECUTABLE_LEN],
        pid_tgid: u64,
        stack_id: u64,
        protection: u64,
        variant: FixedMmapViolation,
    },
}

trait SerialisedContent {
    #[cfg(feature = "user")]
    fn read(&mut self, content: &mut [u8]) -> Result<&mut Self, OsSanitizerError>;
    fn write(&mut self, content: &[u8]) -> Result<&mut Self, OsSanitizerError>;

    #[cfg(feature = "user")]
    fn read_u64(&mut self, content: &mut u64) -> Result<&mut Self, OsSanitizerError> {
        let mut buf = [0u8; size_of::<u64>()];
        let next = self.read(&mut buf)?;
        *content = u64::from_be_bytes(buf);
        Ok(next)
    }
}

impl SerialisedContent for [u8] {
    #[cfg(feature = "user")]
    fn read(&mut self, content: &mut [u8]) -> Result<&mut Self, OsSanitizerError> {
        content
            .copy_from_slice(self.get_mut(..content.len()).ok_or({
                OsSanitizerError::SerialisationError("not enough space to serialise")
            })?);
        self.get_mut(content.len()..).ok_or({
            OsSanitizerError::SerialisationError("not enough space to continue serialising")
        })
    }

    fn write(&mut self, content: &[u8]) -> Result<&mut Self, OsSanitizerError> {
        let dest = self
            .get_mut(..content.len())
            .ok_or(OsSanitizerError::SerialisationError(
                "not enough space to serialise",
            ))?;
        unsafe {
            // we use unsafe here because copy_from_slice may "panic"
            dest.as_mut_ptr().copy_from(content.as_ptr(), content.len());
        }
        self.get_mut(content.len()..).ok_or({
            OsSanitizerError::SerialisationError("not enough space to continue serialising")
        })
    }
}

impl OsSanitizerReport {
    #[inline(always)]
    pub fn serialise_into(&self, buf: &mut [u8]) -> Result<(), OsSanitizerError> {
        let buf = buf.write(&[match self {
            OsSanitizerReport::RwxVma { .. } => 0u8,
            OsSanitizerReport::PrintfMutability { .. } => 1,
            OsSanitizerReport::SystemMutability { .. } => 2,
            OsSanitizerReport::SystemAbsolute { .. } => 3,
            OsSanitizerReport::FilePointerLocking { .. } => 4,
            OsSanitizerReport::Sprintf { .. } => 5,
            OsSanitizerReport::Snprintf { .. } => 6,
            OsSanitizerReport::Strcpy { .. } => 7,
            OsSanitizerReport::Strncpy { .. } => 8,
            OsSanitizerReport::Memcpy { .. } => 9,
            OsSanitizerReport::Open { .. } => 10,
            OsSanitizerReport::Access { .. } => 11,
            OsSanitizerReport::Gets { .. } => 12,
            OsSanitizerReport::FixedMmap { .. } => 13,
        }])?;
        let buf = match self {
            OsSanitizerReport::RwxVma {
                executable,
                pid_tgid,
                stack_id,
                ..
            }
            | OsSanitizerReport::PrintfMutability {
                executable,
                pid_tgid,
                stack_id,
                ..
            }
            | OsSanitizerReport::SystemMutability {
                executable,
                pid_tgid,
                stack_id,
                ..
            }
            | OsSanitizerReport::SystemAbsolute {
                executable,
                pid_tgid,
                stack_id,
                ..
            }
            | OsSanitizerReport::FilePointerLocking {
                executable,
                pid_tgid,
                stack_id,
            }
            | OsSanitizerReport::Sprintf {
                executable,
                pid_tgid,
                stack_id,
                ..
            }
            | OsSanitizerReport::Snprintf {
                executable,
                pid_tgid,
                stack_id,
                ..
            }
            | OsSanitizerReport::Strcpy {
                executable,
                pid_tgid,
                stack_id,
                ..
            }
            | OsSanitizerReport::Strncpy {
                executable,
                pid_tgid,
                stack_id,
                ..
            }
            | OsSanitizerReport::Memcpy {
                executable,
                pid_tgid,
                stack_id,
                ..
            }
            | OsSanitizerReport::Open {
                executable,
                pid_tgid,
                stack_id,
                ..
            }
            | OsSanitizerReport::Access {
                executable,
                pid_tgid,
                stack_id,
            }
            | OsSanitizerReport::Gets {
                executable,
                pid_tgid,
                stack_id,
            }
            | OsSanitizerReport::FixedMmap {
                executable,
                pid_tgid,
                stack_id,
                ..
            } => buf
                .write(executable)?
                .write(&pid_tgid.to_be_bytes())?
                .write(&stack_id.to_be_bytes())?,
        };
        match self {
            OsSanitizerReport::RwxVma { start, end, .. } => {
                buf.write(&start.to_be_bytes())?.write(&end.to_be_bytes())?;
            }
            OsSanitizerReport::PrintfMutability {
                template_param,
                template,
                ..
            } => {
                buf.write(&template_param.to_be_bytes())?.write(template)?;
            }
            OsSanitizerReport::SystemMutability {
                command_param,
                command,
                ..
            }
            | OsSanitizerReport::SystemAbsolute {
                command_param,
                command,
                ..
            } => {
                buf.write(&command_param.to_be_bytes())?.write(command)?;
            }
            OsSanitizerReport::FilePointerLocking { .. } => {}
            OsSanitizerReport::Sprintf { dest, .. } => {
                buf.write(&dest.to_be_bytes())?;
            }
            OsSanitizerReport::Snprintf {
                srcptr,
                size,
                computed,
                count,
                kind,
                index,
                ..
            } => {
                let buf = buf
                    .write(&srcptr.to_be_bytes())?
                    .write(&size.to_be_bytes())?
                    .write(&computed.to_be_bytes())?
                    .write(&count.to_be_bytes())?;
                buf[0] = match kind {
                    SnprintfViolation::DefiniteLeak => 1,
                    SnprintfViolation::PossibleLeak => 0,
                };
                let buf = &mut buf[1..];
                buf.write(&index.to_be_bytes())?;
            }
            OsSanitizerReport::Strcpy {
                dest,
                src,
                len_checked,
                ..
            } => {
                let buf = buf.write(&dest.to_be_bytes())?.write(&src.to_be_bytes())?;
                buf[0] = if *len_checked { 1 } else { 0 };
            }
            OsSanitizerReport::Strncpy {
                len,
                allocated,
                dest,
                src,
                variant,
                ..
            }
            | OsSanitizerReport::Memcpy {
                len,
                allocated,
                dest,
                src,
                variant,
                ..
            } => {
                let buf = buf
                    .write(&len.to_be_bytes())?
                    .write(&allocated.to_be_bytes())?
                    .write(&dest.to_be_bytes())?
                    .write(&src.to_be_bytes())?;
                buf[0] = match variant {
                    CopyViolation::Strlen => 0,
                    CopyViolation::Malloc => 1,
                };
            }
            OsSanitizerReport::Open {
                i_mode,
                filename,
                variant,
                ..
            } => {
                let buf = buf.write(&i_mode.to_be_bytes())?.write(filename)?;
                buf[0] = match variant {
                    OpenViolation::Perms => 0,
                    OpenViolation::Toctou(toctou) => match toctou {
                        ToctouVariant::Access => 1,
                        ToctouVariant::Stat => 2,
                        ToctouVariant::Statx => 3,
                    },
                };
            }
            OsSanitizerReport::Access { .. } => {}
            OsSanitizerReport::Gets { .. } => {}
            OsSanitizerReport::FixedMmap {
                protection,
                variant,
                ..
            } => {
                let buf = buf.write(&protection.to_be_bytes())?;
                buf[0] = match variant {
                    FixedMmapViolation::HintUsed => 0,
                    FixedMmapViolation::FixedMmapUnmapped => 1,
                    FixedMmapViolation::FixedMmapBadProt => 2,
                }
            }
        }
        Ok(())
    }
}

#[cfg(feature = "user")]
impl TryFrom<[u8; SERIALIZED_SIZE]> for OsSanitizerReport {
    type Error = OsSanitizerError;

    fn try_from(mut value: [u8; SERIALIZED_SIZE]) -> Result<Self, Self::Error> {
        let value = &mut value;
        let discriminant = value[0];
        let value = &mut value[1..];
        let mut executable = [0u8; EXECUTABLE_LEN];
        let mut pid_tgid = 0;
        let mut stack_id = 0;
        let value = value
            .read(&mut executable)?
            .read_u64(&mut pid_tgid)?
            .read_u64(&mut stack_id)?;
        Ok(match discriminant {
            0u8 => {
                let mut start = 0;
                let mut end = 0;
                value.read_u64(&mut start)?.read_u64(&mut end)?;
                OsSanitizerReport::RwxVma {
                    executable,
                    pid_tgid,
                    stack_id,
                    start,
                    end,
                }
            }
            1 => {
                let mut template_param = 0;
                let mut template = [0; TEMPLATE_LEN];
                value.read_u64(&mut template_param)?.read(&mut template)?;
                OsSanitizerReport::PrintfMutability {
                    executable,
                    pid_tgid,
                    stack_id,
                    template_param,
                    template,
                }
            }
            2 => {
                let mut command_param = 0;
                let mut command = [0; TEMPLATE_LEN];
                value.read_u64(&mut command_param)?.read(&mut command)?;
                OsSanitizerReport::SystemMutability {
                    executable,
                    pid_tgid,
                    stack_id,
                    command_param,
                    command,
                }
            }
            3 => {
                let mut command_param = 0;
                let mut command = [0; TEMPLATE_LEN];
                value.read_u64(&mut command_param)?.read(&mut command)?;
                OsSanitizerReport::SystemAbsolute {
                    executable,
                    pid_tgid,
                    stack_id,
                    command_param,
                    command,
                }
            }
            4 => OsSanitizerReport::FilePointerLocking {
                executable,
                pid_tgid,
                stack_id,
            },
            5 => {
                let mut dest = 0;
                value.read_u64(&mut dest)?;
                OsSanitizerReport::Sprintf {
                    executable,
                    pid_tgid,
                    stack_id,
                    dest,
                }
            }
            6 => {
                let mut srcptr = 0;
                let mut size = 0;
                let mut computed = 0;
                let mut count = 0;
                let mut index = 0;
                let value = value
                    .read_u64(&mut srcptr)?
                    .read_u64(&mut size)?
                    .read_u64(&mut computed)?
                    .read_u64(&mut count)?;
                let kind = match value[0] {
                    1 => SnprintfViolation::DefiniteLeak,
                    0 => SnprintfViolation::PossibleLeak,
                    _ => unreachable!(),
                };
                let value = &mut value[1..];
                value.read_u64(&mut index)?;
                OsSanitizerReport::Snprintf {
                    executable,
                    pid_tgid,
                    stack_id,
                    srcptr,
                    size,
                    computed,
                    count,
                    kind,
                    index,
                }
            }
            7 => {
                let mut dest = 0;
                let mut src = 0;
                let value = value.read_u64(&mut dest)?.read_u64(&mut src)?;
                let len_checked = value[0] == 1;
                OsSanitizerReport::Strcpy {
                    executable,
                    pid_tgid,
                    stack_id,
                    dest,
                    src,
                    len_checked,
                }
            }
            8 => {
                let mut len = 0;
                let mut allocated = 0;
                let mut dest = 0;
                let mut src = 0;
                let value = value
                    .read_u64(&mut len)?
                    .read_u64(&mut allocated)?
                    .read_u64(&mut dest)?
                    .read_u64(&mut src)?;
                let variant = match value[0] {
                    0 => CopyViolation::Strlen,
                    1 => CopyViolation::Malloc,
                    _ => unreachable!(),
                };
                OsSanitizerReport::Strncpy {
                    executable,
                    pid_tgid,
                    stack_id,
                    len,
                    allocated,
                    dest,
                    src,
                    variant,
                }
            }
            9 => {
                let mut len = 0;
                let mut allocated = 0;
                let mut dest = 0;
                let mut src = 0;
                let value = value
                    .read_u64(&mut len)?
                    .read_u64(&mut allocated)?
                    .read_u64(&mut dest)?
                    .read_u64(&mut src)?;
                let variant = match value[0] {
                    0 => CopyViolation::Strlen,
                    1 => CopyViolation::Malloc,
                    _ => unreachable!(),
                };
                OsSanitizerReport::Memcpy {
                    executable,
                    pid_tgid,
                    stack_id,
                    len,
                    allocated,
                    dest,
                    src,
                    variant,
                }
            }
            10 => {
                let mut i_mode = 0;
                let mut filename = [0; FILENAME_LEN];
                let value = value.read_u64(&mut i_mode)?.read(&mut filename)?;
                let variant = match value[0] {
                    0 => OpenViolation::Perms,
                    1 => OpenViolation::Toctou(ToctouVariant::Access),
                    2 => OpenViolation::Toctou(ToctouVariant::Stat),
                    3 => OpenViolation::Toctou(ToctouVariant::Statx),
                    _ => unreachable!(),
                };
                OsSanitizerReport::Open {
                    executable,
                    pid_tgid,
                    stack_id,
                    i_mode,
                    filename,
                    variant,
                }
            }
            11 => OsSanitizerReport::Access {
                executable,
                pid_tgid,
                stack_id,
            },
            12 => OsSanitizerReport::Gets {
                executable,
                pid_tgid,
                stack_id,
            },
            13 => {
                let mut protection = 0;
                let value = value.read_u64(&mut protection)?;
                let variant = match value[0] {
                    0 => FixedMmapViolation::HintUsed,
                    1 => FixedMmapViolation::FixedMmapUnmapped,
                    2 => FixedMmapViolation::FixedMmapBadProt,
                    _ => unreachable!(),
                };
                OsSanitizerReport::FixedMmap {
                    executable,
                    pid_tgid,
                    stack_id,
                    protection,
                    variant,
                }
            }
            _ => {
                unreachable!("did you forget to implement a report type?")
            }
        })
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for OsSanitizerReport {}

impl From<OsSanitizerError> for u32 {
    fn from(value: OsSanitizerError) -> Self {
        unsafe { *<*const _>::from(&value).cast::<u32>() }
    }
}

#[inline(always)]
pub fn approximate_range(base: usize, len: usize) -> Option<usize> {
    if len == 0 {
        return None;
    }

    // ilog2 causes a bpf linkage error
    // let zeroable = len.ilog2();
    let mut zeroable = 0;
    while (1 << zeroable) <= len {
        zeroable += 1;
        if zeroable > size_of_val(&len) * 8 {
            return None;
        }
    }

    let mask = !(usize::MAX % (1 << (zeroable - 1)));

    let approximate = (base + len - 1) & mask;
    Some(approximate)
}

#[cfg(test)]
mod test {
    #[test]
    fn approximate_range() {
        for base in 0..128 {
            for len in 0..128 {
                if let Some(approx) = super::approximate_range(base, len) {
                    assert!(
                        (base..(base + len)).contains(&approx),
                        "expected {approx} to be in [{base}, {base}+{len})"
                    );
                }
            }
        }
    }
}
