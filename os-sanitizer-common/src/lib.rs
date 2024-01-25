#![cfg_attr(not(feature = "user"), no_std)]

use aya_bpf_cty::uintptr_t;
use core::mem::size_of_val;
use core::mem::MaybeUninit;

pub const EXECUTABLE_LEN: usize = 16;
pub const WRITTEN_LEN: usize = 128;
pub const FILENAME_LEN: usize = 128;
pub const TEMPLATE_LEN: usize = 128;

#[repr(u32)]
pub enum OsSanitizerError {
    MissingArg(&'static str, usize) = 1,
    CouldntReadKernel(&'static str, uintptr_t, usize),
    CouldntReadUser(&'static str, uintptr_t, usize),
    CouldntRecoverStack(&'static str, i64),
    CouldntGetPath(&'static str, i64),
    CouldntGetComm(&'static str, i64),
    CouldntAccessBuffer(&'static str),
    InvalidUtf8(&'static str),
    OutOfSpace(&'static str),
    RacefulAccess(&'static str),
    UnexpectedNull(&'static str),
    CouldntFindVma(&'static str, i64, u32, u32),
    ImpossibleFile,
    Unreachable(&'static str),
}

#[derive(Copy, Clone)]
#[repr(u64, align(8))]
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
#[repr(u64, align(8))]
pub enum OpenViolation {
    Perms,
    Toctou,
}

#[derive(Copy, Clone)]
#[repr(u64, align(8))]
pub enum CopyViolation {
    Strlen,
    Malloc,
}

#[derive(Copy, Clone, Ord, PartialOrd, PartialEq, Eq)]
#[repr(u64, align(8))]
pub enum SnprintfViolation {
    PossibleLeak,
    DefiniteLeak,
}

#[derive(Copy, Clone)]
#[repr(u64, align(8))]
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
    FilePointerLocking {
        executable: [u8; EXECUTABLE_LEN],
        pid_tgid: u64,
        stack_id: u64,
    },
    Sprintf {
        executable: [u8; EXECUTABLE_LEN],
        pid_tgid: u64,
        stack_id: u64,
        dest: uintptr_t,
    },
    Snprintf {
        executable: [u8; EXECUTABLE_LEN],
        pid_tgid: u64,
        stack_id: u64,
        srcptr: uintptr_t,
        size: usize,
        computed: usize,
        count: usize,
        kind: SnprintfViolation,
        index: usize,
    },
    Strcpy {
        executable: [u8; EXECUTABLE_LEN],
        pid_tgid: u64,
        stack_id: u64,
        dest: uintptr_t,
        src: uintptr_t,
        len_checked: bool,
    },
    Strncpy {
        executable: [u8; EXECUTABLE_LEN],
        pid_tgid: u64,
        stack_id: u64,
        len: u64,
        allocated: u64,
        dest: uintptr_t,
        src: uintptr_t,
        variant: CopyViolation,
    },
    Memcpy {
        executable: [u8; EXECUTABLE_LEN],
        pid_tgid: u64,
        stack_id: u64,
        len: u64,
        allocated: u64,
        dest: uintptr_t,
        src: uintptr_t,
        variant: CopyViolation,
    },
    Open {
        executable: [u8; EXECUTABLE_LEN],
        pid_tgid: u64,
        stack_id: u64,
        i_mode: u64,
        filename: [u8; FILENAME_LEN],
        variant: OpenViolation,
        toctou: Option<ToctouVariant>,
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
}

impl OsSanitizerReport {
    #[inline(always)]
    pub unsafe fn zeroed_init<F>(f: F) -> Self
    where
        F: FnOnce() -> Self,
    {
        let mut base = MaybeUninit::zeroed();
        base.write(f());
        base.assume_init()
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
