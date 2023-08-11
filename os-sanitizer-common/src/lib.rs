#![cfg_attr(not(feature = "user"), no_std)]

use aya_bpf_cty::uintptr_t;
use core::mem::size_of_val;

pub const EXECUTABLE_LEN: usize = 128;

#[repr(u32)]
pub enum OsSanitizerError {
    MissingArg(&'static str, usize) = 1,
    CouldntReadKernel(&'static str, uintptr_t, usize),
    CouldntReadUser(&'static str, uintptr_t, usize),
    CouldntRecoverStack(&'static str, i64),
    CouldntGetComm(&'static str, i64),
    CouldntAccessBuffer(&'static str),
    InvalidUtf8(&'static str),
    OutOfSpace(&'static str),
    RacefulAccess(&'static str),
    ImpossibleFile,
    Unreachable(&'static str),
}

#[derive(Copy, Clone)]
#[repr(u64, align(8))]
pub enum CopyViolation {
    Strlen,
    Malloc,
}

#[derive(Copy, Clone)]
#[repr(u64, align(8))]
pub enum FunctionInvocationReport {
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
    Access {
        executable: [u8; 128],
        pid_tgid: u64,
        stack_id: u64,
    },
    Gets {
        executable: [u8; 128],
        pid_tgid: u64,
        stack_id: u64,
    },
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FunctionInvocationReport {}

#[derive(Copy, Clone)]
pub struct FileAccessReport {
    pub pid_tgid: u64,
    pub i_mode: u16,
    pub executable: [u8; EXECUTABLE_LEN],
    pub filename: [u8; EXECUTABLE_LEN * 2],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FileAccessReport {}

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
