#![cfg_attr(not(feature = "user"), no_std)]

use aya_bpf_cty::uintptr_t;

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
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FunctionInvocationReport {}

#[derive(Copy, Clone)]
pub struct FileAccessReport {
    pub pid_tgid: u64,
    pub i_mode: u16,
    pub filename: [u8; 256],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FileAccessReport {}

impl From<OsSanitizerError> for u32 {
    fn from(value: OsSanitizerError) -> Self {
        unsafe { *<*const _>::from(&value).cast::<u32>() }
    }
}
