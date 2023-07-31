#![cfg_attr(not(feature = "user"), no_std)]

use aya_bpf_cty::uintptr_t;

#[repr(u32)]
pub enum OsSanitizerError {
    MissingArg(&'static str, usize) = 1,
    CouldntReadKernel(&'static str, uintptr_t, usize),
    CouldntReadUser(&'static str, uintptr_t, usize),
    CouldntAccessBuffer(&'static str),
    InvalidUtf8(&'static str),
    OutOfSpace(&'static str),
    RacefulAccess(&'static str),
    ImpossibleFile,
    Unreachable,
}

#[derive(Copy, Clone)]
pub struct Report {
    pub pid_tgid: u64,
    pub i_mode: u16,
    pub filename: [u8; 256],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Report {}

impl From<OsSanitizerError> for u32 {
    fn from(value: OsSanitizerError) -> Self {
        unsafe { *<*const _>::from(&value).cast::<u32>() }
    }
}
