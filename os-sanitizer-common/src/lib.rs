#![cfg_attr(not(feature = "user"), no_std)]

use aya_bpf_cty::uintptr_t;

#[repr(u32)]
pub enum OsSanitizerError {
    MISSING_ARG(&'static str, usize) = 1,
    COULDNT_READ_KERNEL(&'static str, uintptr_t, usize),
    COULDNT_READ_USER(&'static str, uintptr_t, usize),
    COULDNT_ACCESS_BUFFER(&'static str),
    INVALID_UTF8(&'static str),
    OUT_OF_SPACE(&'static str),
    RACEFUL_ACCESS(&'static str),
    IMPOSSIBLE_FILE,
}

impl From<OsSanitizerError> for u32 {
    fn from(value: OsSanitizerError) -> Self {
        unsafe { *<*const _>::from(&value).cast::<u32>() }
    }
}
