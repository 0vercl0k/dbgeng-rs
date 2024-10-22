// Axel '0vercl0k' Souchet - March 16 2024
pub mod as_pcstr;
pub mod bits;
pub mod client;

#[allow(non_snake_case)]
#[inline(always)]
pub fn DEBUG_EXTENSION_VERSION(major: u32, minor: u32) -> u32 {
    ((major & 0xffff) << 16) | (minor & 0xffff)
}
