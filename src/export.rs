use std::fmt::Display;

pub use paste::paste;
use windows::core::{IUnknown, Interface, PCSTR};
use windows::Win32::Foundation::{E_ABORT, S_OK};

use crate::client::DebugClient;
use crate::dlogln;

pub type RawIUnknown = *mut std::ffi::c_void;

#[macro_export]
macro_rules! export_cmd {
    ($name:ident) => {
        $crate::export::paste! {
            #[export_name = stringify!($name)]
            pub extern "C" fn [< __export_ $name >] (raw_client: *mut std::ffi::c_void, args: *const std::ffi::c_char) -> i32 {
                $crate::export::wrap_cmd(raw_client, args, $name)
            }
        }
    };
}

/// This function wraps the idiomatic Rust implementation of a command to
/// display an error to WinDbg if the inner function fails.
pub fn wrap_cmd<E: Display>(
    raw_client: *mut std::ffi::c_void,
    args: *const std::ffi::c_char,
    callback: impl FnOnce(&DebugClient, String) -> Result<(), E>,
) -> i32 {
    let args = PCSTR(args as *const _);

    // We do not own the `raw_client` interface  so we want to created a borrow. If
    // we don't, the object will get Release()'d when it gets dropped which will
    // lead to a use-after-free.
    let Some(client) = (unsafe { IUnknown::from_raw_borrowed(&raw_client) }) else {
        return E_ABORT.0;
    };

    let Ok(dbg) = DebugClient::new(client) else {
        return E_ABORT.0;
    };

    let Ok(args) = (unsafe { args.to_string() }) else {
        return E_ABORT.0;
    };

    // Parse the arguments using `clap`. Currently splitting arguments by
    // whitespaces.
    // let args = match P::try_parse_from(args.split_whitespace()) {
    //     Ok(a) => a,
    //     Err(e) => {
    //         let _ = dlogln!(dbg, "{e}");
    //         return E_ABORT;
    //     }
    // };

    match callback(&dbg, args) {
        Err(e) => {
            let _ = dlogln!(dbg, "Ran into an error: {e:#}");
            E_ABORT.0
        }
        Ok(_) => S_OK.0,
    }
}
