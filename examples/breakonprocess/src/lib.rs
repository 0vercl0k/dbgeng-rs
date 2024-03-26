use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::sync::Once;

use anyhow::{Context, Result};
use dbgeng::breakpoint::{BreakpointFlags, BreakpointType, DebugBreakpoint};
use dbgeng::client::DebugClient;
use dbgeng::events::{DebugInstruction, EventCallbacks};
use dbgeng::{dlogln, export_cmd};
use windows::core::{GUID, HRESULT};
use windows::Win32::Foundation::S_OK;
use windows::Win32::System::Diagnostics::Debug::Extensions::{
    DEBUG_NOTIFY_SESSION_ACCESSIBLE, DEBUG_STACK_FRAME,
};
use zerocopy::{AsBytes, FromBytes, FromZeroes};

#[derive(AsBytes, FromBytes, FromZeroes, Debug)]
#[repr(C)]
struct UnicodeString {
    length: u16,
    max_length: u16,
    _pad: u32,
    buffer: u64,
}

fn read_unicode_string(client: &DebugClient, addr: u64) -> Result<String> {
    let mut str = UnicodeString::new_zeroed();
    client
        .read_virtual_exact(addr, str.as_bytes_mut())
        .context("failed to read UnicodeString")?;

    let mut buf = vec![0u16; (str.length / 2) as usize];
    client
        .read_virtual_exact(str.buffer, &mut buf.as_bytes_mut())
        .context("failed to read UnicodeString buffer")?;

    Ok(String::from_utf16(&buf).context("failed to convert UnicodeString")?)
}

thread_local! {
    static CLIENT: OnceCell<DebugClient> = OnceCell::new();
    static BREAKPOINTS: bp::CallbackBreakpoints = bp::CallbackBreakpoints::new();
}

mod bp {
    use super::*;

    struct CallbackBreakpointData {
        bp: DebugBreakpoint,
        callback: Box<dyn FnMut(&DebugClient, &DebugBreakpoint) -> Result<DebugInstruction>>,
    }

    pub struct CallbackBreakpoints {
        inner: RefCell<HashMap<GUID, CallbackBreakpointData>>,
    }

    impl CallbackBreakpoints {
        pub fn new() -> Self {
            Self {
                inner: RefCell::new(HashMap::new()),
            }
        }

        pub fn insert<
            T: FnMut(&DebugClient, &DebugBreakpoint) -> Result<DebugInstruction> + 'static,
        >(
            &self,
            bp: DebugBreakpoint,
            cb: T,
        ) {
            self.inner
                .borrow_mut()
                .insert(bp.guid().unwrap(), CallbackBreakpointData {
                    bp,
                    callback: Box::new(cb),
                });
        }

        pub fn call(&self, client: &DebugClient, bp: &DebugBreakpoint) -> DebugInstruction {
            let mut inner = self.inner.borrow_mut();
            if let Some(data) = inner.get_mut(&bp.guid().unwrap()) {
                match (data.callback)(client, bp) {
                    Ok(i) => i,
                    Err(e) => {
                        let _ = dbgeng::dlogln!(client, "Error in breakpoint callback: {e:?}");
                        DebugInstruction::NoChange
                    }
                }
            } else {
                DebugInstruction::NoChange
            }
        }
    }
}

mod cmd {
    use super::*;

    fn break_on_process(_client: &DebugClient, args: String) -> anyhow::Result<()> {
        let mut args = args.split_whitespace();
        let process_name = args.next().context("missing process name")?.to_string();

        CLIENT.with(|c| -> anyhow::Result<()> {
            let client: &DebugClient = c.get().context("client not set")?;

            let bp = client.add_breakpoint(BreakpointType::Code, None)?;

            bp.set_offset_expression("nt!NtCreateUserProcess")?;
            bp.set_flags(BreakpointFlags::ENABLED)?;

            BREAKPOINTS.with(|breakpoints| {
                breakpoints.insert(bp, move |client, bp| -> Result<DebugInstruction> {
                    bpproc_create(client, bp, process_name.clone())
                });
            });

            Ok(())
        })?;

        Ok(())
    }

    export_cmd!(bop, break_on_process);
    export_cmd!(breakonprocess, break_on_process);
}

struct PluginEventCallbacks;
impl EventCallbacks for PluginEventCallbacks {
    fn breakpoint(&self, client: &DebugClient, bp: &DebugBreakpoint) -> DebugInstruction {
        BREAKPOINTS.with(|breakpoints| breakpoints.call(client, bp))
    }
}

fn bpproc_create(
    client: &DebugClient,
    bp: &DebugBreakpoint,
    desired_name: String,
) -> Result<DebugInstruction> {
    // Read out RTL_USER_PROCESS_PARAMETERS from the stack.
    let rsp = client.reg64("rsp").context("failed to read rsp")?;

    let nt = client.get_sym_module("nt").context("failed to get nt")?;

    let mut ptr_proc_params = 0u64;
    client
        .read_virtual_exact(rsp + (8 * 8) + 8, ptr_proc_params.as_bytes_mut())
        .context("failed to read parameters")?;

    // Get the offset to ImagePathName.
    let image_path_name_offset = nt
        .get_type("_RTL_USER_PROCESS_PARAMETERS")
        .context("failed to get _RTL_USER_PROCESS_PARAMETERS")?
        .get_field_offset("ImagePathName")
        .context("failed to get ImagePathName offset")?;

    // e.g: "\??\C:\windows\system32\conhost.exe"
    let image_path_name =
        read_unicode_string(client, ptr_proc_params + image_path_name_offset as u64)?;

    dlogln!(client, "Image loaded: {image_path_name}")?;

    // Compare the name to the desired name.
    if !image_path_name
        .to_lowercase()
        .ends_with(&desired_name.to_lowercase())
    {
        // No match. Return without changing execution.
        return Ok(DebugInstruction::NoChange);
    }

    // Alright. Cache rcx/rdx for pProcHandle and pThrdHandle.
    let p_proc_handle = client.reg64("rcx").context("failed to read rcx")?;
    let p_thrd_handle = client.reg64("rdx").context("failed to read rdx")?;

    // Read out 2 stack frames, and set a breakpoint after `KiSystemServiceCopyEnd`.
    let stack = client
        .context_stack_frames(3)
        .context("failed to read stack")?;
    let ra = stack[2].ReturnOffset;

    let bp = client.add_breakpoint(BreakpointType::Code, None)?;
    bp.set_offset(ra)
        .context("failed to set postcreate breakpoint addr")?;
    bp.set_flags(BreakpointFlags::ENABLED)
        .context("failed to set postcreate breakpoint flags")?;

    BREAKPOINTS.with(|breakpoints| {
        breakpoints.insert(bp, move |client, _bp| {
            bpproc_postcreate(client, p_proc_handle, p_thrd_handle)
        });
    });

    Ok(DebugInstruction::NoChange)
}

fn bpproc_postcreate(
    client: &DebugClient,
    p_proc_handle: u64,
    p_thrd_handle: u64,
) -> Result<DebugInstruction> {
    // Read the handles, ensuring that we truncate the upper 48 bits
    // (which indicates if a handle belongs to the kernel).
    let proc_handle = client.read_virtual_field::<u64>(p_proc_handle)? & 0xFFFF;
    let thrd_handle = client.read_virtual_field::<u64>(p_thrd_handle)? & 0xFFFF;

    Ok(DebugInstruction::NoChange)
}

fn init_accessible(client: DebugClient) -> anyhow::Result<()> {
    dbgeng::dlogln!(client, "Extension loaded")?;
    client.set_event_callbacks(PluginEventCallbacks)?;

    CLIENT.with(|c| {
        c.set(client)
            .map_err(|_e| anyhow::anyhow!("Failed to set the client"))
    })?;
    Ok(())
}

#[export_name = "DebugExtensionInitialize"]
fn init(version: *mut u32, flags: *mut u32) -> HRESULT {
    unsafe {
        *version = 0x0001_0000;
        *flags = 0x00000000;
    }

    S_OK
}

#[export_name = "DebugExtensionUninitialize"]
fn uninit() {
    CLIENT.with(|c| {
        // Drop the client.
        // c.take();
    });
}

#[export_name = "DebugExtensionNotify"]
extern "C" fn notify(notify: u32, _argument: u64) {
    static INIT_ONCE: Once = Once::new();

    match notify {
        DEBUG_NOTIFY_SESSION_ACCESSIBLE => {
            INIT_ONCE.call_once(|| {
                // If we fail to create the client here, we're boned.
                let client = DebugClient::create().unwrap();

                if let Err(e) = init_accessible(client.clone()) {
                    let _ = dbgeng::dlogln!(client, "Failed to initialize the extension: {e}");
                }
            });
        }
        _ => {}
    }
}
