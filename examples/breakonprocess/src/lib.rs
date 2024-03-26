use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;

use anyhow::{Context, Result};
use dbgeng::breakpoint::DebugBreakpoint;
use dbgeng::client::DebugClient;
use dbgeng::events::{DebugInstruction, EventCallbacks};
use dbgeng::{dlogln, export_cmd};
use windows::core::{GUID, HRESULT};
use windows::Win32::Foundation::S_OK;
use windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_NOTIFY_SESSION_ACCESSIBLE;

struct CallbackBreakpointData {
    bp: DebugBreakpoint,
    callback: Box<dyn FnMut(&DebugClient, &DebugBreakpoint) -> Result<DebugInstruction>>,
}

struct CallbackBreakpoints {
    inner: RefCell<HashMap<GUID, CallbackBreakpointData>>,
}

impl CallbackBreakpoints {
    fn new() -> Self {
        Self {
            inner: RefCell::new(HashMap::new()),
        }
    }

    fn insert<T: FnMut(&DebugClient, &DebugBreakpoint) -> Result<DebugInstruction> + 'static>(
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

    fn call(&self, client: &DebugClient, bp: &DebugBreakpoint) -> DebugInstruction {
        let mut inner = self.inner.borrow_mut();
        if let Some(data) = inner.get_mut(&bp.guid().unwrap()) {
            match (data.callback)(client, bp) {
                Ok(i) => i,
                Err(e) => {
                    let _ = dbgeng::dlogln!(client, "Error in breakpoint callback: {e:#}");
                    DebugInstruction::NoChange
                }
            }
        } else {
            DebugInstruction::NoChange
        }
    }
}

thread_local! {
    static CLIENT: OnceCell<DebugClient> = OnceCell::new();
    static BREAKPOINTS: CallbackBreakpoints = CallbackBreakpoints::new();
}

mod cmd {
    use dbgeng::breakpoint::{BreakpointFlags, BreakpointType};

    use super::*;

    fn breakonprocess(_client: &DebugClient, args: String) -> anyhow::Result<()> {
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

    export_cmd!(breakonprocess);
}

fn bpproc_create(
    client: &DebugClient,
    bp: &DebugBreakpoint,
    desired_name: String,
) -> Result<DebugInstruction> {
    // Read out RTL_USER_PROCESS_PARAMETERS from the stack.
    let rsp = client.reg64("rsp").context("failed to read rsp")?;

    let nt = client.get_sym_module("ntoskrnl.exe")?;

    // Get the offset to ImagePathName.
    let image_path_name_offset = nt
        .get_type("_RTL_USER_PROCESS_PARAMETERS")
        .context("failed to get _RTL_USER_PROCESS_PARAMETERS")?
        .get_field_offset("ImagePathName")
        .context("failed to get ImagePathName offset")?;

    // Read the ImagePathName.
    let image_path_name = client
        .read_ustr_virtual(rsp + image_path_name_offset as u64)
        .context("failed to read ImagePathName")?;

    dlogln!(client, "Image loaded: {image_path_name}")?;
    Ok(DebugInstruction::NoChange)
}

fn bpproc_postcreate() -> DebugInstruction {
    DebugInstruction::NoChange
}

struct PluginEventCallbacks;
impl EventCallbacks for PluginEventCallbacks {
    fn breakpoint(&self, client: &DebugClient, bp: &DebugBreakpoint) -> DebugInstruction {
        BREAKPOINTS.with(|breakpoints| breakpoints.call(client, bp))
    }
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

#[export_name = "DebugExtensionNotify"]
extern "C" fn notify(notify: u32, _argument: u64) {
    match notify {
        DEBUG_NOTIFY_SESSION_ACCESSIBLE => {
            // If we fail to create the client here, we're boned.
            let client = DebugClient::create().unwrap();

            if let Err(e) = init_accessible(client.clone()) {
                let _ = dbgeng::dlogln!(client, "Failed to initialize the extension: {e}");
            }
        }
        _ => {}
    }
}
