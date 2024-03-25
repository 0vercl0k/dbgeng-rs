use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;

use anyhow::Context;
use dbgeng::breakpoint::DebugBreakpoint;
use dbgeng::client::DebugClient;
use dbgeng::events::{DebugInstruction, EventCallbacks};
use dbgeng::export_cmd;
use windows::core::{GUID, HRESULT};
use windows::Win32::Foundation::S_OK;
use windows::Win32::System::Diagnostics::Debug::Extensions::DEBUG_NOTIFY_SESSION_ACCESSIBLE;

thread_local! {
    static CLIENT: OnceCell<DebugClient> = OnceCell::new();
    static CALLBACKS: RefCell<HashMap<GUID, Box<dyn FnMut() -> DebugInstruction>>> = RefCell::new(HashMap::new());
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

            CALLBACKS.with_borrow_mut(|callbacks| {
                callbacks.insert(
                    bp.guid().unwrap(),
                    Box::new(move || -> DebugInstruction { bpproc_create(process_name.clone()) }),
                );
            });

            Ok(())
        })?;

        Ok(())
    }

    export_cmd!(breakonprocess);
}

fn bpproc_create(desired_name: String) -> DebugInstruction {
    DebugInstruction::NoChange
}

struct PluginEventCallbacks;
impl EventCallbacks for PluginEventCallbacks {
    fn breakpoint(&self, _client: &DebugClient, bp: &DebugBreakpoint) -> DebugInstruction {
        CALLBACKS.with(|c| {
            let mut callbacks = c.borrow_mut();
            let id = bp.guid().unwrap();
            if let Some(callback) = callbacks.get_mut(&id) {
                callback()
            } else {
                DebugInstruction::NoChange
            }
        })
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
