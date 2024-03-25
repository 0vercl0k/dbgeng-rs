use windows::core::{implement, HRESULT};
use windows::Win32::System::Diagnostics::Debug::Extensions::{
    IDebugBreakpoint, IDebugEventCallbacks, IDebugEventCallbacks_Impl, DEBUG_STATUS_BREAK,
    DEBUG_STATUS_GO, DEBUG_STATUS_GO_HANDLED, DEBUG_STATUS_GO_NOT_HANDLED,
    DEBUG_STATUS_IGNORE_EVENT, DEBUG_STATUS_NO_CHANGE, DEBUG_STATUS_RESTART_REQUESTED,
    DEBUG_STATUS_STEP_BRANCH, DEBUG_STATUS_STEP_INTO, DEBUG_STATUS_STEP_OVER,
};
use windows::Win32::System::Diagnostics::Debug::EXCEPTION_RECORD64;

use crate::breakpoint::DebugBreakpoint;
use crate::client::DebugClient;

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DebugInstruction {
    /// Suspend the target.
    Break,
    /// Continue execution for a single instruction.
    StepInto,
    /// Continue execution until the next branch instruction.
    StepBranch,
    /// Continue execution for a single instruction, stepping over call
    /// instructions.
    StepOver,
    /// Continue execution and flag the event as unhandled.
    GoNotHandled,
    /// Continue execution and flag the event as handled.
    GoHandled,
    /// Continue execution.
    Go,
    /// Ignore the event.
    IgnoreEvent,
    /// Restart the target.
    Restart,
    /// No instruction; return if your event handler is uninterested in the
    /// event.
    #[default]
    NoChange,
}

impl DebugInstruction {
    fn to_status(&self) -> u32 {
        match self {
            DebugInstruction::Break => DEBUG_STATUS_BREAK,
            DebugInstruction::StepInto => DEBUG_STATUS_STEP_INTO,
            DebugInstruction::StepBranch => DEBUG_STATUS_STEP_BRANCH,
            DebugInstruction::StepOver => DEBUG_STATUS_STEP_OVER,
            DebugInstruction::GoNotHandled => DEBUG_STATUS_GO_NOT_HANDLED,
            DebugInstruction::GoHandled => DEBUG_STATUS_GO_HANDLED,
            DebugInstruction::Go => DEBUG_STATUS_GO,
            DebugInstruction::IgnoreEvent => DEBUG_STATUS_IGNORE_EVENT,
            DebugInstruction::Restart => DEBUG_STATUS_RESTART_REQUESTED,
            DebugInstruction::NoChange => DEBUG_STATUS_NO_CHANGE,
        }
    }
}

pub trait EventCallbacks {
    fn breakpoint(&self, client: &DebugClient, bp: &DebugBreakpoint) -> DebugInstruction;
}

#[implement(IDebugEventCallbacks)]
pub(crate) struct DbgEventCallbacks {
    client: DebugClient,
    callbacks: Box<dyn EventCallbacks>,
}

impl DbgEventCallbacks {
    pub(crate) fn new(client: DebugClient, callbacks: Box<dyn EventCallbacks + 'static>) -> Self {
        Self { client, callbacks }
    }
}

impl IDebugEventCallbacks_Impl for DbgEventCallbacks {
    fn GetInterestMask(&self) -> windows::core::Result<u32> {
        todo!()
    }

    fn Breakpoint(
        &self,
        bp: ::core::option::Option<&IDebugBreakpoint>,
    ) -> windows::core::Result<()> {
        let bp = bp
            .expect("breakpoint callback called with NULL breakpoint")
            .to_owned();

        // N.B: The breakpoint must be represented as "borrowed" because it could be
        // invalid after this callback returns.
        let res = self
            .callbacks
            .breakpoint(&self.client, &DebugBreakpoint::new(bp).unwrap());

        // N.B: This is pretty lame; the API is declared to return a HRESULT, but it
        // does not actually return a HRESULT. We'll need to shim our return
        // value into a HRESULT-looking thing. Ok(_) maps to 0, and Err(e) maps
        // to e.code(). So we'll always return an "error".
        let res = HRESULT(res.to_status() as i32);
        Err(res.into())
    }

    fn Exception(
        &self,
        exception: *const EXCEPTION_RECORD64,
        firstchance: u32,
    ) -> windows::core::Result<()> {
        todo!()
    }

    fn CreateThread(
        &self,
        handle: u64,
        dataoffset: u64,
        startoffset: u64,
    ) -> windows::core::Result<()> {
        todo!()
    }

    fn ExitThread(&self, exitcode: u32) -> windows::core::Result<()> {
        todo!()
    }

    fn CreateProcessA(
        &self,
        imagefilehandle: u64,
        handle: u64,
        baseoffset: u64,
        modulesize: u32,
        modulename: &windows::core::PCSTR,
        imagename: &windows::core::PCSTR,
        checksum: u32,
        timedatestamp: u32,
        initialthreadhandle: u64,
        threaddataoffset: u64,
        startoffset: u64,
    ) -> windows::core::Result<()> {
        todo!()
    }

    fn ExitProcess(&self, exitcode: u32) -> windows::core::Result<()> {
        todo!()
    }

    fn LoadModule(
        &self,
        imagefilehandle: u64,
        baseoffset: u64,
        modulesize: u32,
        modulename: &windows::core::PCSTR,
        imagename: &windows::core::PCSTR,
        checksum: u32,
        timedatestamp: u32,
    ) -> windows::core::Result<()> {
        todo!()
    }

    fn UnloadModule(
        &self,
        imagebasename: &windows::core::PCSTR,
        baseoffset: u64,
    ) -> windows::core::Result<()> {
        todo!()
    }

    fn SystemError(&self, error: u32, level: u32) -> windows::core::Result<()> {
        todo!()
    }

    fn SessionStatus(&self, status: u32) -> windows::core::Result<()> {
        todo!()
    }

    fn ChangeDebuggeeState(&self, flags: u32, argument: u64) -> windows::core::Result<()> {
        todo!()
    }

    fn ChangeEngineState(&self, flags: u32, argument: u64) -> windows::core::Result<()> {
        todo!()
    }

    fn ChangeSymbolState(&self, flags: u32, argument: u64) -> windows::core::Result<()> {
        todo!()
    }
}
