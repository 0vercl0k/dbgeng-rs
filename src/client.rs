// Axel '0vercl0k' Souchet - January 21 2024
//! This contains the main class, [`DebugClient`], which is used to interact
//! with Microsoft's Debug Engine library via the documented COM objects.
use std::collections::HashMap;
use std::ffi::{CString, OsStr};
use std::mem::MaybeUninit;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use windows::Win32::System::Diagnostics::Debug::Extensions::{
    DEBUG_ADDSYNTHMOD_DEFAULT, DEBUG_EXECUTE_DEFAULT, DEBUG_OUTCTL_THIS_CLIENT,
    DEBUG_OUTPUT_NORMAL, DEBUG_VALUE, DEBUG_VALUE_FLOAT32, DEBUG_VALUE_FLOAT64,
    DEBUG_VALUE_FLOAT80, DEBUG_VALUE_FLOAT128, DEBUG_VALUE_INT8, DEBUG_VALUE_INT16,
    DEBUG_VALUE_INT32, DEBUG_VALUE_INT64, DEBUG_VALUE_VECTOR64, DEBUG_VALUE_VECTOR128,
    IDebugClient5, IDebugControl3, IDebugDataSpaces4, IDebugOutputCallbacks,
    IDebugOutputCallbacks_Impl, IDebugRegisters, IDebugSymbols3,
};
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;
use windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE;
use windows::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
};
use windows::core::{IUnknown, Interface, implement};
use windows_core::{ComObjectInterface, StaticComObject};

use crate::as_pcstr::AsPCSTR;
use crate::bits::Bits;

/// Extract [`u128`] off a [`DEBUG_VALUE`].
pub fn u128_from_debugvalue(v: DEBUG_VALUE) -> Result<u128> {
    let value = match v.Type {
        DEBUG_VALUE_FLOAT80 => {
            let f80 = unsafe { v.Anonymous.F80Bytes };
            let mut bytes = [0; 16];
            bytes[0..10].copy_from_slice(&f80);

            u128::from_le_bytes(bytes)
        }
        DEBUG_VALUE_VECTOR128 => u128::from_le_bytes(unsafe { v.Anonymous.VI8 }),
        DEBUG_VALUE_FLOAT128 => u128::from_le_bytes(unsafe { v.Anonymous.F128Bytes }),
        _ => {
            bail!("expected float128 values, but got Type={:#x}", v.Type);
        }
    };

    Ok(value)
}

/// Extract a [`u64`]/[`u32`]/[`u16`]/[`u8`]/[`f64`] off a [`DEBUG_VALUE`].
pub fn u64_from_debugvalue(v: DEBUG_VALUE) -> Result<u64> {
    let value = match v.Type {
        DEBUG_VALUE_INT64 => {
            let parts = unsafe { v.Anonymous.I64Parts32 };

            (u64::from(parts.HighPart) << 32) | u64::from(parts.LowPart)
        }
        DEBUG_VALUE_INT32 => unsafe { v.Anonymous.I32 }.into(),
        DEBUG_VALUE_INT16 => unsafe { v.Anonymous.I16 }.into(),
        DEBUG_VALUE_INT8 => unsafe { v.Anonymous.I8 }.into(),
        DEBUG_VALUE_VECTOR64 => {
            u64::from_le_bytes(unsafe { &v.Anonymous.VI8[0..8] }.try_into().unwrap())
        }
        DEBUG_VALUE_FLOAT64 => unsafe { v.Anonymous.F64 }.to_bits(),
        DEBUG_VALUE_FLOAT32 => f64::from(unsafe { v.Anonymous.F32 }).to_bits(),
        _ => {
            bail!("expected int/float values, but got Type={:#x}", v.Type);
        }
    };

    Ok(value)
}

/// Intel x86 segment descriptor.
#[derive(Default, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Seg {
    /// Is the segment present?
    pub present: bool,
    /// Segment selector.
    pub selector: u16,
    /// Base address.
    pub base: u64,
    /// Limit.
    pub limit: u32,
    /// Segment attributes.
    pub attr: u16,
}

impl Seg {
    /// Build a [`Seg`] from a `selector` and its raw value as read in the GDT.
    pub fn from_descriptor(selector: u64, value: u128) -> Self {
        let limit = (value.bits(0..=15) | (value.bits(48..=51) << 16)) as u32;
        let mut base = value.bits(16..=39) | (value.bits(56..=63) << 24);
        let present = value.bit(47) == 1;
        let attr = value.bits(40..=55) as u16;
        let selector = selector as u16;
        let non_system = value.bit(44);
        if non_system == 0 {
            base |= value.bits(64..=95) << 32;
        }

        let granularity = value.bit(55) == 1;
        let increment = if granularity { 0x1_000 } else { 1 };
        let limit = limit
            .wrapping_mul(increment)
            .wrapping_add(if granularity { 0xfff } else { 0 });

        Seg {
            present,
            selector,
            base: base as u64,
            limit,
            attr,
        }
    }

    pub fn end_addr(&self) -> u64 {
        self.base.wrapping_add(self.limit.into())
    }
}

/// Macro to make it nicer to invoke [`DebugClient::logln`] /
/// [`DebugClient::log`] by avoiding to [`format!`] everytime the arguments.
#[macro_export]
macro_rules! dlogln {
    ($dbg:ident, $($arg:tt)*) => {{
        $dbg.logln(format!($($arg)*))
    }};
}

#[macro_export]
macro_rules! dlog {
    ($dbg:ident, $($arg:tt)*) => {{
        $dbg.log(format!($($arg)*))
    }};
}

/// Store the state of our debug output callbacks. This is used to know when to
/// capture IO from the `IDebugOutputCallbacks::Output` method.
#[derive(Default)]
struct DebugOutputCallbacksInner {
    capturing: bool,
    buffer: String,
}

impl DebugOutputCallbacksInner {
    const fn new() -> Self {
        Self {
            capturing: false,
            buffer: String::new(),
        }
    }
}

#[implement(IDebugOutputCallbacks)]
struct DebugOutputCallbacks {
    inner: Mutex<DebugOutputCallbacksInner>,
}

impl DebugOutputCallbacks {
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(DebugOutputCallbacksInner::new()),
        }
    }

    fn capture_while<F: FnOnce() -> Result<()>>(&self, f: F) -> Result<String> {
        {
            let mut inner = self.inner.lock().unwrap();
            inner.capturing = true;
            inner.buffer.clear();
        }

        // Make sure the hold is not locked at this point because we'll be reentrant and
        // deadlock otherwise:
        //
        // ```text
        // 06 snapshot!std::sys::sync::mutex::futex::Mutex::lock
        // 07 snapshot!std::sync::poison::mutex::Mutex<core::cell::RefCell<dbgeng::client::DebugOutputCallbacksInner> >::lock<core::cell::RefCell<dbgeng::client::DebugOutputCallbacksInner> >
        // 08 snapshot!dbgeng::client::impl$3::Output
        // 09 snapshot!windows::Win32::System::Diagnostics::Debug::Extensions::impl$267::new::Output<dbgeng::client::DebugOutputCallbacks_Impl,-1>
        // ...
        // 0f kdexts!irql
        // ...
        // 19 snapshot!windows::Win32::System::Diagnostics::Debug::Extensions::IDebugControl3::Execute<windows_strings::pcstr::PCSTR>
        // 1a snapshot!dbgeng::client::DebugClient::exec<ref$<str$> >
        // 1b snapshot!dbgeng::client::impl$4::exec_with_capture::closure$0<ref$<str$> >
        // 1c snapshot!dbgeng::client::DebugOutputCallbacks::capture_while<dbgeng::client::impl$4::exec_with_capture::closure_env$0<ref$<str$> > >
        // 1d snapshot!dbgeng::client::DebugClient::exec_with_capture<ref$<str$> >
        // 1e snapshot!snapshot::state
        // ```
        let res = f();

        let mut inner = self.inner.lock().unwrap();
        inner.capturing = false;

        res?;

        Ok(inner.buffer.clone())
    }
}

impl IDebugOutputCallbacks_Impl for DebugOutputCallbacks_Impl {
    fn Output(&self, _mask: u32, text: &windows::core::PCSTR) -> windows::core::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.capturing {
            return Ok(());
        }

        let s = str::from_utf8(unsafe { text.as_bytes() }).unwrap_or_default();
        inner.buffer.push_str(s);

        Ok(())
    }
}

/// Callbacks used to capture output from the debug engine.
static DEBUG_OUTPUT_CALLBACKS: StaticComObject<DebugOutputCallbacks> =
    DebugOutputCallbacks::new().into_static();

/// A debug client wraps a bunch of COM interfaces and provides higher level
/// features such as dumping registers, reading the GDT, reading virtual memory,
/// etc.
pub struct DebugClient {
    control: IDebugControl3,
    capturing_control: IDebugControl3,
    registers: IDebugRegisters,
    dataspaces: IDebugDataSpaces4,
    symbols: IDebugSymbols3,
}

impl DebugClient {
    pub fn new(client_unknown: &IUnknown) -> Result<Self> {
        let control = client_unknown.cast()?;
        let client: IDebugClient5 = client_unknown.cast()?;
        let capturing_client: IDebugClient5 = unsafe { client.CreateClient() }?.cast()?;
        let capturing_control = capturing_client.cast()?;

        let registers = client_unknown.cast()?;
        let dataspaces = client_unknown.cast()?;
        let symbols = client_unknown.cast()?;

        // We create a second client to be able to capture only what we want. If we were
        // to register those callbacks onto `client_unknown`, we would also intercept
        // our own `dlogln` statements and then there's no way for us to send it back to
        // wherever it was going before (where the debugger would display it in the
        // debugging window).
        unsafe { capturing_client.SetOutputCallbacks(DEBUG_OUTPUT_CALLBACKS.as_interface_ref()) }?;

        Ok(Self {
            control,
            capturing_control,
            registers,
            dataspaces,
            symbols,
        })
    }

    /// Output a message `s`.
    fn output<Str: Into<Vec<u8>>>(&self, mask: u32, s: Str) -> Result<()> {
        let cstr = CString::new(s.into())?;
        unsafe { self.control.Output(mask, cstr.as_pcstr()) }.context("Output failed")
    }

    /// Log a message in the debugging window.
    #[allow(dead_code)]
    pub fn log<Str: Into<Vec<u8>>>(&self, args: Str) -> Result<()> {
        self.output(DEBUG_OUTPUT_NORMAL, args)
    }

    /// Log a message followed by a new line in the debugging window.
    pub fn logln<Str: Into<Vec<u8>>>(&self, args: Str) -> Result<()> {
        self.output(DEBUG_OUTPUT_NORMAL, "[dbgeng-rs] ")?;
        self.output(DEBUG_OUTPUT_NORMAL, args)?;
        self.output(DEBUG_OUTPUT_NORMAL, "\n")
    }

    /// Execute a command on a specific `IDebugControl3`. This is useful to
    /// capture certain outputs, but at the same time leave some other ones the
    /// way they are.
    fn exec_on<Str: Into<Vec<u8>>>(control: IDebugControl3, cmd: Str) -> Result<()> {
        let cstr = CString::new(cmd.into())?;
        unsafe {
            control.Execute(
                DEBUG_OUTCTL_THIS_CLIENT,
                cstr.as_pcstr(),
                DEBUG_EXECUTE_DEFAULT,
            )
        }
        .with_context(|| format!("Execute({cstr:?}) failed"))
    }

    /// Execute a debugger command.
    pub fn exec<Str: Into<Vec<u8>>>(&self, cmd: Str) -> Result<()> {
        Self::exec_on(self.control.clone(), cmd)
    }

    /// Execute a debugger command and capture the output.
    pub fn exec_with_capture<Str: Into<Vec<u8>>>(&self, cmd: Str) -> Result<String> {
        let output = DEBUG_OUTPUT_CALLBACKS
            .capture_while(|| Self::exec_on(self.capturing_control.clone(), cmd))?;

        Ok(output)
    }

    /// Get the register indices from names.
    pub fn reg_indices(&self, names: &[&str]) -> Result<Vec<u32>> {
        let mut indices = Vec::with_capacity(names.len());
        for name in names {
            let indice = unsafe {
                self.registers
                    .GetIndexByName(CString::new(*name)?.as_pcstr())
            }
            .with_context(|| format!("GetIndexByName failed for {name}"))?;

            indices.push(indice);
        }

        Ok(indices)
    }

    /// Get the value of multiple registers.
    pub fn reg_values(&self, indices: &[u32]) -> Result<Vec<DEBUG_VALUE>> {
        let mut values = vec![DEBUG_VALUE::default(); indices.len()];
        unsafe {
            self.registers.GetValues(
                indices.len().try_into()?,
                Some(indices.as_ptr()),
                0,
                values.as_mut_ptr(),
            )
        }
        .with_context(|| format!("GetValues failed for {indices:?}"))?;

        Ok(values)
    }

    /// Get [`u128`] values for the registers identified by their names.
    pub fn regs128(&self, names: &[&str]) -> Result<Vec<u128>> {
        let indices = self.reg_indices(names)?;
        let values = self.reg_values(&indices)?;

        values.into_iter().map(u128_from_debugvalue).collect()
    }

    /// Get [`u128`] values for the registers identified by their names but
    /// returned in a dictionary with their names.
    pub fn regs128_dict<'a>(&self, names: &[&'a str]) -> Result<HashMap<&'a str, u128>> {
        let values = self.regs128(names)?;

        Ok(HashMap::from_iter(
            names.iter().zip(values).map(|(k, v)| (*k, v)),
        ))
    }

    /// Get the values of a set of registers identified by their names.
    pub fn regs64(&self, names: &[&str]) -> Result<Vec<u64>> {
        let indices = self.reg_indices(names)?;
        let values = self.reg_values(&indices)?;

        values.into_iter().map(u64_from_debugvalue).collect()
    }

    /// Get the values of a set of registers identified by their names and store
    /// both their names / values in a dictionary.
    pub fn regs64_dict<'a>(&self, names: &[&'a str]) -> Result<HashMap<&'a str, u64>> {
        let values = self.regs64(names)?;

        Ok(HashMap::from_iter(
            names.iter().zip(values).map(|(k, v)| (*k, v)),
        ))
    }

    /// Get the value of a register identified by its name.
    pub fn reg64(&self, name: &str) -> Result<u64> {
        let v = self.regs64(&[name])?;

        Ok(v[0])
    }

    /// Get the value of a specific MSR.
    pub fn msr(&self, msr: u32) -> Result<u64> {
        unsafe { self.dataspaces.ReadMsr(msr) }
            .with_context(|| format!("ReadMsr failed for {msr:#x}"))
    }

    /// Read a segment descriptor off the GDT.
    pub fn gdt_entry(&self, gdt_base: u64, gdt_limit: u16, selector: u64) -> Result<Seg> {
        // Let's first get the index out of the selector; here's what the selector looks
        // like (Figure 3-6. Segment Selector):
        //
        // 15                                                 3    2        0
        // +--------------------------------------------------+----+--------+
        // |          Index                                   | TI |   RPL  |
        // +--------------------------------------------------+----+--------+
        //
        // TI = Table Indicator: 0 = GDT, 1 = LDT
        //

        // The function will read the descriptor off the GDT, so let's make sure the
        // table indicator matches that.
        let ti = selector.bit(2);
        if ti != 0 {
            bail!("expected a GDT table indicator when reading segment descriptor");
        }

        // Extract the index so that we can calculate the address of the GDT entry.
        let index = selector.bits(3..=15);
        // 3.5.1 Segment Descriptor Tables
        // "As with segments, the limit value is added to the base address to get the
        // address of the last valid byte. A limit value of 0 results in exactly one
        // valid byte. Because segment descriptors are always 8 bytes long, the GDT
        // limit should always be one less than an integral multiple of eight (that is,
        // 8N – 1)"
        let gdt_limit = gdt_limit as u64;
        assert!((gdt_limit + 1).is_multiple_of(8));
        let max_index = (gdt_limit + 1) / 8;
        if index >= max_index {
            bail!(
                "the selector {selector:#x} has an index ({index:#x}) larger than the maximum allowed ({max_index:#})"
            );
        }

        // Most GDT entries are 8 bytes long but some are 16, so accounting for that.
        //
        // 3.5 SYSTEM DESCRIPTOR TYPES
        // "When the S (descriptor type) flag in a segment descriptor is clear, the
        // descriptor type is a system descriptor." "Note that system
        // descriptors in IA-32e mode are 16 bytes instead of 8 bytes."
        let mut descriptor = [0; 16];
        // 3.4.2 Segment Selectors
        // "The processor multiplies the index value by 8 (the number of bytes in a
        // segment descriptor).."
        let entry_addr = gdt_base + (index * 8u64);

        // Read the entry.
        self.read_virtual_exact(entry_addr, &mut descriptor)?;

        // Build the descriptor.
        Ok(Seg::from_descriptor(
            selector,
            u128::from_le_bytes(descriptor),
        ))
    }

    /// Read an exact amount of virtual memory.
    pub fn read_virtual_exact(&self, vaddr: u64, buf: &mut [u8]) -> Result<()> {
        let amount_read = self.read_virtual(vaddr, buf)?;
        if amount_read != buf.len() {
            bail!(
                "expected to read_virtual {:#x} bytes, but read {:#x}",
                buf.len(),
                amount_read
            );
        }

        Ok(())
    }

    /// Read virtual memory.
    pub fn read_virtual(&self, vaddr: u64, buf: &mut [u8]) -> Result<usize> {
        let mut amount_read = 0;
        unsafe {
            self.dataspaces.ReadVirtual(
                vaddr,
                buf.as_mut_ptr().cast(),
                buf.len().try_into()?,
                Some(&mut amount_read),
            )
        }
        .context("ReadVirtual failed")?;

        Ok(usize::try_from(amount_read)?)
    }

    /// Get the debuggee type.
    pub fn debuggee_type(&self) -> Result<(u32, u32)> {
        let mut class = 0;
        let mut qualifier = 0;
        unsafe { self.control.GetDebuggeeType(&mut class, &mut qualifier) }?;

        Ok((class, qualifier))
    }

    /// Get the processor type of the target.
    pub fn processor_type(&self) -> Result<IMAGE_FILE_MACHINE> {
        let proc_type = unsafe { self.control.GetActualProcessorType() }
            .context("GetActualProcessorType failed")?;

        Ok(IMAGE_FILE_MACHINE(proc_type.try_into()?))
    }

    /// Get the number of processors in the target.
    pub fn processor_number(&self) -> Result<u32> {
        unsafe { self.control.GetNumberProcessors() }.context("GetNumberProcessors failed")
    }

    /// Get an address for a named symbol.
    pub fn get_address_by_name<Str: Into<Vec<u8>>>(&self, symbol: Str) -> Result<u64> {
        let symbol_cstr = CString::new(symbol.into())?;

        unsafe { self.symbols.GetOffsetByName(symbol_cstr.as_pcstr()) }
            .context("GetOffsetByName failed")
    }

    /// Read a NULL terminated string at `addr`.
    pub fn read_cstring(&self, addr: u64) -> Result<String> {
        let maxbytes = 100;
        let mut buffer = vec![0; maxbytes];
        let mut length = 0;
        unsafe {
            self.dataspaces.ReadMultiByteStringVirtual(
                addr,
                maxbytes as u32,
                Some(buffer.as_mut()),
                Some(&mut length),
            )
        }?;

        if length == 0 {
            bail!("length is zero")
        }

        let length = length as usize;
        buffer.resize(length - 1, 0);

        Ok(String::from_utf8_lossy(&buffer).into_owned())
    }

    /// Evaluate an expression as a u64.
    pub fn eval64<Str: Into<Vec<u8>>>(&self, expr: Str) -> Result<u64> {
        let expr = CString::new(expr.into())?;
        let mut val = DEBUG_VALUE::default();
        unsafe {
            self.control
                .Evaluate(expr.as_pcstr(), DEBUG_VALUE_INT64, &mut val, None)
        }?;

        Ok(unsafe { val.Anonymous.Anonymous.I64 })
    }

    /// Add a synthetic module from a PE base.
    pub fn add_synthetic_module<Str1, Str2>(
        &self,
        base_expr: Str1,
        module_name: Str2,
        module_path: PathBuf,
    ) -> Result<()>
    where
        Str1: Into<Vec<u8>>,
        Str2: Into<Vec<u8>>,
    {
        // Let's evaluate the expression and get the pointer..
        let baseptr = self.eval64(base_expr)?;

        // ..read the DOS header..
        let dos_header = self.read_type_virtual::<IMAGE_DOS_HEADER>(baseptr)?;
        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            bail!("Bad DOS header signature at {baseptr:#x}");
        }

        // ..we can use `IMAGE_NT_HEADERS32` because `SizeOfImage` is at the same offset
        // for 32/64 bit
        let Some(nt_header_addr) = baseptr.checked_add(dos_header.e_lfanew as u64) else {
            bail!("Overflow when calculating NT header base address");
        };

        let nt_headers = self.read_type_virtual::<IMAGE_NT_HEADERS32>(nt_header_addr)?;
        if nt_headers.Signature != IMAGE_NT_SIGNATURE {
            bail!("Bad NT header signature at {nt_header_addr:#x}")
        }

        let image_size = nt_headers.OptionalHeader.SizeOfImage;
        let imagepath = CString::new(
            module_path
                .canonicalize()?
                .to_str()
                .context("Path is not valid")?,
        )?;
        let modulename = CString::new(module_name)?;
        let moduleimage = CString::new(
            module_path
                .file_name()
                .and_then(OsStr::to_str)
                .context("No filename present")?,
        )?;

        unsafe {
            self.symbols.AddSyntheticModule(
                baseptr,
                image_size,
                imagepath.as_pcstr(),
                modulename.as_pcstr(),
                DEBUG_ADDSYNTHMOD_DEFAULT,
            )
        }?;

        // Reload symbols for the new module, must do it w/ full DLL name
        unsafe { self.symbols.Reload(moduleimage.as_pcstr()) }
            .context("failed to reload after adding syn module")
    }

    /// Remove a synthetic module by base address.
    pub fn remove_synthetic_module(&self, base: u64) -> Result<()> {
        unsafe { self.symbols.RemoveSyntheticModule(base) }.context("failed to remove syn module")
    }

    /// Remove a synthetic module by name.
    pub fn remove_synthetic_module_by_name<Str: Into<Vec<u8>>>(&self, name: Str) -> Result<()> {
        let mut base = 0u64;
        let name = CString::new(name)?;
        unsafe {
            self.symbols
                .GetModuleByModuleName(name.as_pcstr(), 0, None, Some(&mut base))
        }?;

        self.remove_synthetic_module(base)
    }

    /// Read a sized type from debugger memory.
    ///
    /// # Safety
    ///
    /// Caller needs to make sure the type is valid.
    pub fn read_type_virtual<T>(&self, vaddr: u64) -> Result<T> {
        let mut ty = MaybeUninit::<T>::uninit();
        let mut nread = 0u32;
        let typesz = size_of::<T>();

        unsafe {
            self.dataspaces.ReadVirtual(
                vaddr,
                ty.as_mut_ptr() as _,
                typesz as u32,
                Some(&mut nread),
            )?;
        }
        if nread as usize != typesz {
            bail!("Invalid length read for type");
        }

        Ok(unsafe { ty.assume_init() })
    }
}

#[cfg(test)]
mod tests {
    use super::Seg;

    #[test]
    fn gdt() {
        // 32-bit compatibility mode for Windows x64.
        let s = Seg::from_descriptor(0x23, 0xcffb00_0000ffff);
        assert_eq!(s.end_addr(), 0xffffffff);

        // Regular code segment for Windows x64.
        let s = Seg::from_descriptor(0x33, 0x20fb00_00000000);
        assert_eq!(s.base, 0);
        assert_eq!(s.end_addr(), 0);

        // TSS64 segment.
        let s = Seg::from_descriptor(0x40, 0xfffff805_3f008b16_90000067);
        assert_eq!(s.base, 0xfffff805_3f169000);
        assert_eq!(s.end_addr(), 0xfffff805_3f169067);

        // TEB32 of a WOW64 process.
        let s = Seg::from_descriptor(0x53, 0x740f33a_30003c00);
        assert_eq!(s.base, 0x73a3000);
        assert_eq!(s.end_addr(), 0x73a6c00);
    }
}
