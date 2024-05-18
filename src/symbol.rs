use std::ffi::CString;

use anyhow::{Context, Result};
use windows::Win32::System::Diagnostics::Debug::Extensions::IDebugSymbols3;

use crate::as_pcstr::AsPCSTR;

#[derive(Clone)]
pub struct SymbolModule {
    /// The debugger symbols interface.
    symbols: IDebugSymbols3,
    /// The base address of this module.
    base: u64,
}

impl SymbolModule {
    pub(crate) fn new(symbols: IDebugSymbols3, base: u64) -> Self {
        Self { symbols, base }
    }

    pub fn get_type(&self, name: &str) -> Result<SymbolType> {
        let name = CString::new(name).context("failed to convert name to CString")?;
        let id = unsafe { self.symbols.GetTypeId(self.base, name.as_pcstr()) }
            .context("failed to get type ID by name")?;

        Ok(SymbolType {
            module: self.clone(),
            id,
        })
    }
}

#[derive(Clone)]
pub struct SymbolType {
    /// The module that owns this type.
    module: SymbolModule,
    /// The type ID of this symbol.
    id: u32,
}

impl SymbolType {
    pub fn get_field_offset(&self, name: &str) -> Result<u32> {
        let name = CString::new(name).context("failed to convert name to CString")?;
        let offset = unsafe {
            self.module
                .symbols
                .GetFieldOffset(self.module.base, self.id, name.as_pcstr())
        }
        .context("failed to get field offset by name")?;

        Ok(offset)
    }
}
