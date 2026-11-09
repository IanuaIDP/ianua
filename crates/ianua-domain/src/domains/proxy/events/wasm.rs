//! Events about the WASM modules a tenant uploads for custom stages.

use time::OffsetDateTime;

use crate::domains::proxy::stages::stage::ModuleRef;
use crate::shared::events::data::EventData;
use crate::shared::events::event::tenant_event;

/// A tenant uploaded a WASM module for use in a `Custom` stage.
///
/// It is tied to no stage. The tenant assigns the returned `module_ref` to a
/// `WasmStageRef` themselves, the same way every other stage change is made.
#[derive(Debug)]
pub struct WasmModuleUploaded {
    /// The content-addressed reference the module is stored under.
    pub(crate) module_ref: ModuleRef,
    /// The size of the module's bytecode, in bytes.
    pub(crate) byte_len: u64,
    /// When the module was uploaded.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    WasmModuleUploaded => crate::types::event_type::ProxyEvent::WasmModuleUploaded,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("module_ref", self.module_ref.as_str())
            .field("byte_len", self.byte_len.to_string())
    }
}
