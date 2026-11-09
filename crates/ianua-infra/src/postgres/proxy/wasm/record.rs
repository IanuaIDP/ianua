//! A module as its row holds it: its bytes, which never change.

/// A module as it is read.
pub(super) struct ModuleRecord {
    pub(super) bytecode: Vec<u8>,
}

impl ModuleRecord {
    /// The module's bytes.
    pub(super) fn into_bytecode(self) -> Vec<u8> {
        self.bytecode
    }
}
