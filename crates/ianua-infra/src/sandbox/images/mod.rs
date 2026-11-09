//! Companies' own images: pinned to their digest by asking their registry
//! ([`RegistryImageResolver`]), and scanned for known vulnerabilities
//! before they first run ([`CommandImageScanner`], or [`NoImageScanner`]
//! where no scanner is set up, which clears none).

mod registry;
mod scanner;

pub use registry::RegistryImageResolver;
pub use scanner::{CommandImageScanner, NoImageScanner, ScanSettings};
