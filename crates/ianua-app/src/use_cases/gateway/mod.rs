//! Declarative gateway configuration: one document describing a tenant's
//! routes, services, pipelines, stream routes, egress policies and
//! consumers, exported and applied as a whole.
//!
//! A gateway configured by clicking is one nobody can review, reproduce or
//! roll back. A document keyed by name can live in a repository, be diffed
//! in a pull request, and be applied to staging before production.

pub(crate) mod apply;
pub mod diff;
pub mod document;
pub(crate) mod export_config;
pub(crate) mod import_config;
pub(crate) mod lookup;
pub(crate) mod normalize;

pub use export_config::{ExportConfigPorts, ExportConfigUseCase};
pub use import_config::{
    ApplyPlan, ImportCheckPorts, ImportConfigPorts, ImportConfigRequest, ImportConfigUseCase,
    RecordPorts,
};
