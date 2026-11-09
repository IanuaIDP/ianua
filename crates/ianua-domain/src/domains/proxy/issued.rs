//! What a tenant is handed for its stages without any pipeline changing: a
//! canary decoy to plant, and a WASM module for a custom stage.
//!
//! Neither is kept on a pipeline. The tenant puts the decoy or the module's
//! reference into a stage the way every other stage change is made. What is
//! recorded is that one was handed out, and to whom. Each is a short-lived
//! value: it admits the person, raises its record and is dropped once the
//! record is taken.

use std::marker::PhantomData;

use crate::domains::proxy::events::{CanaryTokenGenerated, WasmModuleUploaded};
use crate::domains::proxy::stages::stage::ModuleRef;
use crate::domains::routing::control::{RoutingControl, RoutingRight};
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};

/// A canary decoy handed to a person who may change pipelines.
///
/// Sam may only view pipelines. Without this check, he asks for decoys to
/// learn what the tenant plants, and leaves them out of what he steals.
#[derive(Debug)]
pub struct CanaryIssue<T: TenantScope> {
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> CanaryIssue<T> {
    /// Hands `by` a decoy. The token itself is made outside the domain and
    /// never recorded. Raises `proxy.canary_token_generated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change pipelines.
    pub fn issue(by: &RoutingControl<'_>) -> Result<Self, DomainError> {
        by.ensure_may(RoutingRight::ChangePipeline)?;
        let mut issue = Self {
            raised: Raised::default(),
            _scope: PhantomData,
        };
        issue.raised.raise(CanaryTokenGenerated {
            occurred_at: crate::shared::clock::now(),
        });
        Ok(issue)
    }
}

impl<T: TenantScope> Raises for CanaryIssue<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// A WASM module a person who may change pipelines uploads for a custom
/// stage.
///
/// Sam may only view pipelines. Without this check, he uploads a module of
/// his own to run inside the proxy, in front of every route that names it.
#[derive(Debug)]
pub struct WasmModuleUpload<T: TenantScope> {
    byte_len: u64,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> WasmModuleUpload<T> {
    /// Admits `by` uploading `bytecode`. Nothing is raised until the module
    /// is stored, since only the store names it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change pipelines.
    pub fn admit(bytecode: &[u8], by: &RoutingControl<'_>) -> Result<Self, DomainError> {
        by.ensure_may(RoutingRight::ChangePipeline)?;
        Ok(Self {
            byte_len: u64::try_from(bytecode.len()).unwrap_or(u64::MAX),
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The module was stored under `module_ref`. Raises
    /// `proxy.wasm_module_uploaded` with the reference and the module's size.
    pub fn record_upload(&mut self, module_ref: ModuleRef) {
        self.raised.raise(WasmModuleUploaded {
            module_ref,
            byte_len: self.byte_len,
            occurred_at: crate::shared::clock::now(),
        });
    }
}

impl<T: TenantScope> Raises for WasmModuleUpload<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::{PipelineAction, SystemPermission};
    use crate::domains::routing::fixtures::holding;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::events::{raised, raised_names};

    const MODULE: &[u8] = b"\0asm\x01\0\0\0";

    fn changing_pipelines() -> RoutingControl<'static> {
        holding(&[SystemPermission::Pipeline(PipelineAction::Update)])
    }

    fn viewing_pipelines() -> RoutingControl<'static> {
        holding(&[SystemPermission::Pipeline(PipelineAction::View)])
    }

    /// Fay asks for a decoy. That one was handed out is raised.
    #[test]
    fn issuing_a_canary_raises_proxy_canary_token_generated() {
        let mut issue = CanaryIssue::<ResolvedTenant>::issue(&changing_pipelines()).unwrap();

        assert_eq!(raised_names(&mut issue), ["proxy.canary_token_generated"]);
    }

    /// Pipeline-viewing permission does not permit canary issuance. The
    /// request is forbidden.
    #[test]
    fn a_canary_needs_the_pipeline_right() {
        let issued = CanaryIssue::<ResolvedTenant>::issue(&viewing_pipelines());

        assert!(matches!(issued, Err(DomainError::Forbidden(_))));
    }

    /// Fay uploads a module and the store keeps it. The upload is raised
    /// with the reference the store gave it and its size.
    #[test]
    fn a_stored_module_raises_proxy_wasm_module_uploaded() {
        let mut upload =
            WasmModuleUpload::<ResolvedTenant>::admit(MODULE, &changing_pipelines()).unwrap();

        upload.record_upload(ModuleRef::new("sha256:abc").unwrap());

        let events = raised(&mut upload);
        assert_eq!(
            events[0].event_type().to_string(),
            "proxy.wasm_module_uploaded"
        );
        assert_eq!(events[0].payload().get("module_ref"), Some("sha256:abc"));
        assert_eq!(events[0].payload().get("byte_len"), Some("8"));
    }

    /// Fay's upload is admitted but the store refuses the module. Nothing
    /// was stored, so nothing is raised.
    #[test]
    fn an_upload_never_stored_raises_nothing() {
        let mut upload =
            WasmModuleUpload::<ResolvedTenant>::admit(MODULE, &changing_pipelines()).unwrap();

        assert!(raised_names(&mut upload).is_empty());
    }

    /// A caller with only pipeline-viewing permission is forbidden admission
    /// to upload a WASM module.
    #[test]
    fn an_upload_needs_the_pipeline_right() {
        let admitted = WasmModuleUpload::<ResolvedTenant>::admit(MODULE, &viewing_pipelines());

        assert!(matches!(admitted, Err(DomainError::Forbidden(_))));
    }
}
