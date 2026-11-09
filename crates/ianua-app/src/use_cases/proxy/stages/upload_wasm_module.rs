//! Upload WASM module: store a tenant-authored module and return the
//! content-addressed reference a `Custom` stage names it by.
//!
//! This is the only way a module reference comes into existence. The store
//! computes it from the bytecode, so a tenant never names bytes it has not
//! uploaded here first.

use std::sync::Arc;

use ianua_domain::domains::proxy::issued::WasmModuleUpload;
use ianua_domain::domains::proxy::stages::stage::ModuleRef;
use ianua_domain::domains::routing::control::RoutingControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::proxy::WasmModuleStore;
use crate::use_case::Command;

/// The ports [`UploadWasmModuleUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UploadWasmModulePorts {
    /// Keeps the bytecode and computes its reference.
    pub wasm_module_store: Arc<dyn WasmModuleStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Uploads a tenant's WASM stage module.
pub struct UploadWasmModuleUseCase {
    ports: UploadWasmModulePorts,
}

impl UploadWasmModuleUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UploadWasmModulePorts) -> Self {
        Self { ports }
    }
}

impl Command for UploadWasmModuleUseCase {
    type Caller = CallerContext;
    type Input = Vec<u8>;
    type Output = Result<ModuleRef, AppError>;

    /// Stores `bytecode`, records `proxy.wasm_module_uploaded`, and returns
    /// its reference.
    ///
    /// No stage is created or changed: the caller puts the reference in a
    /// `Custom` stage the way every other stage change is made.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not change pipelines.
    /// - `AppError::Domain` when `bytecode` is larger than a module may be.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        bytecode: Vec<u8>,
    ) -> Result<ModuleRef, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let mut upload =
            WasmModuleUpload::<ResolvedTenant>::admit(&bytecode, &RoutingControl::new(&authority))
                .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let module_ref = self
            .ports
            .wasm_module_store
            .save(&tenant, &bytecode)
            .await
            .map_err(AppError::from_domain)?;
        upload.record_upload(module_ref.clone());

        auditor
            .dispatch_by(&caller.actor(), upload.take_events(&tenant))
            .await
            .or_internal()?;

        Ok(module_ref)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{PipelineAction, SystemPermission};
    use ianua_domain::shared::errors::DomainError;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::FakeWasmModuleStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const MODULE: &[u8] = b"\0asm\x01\0\0\0";

    fn upload(
        max_bytes: usize,
        authorities: FakeTenantAuthorities,
        audit: &Arc<FakeEventDispatcher>,
    ) -> Result<ModuleRef, AppError> {
        let use_case = UploadWasmModuleUseCase::new(UploadWasmModulePorts {
            wasm_module_store: Arc::new(FakeWasmModuleStore::limited_to(max_bytes)),
            tenant_authorities: Arc::new(authorities),
        });
        block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), MODULE.to_vec()))
    }

    /// Ann uploads a module for a custom stage. She gets its reference and
    /// the upload is recorded.
    #[test]
    fn a_module_is_stored_and_its_reference_returned() {
        let audit = Arc::new(FakeEventDispatcher::new());

        let module_ref = upload(1024, FakeTenantAuthorities::holding_everything(), &audit).unwrap();

        assert!(module_ref.as_str().starts_with("sha256:"));
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["proxy.wasm_module_uploaded"]
        );
    }

    /// Ann uploads a module the store refuses to keep, as it refuses one
    /// past the size a module may be. The store decides that size, not this
    /// use case: what is shown here is that its refusal reaches Ann as
    /// invalid, and that no upload is recorded for a module never stored.
    #[test]
    fn a_module_the_store_refuses_is_invalid_and_not_recorded() {
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = upload(4, FakeTenantAuthorities::holding_everything(), &audit);

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// A pipeline viewer cannot upload a WASM module, and the refusal creates
    /// no upload audit record.
    #[test]
    fn a_caller_without_the_pipeline_right_is_refused() {
        let audit = Arc::new(FakeEventDispatcher::new());

        let result = upload(
            1024,
            FakeTenantAuthorities::holding(&[SystemPermission::Pipeline(PipelineAction::View)]),
            &audit,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(audit.records.lock().unwrap().is_empty());
    }

    /// Uploading a WASM module with a signed-out session fails authentication.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = upload(
            1024,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            &Arc::new(FakeEventDispatcher::new()),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
