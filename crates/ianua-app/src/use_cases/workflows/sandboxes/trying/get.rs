//! Get trial: how one trial of a sandbox version went, for someone who may
//! view workflows.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::WorkflowAction;
use ianua_domain::domains::workflows::control::WorkflowControl;
use ianua_domain::domains::workflows::sandbox::trial::SandboxTrial;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{SandboxId, SandboxTrialId};

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::workflows::SandboxTrialStore;
use crate::use_case::Query;
use crate::use_cases::workflows::sandboxes::trying::lookup::existing_trial;

/// Which trial to read.
pub struct GetTrialRequest {
    /// The sandbox whose version it tries.
    pub sandbox_id: SandboxId,
    /// The test execution whose result and output are requested.
    pub trial_id: SandboxTrialId,
}

/// The ports [`GetTrialUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GetTrialPorts {
    /// Keeps the trials.
    pub trials: Arc<dyn SandboxTrialStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads trials.
pub struct GetTrialUseCase {
    ports: GetTrialPorts,
}

impl GetTrialUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: GetTrialPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetTrialUseCase {
    type Caller = CallerContext;
    type Input = GetTrialRequest;
    type Output = Result<SandboxTrial<ResolvedTenant>, AppError>;

    /// The trial `request.trial_id` of the sandbox it names: its input,
    /// and how it went once it ran.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view workflows.
    /// - `AppError::NotFound` when the tenant has no such trial of that
    ///   sandbox, or it was cleared.
    /// - `AppError::Internal` when the store fails.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: GetTrialRequest,
    ) -> Result<SandboxTrial<ResolvedTenant>, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        WorkflowControl::new(&authority)
            .ensure_may(WorkflowAction::View)
            .map_err(AppError::from_domain)?;
        existing_trial(
            self.ports.trials.as_ref(),
            &ctx.tenant(),
            &request.sandbox_id,
            &request.trial_id,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::SystemPermission;
    use ianua_domain::domains::workflows::data::FlowData;

    use super::*;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::workflows::{
        FakeSandboxTrialStore, built_version_of, managing, person, python_sandbox,
    };
    use crate::test_support::{block_on, test_ctx};

    const VIEWS: [SystemPermission; 1] = [SystemPermission::Workflows(WorkflowAction::View)];

    /// Max, who may view workflows, reads Tess's trial of a sandbox; asked
    /// for it under another sandbox, it is not found.
    #[test]
    fn a_trial_is_read_only_under_its_own_sandbox() {
        let mut sandbox = python_sandbox();
        let version = built_version_of(&mut sandbox);
        let trial = sandbox
            .try_version(
                &managing(&person("tess@corp.test")),
                &version,
                FlowData::null(),
            )
            .unwrap();
        let use_case = GetTrialUseCase::new(GetTrialPorts {
            trials: Arc::new(FakeSandboxTrialStore::holding(&trial)),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&VIEWS)),
        });
        let read = |sandbox_id| {
            block_on(use_case.execute(
                &test_ctx(),
                GetTrialRequest {
                    sandbox_id,
                    trial_id: *trial.id(),
                },
            ))
        };

        let own = read(*sandbox.id());
        let other = read(SandboxId::new());

        assert_eq!(own.unwrap().id(), trial.id());
        assert!(matches!(other, Err(AppError::NotFound(_))));
    }
}
