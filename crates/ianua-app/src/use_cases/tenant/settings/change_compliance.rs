//! Change compliance: replace where a tenant's data must stay, how long its
//! audit trail is kept, and whether operators may act as its users.

use std::sync::Arc;

use ianua_domain::domains::tenant::compliance::{
    CompliancePosture, OperatorImpersonation, Residency,
};
use ianua_domain::domains::tenant::compliance_limits::ComplianceLimits;
use ianua_domain::domains::tenant::control::{TenantArea, TenantControl};
use ianua_domain::shared::events::raised::RaisesComplete as _;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgUserStore, OrganizationStore};
use crate::ports::tenant::TenantStore;
use crate::services::authentication::fresh_proof::admin::{AdminProofSources, proved_admin};
use crate::services::authentication::fresh_proof::{FreshProofs, ReenteredProof};
use crate::services::lookup::existing_tenant;
use crate::use_case::Command;

/// The posture asked for, with what the caller gave to prove who they are.
pub struct ChangeComplianceRequest {
    /// The jurisdiction the tenant's data must stay in, or anywhere.
    pub data_residency: Residency,
    /// How many days audit records are kept.
    pub audit_retention_days: u32,
    /// Whether operators may act as the tenant's users.
    pub operator_impersonation: OperatorImpersonation,
    /// What the caller typed again just now to prove who they are.
    pub proof: ReenteredProof,
}

/// The ports [`ChangeComplianceUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeCompliancePorts {
    /// Loads and saves the workspace's compliance settings.
    pub tenant_store: Arc<dyn TenantStore>,
    /// What a caller holds in their tenant, and who is signed in.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Turns what the caller typed again into a fresh proof of them.
    pub fresh_proofs: Arc<dyn FreshProofs>,
    /// Organization members, for a member changing the posture.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Organizations, for a member changing the posture.
    pub organizations: Arc<dyn OrganizationStore>,
}

/// Replaces the caller's tenant's compliance posture.
pub struct ChangeComplianceUseCase {
    limits: ComplianceLimits,
    ports: ChangeCompliancePorts,
}

impl ChangeComplianceUseCase {
    /// A use case under the deployment's compliance `limits`, writing
    /// through `ports`.
    #[must_use]
    pub fn new(limits: ComplianceLimits, ports: ChangeCompliancePorts) -> Self {
        Self { limits, ports }
    }

    /// The posture `req` asks for, refused outside the deployment's range.
    fn posture(&self, req: &ChangeComplianceRequest) -> Result<CompliancePosture, AppError> {
        CompliancePosture::new(
            req.data_residency,
            req.audit_retention_days,
            req.operator_impersonation,
            &self.limits,
        )
        .map_err(|error| AppError::from_domain(error.into()))
    }
}

impl Command for ChangeComplianceUseCase {
    type Caller = CallerContext;
    type Input = ChangeComplianceRequest;
    type Output = Result<(), AppError>;

    /// Replaces the compliance posture of the tenant `ctx` acts in and
    /// records `tenant.compliance_changed` with the posture before and
    /// after.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without compliance rights, through a key or for inadequate fresh proof.
    /// - `AppError::StepUpRequired` for a missing factor code; `AccountLocked` after too many wrong codes.
    /// - `AppError::Domain` for retention outside deployment bounds, incompatible deployment/data residency or a closed tenant.
    /// - `AppError::NotFound` for a missing tenant; `Internal` on persistence or audit failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        req: ChangeComplianceRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        TenantControl::new(&authority)
            .ensure_may(&ctx.tenant_id(), TenantArea::Compliance)
            .map_err(AppError::from_domain)?;
        let posture = self.posture(&req)?;
        let sources = AdminProofSources {
            authorities: self.ports.tenant_authorities.as_ref(),
            proofs: self.ports.fresh_proofs.as_ref(),
            members: self.ports.org_users.as_ref(),
            organizations: self.ports.organizations.as_ref(),
        };
        let admin = proved_admin(sources, ctx, req.proof).await?;
        let mut tenant =
            existing_tenant(self.ports.tenant_store.as_ref(), &ctx.tenant_id()).await?;
        tenant
            .change_compliance(
                TenantControl::new(&authority),
                admin.fresh(),
                posture,
                &self.limits,
            )
            .map_err(AppError::from_domain)?;
        self.ports.tenant_store.save(&tenant).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), tenant.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{right_password, wrong_password};
    use crate::test_support::operator::operator_without_grant;
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Setup {
        uc: ChangeComplianceUseCase,
        tenants: Arc<FakeTenantStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn with(ports: ChangeCompliancePorts) -> Self {
            let tenants = Arc::new(FakeTenantStore::holding(test_tenant_for_ctx()));
            Self {
                uc: ChangeComplianceUseCase::new(
                    ComplianceLimits::default(),
                    ChangeCompliancePorts {
                        tenant_store: tenants.clone(),
                        ..ports
                    },
                ),
                tenants,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn refusing(authorities: FakeTenantAuthorities) -> Self {
            Self::with(ChangeCompliancePorts {
                tenant_authorities: Arc::new(authorities),
                ..ChangeCompliancePorts::fakes()
            })
        }

        fn change_as(
            &self,
            ctx: &CallerContext,
            req: ChangeComplianceRequest,
        ) -> Result<(), AppError> {
            block_on(self.uc.execute(ctx, &test_auditor(self.audit.clone()), req))
        }

        fn change(&self, req: ChangeComplianceRequest) -> Result<(), AppError> {
            self.change_as(&test_ctx(), req)
        }

        fn stored(&self) -> CompliancePosture {
            block_on(self.tenants.find_by_id(&test_ctx().tenant_id()))
                .unwrap()
                .unwrap()
                .compliance()
                .clone()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn keep_for(days: u32) -> ChangeComplianceRequest {
        ChangeComplianceRequest {
            data_residency: Residency::Anywhere,
            audit_retention_days: days,
            operator_impersonation: OperatorImpersonation::Forbidden,
            proof: right_password(),
        }
    }

    /// Ann, who proved herself just now, keeps Acme's audit trail for two
    /// years. The posture is saved and the change recorded.
    #[test]
    fn a_proved_admin_changes_the_posture_and_it_is_recorded() {
        let setup = Setup::with(ChangeCompliancePorts::fakes());

        setup.change(keep_for(730)).unwrap();

        assert_eq!(setup.stored().audit_retention_days(), 730);
        assert_eq!(setup.recorded(), vec!["tenant.compliance_changed"]);
    }

    /// Retention below the deployment's minimum is refused. The tenant keeps
    /// its existing retention and no change is recorded.
    #[test]
    fn a_retention_outside_the_deployments_range_is_refused() {
        let setup = Setup::with(ChangeCompliancePorts::fakes());

        let result = setup.change(keep_for(5));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(setup.stored().audit_retention_days(), 365);
        assert!(setup.recorded().is_empty());
    }

    /// A tenant that does not exist is not found.
    #[test]
    fn an_unknown_tenant_is_not_found() {
        let uc = ChangeComplianceUseCase::new(
            ComplianceLimits::default(),
            ChangeCompliancePorts::fakes(),
        );

        let result = block_on(uc.execute(
            &test_ctx(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            keep_for(730),
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A wrong password cannot authorize operator impersonation. The tenant
    /// keeps forbidding operators from acting as its users.
    #[test]
    fn a_wrong_password_is_refused() {
        let setup = Setup::with(ChangeCompliancePorts::fakes());
        let request = ChangeComplianceRequest {
            operator_impersonation: OperatorImpersonation::Allowed,
            proof: wrong_password(),
            ..keep_for(365)
        };

        let result = setup.change(request);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(
            setup.stored().operator_impersonation(),
            OperatorImpersonation::Forbidden
        );
    }

    /// A caller without compliance-update rights cannot shorten audit
    /// retention. The existing retention stays.
    #[test]
    fn a_caller_without_the_right_is_refused() {
        let setup = Setup::refusing(FakeTenantAuthorities::holding(&[]));

        let result = setup.change(keep_for(30));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.stored().audit_retention_days(), 365);
    }

    /// A signed-out session cannot change the tenant's compliance posture.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = Setup::refusing(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = setup.change(keep_for(730));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// An operator without an impersonation grant cannot enable operator
    /// impersonation for the tenant.
    #[test]
    fn an_operator_without_a_grant_is_refused() {
        let setup = Setup::with(ChangeCompliancePorts::fakes());
        let request = ChangeComplianceRequest {
            operator_impersonation: OperatorImpersonation::Allowed,
            ..keep_for(365)
        };

        let result = setup.change_as(&operator_without_grant(), request);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
