//! Revoke impersonation: an operator ends their own grant early.

use std::sync::Arc;

use ianua_domain::domains::operator::impersonation::ImpersonationGrant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{EventLabel, ImpersonationGrantId};

use crate::acting::OperatorAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::OperatorCaller;
use crate::error::{AppError, OrConflict, OrInternal};
use crate::ports::operator::ImpersonationGrantStore;
use crate::ports::shared::AuditLabelResolver;
use crate::ports::tenant::TenantStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::operator::lookup::owned_grant;

/// The ports [`RevokeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokePorts {
    /// Impersonation grants.
    pub grant_store: Arc<dyn ImpersonationGrantStore>,
    /// Tenants, to scope the label lookup to the grant's.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Labels captured into the audit payload.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Revokes an impersonation grant its holder no longer needs.
pub struct RevokeUseCase {
    ports: RevokePorts,
}

impl RevokeUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: RevokePorts) -> Self {
        Self { ports }
    }

    /// The impersonated user's audit label, falling back to their id when
    /// the tenant or the user no longer exists: a grant on a deleted tenant
    /// must still be revocable.
    async fn user_label(&self, grant: &ImpersonationGrant) -> Result<EventLabel, AppError> {
        let fallback = || EventLabel::of(&grant.user_id().to_string());
        let Some(tenant) = self
            .ports
            .tenant_store
            .find_by_id(grant.tenant_id())
            .await
            .or_internal()?
        else {
            return Ok(fallback());
        };
        let label = self
            .ports
            .audit_label_resolver
            .user(&ScopedTenant::from_registry(&tenant), grant.user_id())
            .await
            .or_internal()?;
        Ok(label.unwrap_or_else(fallback))
    }
}

impl Command for RevokeUseCase {
    type Caller = OperatorCaller;
    type Input = ImpersonationGrantId;
    type Output = Result<(), AppError>;

    /// Revokes the calling operator's grant `grant_id` at once and records
    /// `operator.impersonation_revoked`, attributed to the grant's tenant.
    ///
    /// Another operator who sees a grant misused ends it by disabling its
    /// holder, which stops every grant they hold.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for a missing acting operator/key; `Forbidden` for an unusable key or disabled operator.
    /// - `AppError::NotFound` for a missing/foreign grant; `Domain` for an already revoked grant.
    /// - `AppError::Conflict` for a concurrent revocation; `Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &OperatorCaller,
        auditor: &RequestAuditor,
        grant_id: ImpersonationGrantId,
    ) -> Result<(), AppError> {
        let authority = self.ports.operator_authorities.authority(caller).await?;
        let mut grant = owned_grant(self.ports.grant_store.as_ref(), &grant_id, &authority).await?;
        let user_label = self.user_label(&grant).await?;
        grant
            .revoke(&authority, user_label)
            .map_err(AppError::from_domain)?;
        self.ports
            .grant_store
            .save(&grant)
            .await
            .or_conflict(message!(
                "authentication-the-grant-was-revoked-meanwhile",
                "the grant was revoked meanwhile"
            ))?;
        auditor
            .dispatch_by(&authority.actor(), grant.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{OperatorId, TenantId, UserId};

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, Refusal};
    use crate::test_support::operator::{
        FakeGrantStore, stored_grant, test_operator_caller, test_operator_id,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    struct Setup {
        uc: RevokeUseCase,
        grants: Arc<FakeGrantStore>,
        audit: Arc<FakeEventDispatcher>,
        grant_id: ImpersonationGrantId,
    }

    impl Setup {
        fn holding(holder: OperatorId, authorities: FakeOperatorAuthorities) -> Self {
            let grant = stored_grant(holder, TenantId::new(), UserId::new());
            let grant_id = *grant.id();
            let grants = Arc::new(FakeGrantStore::holding([grant]));
            Self {
                uc: RevokeUseCase::new(RevokePorts {
                    grant_store: grants.clone(),
                    operator_authorities: Arc::new(authorities),
                    ..RevokePorts::fakes()
                }),
                grants,
                audit: Arc::new(FakeEventDispatcher::new()),
                grant_id,
            }
        }

        fn new() -> Self {
            Self::holding(test_operator_id(), FakeOperatorAuthorities::admitting())
        }

        fn revoke(&self, grant_id: ImpersonationGrantId) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &test_operator_caller(),
                &test_auditor(self.audit.clone()),
                grant_id,
            ))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Bob is done with Ann's ticket and ends his grant. It is revoked and
    /// the revocation recorded, even though its tenant is gone.
    #[test]
    fn revoke_grant_and_audits() {
        let setup = Setup::new();

        setup.revoke(setup.grant_id).unwrap();

        assert_eq!(setup.grants.revoked(), 1);
        assert_eq!(setup.recorded(), vec!["operator.impersonation_revoked"]);
    }

    /// Bob ends his grant twice. The second is refused as a transition the
    /// grant cannot make, and only the first is recorded.
    #[test]
    fn revoke_already_revoked_is_refused() {
        let setup = Setup::new();
        setup.revoke(setup.grant_id).unwrap();

        let result = setup.revoke(setup.grant_id);

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::InvalidTransition(_)))
        ));
        assert_eq!(setup.recorded().len(), 1);
    }

    /// Bob names a grant that does not exist. It is not found and nothing
    /// is recorded.
    #[test]
    fn revoke_nonexistent_returns_not_found() {
        let setup = Setup::new();

        let result = setup.revoke(ImpersonationGrantId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.recorded().is_empty());
    }

    /// Another operator's grant answers not found when revocation is
    /// requested, and the grant remains unrevoked.
    #[test]
    fn another_operators_grant_reads_as_missing() {
        let setup = Setup::holding(OperatorId::new(), FakeOperatorAuthorities::admitting());

        let result = setup.revoke(setup.grant_id);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(setup.grants.revoked(), 0);
    }

    /// A disabled operator's authority refusal prevents revoking a grant.
    #[test]
    fn a_disabled_operator_is_refused() {
        let setup = Setup::holding(
            test_operator_id(),
            FakeOperatorAuthorities::refusing(Refusal::Forbidden),
        );

        let result = setup.revoke(setup.grant_id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An unauthenticated operator cannot revoke an impersonation grant.
    #[test]
    fn a_signed_out_operator_is_refused() {
        let setup = Setup::holding(
            test_operator_id(),
            FakeOperatorAuthorities::refusing(Refusal::SignedOut),
        );

        let result = setup.revoke(setup.grant_id);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
