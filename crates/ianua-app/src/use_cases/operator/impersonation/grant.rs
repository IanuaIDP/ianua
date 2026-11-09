//! Grant impersonation: an operator takes a time-limited grant to act as
//! one tenant user, with a documented reason.

use std::sync::Arc;

use ianua_domain::domains::operator::impersonation::{ImpersonationGrant, ImpersonationTerms};
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{EventLabel, ImpersonationGrantId, UserId};

use crate::acting::OperatorAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::OperatorCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::operator::ImpersonationGrantStore;
use crate::ports::shared::{AuditLabelResolver, CrossTenantUserChecker};
use crate::ports::tenant::TenantStore;
use crate::services::lookup::existing_tenant;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The ports [`GrantUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct GrantPorts {
    /// Impersonation grants.
    pub grant_store: Arc<dyn ImpersonationGrantStore>,
    /// Tenants, for the one the user is in and whether it allows
    /// impersonation.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Whether the user exists in that tenant.
    pub user_checker: Arc<dyn CrossTenantUserChecker>,
    /// Labels captured into the audit payload.
    pub audit_label_resolver: Arc<dyn AuditLabelResolver>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
}

/// Makes an impersonation grant for the operator who asks for it.
pub struct GrantUseCase {
    ports: GrantPorts,
}

impl GrantUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: GrantPorts) -> Self {
        Self { ports }
    }

    /// Refuses a grant for a user its tenant does not hold.
    async fn ensure_user_in(&self, grant: &ImpersonationGrant) -> Result<(), AppError> {
        let present = self
            .ports
            .user_checker
            .exists_in_tenant(grant.tenant_id(), grant.user_id())
            .await
            .or_internal()?;
        if !present {
            return Err(AppError::NotFound(message!(
                "operator-target-user-not-found-in-tenant",
                "target user not found in tenant"
            )));
        }
        Ok(())
    }

    /// Refuses a second grant while the operator still holds one for the
    /// same user.
    async fn ensure_no_active_grant(&self, grant: &ImpersonationGrant) -> Result<(), AppError> {
        let existing = self
            .ports
            .grant_store
            .find_active(grant.operator_id(), grant.tenant_id(), grant.user_id())
            .await
            .or_internal()?;
        match existing {
            Some(_) => Err(AppError::Conflict(message!(
                "operator-active-impersonation-grant-already-exists",
                "active impersonation grant already exists"
            ))),
            None => Ok(()),
        }
    }

    /// The audit label of `user` in `tenant`, or their id when it has none.
    async fn user_label(&self, tenant: &Tenant, user: &UserId) -> Result<EventLabel, AppError> {
        let label = self
            .ports
            .audit_label_resolver
            .user(&ScopedTenant::from_registry(tenant), user)
            .await
            .or_internal()?;
        Ok(label.unwrap_or_else(|| EventLabel::of(&user.to_string())))
    }
}

impl Command for GrantUseCase {
    type Caller = OperatorCaller;
    type Input = ImpersonationTerms;
    type Output = Result<ImpersonationGrantId, AppError>;

    /// Grants the calling operator the right to act as the user `terms`
    /// names, for the reason and until the time it gives, records
    /// `operator.impersonation_granted`, and hands back the grant's id,
    /// which the operator names on every request made as the user.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for a missing acting operator/key; `Forbidden` for an unusable key, disabled operator or tenant forbidding impersonation.
    /// - `AppError::NotFound` for a missing tenant or user outside it; `Domain` for a grant already ended or longer than 24 hours.
    /// - `AppError::Conflict` for an existing active grant to this user; `Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &OperatorCaller,
        auditor: &RequestAuditor,
        terms: ImpersonationTerms,
    ) -> Result<ImpersonationGrantId, AppError> {
        let authority = self.ports.operator_authorities.authority(caller).await?;
        let tenant = existing_tenant(self.ports.tenant_store.as_ref(), &terms.tenant_id).await?;
        let user_label = self.user_label(&tenant, &terms.user_id).await?;
        let mut grant = ImpersonationGrant::create(&authority, &tenant, terms, user_label)
            .map_err(AppError::from_domain)?;
        self.ensure_user_in(&grant).await?;
        self.ensure_no_active_grant(&grant).await?;
        self.ports.grant_store.save(&grant).await.or_internal()?;
        auditor
            .dispatch_by(&authority.actor(), grant.take_events())
            .await
            .or_internal()?;
        Ok(*grant.id())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::compliance::OperatorImpersonation;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{TenantId, Text};
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, Refusal};
    use crate::test_support::operator::{FakeGrantStore, test_operator_caller};
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx_with};
    use crate::test_support::{
        FakeCrossTenantUserChecker, FakeEventDispatcher, block_on, test_auditor, test_ctx,
    };

    struct Setup {
        uc: GrantUseCase,
        grants: Arc<FakeGrantStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Setup {
        fn with(ports: GrantPorts) -> Self {
            let grants = Arc::new(FakeGrantStore::empty());
            Self {
                uc: GrantUseCase::new(GrantPorts {
                    grant_store: grants.clone(),
                    ..ports
                }),
                grants,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ports() -> GrantPorts {
            Self::in_tenant(OperatorImpersonation::Allowed)
        }

        fn in_tenant(impersonation: OperatorImpersonation) -> GrantPorts {
            let tenant = test_tenant_for_ctx_with(impersonation);
            GrantPorts {
                tenant_store: Arc::new(FakeTenantStore::holding(tenant)),
                ..GrantPorts::fakes()
            }
        }

        fn new() -> Self {
            Self::with(Self::ports())
        }

        fn refusing(refusal: Refusal) -> Self {
            Self::with(GrantPorts {
                operator_authorities: Arc::new(FakeOperatorAuthorities::refusing(refusal)),
                ..Self::ports()
            })
        }

        fn grant(&self, terms: ImpersonationTerms) -> Result<ImpersonationGrantId, AppError> {
            block_on(self.uc.execute(
                &test_operator_caller(),
                &test_auditor(self.audit.clone()),
                terms,
            ))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn terms_until(expires_at: OffsetDateTime) -> ImpersonationTerms {
        ImpersonationTerms {
            tenant_id: test_ctx().tenant_id(),
            user_id: UserId::new(),
            reason: Text::new("reason", "Customer ticket #12345").unwrap(),
            expires_at,
        }
    }

    fn for_an_hour() -> ImpersonationTerms {
        terms_until(clock::now() + Duration::hours(1))
    }

    /// Bob takes an hour's grant to act as Ann for a support ticket. It is
    /// saved, the grant recorded, and Bob gets the id he names it by.
    #[test]
    fn grant_impersonation_and_audits() {
        let setup = Setup::new();

        let id = setup.grant(for_an_hour()).unwrap();

        assert_eq!(setup.grants.count(), 1);
        assert!(block_on(setup.grants.find_by_id(&id)).unwrap().is_some());
        assert_eq!(setup.recorded(), vec!["operator.impersonation_granted"]);
    }

    /// Bob asks twice for the same user while the first grant holds. The
    /// second is refused as a conflict.
    #[test]
    fn grant_duplicate_returns_conflict() {
        let setup = Setup::new();
        let first = for_an_hour();
        let again = ImpersonationTerms {
            user_id: first.user_id,
            ..for_an_hour()
        };
        setup.grant(first).unwrap();

        let result = setup.grant(again);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(setup.grants.count(), 1);
    }

    /// A grant that has already ended is refused, and nothing is recorded.
    #[test]
    fn grant_expired_returns_domain_error() {
        let setup = Setup::new();

        let result = setup.grant(terms_until(clock::now() - Duration::seconds(1)));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(setup.recorded().is_empty());
    }

    /// A grant of 25 hours runs past the longest allowed and is refused.
    #[test]
    fn grant_exceeding_max_duration_returns_domain_error() {
        let setup = Setup::new();

        let result = setup.grant(terms_until(clock::now() + Duration::hours(25)));

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Twenty-four hours is the longest grant allowed, not the shortest
    /// refused: Bob asking for exactly the documented maximum gets it.
    #[test]
    fn a_grant_of_exactly_the_maximum_duration_is_allowed() {
        let setup = Setup::new();
        let now = clock::now();
        let _clock = clock::freeze(now);

        let result = setup.grant(terms_until(now + Duration::hours(24)));

        assert!(result.is_ok(), "{result:?}");
    }

    /// Bob names a tenant that does not exist. It is not found and nothing
    /// is recorded.
    #[test]
    fn grant_in_an_unknown_tenant_returns_not_found() {
        let setup = Setup::new();
        let elsewhere = ImpersonationTerms {
            tenant_id: TenantId::new(),
            ..for_an_hour()
        };

        let result = setup.grant(elsewhere);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.recorded().is_empty());
    }

    /// Bob names a user the tenant does not have. It is not found.
    #[test]
    fn grant_nonexistent_user_returns_not_found() {
        let setup = Setup::with(GrantPorts {
            user_checker: Arc::new(FakeCrossTenantUserChecker::rejecting()),
            ..Setup::ports()
        });

        let result = setup.grant(for_an_hour());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A tenant that forbids operator impersonation refuses a grant and
    /// leaves the grant store empty.
    #[test]
    fn a_tenant_that_forbids_impersonation_refuses_the_grant() {
        let setup = Setup::with(Setup::in_tenant(OperatorImpersonation::Forbidden));

        let result = setup.grant(for_an_hour());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.grants.count(), 0);
    }

    /// A tenant that forbids impersonation answers forbidden even when the
    /// requested user is absent, without disclosing that absence.
    #[test]
    fn a_tenant_that_forbids_impersonation_tells_nothing_of_an_unknown_user() {
        let setup = Setup::with(GrantPorts {
            user_checker: Arc::new(FakeCrossTenantUserChecker::rejecting()),
            ..Setup::in_tenant(OperatorImpersonation::Forbidden)
        });

        let result = setup.grant(for_an_hour());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A disabled operator's authority refusal prevents creating a grant,
    /// leaving the grant store empty.
    #[test]
    fn a_disabled_operator_is_refused() {
        let setup = Setup::refusing(Refusal::Forbidden);

        let result = setup.grant(for_an_hour());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.grants.count(), 0);
    }

    /// An unauthenticated operator cannot obtain an impersonation grant,
    /// and no grant event is recorded.
    #[test]
    fn a_signed_out_operator_is_refused() {
        let setup = Setup::refusing(Refusal::SignedOut);

        let result = setup.grant(for_an_hour());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(setup.recorded().is_empty());
    }
}
