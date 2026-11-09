//! Act as: the caller a tenant admin acts through as the person an
//! impersonation names, once `acting` grants it now.
//!
//! The caller carries the admin's own session and the impersonation, and
//! `acting` works out what it holds again on every use: what the person
//! holds, while the admin's session counts and the window is open. A window
//! that ran out, an end the person asked for, or a lock put on the account
//! stops the admin at once, since nothing is trusted from an earlier check.
//! Every action taken through it is recorded as the admin's, done as the
//! person through the impersonation.

use std::sync::Arc;

use ianua_domain::message;
use ianua_domain::types::SupportImpersonationId;
use time::OffsetDateTime;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::identity::SupportImpersonationStore;
use crate::use_case::Query;
use crate::use_cases::identity::impersonation::lookup::involving;

/// The ports [`ActAsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ActAsPorts {
    /// Keeps the impersonations.
    pub impersonation_store: Arc<dyn SupportImpersonationStore>,
    /// Who is signed in to the caller's session, and what a caller acting
    /// through an impersonation holds.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// The caller an admin acts through as the person, and until when.
#[derive(Debug, Clone)]
pub struct ActingAs {
    /// The caller every later request acts as: the admin, through the
    /// impersonation, holding what the person holds.
    pub caller: CallerContext,
    /// When the window closes and the caller stops counting.
    pub ends_at: OffsetDateTime,
}

/// Gives the admin signed in the caller they act through as the person.
pub struct ActAsUseCase {
    ports: ActAsPorts,
}

impl ActAsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ActAsPorts) -> Self {
        Self { ports }
    }
}

impl Query for ActAsUseCase {
    type Caller = CallerContext;
    type Input = SupportImpersonationId;
    type Output = Result<ActingAs, AppError>;

    /// The caller the admin signed in to `ctx`'s session acts through as the
    /// person impersonation `id` names, once `acting` grants it: they are
    /// its admin, its window is open, and the account may sign in now.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with no tenant
    ///   session, or it no longer counts.
    /// - `AppError::NotFound` when there is no such impersonation involving
    ///   them.
    /// - `AppError::Forbidden` when they are not its admin, it is not active
    ///   or its window is over, or the account may not sign in now.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        id: SupportImpersonationId,
    ) -> Result<ActingAs, AppError> {
        let admin = self.ports.tenant_authorities.signed_in(ctx).await?;
        let store = self.ports.impersonation_store.as_ref();
        let impersonation = involving(store, &ctx.tenant(), &id, admin.account.id()).await?;
        let caller = ctx.through_support_impersonation(id, *impersonation.user_id())?;
        self.ports.tenant_authorities.authority(&caller).await?;
        let ends_at = impersonation.ends_at().ok_or_else(not_active)?;
        Ok(ActingAs { caller, ends_at })
    }
}

/// The refusal for an impersonation whose window is not open.
fn not_active() -> AppError {
    AppError::Forbidden(message!(
        "identity-the-impersonation-is-not-active",
        "the impersonation is not active"
    ))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::builder::ActedThrough;
    use ianua_domain::domains::identity::impersonation::SupportImpersonation;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::authentication::test_caller_id;
    use crate::test_support::identity::{
        FakeSupportImpersonationStore, impersonation_active, impersonation_asked,
        support_acting_over,
    };
    use crate::test_support::{block_on, test_ctx};

    /// Ann, signed in, asks to act through `held`, in a tenant holding her
    /// and `other`.
    fn act_as(
        held: &SupportImpersonation<ResolvedTenant>,
        other: UserId,
    ) -> Result<ActingAs, AppError> {
        let store = Arc::new(FakeSupportImpersonationStore::holding(held));
        let use_case = ActAsUseCase::new(ActAsPorts {
            impersonation_store: store.clone(),
            tenant_authorities: support_acting_over(store, other),
        });
        block_on(use_case.execute(&test_ctx(), *held.id()))
    }

    /// Bob approved Ann acting as him. Within the window she gets a caller
    /// that holds what Bob holds, and every action through it is recorded
    /// as Ann's, done as Bob through the impersonation.
    #[test]
    fn the_admin_acts_as_the_person_within_an_open_window() {
        let bob = UserId::new();
        let active = impersonation_active(test_caller_id(), bob);

        let acting = act_as(&active, bob).unwrap();

        assert_eq!(
            acting.caller.audit_context().acted_through(),
            ActedThrough::SupportImpersonation {
                admin: test_caller_id(),
                as_user: bob,
                impersonation: *active.id(),
            }
        );
    }

    /// Ann cannot act as Bob while her impersonation request awaits his approval.
    #[test]
    fn a_request_not_yet_approved_is_refused() {
        let bob = UserId::new();
        let asked = impersonation_asked(test_caller_id(), bob);

        let result = act_as(&asked, bob);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// The impersonated person cannot use the approved impersonation as
    /// though they were its requesting administrator.
    #[test]
    fn only_the_admin_acts_through_it() {
        let sam = UserId::new();
        let active = impersonation_active(sam, test_caller_id());

        let result = act_as(&active, sam);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
