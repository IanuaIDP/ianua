//! List user sign-ins: a user's sign-ins from the tenant's audit trail,
//! failed ones included, for the person themselves or for someone who may
//! view users.
//!
//! The trail files a sign-in under the person who made it, but a failed
//! attempt under the platform, naming only the address typed, and a
//! lockout naming the account. So the list is narrowed to the person's
//! sign-ins as [`sign_ins_of`] works them out: the ones they made, the
//! lockouts of their account, and the failed attempts typed with an address
//! while their account held it. One query reads them, so they page as one
//! list, newest first.

use std::sync::Arc;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::listing::{PageRequest, SortOrder};
use crate::ports::audit::{AuditLogFilter, AuditLogPage, TenantAuditLogStore};
use crate::ports::identity::UserStore;
use crate::services::identity::sign_ins::sign_ins_of;
use crate::services::lookup::existing_user;
use crate::use_case::Query;
use crate::use_cases::identity::whose::{Whose, readable_account};

/// Whose sign-ins, and which page of them.
pub struct ListSignInsRequest {
    /// The signed-in person's own, or another user's.
    pub whose: Whose,
    /// The page of entries, newest first.
    pub page: PageRequest,
}

/// The ports [`ListSignInsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListSignInsPorts {
    /// The tenant's audit trail.
    pub audit_log: Arc<dyn TenantAuditLogStore>,
    /// The accounts, for the address the person signs in with.
    pub user_store: Arc<dyn UserStore>,
    /// Who the caller is and what they hold in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists a user's sign-ins.
pub struct ListSignInsUseCase {
    ports: ListSignInsPorts,
}

impl ListSignInsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListSignInsPorts) -> Self {
        Self { ports }
    }
}

impl Query for ListSignInsUseCase {
    type Caller = CallerContext;
    type Input = ListSignInsRequest;
    type Output = Result<AuditLogPage, AppError>;

    /// The sign-ins of `request.whose`, successful and failed, newest
    /// first, with where each came from.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts, or a person listing their own came with no session.
    /// - `AppError::Forbidden` when the caller lists another user's without
    ///   the right to view users.
    /// - `AppError::NotFound` when the account is gone.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        request: ListSignInsRequest,
    ) -> Result<AuditLogPage, AppError> {
        let authorities = self.ports.tenant_authorities.as_ref();
        let user_id = readable_account(authorities, ctx, request.whose).await?;
        let tenant = ctx.tenant();
        let account = existing_user(self.ports.user_store.as_ref(), &tenant, &user_id).await?;
        let audit_log = self.ports.audit_log.as_ref();
        let filter = AuditLogFilter {
            sign_ins_of: Some(
                sign_ins_of(audit_log, &tenant, &user_id, account.email())
                    .await
                    .or_internal()?,
            ),
            ..AuditLogFilter::default()
        };
        audit_log
            .query(&tenant, &filter, &SortOrder::default(), &request.page)
            .await
            .map_err(AppError::from_domain)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::types::{Email, UserId};

    use super::*;
    use crate::listing::Limit;
    use crate::ports::audit::HeldAddress;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::audit::WatchedAuditLog;
    use crate::test_support::authentication::test_caller_id;
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{block_on, test_ctx};

    fn list(
        log: &Arc<WatchedAuditLog>,
        authorities: FakeTenantAuthorities,
        whose: Whose,
        user: UserId,
    ) -> Result<AuditLogPage, AppError> {
        let use_case = ListSignInsUseCase::new(ListSignInsPorts {
            audit_log: log.clone(),
            user_store: Arc::new(FakeUserStore::with_user(user, "ann@acme.test")),
            tenant_authorities: Arc::new(authorities),
        });
        let request = ListSignInsRequest {
            whose,
            page: PageRequest::first(Limit::new(20).unwrap()),
        };
        block_on(use_case.execute(&test_ctx(), request))
    }

    /// Ann's sign-in query follows the address-history query in her tenant.
    /// It selects her account and held address without a target filter, so
    /// attempts recorded by address can be included.
    #[test]
    fn a_person_reads_their_own_sign_ins() {
        let log = Arc::new(WatchedAuditLog::default());
        let ann = test_caller_id();

        list(&log, FakeTenantAuthorities::holding(&[]), Whose::Own, ann).unwrap();

        let asked = log.asked();
        assert_eq!(asked.len(), 2);
        assert!(
            asked
                .iter()
                .all(|(tenant, _)| *tenant == Some(test_ctx().tenant_id()))
        );
        let sign_ins = asked[1].1.sign_ins_of.clone().unwrap();
        assert_eq!(sign_ins.user, ann);
        assert_eq!(
            sign_ins.addresses,
            [HeldAddress {
                address: Email::new("ann@acme.test").unwrap(),
                since: None,
                until: None,
            }]
        );
        assert_eq!(asked[1].1.target, None);
    }

    /// Ann, who may view users, reads Bob's sign-ins while looking into a
    /// stolen password.
    #[test]
    fn an_admin_reads_someones_sign_ins() {
        let log = Arc::new(WatchedAuditLog::default());
        let bob = UserId::new();

        list(
            &log,
            FakeTenantAuthorities::holding(&[SystemPermission::Users(UserAction::View)]),
            Whose::OnBehalfOf(bob),
            bob,
        )
        .unwrap();

        assert_eq!(log.asked()[1].1.sign_ins_of.as_ref().unwrap().user, bob);
    }

    /// A sign-in listing for a missing account returns not found without
    /// querying the audit trail.
    #[test]
    fn a_gone_account_is_not_found() {
        let log = Arc::new(WatchedAuditLog::default());

        let result = list(
            &log,
            FakeTenantAuthorities::holding(&[SystemPermission::Users(UserAction::View)]),
            Whose::OnBehalfOf(UserId::new()),
            UserId::new(),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(log.asked().is_empty());
    }

    /// Without user-viewing rights, Bob's sign-in listing is refused before
    /// querying the audit trail.
    #[test]
    fn a_caller_who_may_not_view_users_is_refused() {
        let log = Arc::new(WatchedAuditLog::default());
        let bob = UserId::new();

        let result = list(
            &log,
            FakeTenantAuthorities::holding(&[]),
            Whose::OnBehalfOf(bob),
            bob,
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(log.asked().is_empty());
    }

    /// A signed-out person cannot list their own sign-ins.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let log = Arc::new(WatchedAuditLog::default());

        let result = list(
            &log,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            Whose::Own,
            test_caller_id(),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
