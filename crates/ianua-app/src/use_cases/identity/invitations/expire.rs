//! Expire invitations: the background sweep that marks invitations whose
//! link ran out as expired, and closes the accounts that waited on them.
//!
//! A link past its expiry already does nothing. Marking the invitation says
//! so on the record, so the invited account no longer waits in the user
//! list as invited for good.

use std::sync::Arc;

use ianua_domain::domains::identity::invitations::invitation::Invitation;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ActorRef;
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::listing::{Limit, PageRequest};
use crate::ports::identity::{InvitationStore, UserStore};
use crate::ports::runtime::UnitOfWork;
use crate::ports::tenant::TenantStore;
use crate::services::kept_together::kept_together;
use crate::services::lookup::existing_user;
use crate::services::tenant_batches::TenantBatches;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The ports [`ExpireUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ExpirePorts {
    /// Lists the tenants to look in.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Finds and saves invitations.
    pub invitation_store: Arc<dyn InvitationStore>,
    /// Loads and saves the accounts that waited on them.
    pub user_store: Arc<dyn UserStore>,
    /// Keeps each invitation's changes and the record of them together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Marks every invitation whose link ran out as expired.
pub struct ExpireUseCase {
    ports: ExpirePorts,
}

/// One tenant the sweep works in, with the auditor its records go through.
struct InTenant<'a> {
    tenant: ScopedTenant,
    auditor: &'a RequestAuditor,
    now: OffsetDateTime,
}

impl ExpireUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ExpirePorts) -> Self {
        Self { ports }
    }

    /// How many of one tenant's invitations were marked expired.
    async fn expire_in(&self, within: &InTenant<'_>) -> Result<u64, AppError> {
        let mut request = PageRequest::first(Limit::internal(500));
        let mut expired = 0;
        loop {
            let page = self
                .ports
                .invitation_store
                .find_lapsed(&within.tenant, within.now, &request)
                .await
                .or_internal()?;
            let next = request.following(&page);
            expired += self.expire_batch(within, page.items).await;
            let Some(next) = next else {
                return Ok(expired);
            };
            request = next;
        }
    }

    /// Attempts each invitation once, keeping failures for a later sweep rather
    /// than allowing them to prevent progress through the current batch.
    async fn expire_batch(
        &self,
        within: &InTenant<'_>,
        lapsed: Vec<Invitation<ResolvedTenant>>,
    ) -> u64 {
        let mut expired = 0;
        for invitation in lapsed {
            let invitation_id = *invitation.id();
            let lapsing = self.lapse(within, invitation);
            match kept_together(self.ports.unit_of_work.as_ref(), lapsing).await {
                Ok(()) => expired += 1,
                Err(error) => tracing::warn!(
                    tenant_id = %*within.tenant,
                    %invitation_id,
                    %error,
                    "invitation could not be marked expired; tried again next run"
                ),
            }
        }
        expired
    }

    /// Marks `invitation` expired, closes the account that waited on it,
    /// and records it, by the platform.
    async fn lapse(
        &self,
        within: &InTenant<'_>,
        mut invitation: Invitation<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let (users, tenant) = (self.ports.user_store.as_ref(), &within.tenant);
        let mut user = existing_user(users, tenant, invitation.user_id()).await?;
        invitation
            .lapse(&user, within.now)
            .map_err(AppError::from_domain)?;
        let closed = invitation.close_unanswered(&mut user);
        closed.map_err(AppError::from_domain)?;

        let invitations = self.ports.invitation_store.as_ref();
        invitations.save(tenant, &invitation).await.or_internal()?;
        users.save(tenant, &user).await.or_internal()?;
        within
            .auditor
            .dispatch_by(&ActorRef::System, invitation.take_events(tenant))
            .await
            .or_internal()
    }
}

impl Command for ExpireUseCase {
    type Caller = ();
    type Input = OffsetDateTime;
    type Output = Result<u64, AppError>;

    /// Marks every invitation in every tenant whose link ran out by `now`
    /// as expired, closes the account that waited on each, and returns how
    /// many were marked.
    ///
    /// Each invitation is kept together with its record as one unit. One
    /// that cannot be marked is logged and tried again on the next run; it
    /// does not stop the others. Each tenant's records go through `auditor`
    /// scoped to that tenant, attributed to the system.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the tenants or a tenant's lapsed
    ///   invitations cannot be read.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        now: OffsetDateTime,
    ) -> Result<u64, AppError> {
        let mut expired = 0;
        let mut tenants = TenantBatches::over(self.ports.tenant_store.as_ref());
        while let Some(batch) = tenants.next().await? {
            for tenant in &batch {
                let tenant_auditor = auditor.with_tenant(*tenant.id());
                let within = InTenant {
                    tenant: ScopedTenant::for_background(*tenant.id()),
                    auditor: &tenant_auditor,
                    now,
                };
                expired += self.expire_in(&within).await?;
            }
        }
        Ok(expired)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::identity::invitations::status::InvitationStatus;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{RoleId, UserId};

    use super::*;
    use crate::ports::runtime::Settlement;
    use crate::test_support::identity::{
        FakeInvitationStore, FakeUserStore, InvitationSeed, hash_of_link, stored_user,
    };
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{
        FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor, test_ctx,
    };

    /// Acme's stores, with invitations seeded into them, and what watches
    /// the sweep.
    struct Acme {
        users: Arc<FakeUserStore>,
        invitations: Arc<FakeInvitationStore>,
        unit: Arc<RecordingUnitOfWork>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Acme {
        fn new() -> Self {
            Self {
                users: Arc::new(FakeUserStore::empty()),
                invitations: Arc::new(FakeInvitationStore::empty()),
                unit: Arc::new(RecordingUnitOfWork::default()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// Invites someone whose link carries `link` and runs out at
        /// `expires_at`, and returns their waiting account.
        fn invite(&self, link: &str, expires_at: OffsetDateTime) -> UserId {
            let user_id = UserId::new();
            let email = format!("{link}@acme.com");
            self.users
                .add(stored_user(user_id, &email, UserStatus::Invited));
            let invitation = InvitationSeed::for_user(user_id, &email, RoleId::new(), link)
                .expiring_at(expires_at)
                .stored();
            block_on(self.invitations.save(&test_ctx().tenant(), &invitation)).unwrap();
            user_id
        }

        fn sweep(&self) -> u64 {
            let use_case = ExpireUseCase::new(ExpirePorts {
                tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
                invitation_store: self.invitations.clone(),
                user_store: self.users.clone(),
                unit_of_work: self.unit.clone(),
            });
            block_on(use_case.execute(&(), &test_auditor(self.sink.clone()), clock::now())).unwrap()
        }

        fn status(&self, link: &str) -> InvitationStatus {
            block_on(
                self.invitations
                    .find_by_token_hash(&test_ctx().tenant(), &hash_of_link(link)),
            )
            .unwrap()
            .unwrap()
            .status()
        }
    }

    fn ago(hours: i64) -> OffsetDateTime {
        clock::now() - time::Duration::hours(hours)
    }

    /// More than one batch of expired invitations is processed in bounded reads.
    /// A missing account in the first batch stays pending without starving later
    /// invitations, and a second sweep retries only that failed invitation.
    #[test]
    fn expiry_reads_bounded_batches_and_progresses_past_failures() {
        let acme = Acme::new();
        let failed =
            InvitationSeed::for_user(UserId::new(), "failed@acme.com", RoleId::new(), "failed")
                .expiring_at(ago(48))
                .stored();
        block_on(acme.invitations.save(&test_ctx().tenant(), &failed)).unwrap();
        for index in 0..501 {
            acme.invite(&format!("invitee-{index}"), ago(24));
        }

        assert_eq!(acme.sweep(), 501);
        assert_eq!(acme.status("failed"), InvitationStatus::Pending);
        assert_eq!(acme.sink.records.lock().unwrap().len(), 501);
        assert_eq!(acme.sweep(), 0);
        assert_eq!(acme.sink.records.lock().unwrap().len(), 501);
        let reads = acme.invitations.lapsed_reads();
        assert!(
            reads.iter().all(|count| *count <= 500),
            "unbounded reads: {reads:?}"
        );
        assert_eq!(reads.iter().sum::<usize>(), 503);
    }

    /// Bob's invitation ran out yesterday. The sweep marks it expired,
    /// closes his waiting account, and records it.
    #[test]
    fn a_lapsed_invitation_is_marked_expired_and_its_account_closed() {
        let acme = Acme::new();
        let bob = acme.invite("bob", ago(24));

        let expired = acme.sweep();

        assert_eq!(expired, 1);
        assert_eq!(acme.status("bob"), InvitationStatus::Expired);
        assert_eq!(acme.users.get_status(&bob), Some(UserStatus::Deactivated));
        assert_eq!(
            acme.sink.records.lock().unwrap().as_slice(),
            ["identity.invitation_expired"]
        );
    }

    /// Cleo's invitation works for another day. The sweep leaves it and her
    /// account alone.
    #[test]
    fn an_invitation_that_still_works_is_left_alone() {
        let acme = Acme::new();
        let cleo = acme.invite("cleo", clock::now() + time::Duration::days(1));

        let expired = acme.sweep();

        assert_eq!(expired, 0);
        assert_eq!(acme.status("cleo"), InvitationStatus::Pending);
        assert_eq!(acme.users.get_status(&cleo), Some(UserStatus::Invited));
        assert!(acme.sink.records.lock().unwrap().is_empty());
    }

    /// Two invitations ran out. Each is marked and committed on its own.
    #[test]
    fn each_lapsed_invitation_is_kept_as_one_unit() {
        let acme = Acme::new();
        acme.invite("bob", ago(24));
        acme.invite("dan", ago(2));

        acme.sweep();

        assert_eq!(
            acme.unit.settlements(),
            vec![Settlement::Commit, Settlement::Commit]
        );
    }

    /// Eve's invited account is gone, so her lapsed invitation cannot be
    /// closed. The sweep skips it and still marks Bob's.
    #[test]
    fn an_invitation_that_cannot_be_marked_does_not_stop_the_others() {
        let acme = Acme::new();
        let eve = InvitationSeed::for_user(UserId::new(), "eve@acme.com", RoleId::new(), "eve")
            .expiring_at(ago(48))
            .stored();
        block_on(acme.invitations.save(&test_ctx().tenant(), &eve)).unwrap();
        acme.invite("bob", ago(24));

        let expired = acme.sweep();

        assert_eq!(expired, 1);
        assert_eq!(acme.status("eve"), InvitationStatus::Pending);
        assert_eq!(acme.status("bob"), InvitationStatus::Expired);
    }
}
