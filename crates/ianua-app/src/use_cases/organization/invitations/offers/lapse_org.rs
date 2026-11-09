//! The background sweep that marks invitations expired once their link has
//! run out, and closes the accounts that waited on them.

use std::sync::Arc;

use ianua_domain::domains::organization::members::invitation::OrgInvitation;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::ActorRef;
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::listing::{Limit, PageRequest};
use crate::ports::organization::{OrgInvitationStore, OrgUserStore};
use crate::ports::runtime::UnitOfWork;
use crate::services::kept_together::kept_together;
use crate::services::sweep_round::SweepRound;
use crate::use_case::Command;

/// The ports [`LapseOrgUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct LapseOrgPorts {
    /// Lists the invitations that ran out, across every organization, and
    /// saves each one expired.
    pub org_invitation_store: Arc<dyn OrgInvitationStore>,
    /// Loads and saves the account that waited on each invitation.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// Keeps each expiry, the account's close and the record together.
    pub unit_of_work: Arc<dyn UnitOfWork>,
}

/// Marks invitations expired once their link has run out, and records
/// `OrgUserInvitationExpired` for each.
///
/// It runs as a periodic job of the platform, with nobody asking. A link
/// past its expiry already does nothing; marking it says so on the record,
/// so the account invited stops waiting in the member list for good.
pub struct LapseOrgUseCase {
    ports: LapseOrgPorts,
}

impl LapseOrgUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: LapseOrgPorts) -> Self {
        Self { ports }
    }

    /// Attempts each invitation in a bounded batch once and counts failures
    /// without allowing them to prevent later pages from being processed.
    async fn lapse_batch(
        &self,
        auditor: &RequestAuditor,
        invitations: Vec<OrgInvitation>,
        now: OffsetDateTime,
        mut round: SweepRound,
    ) -> SweepRound {
        for mut invitation in invitations {
            round = match self.lapse(auditor, &mut invitation, now).await {
                Ok(()) => round.with_changed(),
                Err(error) => {
                    tracing::warn!(
                        invitation = %invitation.id(),
                        %error,
                        "invitation could not be expired; left for the next sweep"
                    );
                    round.with_failed()
                }
            };
        }
        round
    }

    /// Marks `invitation` expired at `now`, closes the account that waited
    /// on it, and records the expiry against its organization, all three
    /// kept together.
    async fn lapse(
        &self,
        auditor: &RequestAuditor,
        invitation: &mut OrgInvitation,
        now: OffsetDateTime,
    ) -> Result<(), AppError> {
        invitation.lapse(now).map_err(AppError::from_domain)?;
        let kept = self.expiry_kept(auditor, invitation);
        kept_together(self.ports.unit_of_work.as_ref(), kept).await
    }

    /// Saves `invitation` expired, closes the account that waited on it,
    /// and records the expiry.
    async fn expiry_kept(
        &self,
        auditor: &RequestAuditor,
        invitation: &mut OrgInvitation,
    ) -> Result<(), AppError> {
        self.ports
            .org_invitation_store
            .save(invitation)
            .await
            .or_internal()?;
        self.close_waiting_account(invitation).await?;
        auditor
            .with_organization(*invitation.organization_id())
            .dispatch_by(&ActorRef::System, invitation.take_events())
            .await
            .or_internal()
    }

    /// Closes the account `invitation` was for, while it still waits to
    /// join. An account that joined some other way, or is gone, is left
    /// as it is.
    async fn close_waiting_account(&self, invitation: &OrgInvitation) -> Result<(), AppError> {
        let members = self.ports.org_user_store.as_ref();
        let Some(mut invitee) = members
            .find_by_id_in_org(invitation.organization_id(), invitation.org_user_id())
            .await
            .or_internal()?
        else {
            return Ok(());
        };
        if let Err(error) = invitation.close_unanswered(&mut invitee) {
            tracing::info!(%error, "invited account no longer waits; left as it is");
            return Ok(());
        }
        members.save(&invitee).await.or_internal()
    }
}

impl Command for LapseOrgUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<SweepRound, AppError>;

    /// Marks every pending invitation whose link ran out by now expired,
    /// closes the account each one was for, and records
    /// `organization.org_user_invitation_expired` against its organization,
    /// by the platform. Each expiry, the account's close and the record are
    /// kept together: an invitation whose expiry cannot be kept whole keeps
    /// no change, is logged, counted as failed and found again by the next
    /// sweep.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` if listing the invitations fails.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<SweepRound, AppError> {
        let now = clock::now();
        let mut request = PageRequest::first(Limit::internal(500));
        let mut round = SweepRound::default();
        loop {
            let page = self
                .ports
                .org_invitation_store
                .list_lapsed(now, &request)
                .await
                .or_internal()?;
            let next = request.following(&page);
            round = self.lapse_batch(auditor, page.items, now, round).await;
            let Some(next) = next else {
                return Ok(round);
            };
            request = next;
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
    use ianua_domain::types::{OrgUserId, OrganizationId, TokenHash};

    use super::*;
    use crate::ports::runtime::Settlement;
    use crate::test_support::organization::{
        FakeOrgInvitationStore, FakeOrgUserStore, expired_org_invitation, invited_org_user,
        org_user_store_with, pending_org_invitation, test_org_user,
    };
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, RecordingUnitOfWork, block_on, test_auditor,
        test_org_caller,
    };

    struct Swept {
        expired: u32,
        invitations: Arc<FakeOrgInvitationStore>,
        members: Arc<FakeOrgUserStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Swept {
        fn pending(&self, organization: &OrganizationId) -> usize {
            block_on(self.invitations.list_pending(organization))
                .unwrap()
                .len()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn link(name: &str) -> TokenHash {
        TokenHash::from_stored(name.to_owned())
    }

    fn sweep(invitations: Vec<OrgInvitation>, members: Vec<OrgUser>) -> Swept {
        let invitations = Arc::new(FakeOrgInvitationStore::holding(invitations));
        let members = Arc::new(org_user_store_with(members));
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = LapseOrgUseCase::new(LapseOrgPorts {
            org_invitation_store: invitations.clone(),
            org_user_store: members.clone(),
            unit_of_work: Arc::new(RecordingUnitOfWork::default()),
        });
        let round = block_on(use_case.execute(&(), &test_auditor(audit.clone()), ())).unwrap();
        assert_eq!(round.failed(), 0);
        Swept {
            expired: round.changed(),
            invitations,
            members,
            audit,
        }
    }

    fn bob_in(organization: OrganizationId) -> OrgUser {
        invited_org_user(organization, "bob@acme.test", OrgRole::Member)
    }

    /// Holds more than one batch across two organizations and refuses one save.
    fn invitations_with_failed_save(
        organizations: &[OrganizationId; 2],
    ) -> Arc<FakeOrgInvitationStore> {
        let failed = expired_org_invitation(
            organizations[0],
            OrgUserId::new(),
            "failed@acme.test",
            link("failed"),
        );
        let failed_id = *failed.id();
        let invitations = Arc::new(FakeOrgInvitationStore::holding(
            std::iter::once(failed).chain((0..501).map(|index| {
                expired_org_invitation(
                    organizations[index % 2],
                    OrgUserId::new(),
                    &format!("invitee-{index}@acme.test"),
                    link(&format!("invitee-{index}")),
                )
            })),
        ));
        invitations.refuse_save(failed_id);
        invitations
    }

    /// A failed invitation remains pending while more than one batch across
    /// organizations completes. Reads stay bounded, audits are not duplicated,
    /// and the next sweep retries only the failed invitation.
    #[test]
    fn organization_expiry_reads_bounded_batches_to_completion() {
        let organizations = [OrganizationId::new(), OrganizationId::new()];
        let invitations = invitations_with_failed_save(&organizations);
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = LapseOrgUseCase::new(LapseOrgPorts {
            org_invitation_store: invitations.clone(),
            ..LapseOrgPorts::fakes()
        });
        let auditor = test_auditor(audit.clone());

        let first = block_on(use_case.execute(&(), &auditor, ())).unwrap();
        let second = block_on(use_case.execute(&(), &auditor, ())).unwrap();

        assert_eq!((first.changed(), first.failed()), (501, 1));
        assert_eq!((second.changed(), second.failed()), (0, 1));
        assert_eq!(audit.records.lock().unwrap().len(), 501);
        assert_eq!(
            block_on(invitations.list_pending(&organizations[0]))
                .unwrap()
                .len(),
            1
        );
        assert!(
            block_on(invitations.list_pending(&organizations[1]))
                .unwrap()
                .is_empty()
        );
        let reads = invitations.lapsed_reads();
        assert!(
            reads.iter().all(|count| *count <= 500),
            "unbounded reads: {reads:?}"
        );
        assert_eq!(reads.iter().sum::<usize>(), 503);
    }

    /// Bob never followed his invitation and its link ran out. The sweep
    /// marks it expired, closes the account that waited on it, and records
    /// the expiry.
    #[test]
    fn a_lapsed_invitation_expires_and_closes_the_account() {
        let organization = test_org_caller().organization_id();
        let bob = bob_in(organization);
        let invitation =
            expired_org_invitation(organization, *bob.id(), "bob@acme.test", link("bob"));
        let bob_id = *bob.id();

        let swept = sweep(vec![invitation], vec![bob]);

        assert_eq!(swept.expired, 1);
        assert_eq!(swept.pending(&organization), 0);
        assert_eq!(
            swept.members.get_status(&bob_id),
            Some(OrgUserStatus::Deactivated)
        );
        assert_eq!(
            swept.recorded(),
            ["organization.org_user_invitation_expired"]
        );
    }

    /// Bob's invitation runs another week. The sweep leaves it pending,
    /// leaves his account waiting and records nothing.
    #[test]
    fn an_invitation_still_running_is_left_alone() {
        let organization = test_org_caller().organization_id();
        let bob = bob_in(organization);
        let invitation =
            pending_org_invitation(organization, *bob.id(), "bob@acme.test", link("bob"));
        let bob_id = *bob.id();

        let swept = sweep(vec![invitation], vec![bob]);

        assert_eq!(swept.expired, 0);
        assert_eq!(swept.pending(&organization), 1);
        assert_eq!(
            swept.members.get_status(&bob_id),
            Some(OrgUserStatus::Invited)
        );
        assert!(swept.recorded().is_empty());
    }

    /// Lapsed invitations of two organizations both expire in one sweep,
    /// each recorded.
    #[test]
    fn lapsed_invitations_of_every_organization_expire() {
        let (acme, globex) = (OrganizationId::new(), OrganizationId::new());
        let bob = bob_in(acme);
        let carol = invited_org_user(globex, "carol@globex.test", OrgRole::Member);
        let invitations = vec![
            expired_org_invitation(acme, *bob.id(), "bob@acme.test", link("bob")),
            expired_org_invitation(globex, *carol.id(), "carol@globex.test", link("carol")),
        ];

        let swept = sweep(invitations, vec![bob, carol]);

        assert_eq!(swept.expired, 2);
        assert_eq!(swept.recorded().len(), 2);
    }

    /// Ann's invitation ran out after she had already joined some other
    /// way. It still expires and is recorded, and her account stays
    /// active.
    #[test]
    fn an_account_that_already_joined_stays_active() {
        let organization = test_org_caller().organization_id();
        let ann = test_org_user(organization, "ann@acme.test", OrgRole::Member);
        let invitation =
            expired_org_invitation(organization, *ann.id(), "ann@acme.test", link("ann"));
        let ann_id = *ann.id();

        let swept = sweep(vec![invitation], vec![ann]);

        assert_eq!(swept.expired, 1);
        assert_eq!(
            swept.members.get_status(&ann_id),
            Some(OrgUserStatus::Active)
        );
        assert_eq!(
            swept.recorded(),
            ["organization.org_user_invitation_expired"]
        );
    }

    /// The account Dave was invited to is gone. His lapsed invitation still
    /// expires and is recorded.
    #[test]
    fn an_invitation_whose_account_is_gone_still_expires() {
        let organization = test_org_caller().organization_id();
        let invitation = expired_org_invitation(
            organization,
            OrgUserId::new(),
            "dave@acme.test",
            link("dave"),
        );

        let swept = sweep(vec![invitation], Vec::new());

        assert_eq!(swept.expired, 1);
        assert_eq!(
            swept.recorded(),
            ["organization.org_user_invitation_expired"]
        );
    }

    /// An audit failure during invitation expiry rolls back the unit of
    /// work and counts the invitation as failed rather than changed.
    #[test]
    fn an_expiry_whose_record_fails_keeps_no_change() {
        let organization = test_org_caller().organization_id();
        let bob = bob_in(organization);
        let invitation =
            expired_org_invitation(organization, *bob.id(), "bob@acme.test", link("bob"));
        let unit = Arc::new(RecordingUnitOfWork::default());
        let use_case = LapseOrgUseCase::new(LapseOrgPorts {
            org_invitation_store: Arc::new(FakeOrgInvitationStore::holding(vec![invitation])),
            org_user_store: Arc::new(org_user_store_with(vec![bob])),
            unit_of_work: unit.clone(),
        });

        let round =
            block_on(use_case.execute(&(), &test_auditor(Arc::new(FailingEventDispatcher)), ()))
                .unwrap();

        assert_eq!((round.changed(), round.failed()), (0, 1));
        assert_eq!(unit.settlements(), [Settlement::Rollback]);
    }
}
