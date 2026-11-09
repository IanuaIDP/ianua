//! Confirm org verification: a member follows the link mailed to their
//! address, and the address is confirmed.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::identity::tokens::email_verification::EmailVerification;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, OrgUserId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgTokenStore, OrgUserStore};
use crate::use_case::Command;
use crate::use_cases::organization::invitations::offers::address_link::AddressLinks;

/// The ports [`ConfirmOrgVerificationUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ConfirmOrgVerificationPorts {
    /// Loads and saves members.
    pub org_user_store: Arc<dyn OrgUserStore>,
    /// Loads and saves verification links.
    pub token_store: Arc<dyn OrgTokenStore<EmailVerification>>,
    /// Hashes the link that was followed.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// Confirms a member's address from the link mailed to it.
pub struct ConfirmOrgVerificationUseCase {
    ports: ConfirmOrgVerificationPorts,
}

impl ConfirmOrgVerificationUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ConfirmOrgVerificationPorts) -> Self {
        Self { ports }
    }
}

impl Command for ConfirmOrgVerificationUseCase {
    type Caller = ();
    type Input = String;
    type Output = Result<OrgUserId, AppError>;

    /// Spends the link `raw_token` for the member it was mailed to, marks
    /// their address confirmed and records
    /// `organization.org_user_email_verified`. A member who waited only on
    /// this becomes active.
    ///
    /// No session is needed: following the link shows the reader holds the
    /// mailbox. It works only while the member still has the address it
    /// went to.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the token is malformed.
    /// - `AppError::NotFound` if the link is unknown or already used, or its
    ///   member is gone.
    /// - `AppError::LinkExpired` if the link ran out of time, or the member
    ///   has moved to another address since: another can be sent.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        raw_token: String,
    ) -> Result<OrgUserId, AppError> {
        let links = AddressLinks {
            members: self.ports.org_user_store.as_ref(),
            tokens: self.ports.token_store.as_ref(),
            token_generator: self.ports.token_generator.as_ref(),
        };
        let mut member = links.confirm(&raw_token).await?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*member.id()), member.take_events())
            .await
            .or_internal()?;
        Ok(*member.id())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::access::token::{OrgToken, OrgTokenRow};
    use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{Email, OrganizationId, TokenHash, Usage};
    use time::Duration;

    use super::*;
    use crate::test_support::organization::{
        FakeOrgTokenStore, FakeOrgUserStore, org_user_store_with, unconfirmed_org_user,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    const LINK: &str = "fake_refresh_link";

    struct Setup {
        uc: ConfirmOrgVerificationUseCase,
        fiona: OrgUserId,
        members: Arc<FakeOrgUserStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    /// Fiona, waiting to confirm `fiona@acme.test`, holding a link mailed to
    /// `sent_to` that runs out `expires_in` from now.
    fn setup(sent_to: &str, expires_in: Duration) -> Setup {
        setup_keeping(sent_to, expires_in, |link| {
            FakeOrgTokenStore::holding([link])
        })
    }

    /// The same, the link kept in the store `kept` makes of it.
    fn setup_keeping(
        sent_to: &str,
        expires_in: Duration,
        kept: impl FnOnce(OrgToken<EmailVerification>) -> FakeOrgTokenStore<EmailVerification>,
    ) -> Setup {
        let fiona = unconfirmed_org_user(OrganizationId::new(), "fiona@acme.test");
        let fiona_id = *fiona.id();
        let link = OrgToken::<EmailVerification>::reconstitute(OrgTokenRow {
            token_hash: TokenHash::from_stored("fake_hash_link".to_owned()),
            org_user_id: fiona_id,
            sent_to: Email::new(sent_to).unwrap(),
            created_at: clock::now() - Duration::hours(3),
            expires_at: clock::now() + expires_in,
            usage: Usage::Unused,
        })
        .unwrap();
        let members = Arc::new(org_user_store_with([fiona]));
        Setup {
            uc: ConfirmOrgVerificationUseCase::new(ConfirmOrgVerificationPorts {
                org_user_store: members.clone(),
                token_store: Arc::new(kept(link)),
                ..ConfirmOrgVerificationPorts::fakes()
            }),
            fiona: fiona_id,
            members,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn confirm(setup: &Setup) -> Result<OrgUserId, AppError> {
        block_on(
            setup
                .uc
                .execute(&(), &test_auditor(setup.audit.clone()), LINK.to_owned()),
        )
    }

    /// Fiona follows her link. Her address is confirmed, she becomes active
    /// and it is recorded.
    #[test]
    fn following_the_link_confirms_the_address() {
        let setup = setup("fiona@acme.test", Duration::hours(1));

        let confirmed = confirm(&setup).unwrap();

        assert_eq!(confirmed, setup.fiona);
        assert_eq!(
            setup.members.get_status(&setup.fiona),
            Some(OrgUserStatus::Active)
        );
        assert_eq!(
            setup.audit.records.lock().unwrap().clone(),
            vec!["organization.org_user_email_verified"]
        );
    }

    /// Replaying a verification link after confirmation returns not found.
    #[test]
    fn a_replayed_link_is_not_found() {
        let setup = setup("fiona@acme.test", Duration::hours(1));
        confirm(&setup).unwrap();

        let replayed = confirm(&setup);

        assert!(matches!(replayed, Err(AppError::NotFound(_))));
    }

    /// A link spent by a competing request returns not found; this request
    /// leaves the member pending verification and writes no audit event.
    #[test]
    fn a_link_spent_by_another_request_a_moment_before_is_not_found() {
        let setup = setup_keeping("fiona@acme.test", Duration::hours(1), |link| {
            FakeOrgTokenStore::raced([link])
        });

        let result = confirm(&setup);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(
            setup.members.get_status(&setup.fiona),
            Some(OrgUserStatus::PendingVerification)
        );
        assert!(setup.audit.records.lock().unwrap().is_empty());
    }

    /// Fiona follows her link after it ran out. She is told it expired, so
    /// she can ask for another, and her address stays unconfirmed.
    #[test]
    fn an_expired_link_is_link_expired() {
        let setup = setup("fiona@acme.test", Duration::hours(-1));

        let result = confirm(&setup);

        assert!(matches!(result, Err(AppError::LinkExpired(_))));
        assert_eq!(
            setup.members.get_status(&setup.fiona),
            Some(OrgUserStatus::PendingVerification)
        );
    }

    /// A verification link for a different address is treated as expired,
    /// leaving the member pending verification.
    #[test]
    fn a_link_to_an_address_the_member_left_confirms_nothing() {
        let setup = setup("fiona.old@acme.test", Duration::hours(1));

        let result = confirm(&setup);

        assert!(matches!(result, Err(AppError::LinkExpired(_))));
        assert_eq!(
            setup.members.get_status(&setup.fiona),
            Some(OrgUserStatus::PendingVerification)
        );
    }

    /// An unknown verification link cannot confirm a member's address.
    #[test]
    fn an_unknown_link_is_not_found() {
        let uc = ConfirmOrgVerificationUseCase::new(ConfirmOrgVerificationPorts::fakes());

        let result = block_on(uc.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            LINK.to_owned(),
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
