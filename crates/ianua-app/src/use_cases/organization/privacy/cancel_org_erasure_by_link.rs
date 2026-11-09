//! A member who asked to be forgotten follows the cancel link mailed to
//! them during the grace period, and their account opens again.
//!
//! Their account is closed while the erasure waits, so they cannot sign in
//! to cancel. The link is how they change their mind.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::message;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::ActorRef;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::input::validate_token;
use crate::ports::organization::{OrgErasureRequestStore, OrgUserStore};
use crate::use_case::Command;
use crate::use_cases::organization::lookup::existing_member;

/// The ports [`CancelOrgErasureByLinkUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CancelOrgErasureByLinkPorts {
    /// Members' erasure requests.
    pub erasures: Arc<dyn OrgErasureRequestStore>,
    /// The members, the one opening again among them.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Hashes the cancel link that was followed.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
}

/// Cancels a member's erasure from the link mailed to them.
pub struct CancelOrgErasureByLinkUseCase {
    ports: CancelOrgErasureByLinkPorts,
}

impl CancelOrgErasureByLinkUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: CancelOrgErasureByLinkPorts) -> Self {
        Self { ports }
    }
}

impl Command for CancelOrgErasureByLinkUseCase {
    type Caller = ();
    type Input = String;
    type Output = Result<(), AppError>;

    /// Cancels the erasure whose cancel link carries `raw_token`, pending
    /// or held, opens its member's account again, and records
    /// `organization.org_user_erasure_cancelled`.
    ///
    /// Following the link proves the reader holds the mailbox it went to.
    /// It counts only while the account still has that address.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the token is malformed, or the erasure is
    ///   past cancelling.
    /// - `AppError::NotFound` if the link is unknown or its member is gone.
    /// - `AppError::Forbidden` when the member left the address the link
    ///   went to.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        raw_token: String,
    ) -> Result<(), AppError> {
        validate_token("token", &raw_token)?;
        let cancel_hash = self.ports.token_generator.hash_raw(&raw_token);
        let erasures = self.ports.erasures.as_ref();
        let mut request = erasures
            .find_by_cancel_token_hash(&cancel_hash)
            .await
            .or_internal()?
            .or_not_found(message!(
                "identity-invalid-erasure-cancel-link",
                "invalid erasure cancel link"
            ))?;
        let users = self.ports.org_users.as_ref();
        let mut member =
            existing_member(users, request.organization_id(), request.org_user_id()).await?;
        request
            .cancel_from_link(&mut member)
            .map_err(AppError::from_domain)?;
        erasures.save(&request).await.or_internal()?;
        users.save(&member).await.or_internal()?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*member.id()), request.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::privacy::erasure::ErasureState;
    use ianua_domain::domains::identity::privacy::erasure_status::ErasureStatus;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
    use ianua_domain::types::{ErasureRequestId, OrgUserId};

    use super::*;
    use crate::test_support::organization::{
        FakeOrgErasureStore, FakeOrgUserStore, org_cancel_link, org_user_store_with,
        stored_org_erasure, test_org_member_at,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: CancelOrgErasureByLinkUseCase,
        users: Arc<FakeOrgUserStore>,
        erasures: Arc<FakeOrgErasureStore>,
        audit: Arc<FakeEventDispatcher>,
        sam: OrgUserId,
        request: ErasureRequestId,
    }

    /// Sam, closing while the erasure he asked for waits at `state`, and
    /// the stores that hold them.
    fn sam_waiting(state: ErasureState) -> Setup {
        let sam = closing_sam();
        let erasure = stored_org_erasure(&sam, (1, 14), state);
        let (sam_id, request) = (*sam.id(), *erasure.id());
        let users = Arc::new(org_user_store_with([sam]));
        let erasures = Arc::new(FakeOrgErasureStore::holding([erasure]));
        Setup {
            uc: CancelOrgErasureByLinkUseCase::new(CancelOrgErasureByLinkPorts {
                erasures: erasures.clone(),
                org_users: users.clone(),
                ..CancelOrgErasureByLinkPorts::fakes()
            }),
            users,
            erasures,
            audit: Arc::new(FakeEventDispatcher::new()),
            sam: sam_id,
            request,
        }
    }

    fn closing_sam() -> OrgUser {
        test_org_member_at(
            test_org_caller().organization_id(),
            "sam@acme.test",
            OrgUserStatus::Closing,
        )
    }

    fn follow(setup: &Setup, raw: String) -> Result<(), AppError> {
        block_on(
            setup
                .uc
                .execute(&(), &test_auditor(setup.audit.clone()), raw),
        )
    }

    /// Sam changes his mind and follows the link. The erasure is cancelled,
    /// his account opens again, and the cancelling is recorded.
    #[test]
    fn following_the_link_cancels_and_reopens() {
        let setup = sam_waiting(ErasureState::Pending);

        follow(&setup, org_cancel_link(&setup.sam)).unwrap();

        assert_eq!(
            setup.erasures.status_of(&setup.request),
            Some(ErasureStatus::Cancelled)
        );
        assert_eq!(
            setup.users.get_status(&setup.sam),
            Some(OrgUserStatus::Active)
        );
        assert_eq!(
            *setup.audit.records.lock().unwrap(),
            ["organization.org_user_erasure_cancelled"]
        );
    }

    /// An unknown cancellation link is not found, and the member's account
    /// stays closing.
    #[test]
    fn an_unknown_link_is_not_found() {
        let setup = sam_waiting(ErasureState::Pending);

        let result = follow(&setup, "guessed".to_owned());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(
            setup.users.get_status(&setup.sam),
            Some(OrgUserStatus::Closing)
        );
    }

    /// The erasure is already being carried out. It is past cancelling,
    /// and nothing is recorded.
    #[test]
    fn an_erasure_under_way_is_past_cancelling() {
        let setup = sam_waiting(ErasureState::Processing);

        let result = follow(&setup, org_cancel_link(&setup.sam));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(setup.audit.records.lock().unwrap().is_empty());
    }
}
