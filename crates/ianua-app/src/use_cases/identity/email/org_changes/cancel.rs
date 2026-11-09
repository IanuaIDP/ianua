//! Cancel org email change: the person reading the old address of an
//! organization member or an operator follows the cancel link mailed there,
//! and the pending change of address stops before it lands.

use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::RaisesComplete as _;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::use_case::Command;
use crate::use_cases::identity::email::org_changes::org_change::{
    OrgChangePorts, changing_account, org_change_by_cancel_link,
};

/// The ports [`CancelOrgChangeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CancelOrgChangePorts {
    /// The pending changes and the accounts they were asked for.
    pub stores: OrgChangePorts,
}

/// Cancels an organization member's or an operator's pending email change
/// from the link mailed to their old address.
pub struct CancelOrgChangeUseCase {
    ports: CancelOrgChangePorts,
}

impl CancelOrgChangeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CancelOrgChangePorts) -> Self {
        Self { ports }
    }
}

impl Command for CancelOrgChangeUseCase {
    type Caller = ();
    type Input = String;
    type Output = Result<(), AppError>;

    /// Cancels the change whose cancel link carries `raw_token`, and records
    /// it.
    ///
    /// Following the link proves the reader holds the old mailbox. It works
    /// until the change lands, even after the confirmation link ran out, and
    /// only while the account still has the old address.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the token is malformed, or the change was
    ///   already confirmed or cancelled.
    /// - `AppError::NotFound` if the link is unknown or its account is gone.
    /// - `AppError::Forbidden` when the account no longer has the address
    ///   the link went to.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        raw_token: String,
    ) -> Result<(), AppError> {
        crate::input::validate_token("token", &raw_token)?;
        let stores = &self.ports.stores;
        let cancel_hash = stores.token_generator.hash_raw(&raw_token);
        let mut change = org_change_by_cancel_link(stores, &cancel_hash).await?;
        let account = changing_account(stores, &change).await?;
        change
            .cancel_from_old_address(account.changing(), clock::now())
            .map_err(AppError::from_domain)?;

        stores.change_store.save(&change).await.or_internal()?;
        auditor.dispatch(&change.take_events()).await.or_internal()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::identity::account::email_change::ChangeState;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::{OrganizationId, PrincipalId};

    use super::*;
    use crate::ports::organization::OrgUserStore;
    use crate::ports::shared::OrgEmailChangeStore;
    use crate::test_support::identity::{FakeEmailChangeStore, stored_change};
    use crate::test_support::organization::{FakeOrgUserStore, test_org_user};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    const CANCEL_LINK: &str = "cancel-owen-change";

    /// Owen, a member of Acme at owen@acme.com, with a change to
    /// new@acme.com waiting, and the cancel link mailed to his old address.
    struct Waiting {
        owen: PrincipalId,
        members: Arc<FakeOrgUserStore>,
        changes: Arc<FakeEmailChangeStore>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Waiting {
        fn new() -> Self {
            let members = Arc::new(FakeOrgUserStore::empty());
            let member = test_org_user(OrganizationId::new(), "owen@acme.com", OrgRole::Member);
            block_on(members.save(&member)).unwrap();
            let owen = PrincipalId::from(*member.id());
            let change = stored_change(
                owen,
                ("owen@acme.com", "new@acme.com"),
                "owen-change",
                clock::now() + time::Duration::hours(1),
            );
            let changes = Arc::new(FakeEmailChangeStore::empty());
            block_on(OrgEmailChangeStore::save(changes.as_ref(), &change)).unwrap();
            Self {
                owen,
                members,
                changes,
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn cancel(&self, raw_token: &str) -> Result<(), AppError> {
            let use_case = CancelOrgChangeUseCase::new(CancelOrgChangePorts {
                stores: OrgChangePorts {
                    change_store: self.changes.clone(),
                    org_user_store: self.members.clone(),
                    ..OrgChangePorts::fakes()
                },
            });
            block_on(use_case.execute(&(), &test_auditor(self.sink.clone()), raw_token.to_owned()))
        }

        fn stage(&self) -> ChangeState {
            block_on(self.changes.find_by_principal(&self.owen))
                .unwrap()
                .unwrap()
                .stage()
        }
    }

    /// Owen reads at his old address that someone asked to move his account,
    /// and follows the cancel link. The change stops and it is recorded.
    #[test]
    fn the_cancel_link_stops_the_change() {
        let waiting = Waiting::new();

        waiting.cancel(CANCEL_LINK).unwrap();

        assert!(matches!(waiting.stage(), ChangeState::Cancelled { .. }));
        assert_eq!(
            waiting.sink.records.lock().unwrap().as_slice(),
            ["identity.management_email_change_cancelled"]
        );
    }

    /// Owen follows the cancel link twice. The second time the change is
    /// already cancelled.
    #[test]
    fn a_cancelled_change_is_not_cancelled_again() {
        let waiting = Waiting::new();
        waiting.cancel(CANCEL_LINK).unwrap();

        let again = waiting.cancel(CANCEL_LINK);

        assert!(matches!(again, Err(AppError::Domain(_))));
    }

    /// A cancel link nobody sent is not found.
    #[test]
    fn an_unknown_link_is_not_found() {
        let waiting = Waiting::new();

        let result = waiting.cancel("nobody-sent-this");

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(waiting.stage(), ChangeState::Waiting);
    }
}
