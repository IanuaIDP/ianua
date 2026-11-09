//! Confirm org email change: an organization member or an operator follows
//! the link mailed to their new address, and their account moves onto it,
//! confirmed.

use std::sync::Arc;

use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::Email;

use crate::auditor::RequestAuditor;
use crate::email::refused_link;
use crate::error::{AppError, OrInternal};
use crate::ports::shared::Mailer;
use crate::use_case::Command;
use crate::use_cases::identity::email::changes::links::{MailedIn, notify_old_address};
use crate::use_cases::identity::email::org_changes::org_change::{
    OrgChangePorts, changing_account, ensure_still_free, org_change_by_link, save_account,
};

/// The ports [`ConfirmOrgChangeUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ConfirmOrgChangePorts {
    /// The pending changes and the accounts they move.
    pub stores: OrgChangePorts,
    /// Tells the old address where the account went.
    pub mailer: Arc<dyn Mailer>,
}

/// Moves an organization member or an operator onto the address their
/// confirmation link was mailed to.
pub struct ConfirmOrgChangeUseCase {
    ports: ConfirmOrgChangePorts,
}

impl ConfirmOrgChangeUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ConfirmOrgChangePorts) -> Self {
        Self { ports }
    }
}

impl Command for ConfirmOrgChangeUseCase {
    type Caller = ();
    type Input = String;
    type Output = Result<Email, AppError>;

    /// Confirms the change `raw_token` belongs to and moves its account onto
    /// the new address, confirmed, returning that address.
    ///
    /// The change lands only on the account that asked for it, never on
    /// whoever follows the link, and only while that account still has the
    /// address it asked from and has not changed how it signs in since. The
    /// old address is told.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` if the token is malformed.
    /// - `AppError::NotFound` if the link is unknown or already used, or its
    ///   account is gone.
    /// - `AppError::LinkExpired` if the link ran out, or the change was
    ///   overtaken by another change to the account.
    /// - `AppError::Conflict` if another account of its kind took the new
    ///   address while the change waited.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        raw_token: String,
    ) -> Result<Email, AppError> {
        crate::input::validate_token("token", &raw_token)?;
        let stores = &self.ports.stores;
        let token_hash = stores.token_generator.hash_raw(&raw_token);
        let mut change = org_change_by_link(stores, &token_hash).await?;
        let mut account = changing_account(stores, &change).await?;
        let proof = change
            .confirm(account.changing(), clock::now())
            .map_err(refused_link)?;
        ensure_still_free(stores, &account, proof.as_email()).await?;
        let old_email = account.email().clone();
        account.move_to(proof);

        save_account(stores, &account).await?;
        stores.change_store.save(&change).await.or_internal()?;
        auditor
            .dispatch(&change.take_events())
            .await
            .or_internal()?;
        notify_old_address(
            self.ports.mailer.as_ref(),
            &old_email,
            MailedIn::Organization,
            account.email(),
        )
        .await;
        Ok(account.email().clone())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::operator::status::OperatorStatus;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::{OperatorId, OrganizationId, PrincipalId, UserId};
    use time::OffsetDateTime;

    use super::*;
    use crate::ports::operator::OperatorStore;
    use crate::ports::organization::OrgUserStore;
    use crate::ports::shared::OrgEmailChangeStore;
    use crate::test_support::identity::{FakeEmailChangeStore, stored_change};
    use crate::test_support::operator::{FakeOperatorStore, stored_operator};
    use crate::test_support::organization::{FakeOrgUserStore, test_org_user};
    use crate::test_support::{FakeEventDispatcher, FakeMailer, block_on, test_auditor};

    const LINK: &str = "change-link";

    /// The control plane, holding one waiting change, and what watches it.
    struct Plane {
        members: Arc<FakeOrgUserStore>,
        operators: Arc<FakeOperatorStore>,
        changes: Arc<FakeEmailChangeStore>,
        mailer: Arc<FakeMailer>,
        sink: Arc<FakeEventDispatcher>,
    }

    impl Plane {
        fn new() -> Self {
            Self {
                members: Arc::new(FakeOrgUserStore::empty()),
                operators: Arc::new(FakeOperatorStore::empty()),
                changes: Arc::new(FakeEmailChangeStore::empty()),
                mailer: Arc::new(FakeMailer::new()),
                sink: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn waiting(&self, principal: PrincipalId, from: &str, until: OffsetDateTime) {
            let change = stored_change(principal, (from, "new@acme.com"), LINK, until);
            block_on(OrgEmailChangeStore::save(self.changes.as_ref(), &change)).unwrap();
        }

        fn confirm(&self, raw_token: &str) -> Result<Email, AppError> {
            let use_case = ConfirmOrgChangeUseCase::new(ConfirmOrgChangePorts {
                stores: OrgChangePorts {
                    change_store: self.changes.clone(),
                    org_user_store: self.members.clone(),
                    operator_store: self.operators.clone(),
                    ..OrgChangePorts::fakes()
                },
                mailer: self.mailer.clone(),
            });
            block_on(use_case.execute(&(), &test_auditor(self.sink.clone()), raw_token.to_owned()))
        }
    }

    fn in_an_hour() -> OffsetDateTime {
        clock::now() + time::Duration::hours(1)
    }

    /// Owen, a member of Acme, follows his link. His account moves to the
    /// new address, confirmed, his old address is told, and the change is
    /// recorded.
    #[test]
    fn a_member_moves_onto_the_new_address() {
        let plane = Plane::new();
        let owen = test_org_user(OrganizationId::new(), "owen@acme.com", OrgRole::Member);
        block_on(plane.members.save(&owen)).unwrap();
        plane.waiting((*owen.id()).into(), "owen@acme.com", in_an_hour());

        let moved_to = plane.confirm(LINK).unwrap();

        assert_eq!(moved_to.as_str(), "new@acme.com");
        let owen = block_on(plane.members.find_by_id(owen.id()))
            .unwrap()
            .unwrap();
        assert_eq!(owen.email().as_str(), "new@acme.com");
        assert!(owen.email_verified());
        assert_eq!(plane.mailer.recipients(), ["owen@acme.com"]);
        assert_eq!(
            plane.sink.records.lock().unwrap().as_slice(),
            ["identity.management_email_change_confirmed"]
        );
    }

    /// Olga, an operator, follows her link. Her account moves to the new
    /// address.
    #[test]
    fn an_operator_moves_onto_the_new_address() {
        let plane = Plane::new();
        let olga_id = OperatorId::new();
        let olga = stored_operator(olga_id, "olga@ops.test", OperatorStatus::Active);
        block_on(plane.operators.save(&olga)).unwrap();
        plane.waiting(olga.principal_id(), "olga@ops.test", in_an_hour());

        plane.confirm(LINK).unwrap();

        let olga = block_on(plane.operators.find_by_id(&olga_id))
            .unwrap()
            .unwrap();
        assert_eq!(olga.email().as_str(), "new@acme.com");
    }

    /// Nora joined Acme as new@acme.com while Owen's change waited. His
    /// confirmation is a conflict, he stays where he was, and nothing is
    /// recorded.
    #[test]
    fn an_address_another_member_took_meanwhile_is_a_conflict() {
        let plane = Plane::new();
        let organization = OrganizationId::new();
        let owen = test_org_user(organization, "owen@acme.com", OrgRole::Member);
        let nora = test_org_user(organization, "new@acme.com", OrgRole::Member);
        block_on(plane.members.save(&owen)).unwrap();
        block_on(plane.members.save(&nora)).unwrap();
        plane.waiting((*owen.id()).into(), "owen@acme.com", in_an_hour());

        let result = plane.confirm(LINK);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        let owen = block_on(plane.members.find_by_id(owen.id()))
            .unwrap()
            .unwrap();
        assert_eq!(owen.email().as_str(), "owen@acme.com");
        assert!(plane.sink.records.lock().unwrap().is_empty());
    }

    /// Oscar, another operator, took new@acme.com while Olga's change
    /// waited. Her confirmation is a conflict and she stays where she was.
    #[test]
    fn an_address_another_operator_took_meanwhile_is_a_conflict() {
        let plane = Plane::new();
        let olga_id = OperatorId::new();
        let olga = stored_operator(olga_id, "olga@ops.test", OperatorStatus::Active);
        let oscar = stored_operator(OperatorId::new(), "new@acme.com", OperatorStatus::Active);
        block_on(plane.operators.save(&olga)).unwrap();
        block_on(plane.operators.save(&oscar)).unwrap();
        plane.waiting(olga.principal_id(), "olga@ops.test", in_an_hour());

        let result = plane.confirm(LINK);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        let olga = block_on(plane.operators.find_by_id(&olga_id))
            .unwrap()
            .unwrap();
        assert_eq!(olga.email().as_str(), "olga@ops.test");
    }

    /// Owen follows his link a day late. It has expired and he stays where
    /// he was.
    #[test]
    fn an_expired_link_moves_nothing() {
        let plane = Plane::new();
        let owen = test_org_user(OrganizationId::new(), "owen@acme.com", OrgRole::Member);
        block_on(plane.members.save(&owen)).unwrap();
        plane.waiting(
            (*owen.id()).into(),
            "owen@acme.com",
            clock::now() - time::Duration::minutes(1),
        );

        let result = plane.confirm(LINK);

        assert!(matches!(result, Err(AppError::LinkExpired(_))));
        let owen = block_on(plane.members.find_by_id(owen.id()))
            .unwrap()
            .unwrap();
        assert_eq!(owen.email().as_str(), "owen@acme.com");
    }

    /// Confirming an email change for a missing account returns not found.
    #[test]
    fn a_change_whose_account_is_gone_is_not_found() {
        let plane = Plane::new();
        plane.waiting(
            PrincipalId::from(UserId::new()),
            "gone@acme.com",
            in_an_hour(),
        );

        let result = plane.confirm(LINK);

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A link nobody sent is not found.
    #[test]
    fn an_unknown_link_is_not_found() {
        let plane = Plane::new();

        let result = plane.confirm("nobody-sent-this");

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
