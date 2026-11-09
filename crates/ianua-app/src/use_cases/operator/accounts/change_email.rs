//! Change operator email: one operator asks to move another operator's
//! account to a new address. A link to confirm goes to the new address, and
//! the address the account has now is warned with a link that stops it;
//! the account keeps its old address until the link is followed.
//!
//! Operators sign in with keys, so no password proves one of them again.
//! Another operator asks instead, as for every change to an operator's
//! account, and nobody moves their own address.

use std::sync::Arc;

use ianua_domain::domains::authentication::tokens::refresh::RefreshTokenGenerator;
use ianua_domain::domains::operator::control::OperatorAuthority;
use ianua_domain::domains::operator::identity::Operator;
use ianua_domain::message;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{Email, OperatorId};

use crate::acting::OperatorAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::OperatorCaller;
use crate::email::LinkScope;
use crate::error::{AppError, OrInternal};
use crate::ports::operator::OperatorStore;
use crate::ports::shared::{Mailer, OrgEmailChangeStore};
use crate::use_case::Command;
use crate::use_cases::identity::email::changes::links::{
    ChangeMails, EmailChangePolicy, MailedIn, NewChange, mail_change_links, new_change,
};
use crate::use_cases::operator::lookup::existing_operator;

/// The ports [`ChangeOperatorEmailUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ChangeOperatorEmailPorts {
    /// Platform operators, and the addresses they already have.
    pub operator_store: Arc<dyn OperatorStore>,
    /// Saves the pending change, which the control plane's confirm step
    /// lands.
    pub change_store: Arc<dyn OrgEmailChangeStore>,
    /// What an operator may do on the platform.
    pub operator_authorities: Arc<dyn OperatorAuthorities>,
    /// Mails the warning and the confirmation link.
    pub mailer: Arc<dyn Mailer>,
    /// Makes confirmation and cancel links.
    pub token_generator: Arc<dyn RefreshTokenGenerator>,
    /// How long the link lasts and the address it is built on.
    pub policy: EmailChangePolicy,
}

/// Whose address moves, and to where.
pub struct ChangeOperatorEmailRequest {
    /// The operator whose address moves. Never the caller.
    pub operator: OperatorId,
    /// The address asked for.
    pub new_email: Email,
    /// Where the links land.
    pub scope: LinkScope,
}

/// Starts a change of another operator's address.
pub struct ChangeOperatorEmailUseCase {
    ports: ChangeOperatorEmailPorts,
}

impl ChangeOperatorEmailUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ChangeOperatorEmailPorts) -> Self {
        Self { ports }
    }

    /// Refuses `email` when an operator already has it.
    async fn ensure_address_free(&self, email: &Email) -> Result<(), AppError> {
        let taken = self
            .ports
            .operator_store
            .find_by_email(email)
            .await
            .or_internal()?;
        if taken.is_some() {
            return Err(AppError::Conflict(message!(
                "identity-email-already-taken",
                "email already taken"
            )));
        }
        Ok(())
    }

    /// The change of `operator`'s address to `new_email` that `by` asks
    /// for, and the raw links that confirm and stop it.
    fn asked_change(
        &self,
        operator: &Operator,
        by: &OperatorAuthority,
        new_email: Email,
    ) -> Result<NewChange, AppError> {
        new_change(
            self.ports.token_generator.as_ref(),
            &self.ports.policy,
            new_email,
            |params| operator.ask_email_change(params, by),
        )
    }
}

impl Command for ChangeOperatorEmailUseCase {
    type Caller = OperatorCaller;
    type Input = ChangeOperatorEmailRequest;
    type Output = Result<(), AppError>;

    /// Records a change of `request.operator`'s address to
    /// `request.new_email`, warns the address they have now and mails a
    /// link to confirm the new one, then records
    /// `identity.management_email_change_requested`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for a missing acting operator/key; `Forbidden` for an unusable key, disabled operator or self-change.
    /// - `AppError::NotFound` for a missing target operator; `Domain` for an unchanged address; `Conflict` for another operator's address.
    /// - `AppError::Internal` on persistence, link or mail failure.
    async fn execute(
        &self,
        caller: &OperatorCaller,
        auditor: &RequestAuditor,
        request: ChangeOperatorEmailRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.operator_authorities.authority(caller).await?;
        let operator =
            existing_operator(self.ports.operator_store.as_ref(), &request.operator).await?;
        self.ensure_address_free(&request.new_email).await?;
        let mut asked = self.asked_change(&operator, &authority, request.new_email)?;
        self.ports
            .change_store
            .save(&asked.change)
            .await
            .or_internal()?;
        let mails = ChangeMails {
            current: operator.email(),
            mailed_in: MailedIn::Organization,
            scope: &request.scope,
            requested_from: caller.audit_context().ip_address().clone(),
        };
        mail_change_links(
            self.ports.mailer.as_ref(),
            &self.ports.policy,
            &asked,
            mails,
        )
        .await?;
        auditor
            .dispatch_by(&authority.actor(), asked.change.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::operator::status::OperatorStatus;

    use super::*;
    use crate::test_support::acting::{FakeOperatorAuthorities, Refusal};
    use crate::test_support::identity::FakeEmailChangeStore;
    use crate::test_support::operator::{
        FakeOperatorStore, stored_operator, test_operator_caller, test_operator_id,
    };
    use crate::test_support::{
        FakeEventDispatcher, FakeMailer, block_on, test_auditor, test_link_scope,
    };

    const NEW_ADDRESS: &str = "carol@ops.ianua.dev";

    struct Setup {
        uc: ChangeOperatorEmailUseCase,
        changes: Arc<FakeEmailChangeStore>,
        mailer: Arc<FakeMailer>,
        audit: Arc<FakeEventDispatcher>,
        carol: OperatorId,
    }

    impl Setup {
        fn with(authorities: FakeOperatorAuthorities, mailer: FakeMailer) -> Self {
            let carol = OperatorId::new();
            let store = Arc::new(FakeOperatorStore::holding([
                stored_operator(test_operator_id(), "bob@ianua.dev", OperatorStatus::Active),
                stored_operator(carol, "carol@ianua.dev", OperatorStatus::Active),
                stored_operator(OperatorId::new(), "dan@ianua.dev", OperatorStatus::Active),
            ]));
            let changes = Arc::new(FakeEmailChangeStore::empty());
            let mailer = Arc::new(mailer);
            let uc = ChangeOperatorEmailUseCase::new(ChangeOperatorEmailPorts {
                operator_store: store,
                change_store: changes.clone(),
                operator_authorities: Arc::new(authorities),
                mailer: mailer.clone(),
                ..ChangeOperatorEmailPorts::fakes()
            });
            Self {
                uc,
                changes,
                mailer,
                audit: Arc::new(FakeEventDispatcher::new()),
                carol,
            }
        }

        fn new() -> Self {
            Self::with(FakeOperatorAuthorities::admitting(), FakeMailer::new())
        }

        fn change(&self, operator: OperatorId, to: &str) -> Result<(), AppError> {
            block_on(self.uc.execute(
                &test_operator_caller(),
                &test_auditor(self.audit.clone()),
                ChangeOperatorEmailRequest {
                    operator,
                    new_email: Email::new(to).unwrap(),
                    scope: test_link_scope(),
                },
            ))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Bob asks to move Carol to a new address. The change waits, Carol's
    /// current address is warned first, the link to confirm goes to the new
    /// address, and the request is recorded as a management account's.
    #[test]
    fn another_operator_asks_and_the_new_address_is_sent_the_link() {
        let setup = Setup::new();

        setup.change(setup.carol, NEW_ADDRESS).unwrap();

        assert_eq!(setup.changes.count(), 1);
        assert_eq!(
            setup.mailer.recipients(),
            vec!["carol@ianua.dev".to_owned(), NEW_ADDRESS.to_owned()]
        );
        assert_eq!(
            setup.recorded(),
            vec!["identity.management_email_change_requested"]
        );
    }

    /// An operator cannot request a change to their own email address;
    /// no pending change or message is stored.
    #[test]
    fn an_operator_cannot_move_their_own_address() {
        let setup = Setup::new();

        let result = setup.change(test_operator_id(), "mallory@evil.test");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.changes.count(), 0);
        assert_eq!(setup.mailer.count(), 0);
    }

    /// A disabled operator's authority refusal prevents requesting another
    /// operator's address change, and no mail is sent.
    #[test]
    fn a_disabled_operator_is_refused() {
        let setup = Setup::with(
            FakeOperatorAuthorities::refusing(Refusal::Forbidden),
            FakeMailer::new(),
        );

        let result = setup.change(setup.carol, NEW_ADDRESS);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.mailer.count(), 0);
    }

    /// An unauthenticated operator cannot request an address change, and
    /// no pending change is stored.
    #[test]
    fn a_signed_out_operator_is_refused() {
        let setup = Setup::with(
            FakeOperatorAuthorities::refusing(Refusal::SignedOut),
            FakeMailer::new(),
        );

        let result = setup.change(setup.carol, NEW_ADDRESS);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(setup.changes.count(), 0);
    }

    /// An address held by another operator causes a conflict, and no mail
    /// is sent.
    #[test]
    fn an_address_another_operator_has_is_refused() {
        let setup = Setup::new();

        let result = setup.change(setup.carol, "dan@ianua.dev");

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(setup.mailer.count(), 0);
    }

    /// Requesting the operator's current address causes a conflict and
    /// creates no pending change.
    #[test]
    fn the_address_the_operator_has_is_refused() {
        let setup = Setup::new();

        let result = setup.change(setup.carol, "carol@ianua.dev");

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(setup.changes.count(), 0);
    }

    /// Bob names an operator who does not exist. It is not found and
    /// nothing is mailed.
    #[test]
    fn an_unknown_operator_is_not_found() {
        let setup = Setup::new();

        let result = setup.change(OperatorId::new(), NEW_ADDRESS);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(setup.mailer.count(), 0);
    }

    /// Failure to mail the warning returns an internal error and records
    /// no address-change request event.
    #[test]
    fn no_change_is_asked_for_when_the_warning_cannot_be_sent() {
        let setup = Setup::with(FakeOperatorAuthorities::admitting(), FakeMailer::refusing());

        let result = setup.change(setup.carol, NEW_ADDRESS);

        assert!(matches!(result, Err(AppError::Internal(_))));
        assert!(setup.recorded().is_empty());
    }
}
