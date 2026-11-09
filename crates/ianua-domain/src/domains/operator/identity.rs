use time::OffsetDateTime;

use crate::domains::authentication::credentials::password::PasswordHasher;
use crate::domains::identity::account::email_change::{
    ChangingAccount, CreateEmailChangeParams, PendingEmailChange,
};
use crate::domains::identity::account::verified_email::VerifiedEmail;
use crate::domains::operator::control::{OperatorAuthority, OperatorSignIn};
use crate::domains::operator::events::{OperatorCreated, OperatorDisabled, OperatorEnabled};
use crate::domains::operator::status::OperatorStatus;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete};
use crate::types::{CredentialChange, Email, EventLabel, OperatorId, PasswordHash, PrincipalId};

/// Stored fields of an [`Operator`], read back by repositories.
pub struct OperatorRow {
    /// The operator's id.
    pub id: OperatorId,
    /// The address the operator signs in with.
    pub email: Email,
    /// The hash of the operator's password.
    pub password_hash: PasswordHash,
    /// Whether the account is active or disabled.
    pub status: OperatorStatus,
    /// When the account was created.
    pub created_at: OffsetDateTime,
}

/// A platform engineer who can sign in to the control plane.
///
/// Operators are not tenant users and belong to no tenant. An operator acts
/// as a tenant user only through a time-limited
/// [`ImpersonationGrant`](crate::domains::operator::impersonation::ImpersonationGrant).
#[derive(Debug)]
pub struct Operator {
    id: OperatorId,
    email: Email,
    password_hash: PasswordHash,
    status: OperatorStatus,
    created_at: OffsetDateTime,
    raised: RaisedEvents,
}

impl Operator {
    /// Creates a new active operator, made by the operator `by`. Raises
    /// `operator.operator_created`.
    ///
    /// An operator reaches every tenant the platform runs. So only a
    /// signed-in, active operator makes another. Without this, anyone who
    /// reaches the operator API makes themselves an operator.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `id` is the acting operator's own.
    pub fn create(
        id: OperatorId,
        email: Email,
        password_hash: PasswordHash,
        by: &OperatorAuthority,
    ) -> Result<Self, DomainError> {
        by.ensure_manages_another(&id)?;
        Ok(Self::made(id, email, password_hash))
    }

    /// Creates the platform's first operator, when it is installed.
    ///
    /// There is nobody yet to make one, so the installer does, once, before
    /// any operator exists. Raises `operator.operator_created`.
    #[must_use]
    pub fn install_first(id: OperatorId, email: Email, password_hash: PasswordHash) -> Self {
        Self::made(id, email, password_hash)
    }

    fn made(id: OperatorId, email: Email, password_hash: PasswordHash) -> Self {
        let mut operator = Self {
            id,
            email,
            password_hash,
            status: OperatorStatus::Active,
            created_at: crate::shared::clock::now(),
            raised: RaisedEvents::default(),
        };
        operator.raised.raise_platform(OperatorCreated {
            operator_id: operator.id,
            email: operator.email.clone(),
            occurred_at: operator.created_at,
        });
        operator
    }

    /// Rebuilds an operator from storage.
    ///
    /// # Errors
    ///
    /// - None. Each field is already a checked type and no two fields can
    ///   contradict each other.
    pub fn reconstitute(row: OperatorRow) -> Result<Self, DomainError> {
        Ok(Self {
            id: row.id,
            email: row.email,
            password_hash: row.password_hash,
            status: row.status,
            created_at: row.created_at,
            raised: RaisedEvents::default(),
        })
    }

    /// The operator's unique identifier.
    #[must_use]
    pub fn id(&self) -> &OperatorId {
        &self.id
    }

    /// The operator's login email.
    #[must_use]
    pub fn email(&self) -> &Email {
        &self.email
    }

    /// The hashed password for operator authentication.
    #[must_use]
    pub fn password_hash(&self) -> &PasswordHash {
        &self.password_hash
    }

    /// Current account status (Active or Disabled).
    #[must_use]
    pub fn status(&self) -> OperatorStatus {
        self.status
    }

    /// When this operator account was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Whether this operator can log in and perform platform actions.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == OperatorStatus::Active
    }

    /// The proof that `raw` is this operator's password, for acting on the
    /// operator plane.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the account is disabled, or `raw`
    ///   is not its password.
    /// - The error `hasher` gives when it cannot check the password.
    pub fn sign_in_with_password(
        &self,
        raw: &str,
        hasher: &impl PasswordHasher,
    ) -> Result<OperatorSignIn, DomainError> {
        if !self.is_active() {
            return Err(DomainError::forbidden(message!(
                "operator-a-disabled-operator-cannot-sign-in",
                "a disabled operator cannot sign in"
            )));
        }
        if !hasher.verify(raw, &self.password_hash)? {
            return Err(DomainError::forbidden(message!(
                "authentication-the-password-is-wrong",
                "the password is wrong"
            )));
        }
        Ok(OperatorSignIn::of(self.id))
    }

    /// Disables the operator account, as the operator `by` decides. Raises
    /// `operator.operator_disabled`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is this operator.
    /// - [`DomainError::InvalidTransition`] when the account is already
    ///   disabled.
    pub fn disable(&mut self, by: &OperatorAuthority) -> Result<(), DomainError> {
        by.ensure_manages_another(&self.id)?;
        self.status = self.status.try_transition(OperatorStatus::Disabled)?;
        self.raised.raise_platform(OperatorDisabled {
            operator_id: self.id,
            operator_label: self.label(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Re-enables a disabled operator account, as the operator `by`
    /// decides. Raises `operator.operator_enabled`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is this operator.
    /// - [`DomainError::InvalidTransition`] when the account is already
    ///   active.
    pub fn enable(&mut self, by: &OperatorAuthority) -> Result<(), DomainError> {
        by.ensure_manages_another(&self.id)?;
        self.status = self.status.try_transition(OperatorStatus::Active)?;
        self.raised.raise_platform(OperatorEnabled {
            operator_id: self.id,
            operator_label: self.label(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// How an audit record names this operator: their sign-in address.
    pub(crate) fn label(&self) -> EventLabel {
        EventLabel::of(self.email.as_str())
    }

    /// The operator as the principal a proof of who they are names, such
    /// as a fresh sign-in before they change their address.
    #[must_use]
    pub fn principal_id(&self) -> PrincipalId {
        PrincipalId::from_uuid(*self.id.as_uuid())
    }

    /// Requests an operator address change authorized by another operator.
    /// The new mailbox must follow its link; the current mailbox is notified and can cancel.
    /// An operator's key alone cannot authorize moving their own address.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] for self-authorization.
    /// [`DomainError::Validation`] if the address is unchanged.
    pub fn ask_email_change(
        &self,
        params: CreateEmailChangeParams,
        by: &OperatorAuthority,
    ) -> Result<PendingEmailChange, DomainError> {
        by.ensure_manages_another(&self.id)?;
        PendingEmailChange::asked_for(ChangingAccount::from(self), params)
    }

    /// Moves the account to an address its holder proved they control,
    /// through the confirm step of an email change.
    ///
    /// Another operator asked for the change through
    /// [`ask_email_change`](Self::ask_email_change), and following the link
    /// sent to the new address proves the mailbox. So nobody else acts
    /// here.
    pub fn change_verified_email(&mut self, email: VerifiedEmail) {
        self.email = email.into_email();
    }
}

impl RaisesComplete for Operator {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

/// An operator asking to change their address, as they stand now.
///
/// Nothing changes an operator's password once the account is made, so no
/// credential change can end a pending address change of theirs.
impl<'a> From<&'a Operator> for ChangingAccount<'a> {
    fn from(operator: &'a Operator) -> Self {
        Self::of(
            operator.principal_id(),
            operator.email(),
            CredentialChange::Never,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::identity::account::control::RecentProof;
    use crate::shared::events::data::FieldValue;
    use crate::test_support::events::raised_complete_names;
    use crate::test_support::fakes::FakeHasher;
    use crate::types::{Lifetime, TokenHash};

    fn bob() -> Email {
        Email::new("bob@ianua.dev").unwrap()
    }

    fn password() -> PasswordHash {
        PasswordHash::from_stored("fake$correct horse".to_owned())
    }

    /// Carol, an operator, acting now.
    fn carol() -> OperatorAuthority {
        OperatorAuthority::assumed(OperatorId::new())
    }

    fn test_operator() -> Operator {
        Operator::create(OperatorId::new(), bob(), password(), &carol()).unwrap()
    }

    /// Bob's operator account is created. It starts active and signs in
    /// with the address it was given.
    #[test]
    fn create_active_operator() {
        let op = test_operator();
        assert!(op.is_active());
        assert_eq!(op.email().as_str(), "bob@ianua.dev");
    }

    /// Carol disables Bob's account and then enables it again. He is
    /// inactive in between and active at the end.
    #[test]
    fn disable_and_reenable() {
        let mut op = test_operator();

        op.disable(&carol()).unwrap();
        assert!(!op.is_active());

        op.enable(&carol()).unwrap();
        assert!(op.is_active());
    }

    /// An operator cannot disable themselves or re-enable themselves after
    /// another operator disables them; the account remains inactive.
    #[test]
    fn an_operator_does_not_change_their_own_account() {
        let mut op = test_operator();
        let himself = OperatorAuthority::assumed(*op.id());

        let disabled = op.disable(&himself);
        op.disable(&carol()).unwrap();
        let enabled = op.enable(&himself);

        assert!(matches!(disabled, Err(DomainError::Forbidden(_))));
        assert!(matches!(enabled, Err(DomainError::Forbidden(_))));
        assert!(!op.is_active());
    }

    /// Bob's account is created with a given id and keeps it. Impersonation
    /// grants and audit lines name him by that id.
    #[test]
    fn an_operator_carries_their_own_id() {
        let id = OperatorId::new();
        let op = Operator::create(id, bob(), password(), &carol()).unwrap();

        assert_eq!(*op.id(), id);
    }

    /// A wrong password is rejected without producing an operator sign-in proof.
    #[test]
    fn a_wrong_password_gives_no_sign_in() {
        let op = test_operator();

        let signed_in = op.sign_in_with_password("tr0ub4dor", &FakeHasher);

        assert!(matches!(signed_in, Err(DomainError::Forbidden(_))));
    }

    /// A disabled operator cannot sign in even with the correct password.
    #[test]
    fn a_disabled_operator_gets_no_sign_in() {
        let mut op = test_operator();
        op.disable(&carol()).unwrap();

        let signed_in = op.sign_in_with_password("correct horse", &FakeHasher);

        assert!(matches!(signed_in, Err(DomainError::Forbidden(_))));
    }

    /// The holder of one account, who proved who they are again just now.
    struct ProvedJustNow(PrincipalId);

    impl crate::domains::identity::sealed::Sealed for ProvedJustNow {}

    impl RecentProof for ProvedJustNow {
        fn proves_recently(&self, account: &PrincipalId) -> bool {
            *account == self.0
        }
    }

    /// A change of `op`'s address to `address`, asked with `proof`.
    fn asked(
        op: &Operator,
        address: &str,
        proof: &ProvedJustNow,
    ) -> Result<PendingEmailChange, DomainError> {
        PendingEmailChange::create(op.into(), moving_to(address), proof)
    }

    /// A change to `address`, with its links.
    fn moving_to(address: &str) -> CreateEmailChangeParams {
        CreateEmailChangeParams {
            new_email: Email::new(address).unwrap(),
            token_hash: TokenHash::from_stored("confirm".to_owned()),
            cancel_token_hash: TokenHash::from_stored("cancel".to_owned()),
            lifetime: Lifetime::seconds(3600).unwrap(),
        }
    }

    /// Carol asks to move Bob's account to `bob@ops.ianua.dev`. The change
    /// waits for that address, and Bob's account moves once the link sent
    /// there is followed.
    #[test]
    fn another_operator_asks_to_move_an_operators_address() {
        let mut op = test_operator();

        let mut change = op
            .ask_email_change(moving_to("bob@ops.ianua.dev"), &carol())
            .unwrap();
        assert_eq!(op.email().as_str(), "bob@ianua.dev");
        let proven = change.confirm((&op).into(), now()).unwrap();
        op.change_verified_email(proven);

        assert_eq!(change.principal_id(), &op.principal_id());
        assert_eq!(op.email().as_str(), "bob@ops.ianua.dev");
    }

    /// An operator's own authority cannot authorize a request to move their
    /// address to another mailbox.
    #[test]
    fn an_operator_does_not_ask_to_move_their_own_address() {
        let op = test_operator();
        let himself = OperatorAuthority::assumed(*op.id());

        let change = op.ask_email_change(moving_to("mallory@evil.test"), &himself);

        assert!(matches!(change, Err(DomainError::Forbidden(_))));
    }

    /// An address-change request authorized by another operator is still
    /// rejected when the requested address matches the current one.
    #[test]
    fn an_operator_is_not_moved_to_the_address_they_have() {
        let op = test_operator();

        let change = op.ask_email_change(moving_to("bob@ianua.dev"), &carol());

        assert!(matches!(change, Err(DomainError::Validation(_))));
    }

    /// Bob proves who he is again, asks to move to `bob@ops.ianua.dev`, and
    /// follows the link sent there. His account moves to the new address.
    #[test]
    fn an_operator_moves_to_an_address_they_confirmed() {
        let mut op = test_operator();
        let proof = ProvedJustNow(op.principal_id());
        let mut change = asked(&op, "bob@ops.ianua.dev", &proof).unwrap();

        let proven = change.confirm((&op).into(), now()).unwrap();
        op.change_verified_email(proven);

        assert_eq!(op.email().as_str(), "bob@ops.ianua.dev");
    }

    /// A fresh proof for another operator cannot start Bob's address change,
    /// and Bob keeps his current email address.
    #[test]
    fn another_persons_proof_starts_no_change_of_an_operators_address() {
        let op = test_operator();
        let mallorys = ProvedJustNow(test_operator().principal_id());

        let change = asked(&op, "mallory@evil.test", &mallorys);

        assert!(matches!(change, Err(DomainError::Forbidden(_))));
        assert_eq!(op.email().as_str(), "bob@ianua.dev");
    }

    /// A pending address change cannot be confirmed using another
    /// operator's account.
    #[test]
    fn a_link_confirms_only_the_operator_who_asked() {
        let op = test_operator();
        let carols = test_operator();
        let proof = ProvedJustNow(op.principal_id());
        let mut change = asked(&op, "bob@ops.ianua.dev", &proof).unwrap();

        let confirmed = change.confirm((&carols).into(), now());

        assert!(confirmed.is_err());
    }

    fn now() -> OffsetDateTime {
        crate::shared::clock::now()
    }

    /// Bob's account, with its creation taken out already.
    fn fresh_operator() -> Operator {
        let mut op = test_operator();
        raised_complete_names(&mut op);
        op
    }

    /// Carol makes Bob's account. The creation is raised for the audit
    /// trail, naming Bob by his address.
    #[test]
    fn creating_raises_operator_created() {
        let mut op = test_operator();

        let events = op.take_events();

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "operator.operator_created"
        );
        assert_eq!(events[0].tenant_id(), None);
    }

    /// The platform is installed and its first operator made. The creation
    /// is raised too.
    #[test]
    fn installing_the_first_operator_raises_operator_created() {
        let mut op = Operator::install_first(OperatorId::new(), bob(), password());

        assert_eq!(
            raised_complete_names(&mut op),
            ["operator.operator_created"]
        );
    }

    /// Carol disables Bob's account and enables it again. Each move is
    /// raised, in order.
    #[test]
    fn disabling_and_enabling_raise_operator_disabled_and_enabled() {
        let mut op = fresh_operator();

        op.disable(&carol()).unwrap();
        op.enable(&carol()).unwrap();

        assert_eq!(
            raised_complete_names(&mut op),
            ["operator.operator_disabled", "operator.operator_enabled"]
        );
    }

    /// Carol disables Bob. The record names Bob by his address.
    #[test]
    fn a_disabled_operator_is_named_by_their_address() {
        let mut op = fresh_operator();

        op.disable(&carol()).unwrap();

        let payload = op.take_events()[0].payload();
        let Some(FieldValue::Reference(named)) = payload.value("operator") else {
            panic!("the operator is not referenced");
        };
        assert_eq!(named.label(), "bob@ianua.dev");
    }

    /// Self-disabling and enabling an already active operator are rejected
    /// without raising account-change events.
    #[test]
    fn a_refused_change_raises_nothing() {
        let mut op = fresh_operator();
        let himself = OperatorAuthority::assumed(*op.id());

        let disabled = op.disable(&himself);
        let enabled = op.enable(&carol());

        assert!(disabled.is_err());
        assert!(enabled.is_err());
        assert!(raised_complete_names(&mut op).is_empty());
    }

    /// Bob's account is read back from storage. Loading it is no change, so
    /// it has raised nothing.
    #[test]
    fn an_operator_read_back_from_storage_has_raised_nothing() {
        let mut op = Operator::reconstitute(OperatorRow {
            id: OperatorId::new(),
            email: bob(),
            password_hash: password(),
            status: OperatorStatus::Active,
            created_at: now(),
        })
        .unwrap();

        assert!(raised_complete_names(&mut op).is_empty());
    }
}
