//! A local account linked to who its owner is at an external identity
//! provider.
//!
//! Signing in through a provider matches on this link, not on the email
//! address. A provider can give an address to somebody else. It never gives
//! them the same subject.
//!
//! A link lets the subject sign in as the account and hold all it holds. So
//! a link is made only from what a provider just vouched for, and only on
//! [`LinkGrounds`]: a sign-in [`admission`] allowed, an admin allowed to act
//! on the account, or the account's holder proving who they are again. An
//! open session is not enough: whoever stole one would link their own
//! provider and keep a way in after the password changes.
//!
//! The holder or an admin may remove a link. Each link and removal is
//! recorded, so the person can be told.
//!
//! [`admission`]: crate::domains::federation::admission::admission

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authentication::mfa::owed::SecondFactor;
use crate::domains::authentication::risk_engine::step_up::StepUpPolicy;
use crate::domains::authentication::sessions::account_check::MaySignIn;
use crate::domains::authentication::sessions::fresh_sign_in::{FreshSignIn, WithFactor};
use crate::domains::authentication::sessions::sign_in_progress::{
    ProviderSignIn, SignInRefused, SignedIn,
};
use crate::domains::authorization::granter::AccountControl;
use crate::domains::federation::admission::{AdmissionOutcome, FederatedAdmission};
use crate::domains::federation::connection::FederatedIdpConnection;
use crate::domains::federation::events::{
    AccountLinked, AccountUnlinked, JitUserProvisioned, LinkReconfirmed,
};
use crate::domains::federation::vouched_identity::VouchedIdentity;
use crate::domains::identity::account::control::{AccountAction, RecentProof, ensure_holder};
use crate::domains::identity::account::user::User;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::types::{ConnectionId, EventLabel, FederatedSubject, PrincipalId, UserId};

/// The link from a subject at one connection's provider to a local account.
///
/// A subject means something only at the provider that issued it, so a link
/// is always to one connection.
#[derive(Debug)]
pub struct FederatedLink<T: TenantScope> {
    connection_id: ConnectionId,
    subject: FederatedSubject,
    user_id: UserId,
    linked_at: OffsetDateTime,
    confirmed_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// A link as stored, for rebuilding it with [`FederatedLink::reconstitute`].
pub struct FederatedLinkRow {
    /// The connection whose provider issued the subject.
    pub connection_id: ConnectionId,
    /// Who the person is at that provider.
    pub subject: FederatedSubject,
    /// The local account it signs in to.
    pub user_id: UserId,
    /// When the link was made.
    pub linked_at: OffsetDateTime,
    /// When its holder last confirmed it, which is when it was made until
    /// they confirm it again.
    pub confirmed_at: OffsetDateTime,
}

/// What allows a subject to be linked to an account.
#[derive(Debug, Clone, Copy)]
pub enum LinkGrounds<'a> {
    /// A first sign-in, and what [`admission`] allowed for it. That is an
    /// existing account with no built-in permission, or the account just made
    /// for a new address. The admission must be the one worked out for the
    /// identity being linked.
    ///
    /// [`admission`]: crate::domains::federation::admission::admission
    Admitted(&'a FederatedAdmission),
    /// An admin acting on the account, who may update users and holds
    /// everything the account holds.
    Control(&'a AccountControl<'a>),
    /// The account's holder, who proved who they are again just now, with
    /// their password and second factor or a passkey.
    Holder(&'a FreshSignIn),
}

/// How a link was made, for the record and for telling the person.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkSource {
    /// A first sign-in through the provider.
    FirstSignIn,
    /// An admin linked it.
    Admin,
    /// The account's holder linked it.
    Holder,
}

impl LinkSource {
    /// The stable name the audit record carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FirstSignIn => "first_sign_in",
            Self::Admin => "admin",
            Self::Holder => "holder",
        }
    }
}

impl LinkGrounds<'_> {
    /// How a link made on these grounds was made.
    #[must_use]
    pub fn source(&self) -> LinkSource {
        match self {
            Self::Admitted(_) => LinkSource::FirstSignIn,
            Self::Control(_) => LinkSource::Admin,
            Self::Holder(_) => LinkSource::Holder,
        }
    }

    /// Whether a sign-in admitted making a new account, which the link is
    /// made for.
    fn provisioned(&self) -> bool {
        let Self::Admitted(admission) = self else {
            return false;
        };
        matches!(admission.outcome(), AdmissionOutcome::Provision(_))
    }

    /// Refuses grounds that do not allow linking `identity` to `account`.
    fn ensure_allows<T: TenantScope>(
        &self,
        identity: &VouchedIdentity,
        account: &User<T>,
    ) -> Result<(), DomainError> {
        match self {
            Self::Control(control) => {
                control.ensure_allowed(account.id(), AccountAction::ChangeSignIn)
            }
            Self::Holder(proof) => ensure_fresh_holder(proof, account),
            Self::Admitted(admission) => {
                admission.ensure_for(identity)?;
                ensure_admitted(admission.outcome(), account)
            }
        }
    }
}

/// Refuses `proof` unless it shows `account`'s holder proved who they are
/// again just now.
fn ensure_fresh_holder<T: TenantScope>(
    proof: &FreshSignIn,
    account: &User<T>,
) -> Result<(), DomainError> {
    if RecentProof::proves_recently(proof, &PrincipalId::from(*account.id())) {
        return Ok(());
    }
    Err(DomainError::forbidden(message!(
        "federation-linking-a-provider-needs-the-account",
        "linking a provider needs the account's holder to prove who they are again"
    )))
}

/// Refuses `account` unless `outcome` admitted it for a new link.
fn ensure_admitted<T: TenantScope>(
    outcome: &AdmissionOutcome,
    account: &User<T>,
) -> Result<(), DomainError> {
    let admitted = match outcome {
        AdmissionOutcome::Returning(_) => {
            return Err(DomainError::conflict(message!(
                "federation-the-subject-is-linked-to-its",
                "the subject is linked to its account already"
            )));
        }
        AdmissionOutcome::Link(user_id) => user_id == account.id(),
        AdmissionOutcome::Provision(address) => address.as_email() == account.email(),
    };
    if admitted {
        return Ok(());
    }
    Err(DomainError::forbidden(message!(
        "federation-the-sign-in-did-not-admit",
        "the sign-in did not admit this account"
    )))
}

/// What allows a link to be removed from an account of tenant `T`.
#[derive(Debug, Clone, Copy)]
pub enum UnlinkGrounds<'a, T: TenantScope> {
    /// An admin acting on the account, who may update users and holds
    /// everything the account holds.
    Control(&'a AccountControl<'a>),
    /// The account's holder, from their own finished sign-in. Removing a
    /// link only takes a way in away, so an open session is enough.
    Holder(&'a SignedIn<T>),
}

/// Who removed a link, for the record and for telling the person.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlinkSource {
    /// An admin removed it.
    Admin,
    /// The account's holder removed it.
    Holder,
}

impl UnlinkSource {
    /// The stable name the audit record carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Holder => "holder",
        }
    }
}

impl<T: TenantScope> UnlinkGrounds<'_, T> {
    /// Who removes a link on these grounds.
    #[must_use]
    pub fn source(&self) -> UnlinkSource {
        match self {
            Self::Control(_) => UnlinkSource::Admin,
            Self::Holder(_) => UnlinkSource::Holder,
        }
    }
}

impl<T: TenantScope> FederatedLink<T> {
    /// Links the subject `identity` names, at the connection it came
    /// through, to `account`, now, on `grounds`.
    ///
    /// The subject comes only from what a provider vouched for. Mallory,
    /// linking from her own account, cannot type in Ann's subject, so Ann's
    /// sign-ins never land in Mallory's account.
    ///
    /// Mel may edit users but holds no admin rights. Without the grounds
    /// check, Mel links her own provider subject to the CEO's account and
    /// signs in as the CEO.
    ///
    /// For [`AdmissionOutcome::Provision`], `account` is the one just made
    /// for the proven address. Addresses are unique in a tenant, and
    /// admission found no account with it, so no older account matches.
    ///
    /// `connection` is the one `identity` came through, which names it on
    /// the record. A link made for an account just provisioned raises
    /// `federation.jit_user_provisioned`; any other raises
    /// `federation.account_linked`, saying how it was made.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Conflict`] for an already linked subject.
    /// Returns [`DomainError::Forbidden`] for a mismatched connection, subject, account
    /// or address; an administrator refused by [`AccountControl::ensure_allowed`];
    /// or fresh proof that is stale or belongs to another account.
    pub fn link(
        identity: &VouchedIdentity,
        account: &User<T>,
        grounds: LinkGrounds<'_>,
        connection: &FederatedIdpConnection<T>,
    ) -> Result<Self, DomainError> {
        if connection.id() != identity.connection_id() {
            return Err(DomainError::forbidden(message!(
                "federation-the-identity-came-through-another-connection",
                "the identity came through another connection"
            )));
        }
        grounds.ensure_allows(identity, account)?;
        let now = crate::shared::clock::now();
        let mut link = Self {
            connection_id: *identity.connection_id(),
            subject: identity.subject().clone(),
            user_id: *account.id(),
            linked_at: now,
            confirmed_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        link.raise_made(&grounds, account, connection);
        Ok(link)
    }

    /// Raises how this link, just made on `grounds`, brought `account` in.
    fn raise_made(
        &mut self,
        grounds: &LinkGrounds<'_>,
        account: &User<T>,
        connection: &FederatedIdpConnection<T>,
    ) {
        let connection_label = label_of(connection);
        let email = account.email().clone();
        if grounds.provisioned() {
            self.raised.raise(JitUserProvisioned {
                connection_id: self.connection_id,
                connection_label,
                user_id: self.user_id,
                email,
                occurred_at: self.linked_at,
            });
            return;
        }
        self.raised.raise(AccountLinked {
            connection_id: self.connection_id,
            connection_label,
            user_id: self.user_id,
            email,
            linked_by: grounds.source(),
            occurred_at: self.linked_at,
        });
    }

    /// Confirms the link again, for its holder who proved who they are just
    /// now. `connection` is the one the link goes through, which names it
    /// on the record. Raises `federation.link_reconfirmed`.
    ///
    /// After the provider's signing key changes, an account holding
    /// built-in permissions stops signing in through it. Whoever holds the
    /// new key could sign in as anyone linked here. The holder confirms
    /// with a fresh sign-in of their own, and the link works again.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `account` is not the linked one, or
    ///   `proof` is stale or for another account.
    /// - [`DomainError::Forbidden`] when `connection` is not the one the
    ///   link goes through.
    pub fn reconfirm(
        &mut self,
        account: &User<T>,
        proof: &FreshSignIn,
        connection: &FederatedIdpConnection<T>,
    ) -> Result<(), DomainError> {
        self.ensure_ends(account, connection)?;
        ensure_fresh_holder(proof, account)?;
        self.confirmed_at = crate::shared::clock::now();
        self.raised.raise(LinkReconfirmed {
            connection_id: self.connection_id,
            connection_label: label_of(connection),
            user_id: self.user_id,
            email: account.email().clone(),
            occurred_at: self.confirmed_at,
        });
        Ok(())
    }

    /// Refuses `account` or `connection` unless they are the two ends of
    /// this link.
    fn ensure_ends(
        &self,
        account: &User<T>,
        connection: &FederatedIdpConnection<T>,
    ) -> Result<(), DomainError> {
        if *account.id() != self.user_id {
            return Err(DomainError::forbidden(message!(
                "federation-the-link-is-for-another-account",
                "the link is for another account"
            )));
        }
        if *connection.id() != self.connection_id {
            return Err(DomainError::forbidden(message!(
                "federation-the-link-goes-through-another-connection",
                "the link goes through another connection"
            )));
        }
        Ok(())
    }

    /// The account this link signs in to, for a sign-in through its
    /// provider, beginning with `sign_in` and owing `owed` under `policy`.
    ///
    /// A provider sign-in opens only the account its subject is linked to.
    /// The use case never names the account itself, so it cannot open
    /// Ann's account for Mallory's subject.
    ///
    /// # Errors
    ///
    /// - [`SignInRefused::BelowBaseline`] when nothing more is owed and the
    ///   sign-in falls short of the baseline.
    pub fn sign_in(
        &self,
        sign_in: ProviderSignIn,
        owed: SecondFactor,
        policy: &StepUpPolicy,
    ) -> Result<MaySignIn<T>, SignInRefused> {
        MaySignIn::through_provider(self.user_id, sign_in, owed, policy)
    }

    /// A fresh proof of this link's account holder, from a sign-in through
    /// its provider made just now: `identity` is what the provider vouched
    /// for, and `sign_in` what the connection made of it.
    ///
    /// Ann's tenant signs everyone in through Okta, so she has no password
    /// or passkey here. Without this she could never prove herself again to
    /// change her address. The provider must vouch for the subject this
    /// link names, so Mallory's own Okta sign-in proves nothing about Ann.
    /// A factor the provider proved counts as at sign-in. Without one,
    /// Ann's own factor answers, when she has one.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `identity` came through another
    ///   connection, or names another subject.
    /// - [`DomainError::Forbidden`] when the provider proved no factor and
    ///   the code is from another account's second factor.
    pub fn fresh_sign_in(
        &self,
        identity: &VouchedIdentity,
        sign_in: ProviderSignIn,
        factor: WithFactor<'_>,
    ) -> Result<FreshSignIn, DomainError> {
        if *identity.connection_id() != self.connection_id || *identity.subject() != self.subject {
            return Err(DomainError::forbidden(message!(
                "federation-the-provider-vouched-for-someone-this",
                "the provider vouched for someone this link does not name"
            )));
        }
        FreshSignIn::through_provider(self.user_id.into(), sign_in, factor)
    }

    /// Removes this link from `account`, once `grounds` allow it.
    /// `connection` is the one the link goes through, which names it on
    /// the record. Raises `federation.account_unlinked`, naming who removed
    /// it, taken once the link is removed from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when an admin may not act on the account,
    ///   as [`AccountControl::ensure_allowed`] says.
    /// - [`DomainError::Forbidden`] when someone other than the account's
    ///   holder is signed in.
    /// - [`DomainError::Forbidden`] when `account` or `connection` is not
    ///   an end of this link.
    pub fn remove(
        &mut self,
        grounds: &UnlinkGrounds<'_, T>,
        account: &User<T>,
        connection: &FederatedIdpConnection<T>,
    ) -> Result<(), DomainError> {
        match grounds {
            UnlinkGrounds::Control(control) => {
                control.ensure_allowed(&self.user_id, AccountAction::ChangeSignIn)?;
            }
            UnlinkGrounds::Holder(person) => ensure_holder(*person, &self.user_id)?,
        }
        self.ensure_ends(account, connection)?;
        self.raised.raise(AccountUnlinked {
            connection_id: self.connection_id,
            connection_label: label_of(connection),
            user_id: self.user_id,
            email: account.email().clone(),
            unlinked_by: grounds.source(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Rebuilds a federated link from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says it was confirmed
    ///   before it was made.
    pub fn reconstitute(row: FederatedLinkRow) -> Result<Self, DomainError> {
        RowCheck::of("federated link")
            .in_order(
                row.linked_at,
                row.confirmed_at,
                "confirmed before it was made",
            )
            .finish()?;
        Ok(Self {
            connection_id: row.connection_id,
            subject: row.subject,
            user_id: row.user_id,
            linked_at: row.linked_at,
            confirmed_at: row.confirmed_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The connection whose provider issued the subject.
    #[must_use]
    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    /// Who the person is at that provider.
    #[must_use]
    pub fn subject(&self) -> &FederatedSubject {
        &self.subject
    }

    /// The local account the subject signs in to.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// When the link was made.
    #[must_use]
    pub fn linked_at(&self) -> OffsetDateTime {
        self.linked_at
    }

    /// When its holder last confirmed it.
    #[must_use]
    pub fn confirmed_at(&self) -> OffsetDateTime {
        self.confirmed_at
    }
}

impl<T: TenantScope> Raises for FederatedLink<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// How the record names `connection`: by its provider name as it is now.
fn label_of<T: TenantScope>(connection: &FederatedIdpConnection<T>) -> EventLabel {
    EventLabel::of(connection.provider_name().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::sessions::fresh_sign_in::{FRESH_FOR, SpentPasskey};
    use crate::domains::authentication::sessions::mfa_factor::FactorProved;
    use crate::domains::authentication::sessions::sign_in_progress::{
        FederatedMethod, LocalMethod, SignInProgress,
    };
    use crate::domains::authorization::granter::Handout;
    use crate::domains::authorization::permission::{RoleAction, SystemPermission, UserAction};
    use crate::domains::federation::account_privilege::AccountPrivilege;
    use crate::domains::federation::admission::{
        AddressOwner, LinkedAccount, Standing, SubjectLink, admission,
    };
    use crate::domains::federation::connection::{EmailTrust, JitProvisioning};
    use crate::domains::federation::fixtures::{connection_at, connection_for, okta};
    use crate::domains::federation::vouched_identity::{
        ProviderEmailVerification, ProviderFactor, VouchedFacts,
    };
    use crate::domains::identity::account::address::AddressStanding;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::builders::user;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::Email;

    fn subject() -> FederatedSubject {
        FederatedSubject::new("00u8x").unwrap()
    }

    fn vouched_as(subject: &str, email: &str) -> VouchedIdentity {
        VouchedIdentity::new(VouchedFacts {
            connection_id: okta(),
            subject: FederatedSubject::new(subject).unwrap(),
            email: Email::new(email).unwrap(),
            email_verification: ProviderEmailVerification::Unstated,
            factor: ProviderFactor::NotPerformed,
        })
    }

    fn vouched(subject: &str) -> VouchedIdentity {
        vouched_as(subject, "someone@acme.com")
    }

    fn link_on(
        account: &User<ResolvedTenant>,
        grounds: LinkGrounds<'_>,
    ) -> Result<FederatedLink<ResolvedTenant>, DomainError> {
        FederatedLink::link(&vouched("00u8x"), account, grounds, &okta_connection())
    }

    /// What Okta, the authority for Acme's addresses and making accounts,
    /// admits `identity` to, given its standing.
    fn admitted(
        identity: &VouchedIdentity,
        linked: SubjectLink,
        owner: AddressOwner,
    ) -> FederatedAdmission {
        let connection = connection_for(
            "acme.com",
            EmailTrust::Authoritative,
            JitProvisioning::Enabled,
        );
        admission(&connection, identity, Standing::assumed(linked, owner)).unwrap()
    }

    /// The admission that links `identity` to `account`, which holds its
    /// proven address and no built-in permission.
    fn admitted_to_link(
        identity: &VouchedIdentity,
        account: &User<ResolvedTenant>,
    ) -> FederatedAdmission {
        let owner = AddressOwner::Unlinked {
            account: *account.id(),
            address: AddressStanding::Verified,
            holds: AccountPrivilege::Ordinary,
        };
        admitted(identity, SubjectLink::NotLinked, owner)
    }

    /// Alice's first Okta sign-in was admitted to link her account. The link
    /// keeps the connection she came through, her subject `00u8x` and her
    /// account.
    #[test]
    fn a_link_ties_the_vouched_subject_at_its_connection_to_one_account() {
        let alice = user(UserId::new(), "alice@acme.com");
        let admitted = admitted_to_link(&vouched("00u8x"), &alice);

        let link = link_on(&alice, LinkGrounds::Admitted(&admitted)).unwrap();

        assert_eq!(*link.connection_id(), okta());
        assert_eq!(link.subject(), &subject());
        assert_eq!(link.user_id(), alice.id());
    }

    /// An admission to link Bob's account cannot authorize a link to the CEO's
    /// account; using it for the CEO returns a forbidden error.
    #[test]
    fn an_admission_links_only_the_account_it_admitted() {
        let ceo = user(UserId::new(), "ceo@acme.com");
        let bob = user(UserId::new(), "bob@acme.com");
        let admitted = admitted_to_link(&vouched("00u8x"), &bob);

        let result = link_on(&ceo, LinkGrounds::Admitted(&admitted));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Bob's admission authorizes his Okta identity. Offering it with
    /// Mallory's identity to link Bob's account returns a forbidden error.
    #[test]
    fn an_admission_links_only_the_identity_it_was_worked_out_for() {
        let bob = user(UserId::new(), "bob@acme.com");
        let bobs_sign_in = vouched_as("00u-bob", "bob@acme.com");
        let mallorys_sign_in = vouched_as("00u-mallory", "mallory@acme.com");
        let admitted = admitted_to_link(&bobs_sign_in, &bob);

        let result = FederatedLink::link(
            &mallorys_sign_in,
            &bob,
            LinkGrounds::Admitted(&admitted),
            &okta_connection(),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A provisioning admission for `new@acme.com` links the account with that
    /// address. Linking the CEO's account at `ceo@acme.com` is forbidden.
    #[test]
    fn a_provisioning_admission_links_only_the_account_made_for_its_address() {
        let newcomer = vouched_as("00u8x", "new@acme.com");
        let admitted = admitted(&newcomer, SubjectLink::NotLinked, AddressOwner::Nobody);
        let made = user(UserId::new(), "new@acme.com");
        let ceo = user(UserId::new(), "ceo@acme.com");

        let okta = okta_connection();
        let for_made =
            FederatedLink::link(&newcomer, &made, LinkGrounds::Admitted(&admitted), &okta);
        let for_ceo = FederatedLink::link(&newcomer, &ceo, LinkGrounds::Admitted(&admitted), &okta);

        assert!(for_made.is_ok());
        assert!(matches!(for_ceo, Err(DomainError::Forbidden(_))));
    }

    /// Alice is already linked, so her sign-in was admitted as returning. It
    /// makes no second link, and the attempt is a conflict.
    #[test]
    fn a_returning_admission_makes_no_new_link() {
        let alice = user(UserId::new(), "alice@acme.com");
        let linked = SubjectLink::Linked(LinkedAccount {
            account: *alice.id(),
            confirmed_at: crate::shared::clock::now(),
            holds: AccountPrivilege::Ordinary,
        });
        let returning = admitted(&vouched("00u8x"), linked, AddressOwner::Nobody);

        let result = link_on(&alice, LinkGrounds::Admitted(&returning));

        assert!(matches!(result, Err(DomainError::Conflict(_))));
    }

    const MEL: [SystemPermission; 1] = [SystemPermission::Users(UserAction::Update)];

    const CEO: [SystemPermission; 2] = [
        SystemPermission::Users(UserAction::Update),
        SystemPermission::Roles(RoleAction::Manage),
    ];

    fn mel_on(ceo: &User<ResolvedTenant>) -> AccountControl<'static> {
        AccountControl::assumed(
            anyone_holding(&MEL),
            *ceo.id(),
            crate::domains::authorization::stewardship::Stewardship::OthersAdminister,
            Handout {
                system: &CEO,
                custom: &[],
            },
        )
    }

    /// Mel's user-editing rights cannot authorize a provider link to the CEO's
    /// account, which also holds role-management rights. The link is forbidden.
    #[test]
    fn someone_holding_less_than_the_account_cannot_link_it() {
        let ceo = user(UserId::new(), "ceo@acme.com");
        let control = mel_on(&ceo);

        let result = link_on(&ceo, LinkGrounds::Control(&control));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    fn fresh_proof_of(account: &User<ResolvedTenant>) -> FreshSignIn {
        let spent = SpentPasskey::new((*account.id()).into(), crate::shared::clock::now());
        FreshSignIn::by_passkey(spent).unwrap()
    }

    /// The CEO proves who she is again with her passkey and links her Okta
    /// subject. It is allowed, though she holds no user rights, and the
    /// record says she linked it herself.
    #[test]
    fn a_holder_links_their_own_account_after_proving_who_they_are() {
        let ceo = user(UserId::new(), "ceo@acme.com");
        let proof = fresh_proof_of(&ceo);
        let grounds = LinkGrounds::Holder(&proof);

        let link = link_on(&ceo, grounds).unwrap();

        assert_eq!(link.user_id(), ceo.id());
        assert_eq!(grounds.source(), LinkSource::Holder);
    }

    /// Mallory's fresh proof identifies her own account. Using it to link an
    /// Okta subject to the CEO's account returns a forbidden error.
    #[test]
    fn a_fresh_proof_links_no_account_but_its_own() {
        let ceo = user(UserId::new(), "ceo@acme.com");
        let mallory = user(UserId::new(), "mallory@acme.com");
        let mallorys_proof = fresh_proof_of(&mallory);

        let result = link_on(&ceo, LinkGrounds::Holder(&mallorys_proof));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Ann's proof cannot authorize a new link once its freshness interval has
    /// elapsed. Attempting the link at that boundary returns a forbidden error.
    #[test]
    fn a_stale_proof_links_nothing() {
        let ann = user(UserId::new(), "ann@acme.com");
        let start = crate::shared::clock::now();
        let _then = crate::shared::clock::freeze(start);
        let proof = fresh_proof_of(&ann);
        let _later = crate::shared::clock::freeze(start + FRESH_FOR);

        let result = link_on(&ann, LinkGrounds::Holder(&proof));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Mallory links from her own account, with a fresh proof of herself,
    /// and the subject is the one Okta vouched for when she signed in there.
    /// She has no way to name Ann's subject instead.
    #[test]
    fn the_linked_subject_is_the_one_the_provider_vouched_for() {
        let mallory = user(UserId::new(), "mallory@acme.com");
        let proof = fresh_proof_of(&mallory);

        let link = FederatedLink::link(
            &vouched("00u-mallory"),
            &mallory,
            LinkGrounds::Holder(&proof),
            &okta_connection(),
        )
        .unwrap();

        assert_eq!(link.subject().as_str(), "00u-mallory");
    }

    fn signed_in_as(account: &User<ResolvedTenant>) -> SignedIn<ResolvedTenant> {
        let progress = SignInProgress::begin(
            LocalMethod::Password,
            SecondFactor::NotOwed,
            &StepUpPolicy::relaxed(),
        )
        .unwrap();
        SignedIn::of((*account.id()).into(), progress)
    }

    /// `account` linked to Okta on a first sign-in, with the link's own
    /// record taken.
    fn linked_to(account: &User<ResolvedTenant>) -> FederatedLink<ResolvedTenant> {
        let admitted = admitted_to_link(&vouched("00u8x"), account);
        let mut link = link_on(account, LinkGrounds::Admitted(&admitted)).unwrap();
        raised_names(&mut link);
        link
    }

    /// Acme's Okta connection, which the links in these tests go through.
    fn okta_connection() -> FederatedIdpConnection<ResolvedTenant> {
        connection_for(
            "acme.com",
            EmailTrust::Authoritative,
            JitProvisioning::Enabled,
        )
    }

    /// Ann is told Okta was linked to her account and did not do it. She
    /// signs in and removes the link from her own session.
    #[test]
    fn a_holder_removes_a_link_from_their_own_session() {
        let ann = user(UserId::new(), "ann@acme.com");
        let mut link = linked_to(&ann);
        let session = signed_in_as(&ann);
        let grounds = UnlinkGrounds::Holder(&session);

        let source = grounds.source();

        assert!(link.remove(&grounds, &ann, &okta_connection()).is_ok());
        assert_eq!(source, UnlinkSource::Holder);
    }

    /// Mel's signed-in session cannot authorize removal of the CEO's Okta
    /// link; the removal returns a forbidden error.
    #[test]
    fn a_session_removes_no_link_but_its_own() {
        let ceo = user(UserId::new(), "ceo@acme.com");
        let mel = user(UserId::new(), "mel@acme.com");
        let mut link = linked_to(&ceo);
        let mels_session = signed_in_as(&mel);

        let result = link.remove(
            &UnlinkGrounds::Holder(&mels_session),
            &ceo,
            &okta_connection(),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Mel can edit users but lacks the CEO's role-management rights. Removing
    /// the CEO's Okta link with Mel's account control is forbidden.
    #[test]
    fn someone_holding_less_than_the_account_cannot_remove_its_link() {
        let ceo = user(UserId::new(), "ceo@acme.com");
        let mut link = linked_to(&ceo);
        let control = mel_on(&ceo);

        let result = link.remove(&UnlinkGrounds::Control(&control), &ceo, &okta_connection());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Ann's provider was re-keyed. She signs in another way, proves who
    /// she is again and confirms her link, which is marked confirmed now.
    /// Mel's proof, for her own account, confirms nothing on Ann's.
    #[test]
    fn a_holder_confirms_their_link_again_with_a_fresh_proof() {
        let ann = user(UserId::new(), "ann@acme.com");
        let mel = user(UserId::new(), "mel@acme.com");
        let mut link = linked_to(&ann);
        let before = link.confirmed_at();

        let by_mel = link.reconfirm(&ann, &fresh_proof_of(&mel), &okta_connection());
        let _later = crate::shared::clock::freeze(before + time::Duration::seconds(1));
        link.reconfirm(&ann, &fresh_proof_of(&ann), &okta_connection())
            .unwrap();

        assert!(matches!(by_mel, Err(DomainError::Forbidden(_))));
        assert!(link.confirmed_at() > before);
    }

    /// Naming Mel's account and fresh proof cannot reconfirm Ann's link. The
    /// attempt is forbidden and leaves the confirmation timestamp unchanged.
    #[test]
    fn a_link_is_confirmed_only_for_the_account_it_signs_in_to() {
        let ann = user(UserId::new(), "ann@acme.com");
        let mel = user(UserId::new(), "mel@acme.com");
        let mut link = linked_to(&ann);
        let before = link.confirmed_at();

        let result = link.reconfirm(&mel, &fresh_proof_of(&mel), &okta_connection());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(link.confirmed_at(), before);
    }

    /// Ann's stale proof cannot reconfirm her link. At the freshness boundary,
    /// reconfirmation is forbidden and the confirmation timestamp stays intact.
    #[test]
    fn a_stale_proof_confirms_no_link() {
        let ann = user(UserId::new(), "ann@acme.com");
        let start = crate::shared::clock::now();
        let _then = crate::shared::clock::freeze(start);
        let mut link = linked_to(&ann);
        let proof = fresh_proof_of(&ann);
        let _later = crate::shared::clock::freeze(start + FRESH_FOR);

        let result = link.reconfirm(&ann, &proof, &okta_connection());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(link.confirmed_at(), start);
    }

    /// A SAML sign-in through Ann's link grants sign-in for Ann's account,
    /// taking the account identifier from the link.
    #[test]
    fn a_provider_sign_in_opens_the_linked_account() {
        let ann = user(UserId::new(), "ann@acme.com");
        let link = linked_to(&ann);

        let may = link
            .sign_in(
                ProviderSignIn::new(FederatedMethod::Saml, FactorProved::NoneYet),
                SecondFactor::NotOwed,
                &StepUpPolicy::relaxed(),
            )
            .unwrap();

        assert_eq!(may.user_id(), ann.id());
    }

    /// A SAML sign-in that proved no second factor.
    fn single_factor() -> ProviderSignIn {
        ProviderSignIn::new(FederatedMethod::Saml, FactorProved::NoneYet)
    }

    /// Ann has no password here and signs in through Okta. She signs in
    /// there again, and her link gives a fresh proof of her account.
    #[test]
    fn a_provider_sign_in_made_now_proves_the_linked_account() {
        let ann = user(UserId::new(), "ann@acme.com");
        let link = linked_to(&ann);

        let proof = link
            .fresh_sign_in(&vouched("00u8x"), single_factor(), WithFactor::NoneOnFile)
            .unwrap();

        assert!(RecentProof::proves_recently(
            &proof,
            &PrincipalId::from(*ann.id())
        ));
    }

    /// A provider identity for Mallory's subject cannot produce fresh proof
    /// through Ann's link; the mismatched subject returns a forbidden error.
    #[test]
    fn another_subjects_sign_in_proves_nothing_about_the_linked_account() {
        let ann = user(UserId::new(), "ann@acme.com");
        let link = linked_to(&ann);

        let proof = link.fresh_sign_in(
            &vouched("00u-mallory"),
            single_factor(),
            WithFactor::NoneOnFile,
        );

        assert!(matches!(proof, Err(DomainError::Forbidden(_))));
    }

    fn text(event: &DomainEvent, key: &str) -> String {
        match event.payload().value(key) {
            Some(FieldValue::Text(value)) => value.clone(),
            other => panic!("{key} is not text: {other:?}"),
        }
    }

    fn reference_label(event: &DomainEvent, key: &str) -> String {
        match event.payload().value(key) {
            Some(FieldValue::Reference(reference)) => reference.label().to_owned(),
            other => panic!("{key} is not a reference: {other:?}"),
        }
    }

    /// Ann's existing account is linked on her first sign-in through Okta.
    /// The link raises `federation.account_linked`, naming her address, Okta
    /// and that a first sign-in made it.
    #[test]
    fn a_first_sign_in_link_raises_account_linked() {
        let ann = user(UserId::new(), "ann@acme.com");
        let admitted = admitted_to_link(&vouched("00u8x"), &ann);

        let mut link = link_on(&ann, LinkGrounds::Admitted(&admitted)).unwrap();

        let events = raised(&mut link);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "federation.account_linked"
        );
        assert_eq!(reference_label(&events[0], "user"), "ann@acme.com");
        assert_eq!(reference_label(&events[0], "connection"), "Okta");
        assert_eq!(events[0].payload().get("linked_by"), Some("first_sign_in"));
    }

    /// A newcomer's account is made on their first sign-in through Okta,
    /// and linked. The link raises `federation.jit_user_provisioned`.
    #[test]
    fn a_link_for_a_provisioned_account_raises_jit_user_provisioned() {
        let newcomer = vouched_as("00u8x", "new@acme.com");
        let admitted = admitted(&newcomer, SubjectLink::NotLinked, AddressOwner::Nobody);
        let made = user(UserId::new(), "new@acme.com");

        let mut link = FederatedLink::link(
            &newcomer,
            &made,
            LinkGrounds::Admitted(&admitted),
            &okta_connection(),
        )
        .unwrap();

        assert_eq!(raised_names(&mut link), ["federation.jit_user_provisioned"]);
    }

    /// Ann's identity and admission belong to Okta's connection. Requesting
    /// the link through a different connection returns a forbidden error.
    #[test]
    fn a_link_through_another_connection_is_refused() {
        let ann = user(UserId::new(), "ann@acme.com");
        let admitted = admitted_to_link(&vouched("00u8x"), &ann);
        let elsewhere = connection_at(
            ConnectionId::new(),
            "acme.com",
            EmailTrust::Authoritative,
            JitProvisioning::Enabled,
        );

        let refused = FederatedLink::link(
            &vouched("00u8x"),
            &ann,
            LinkGrounds::Admitted(&admitted),
            &elsewhere,
        );

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// Ann's link is made, its record taken, and later read back from
    /// storage. Neither has anything left to raise: loading is no change.
    #[test]
    fn a_link_made_or_read_back_has_raised_nothing() {
        let ann = user(UserId::new(), "ann@acme.com");
        let mut made = linked_to(&ann);
        let now = crate::shared::clock::now();
        let mut stored = FederatedLink::<ResolvedTenant>::reconstitute(FederatedLinkRow {
            connection_id: okta(),
            subject: subject(),
            user_id: *ann.id(),
            linked_at: now,
            confirmed_at: now,
        })
        .unwrap();

        assert!(raised_names(&mut made).is_empty());
        assert!(raised_names(&mut stored).is_empty());
    }

    /// Ann confirms her Okta link again after Okta's key changed. The
    /// confirmation is raised, naming her address and Okta.
    #[test]
    fn reconfirming_raises_federation_link_reconfirmed() {
        let ann = user(UserId::new(), "ann@acme.com");
        let mut link = linked_to(&ann);

        link.reconfirm(&ann, &fresh_proof_of(&ann), &okta_connection())
            .unwrap();

        let events = raised(&mut link);
        assert_eq!(
            events[0].event_type().to_string(),
            "federation.link_reconfirmed"
        );
        assert_eq!(reference_label(&events[0], "user"), "ann@acme.com");
        assert_eq!(reference_label(&events[0], "connection"), "Okta");
    }

    /// Ann removes her own Okta link. The removal is raised, saying she
    /// removed it herself.
    #[test]
    fn removing_raises_federation_account_unlinked() {
        let ann = user(UserId::new(), "ann@acme.com");
        let mut link = linked_to(&ann);
        let session = signed_in_as(&ann);

        link.remove(&UnlinkGrounds::Holder(&session), &ann, &okta_connection())
            .unwrap();

        let events = raised(&mut link);
        assert_eq!(
            events[0].event_type().to_string(),
            "federation.account_unlinked"
        );
        assert_eq!(text(&events[0], "unlinked_by"), "holder");
    }

    /// Mel's proof and session cannot authorize changes to Ann's link, and Ann
    /// cannot remove it through another connection. All three attempts fail
    /// without raising events.
    #[test]
    fn a_refused_change_raises_nothing() {
        let ann = user(UserId::new(), "ann@acme.com");
        let mel = user(UserId::new(), "mel@acme.com");
        let mut link = linked_to(&ann);
        let other = connection_at(
            ConnectionId::new(),
            "acme.com",
            EmailTrust::Authoritative,
            JitProvisioning::Enabled,
        );

        let reconfirmed = link.reconfirm(&ann, &fresh_proof_of(&mel), &okta_connection());
        let by_mel = link.remove(
            &UnlinkGrounds::Holder(&signed_in_as(&mel)),
            &ann,
            &okta_connection(),
        );
        let elsewhere = link.remove(&UnlinkGrounds::Holder(&signed_in_as(&ann)), &ann, &other);

        assert!(reconfirmed.is_err());
        assert!(by_mel.is_err());
        assert!(elsewhere.is_err());
        assert!(raised_names(&mut link).is_empty());
    }
}
