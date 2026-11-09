//! What a sign-in through an external identity provider may do with the
//! identity it vouches for.
//!
//! A provider is trusted only for the email domains the tenant proved it
//! owns and bound to its connection, and only for addresses it does not
//! itself call unverified.
//! Inside that, a person it has signed in before comes back to the account
//! they are linked to. The first time, an account with their address is
//! linked to them. When no account has it, one is made only if the
//! connection provisions accounts.
//!
//! An account that holds built-in permissions is never linked this way. Fay
//! may manage federation. Without this rule, she connects a provider she
//! runs, binds `acme.com` to it and signs in as the CEO. Such an account's
//! owner links it themselves instead, after proving who they are again,
//! through [`LinkGrounds::Holder`].
//!
//! [`LinkGrounds::Holder`]: crate::domains::federation::link::LinkGrounds::Holder

use std::fmt;

use time::OffsetDateTime;

use crate::domains::authorization::authority::TenantAccess;
use crate::domains::federation::account_privilege::AccountPrivilege;
use crate::domains::federation::connection::{EmailTrust, FederatedIdpConnection, JitProvisioning};
use crate::domains::federation::link::FederatedLink;
use crate::domains::federation::vouched_identity::{ProviderEmailVerification, VouchedIdentity};
use crate::domains::identity::account::address::AddressStanding;
use crate::domains::identity::account::user::User;
use crate::domains::identity::account::verified_email::VerifiedEmail;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{ConnectionId, FederatedSubject, UserId};

/// Proof that [`admission`] let one vouched identity in, and what it may go
/// on to do.
///
/// Only [`admission`] makes one, and it keeps the connection and subject it
/// was worked out for. A link made on it must be for that identity. Without
/// this, an admission worked out for Bob's sign-in would link Mallory's
/// subject to Bob's account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederatedAdmission {
    connection_id: ConnectionId,
    subject: FederatedSubject,
    outcome: AdmissionOutcome,
}

impl FederatedAdmission {
    /// What the sign-in may go on to do.
    #[must_use]
    pub fn outcome(&self) -> &AdmissionOutcome {
        &self.outcome
    }

    /// Refuses `identity` unless this admission was worked out for it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `identity` came through another
    ///   connection or names another subject.
    pub(crate) fn ensure_for(&self, identity: &VouchedIdentity) -> Result<(), DomainError> {
        if *identity.connection_id() == self.connection_id && *identity.subject() == self.subject {
            return Ok(());
        }
        Err(DomainError::forbidden(message!(
            "federation-the-sign-in-was-admitted-for",
            "the sign-in was admitted for another identity"
        )))
    }
}

/// What an admitted sign-in may go on to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionOutcome {
    /// The subject is linked to this account already.
    Returning(UserId),
    /// The account with this address is linked to the subject now. It holds
    /// no built-in permission. See [`FederatedLink::link`].
    ///
    /// [`FederatedLink::link`]: crate::domains::federation::link::FederatedLink::link
    Link(UserId),
    /// No account has this address. One is made for the proven address and
    /// linked. See [`User::provision`].
    ///
    /// [`User::provision`]: crate::domains::identity::account::user::User::provision
    Provision(VerifiedEmail),
}

/// Why the sign-in is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionRefusal {
    /// The identity was vouched for through a different connection, whose
    /// domains and trust settings are not this one's.
    OtherConnection,
    /// An administrator turned the connection off.
    ConnectionDisabled,
    /// The address is outside every domain the connection may vouch for.
    DomainNotVouched,
    /// The provider says the address is not verified.
    EmailNotVerified,
    /// Nothing proves the person signing in holds the address. The provider
    /// did not say it verified it, and is not trusted as the authority for
    /// its addresses. Such an address neither takes over an existing account
    /// nor gets a new one.
    EmailNotProven,
    /// The account with this address is linked to another subject at this
    /// provider.
    LinkedToAnother,
    /// The account with this address never proved it. An admin or a
    /// directory typed it in, or its owner never followed the link mailed to
    /// it. A provider vouching for the same address does not show the
    /// account belongs to the person signing in.
    AccountAddressUnproven,
    /// The account with this address holds built-in permissions. A provider
    /// does not link it on its own. Its owner signs in, proves who they are
    /// again and links it themselves.
    PrivilegedAccount,
    /// The linked account holds built-in permissions, and the provider's
    /// signing key changed after its holder last confirmed the link. They
    /// sign in another way and confirm it again.
    ConfirmAfterKeyChange,
    /// No account has this address and the connection makes none.
    NoAccount,
}

impl fmt::Display for AdmissionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OtherConnection => "this identity was vouched for through another connection",
            Self::ConnectionDisabled => "this identity provider connection is turned off",
            Self::DomainNotVouched => "this provider may not sign in addresses at that domain",
            Self::EmailNotVerified => "the provider has not verified this address",
            Self::EmailNotProven => {
                "this provider has not proven the address belongs to the person signing in"
            }
            Self::LinkedToAnother => "this account is linked to someone else at this provider",
            Self::AccountAddressUnproven => {
                "the account with this address has not confirmed it, so it cannot be linked"
            }
            Self::PrivilegedAccount => {
                "this account holds admin rights, so sign in to it and link the provider there"
            }
            Self::ConfirmAfterKeyChange => {
                "this provider's key changed, so sign in another way and confirm the link again"
            }
            Self::NoAccount => "no account exists and this connection does not create one",
        })
    }
}

/// The account that has the vouched address, as it stands at this
/// connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressOwner {
    /// No account has the address.
    Nobody,
    /// An account has it and no subject at this provider is linked to it.
    Unlinked {
        /// The address holder considered for linking to this provider.
        account: UserId,
        /// Whether the account itself ever proved the address.
        address: AddressStanding,
        /// Whether the account holds built-in permissions, through every
        /// role and group it has.
        holds: AccountPrivilege,
    },
    /// An account has it and another subject at this provider is linked to
    /// it.
    LinkedToAnother,
}

/// Whether the subject signing in is linked to an account at this connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectLink {
    /// Not linked to any account yet.
    NotLinked,
    /// Linked to an account.
    Linked(LinkedAccount),
}

/// The account a subject is linked to, as it stands now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkedAccount {
    /// The local identity authenticated by this provider subject.
    pub account: UserId,
    /// When its holder last confirmed the link.
    pub confirmed_at: OffsetDateTime,
    /// Whether the account holds built-in permissions, through every role
    /// and group it has.
    pub holds: AccountPrivilege,
}

/// What is already known about the person signing in.
///
/// Only [`Standing::of`] makes one, from the tenant's links, accounts and
/// grants. Its fields are private. Fay may manage federation; if a use case
/// wrote the standing, it would call the CEO's account ordinary and her own
/// provider would link it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Standing {
    linked: SubjectLink,
    address_owner: AddressOwner,
}

/// The tenant's records about one vouched identity, as a use case loads
/// them for [`Standing::of`].
#[derive(Debug)]
pub struct KnownRecords<'a, 'r, T: TenantScope> {
    /// The link from the identity's subject at its connection, if there is
    /// one.
    pub subject_link: Option<&'a FederatedLink<T>>,
    /// The account with the vouched address, if there is one.
    pub address_holder: Option<&'a User<T>>,
    /// The link at the identity's connection to that account, if there is
    /// one.
    pub holder_link: Option<&'a FederatedLink<T>>,
    /// The tenant's records of who holds what.
    pub access: &'a TenantAccess<'r, T>,
}

impl Standing {
    /// Finds the account linked to `identity`, its address holder and their privileges.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] for a subject link with another connection or subject,
    /// an address holder with another address, or a holder link with another connection
    /// or account. Also propagates [`TenantAccess::privilege_of`] errors.
    pub fn of<T: TenantScope>(
        identity: &VouchedIdentity,
        records: &KnownRecords<'_, '_, T>,
        now: OffsetDateTime,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            linked: subject_link(identity, records, now)?,
            address_owner: address_owner(identity, records, now)?,
        })
    }

    /// `linked` and `address_owner`, as a test says, without the records
    /// behind them.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn assumed(linked: SubjectLink, address_owner: AddressOwner) -> Self {
        Self {
            linked,
            address_owner,
        }
    }
}

/// The account `records.subject_link` links `identity`'s subject to, as it
/// stands at `now`.
fn subject_link<T: TenantScope>(
    identity: &VouchedIdentity,
    records: &KnownRecords<'_, '_, T>,
    now: OffsetDateTime,
) -> Result<SubjectLink, DomainError> {
    let Some(link) = records.subject_link else {
        return Ok(SubjectLink::NotLinked);
    };
    if link.connection_id() != identity.connection_id() || link.subject() != identity.subject() {
        return Err(DomainError::forbidden(message!(
            "federation-the-link-loaded-is-for-another-2",
            "the link loaded is for another identity"
        )));
    }
    Ok(SubjectLink::Linked(LinkedAccount {
        account: *link.user_id(),
        confirmed_at: link.confirmed_at(),
        holds: records.access.privilege_of(link.user_id(), now)?,
    }))
}

/// Who holds `identity`'s address in `records`, as they stand at `now`.
fn address_owner<T: TenantScope>(
    identity: &VouchedIdentity,
    records: &KnownRecords<'_, '_, T>,
    now: OffsetDateTime,
) -> Result<AddressOwner, DomainError> {
    let Some(holder) = records.address_holder else {
        return Ok(AddressOwner::Nobody);
    };
    if holder.email() != identity.email() {
        return Err(DomainError::forbidden(message!(
            "federation-the-account-loaded-has-another-address",
            "the account loaded has another address"
        )));
    }
    let Some(link) = records.holder_link else {
        return Ok(AddressOwner::Unlinked {
            account: *holder.id(),
            address: holder.address().standing(),
            holds: records.access.privilege_of(holder.id(), now)?,
        });
    };
    if link.connection_id() != identity.connection_id() || link.user_id() != holder.id() {
        return Err(DomainError::forbidden(message!(
            "federation-the-link-loaded-is-for-another",
            "the link loaded is for another account"
        )));
    }
    Ok(AddressOwner::LinkedToAnother)
}

/// Determines what a federated sign-in may do for `identity` and its `standing`.
/// All subjects, even linked ones, need the matching enabled connection, a vouched
/// domain and a provider-verified address. Other cases follow [`AdmissionRefusal`].
///
/// # Errors
/// [`AdmissionRefusal`] for connection, domain or provider-verification failure;
/// missing mailbox proof when linking or creating; privileged or unproven address holders;
/// a privileged linked account needing confirmation after re-keying; an account linked
/// to another subject; or no account when provisioning is disabled.
pub fn admission<T: TenantScope>(
    connection: &FederatedIdpConnection<T>,
    identity: &VouchedIdentity,
    standing: Standing,
) -> Result<FederatedAdmission, AdmissionRefusal> {
    let outcome = outcome_for(connection, identity, standing)?;
    Ok(FederatedAdmission {
        connection_id: *identity.connection_id(),
        subject: identity.subject().clone(),
        outcome,
    })
}

/// What `identity` may do through `connection`, given its `standing`.
fn outcome_for<T: TenantScope>(
    connection: &FederatedIdpConnection<T>,
    identity: &VouchedIdentity,
    standing: Standing,
) -> Result<AdmissionOutcome, AdmissionRefusal> {
    ensure_vouched(connection, identity)?;
    if let SubjectLink::Linked(linked) = standing.linked {
        return returning(connection, linked);
    }
    by_address_owner(connection, identity, standing.address_owner)
}

/// Refuses an identity `connection` does not stand behind: from another
/// connection, through a disabled one, for an address it may not vouch for,
/// or one the provider calls unverified.
fn ensure_vouched<T: TenantScope>(
    connection: &FederatedIdpConnection<T>,
    identity: &VouchedIdentity,
) -> Result<(), AdmissionRefusal> {
    if !connection.vouched(identity) {
        return Err(AdmissionRefusal::OtherConnection);
    }
    if !connection.is_active() {
        return Err(AdmissionRefusal::ConnectionDisabled);
    }
    if !connection.vouches_for(identity.email()) {
        return Err(AdmissionRefusal::DomainNotVouched);
    }
    if identity.email_verification() == ProviderEmailVerification::Denied {
        return Err(AdmissionRefusal::EmailNotVerified);
    }
    Ok(())
}

/// A subject coming back to its linked account. An account holding
/// built-in permissions comes back only if its holder confirmed the link
/// after the provider's signing key last changed.
fn returning<T: TenantScope>(
    connection: &FederatedIdpConnection<T>,
    linked: LinkedAccount,
) -> Result<AdmissionOutcome, AdmissionRefusal> {
    let stale = linked.confirmed_at < connection.keyed_at();
    if stale && linked.holds == AccountPrivilege::Privileged {
        return Err(AdmissionRefusal::ConfirmAfterKeyChange);
    }
    Ok(AdmissionOutcome::Returning(linked.account))
}

/// What a new subject may become, given who holds its address.
fn by_address_owner<T: TenantScope>(
    connection: &FederatedIdpConnection<T>,
    identity: &VouchedIdentity,
    owner: AddressOwner,
) -> Result<AdmissionOutcome, AdmissionRefusal> {
    match owner {
        AddressOwner::Unlinked {
            holds: AccountPrivilege::Privileged,
            ..
        } => Err(AdmissionRefusal::PrivilegedAccount),
        AddressOwner::Unlinked {
            account,
            address: AddressStanding::Verified,
            holds: AccountPrivilege::Ordinary,
        } => {
            proven_address(connection, identity)?;
            Ok(AdmissionOutcome::Link(account))
        }
        AddressOwner::Unlinked {
            address: AddressStanding::Unverified,
            holds: AccountPrivilege::Ordinary,
            ..
        } => Err(AdmissionRefusal::AccountAddressUnproven),
        AddressOwner::LinkedToAnother => Err(AdmissionRefusal::LinkedToAnother),
        AddressOwner::Nobody => provisioned(connection, identity),
    }
}

/// An account made for a new address, when the connection makes them and
/// the address is proven.
fn provisioned<T: TenantScope>(
    connection: &FederatedIdpConnection<T>,
    identity: &VouchedIdentity,
) -> Result<AdmissionOutcome, AdmissionRefusal> {
    match connection.jit_provisioning() {
        JitProvisioning::Enabled => {
            proven_address(connection, identity).map(AdmissionOutcome::Provision)
        }
        JitProvisioning::Disabled => Err(AdmissionRefusal::NoAccount),
    }
}

/// The address, when the person signing in is shown to hold it. Either the
/// provider said it verified it, or the provider is the authority for its
/// addresses.
///
/// Linking an existing account or making a new one needs that proof. A
/// provider that says nothing proves nothing, because many let a person type
/// any address they like.
fn proven_address<T: TenantScope>(
    connection: &FederatedIdpConnection<T>,
    identity: &VouchedIdentity,
) -> Result<VerifiedEmail, AdmissionRefusal> {
    let confirmed = identity.email_verification() == ProviderEmailVerification::Confirmed;
    let authoritative = connection.email_trust() == EmailTrust::Authoritative;
    if !confirmed && !authoritative {
        return Err(AdmissionRefusal::EmailNotProven);
    }
    Ok(VerifiedEmail::proven(identity.email().clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::group::{Group, GroupMembership};
    use crate::domains::authorization::permission::SystemPermission;
    use crate::domains::authorization::role::{DefaultAssignment, NewRole, Role, RoleAssignment};
    use crate::domains::authorization::stewardship::TenantGrants;
    use crate::domains::federation::fixtures::{connection_for, federation_admin, okta};
    use crate::domains::federation::link::FederatedLinkRow;
    use crate::domains::federation::vouched_identity::{ProviderFactor, VouchedFacts};
    use crate::domains::identity::account::verified_email::proof_of;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::authority::anyone_holding;
    use crate::test_support::builders::{label, user};
    use crate::types::{ConnectionId, Email, FederatedSubject, PrincipalRef, RoleId, TenantId};

    /// The connection these tests sign in through, which takes addresses
    /// only when the provider says it verified them.
    fn connection(provisioning: JitProvisioning) -> FederatedIdpConnection<ResolvedTenant> {
        connection_for("acme.com", EmailTrust::Unverified, provisioning)
    }

    /// The same connection, as the authority for its addresses.
    fn authoritative(provisioning: JitProvisioning) -> FederatedIdpConnection<ResolvedTenant> {
        connection_for("acme.com", EmailTrust::Authoritative, provisioning)
    }

    fn ordinary_link(account: UserId) -> LinkedAccount {
        LinkedAccount {
            account,
            confirmed_at: crate::shared::clock::now(),
            holds: AccountPrivilege::Ordinary,
        }
    }

    fn outcome(
        admitted: Result<FederatedAdmission, AdmissionRefusal>,
    ) -> Result<AdmissionOutcome, AdmissionRefusal> {
        admitted.map(|admission| admission.outcome().clone())
    }

    fn identity(email: &str, verification: ProviderEmailVerification) -> VouchedIdentity {
        VouchedIdentity::new(VouchedFacts {
            connection_id: okta(),
            subject: FederatedSubject::new("00u8x").unwrap(),
            email: Email::new(email).unwrap(),
            email_verification: verification,
            factor: ProviderFactor::NotPerformed,
        })
    }

    fn standing(linked: SubjectLink, address_owner: AddressOwner) -> Standing {
        Standing {
            linked,
            address_owner,
        }
    }

    /// An identity vouched through another connection receives the
    /// other-connection refusal even when its standing claims a linked
    /// subject.
    #[test]
    fn an_identity_from_another_connection_is_refused() {
        let other = VouchedIdentity::new(VouchedFacts {
            connection_id: ConnectionId::new(),
            subject: FederatedSubject::new("00u8x").unwrap(),
            email: Email::new("alice@acme.com").unwrap(),
            email_verification: ProviderEmailVerification::Confirmed,
            factor: ProviderFactor::Performed,
        });

        let result = admission(
            &connection(JitProvisioning::Enabled),
            &other,
            standing(
                SubjectLink::Linked(ordinary_link(UserId::new())),
                AddressOwner::Nobody,
            ),
        );

        assert_eq!(result, Err(AdmissionRefusal::OtherConnection));
    }

    /// A linked subject with an address outside the connection's allowed
    /// domains is refused because its domain is not vouched for.
    #[test]
    fn an_address_outside_the_bound_domains_is_refused_even_for_a_linked_subject() {
        let result = admission(
            &connection(JitProvisioning::Enabled),
            &identity("admin@other.com", ProviderEmailVerification::Confirmed),
            standing(
                SubjectLink::Linked(ordinary_link(UserId::new())),
                AddressOwner::Nobody,
            ),
        );

        assert_eq!(result, Err(AdmissionRefusal::DomainNotVouched));
    }

    /// The provider says outright that `alice@acme.com` is not verified. The
    /// sign-in is refused, even though the connection makes accounts.
    #[test]
    fn an_address_the_provider_calls_unverified_is_refused() {
        let result = admission(
            &connection(JitProvisioning::Enabled),
            &identity("alice@acme.com", ProviderEmailVerification::Denied),
            standing(SubjectLink::NotLinked, AddressOwner::Nobody),
        );

        assert_eq!(result, Err(AdmissionRefusal::EmailNotVerified));
    }

    /// Alice signed in through Okta before and is linked. She signs in again
    /// with no claim about her address. She goes back to her own account.
    #[test]
    fn a_linked_subject_returns_to_its_account() {
        let user_id = UserId::new();

        let result = admission(
            &connection(JitProvisioning::Disabled),
            &identity("alice@acme.com", ProviderEmailVerification::Unstated),
            standing(
                SubjectLink::Linked(ordinary_link(user_id)),
                AddressOwner::Nobody,
            ),
        );

        assert_eq!(outcome(result), Ok(AdmissionOutcome::Returning(user_id)));
    }

    fn verified_owner(account: UserId) -> AddressOwner {
        AddressOwner::Unlinked {
            account,
            address: AddressStanding::Verified,
            holds: AccountPrivilege::Ordinary,
        }
    }

    /// An authoritative provider confirming the CEO's address still cannot
    /// obtain admission to link an account with built-in privileges.
    #[test]
    fn a_provider_never_links_an_account_holding_built_in_permissions() {
        let trusted = authoritative(JitProvisioning::Disabled);
        let ceo = AddressOwner::Unlinked {
            account: UserId::new(),
            address: AddressStanding::Verified,
            holds: AccountPrivilege::Privileged,
        };

        let result = admission(
            &trusted,
            &identity("ceo@acme.com", ProviderEmailVerification::Confirmed),
            standing(SubjectLink::NotLinked, ceo),
        );

        assert_eq!(result, Err(AdmissionRefusal::PrivilegedAccount));
    }

    /// An authoritative provider cannot link an account whose own address
    /// remains unverified, even when the provider confirms that address.
    #[test]
    fn a_provider_cannot_claim_an_account_whose_address_was_never_proven() {
        let trusted = authoritative(JitProvisioning::Disabled);
        let typed_in = AddressOwner::Unlinked {
            account: UserId::new(),
            address: AddressStanding::Unverified,
            holds: AccountPrivilege::Ordinary,
        };

        let result = admission(
            &trusted,
            &identity("mallory@acme.com", ProviderEmailVerification::Confirmed),
            standing(SubjectLink::NotLinked, typed_in),
        );

        assert_eq!(result, Err(AdmissionRefusal::AccountAddressUnproven));
    }

    /// Alice has a confirmed account at `alice@acme.com` and signs in through
    /// Okta for the first time. The provider confirms the address, so her
    /// account is linked to her Okta subject.
    #[test]
    fn the_first_sign_in_links_the_account_that_has_the_address() {
        let user_id = UserId::new();

        let result = admission(
            &connection(JitProvisioning::Disabled),
            &identity("alice@acme.com", ProviderEmailVerification::Confirmed),
            standing(SubjectLink::NotLinked, verified_owner(user_id)),
        );

        assert_eq!(outcome(result), Ok(AdmissionOutcome::Link(user_id)));
    }

    /// An untrusted provider leaving verification unstated cannot obtain
    /// admission to link an existing account; its address is unproven.
    #[test]
    fn an_unproven_address_does_not_take_over_an_existing_account() {
        let result = admission(
            &connection(JitProvisioning::Disabled),
            &identity("ceo@acme.com", ProviderEmailVerification::Unstated),
            standing(SubjectLink::NotLinked, verified_owner(UserId::new())),
        );

        assert_eq!(result, Err(AdmissionRefusal::EmailNotProven));
    }

    /// An admin marks Okta as the authority for Acme's addresses. Alice signs
    /// in with no verified claim, and her existing account is still linked.
    #[test]
    fn an_authoritative_provider_links_without_a_verified_claim() {
        let user_id = UserId::new();
        let trusted = authoritative(JitProvisioning::Disabled);

        let result = admission(
            &trusted,
            &identity("alice@acme.com", ProviderEmailVerification::Unstated),
            standing(SubjectLink::NotLinked, verified_owner(user_id)),
        );

        assert_eq!(outcome(result), Ok(AdmissionOutcome::Link(user_id)));
    }

    /// A new subject claiming Alice's confirmed address is refused when
    /// that address belongs to an account linked to another subject.
    #[test]
    fn an_account_linked_to_another_subject_is_not_taken_over() {
        let result = admission(
            &connection(JitProvisioning::Enabled),
            &identity("alice@acme.com", ProviderEmailVerification::Confirmed),
            standing(SubjectLink::NotLinked, AddressOwner::LinkedToAnother),
        );

        assert_eq!(result, Err(AdmissionRefusal::LinkedToAnother));
    }

    /// `new@acme.com` has no account and the provider confirms it. A connection
    /// that makes accounts creates one. One that does not refuses the sign-in.
    #[test]
    fn a_new_address_is_provisioned_only_when_the_connection_provisions() {
        let provisioning = admission(
            &connection(JitProvisioning::Enabled),
            &identity("new@acme.com", ProviderEmailVerification::Confirmed),
            standing(SubjectLink::NotLinked, AddressOwner::Nobody),
        );
        let not_provisioning = admission(
            &connection(JitProvisioning::Disabled),
            &identity("new@acme.com", ProviderEmailVerification::Confirmed),
            standing(SubjectLink::NotLinked, AddressOwner::Nobody),
        );

        assert_eq!(
            outcome(provisioning),
            Ok(AdmissionOutcome::Provision(VerifiedEmail::proven(
                Email::new("new@acme.com").unwrap()
            )))
        );
        assert_eq!(not_provisioning, Err(AdmissionRefusal::NoAccount));
    }

    /// Enabled provisioning does not admit a new account when an untrusted
    /// provider leaves address verification unstated.
    #[test]
    fn an_unproven_address_does_not_make_a_new_account() {
        let result = admission(
            &connection(JitProvisioning::Enabled),
            &identity("alice@acme.com", ProviderEmailVerification::Unstated),
            standing(SubjectLink::NotLinked, AddressOwner::Nobody),
        );

        assert_eq!(result, Err(AdmissionRefusal::EmailNotProven));
    }

    /// Okta is marked as the authority for Acme's addresses. Someone new
    /// signs in with no verified claim, and an account is still made.
    #[test]
    fn an_authoritative_provider_makes_an_account_without_a_verified_claim() {
        let trusted = authoritative(JitProvisioning::Enabled);

        let result = admission(
            &trusted,
            &identity("new@acme.com", ProviderEmailVerification::Unstated),
            standing(SubjectLink::NotLinked, AddressOwner::Nobody),
        );

        assert!(matches!(
            outcome(result),
            Ok(AdmissionOutcome::Provision(_))
        ));
    }

    /// An admin turns the Okta connection off. Alice, who is already linked,
    /// is refused too.
    #[test]
    fn a_disabled_connection_admits_no_one_not_even_a_linked_subject() {
        let mut disabled = connection(JitProvisioning::Enabled);
        disabled.disable(&federation_admin()).unwrap();

        let result = admission(
            &disabled,
            &identity("alice@acme.com", ProviderEmailVerification::Confirmed),
            standing(
                SubjectLink::Linked(ordinary_link(UserId::new())),
                AddressOwner::Nobody,
            ),
        );

        assert_eq!(result, Err(AdmissionRefusal::ConnectionDisabled));
    }

    /// A link confirmation older than the provider's key timestamp requires
    /// reconfirmation for a privileged account; the same standing with
    /// ordinary privileges is admitted as returning.
    #[test]
    fn a_re_keyed_provider_stops_signing_in_admins_until_they_confirm() {
        let conn = connection(JitProvisioning::Disabled);
        let before = conn.keyed_at() - time::Duration::minutes(1);
        let ann = LinkedAccount {
            account: UserId::new(),
            confirmed_at: before,
            holds: AccountPrivilege::Privileged,
        };
        let bob = LinkedAccount {
            holds: AccountPrivilege::Ordinary,
            ..ann
        };

        let for_ann = returning(&conn, ann);
        let for_bob = returning(&conn, bob);

        assert_eq!(for_ann, Err(AdmissionRefusal::ConfirmAfterKeyChange));
        assert_eq!(for_bob, Ok(AdmissionOutcome::Returning(ann.account)));
    }

    /// Acme's records, where one account holds a role giving some built-in
    /// permissions.
    struct Records {
        roles: Vec<Role<ResolvedTenant>>,
        assignments: Vec<RoleAssignment<ResolvedTenant>>,
    }

    impl Records {
        fn holding(account: &User<ResolvedTenant>, system: &[SystemPermission]) -> Self {
            let role = Role::provisioned(NewRole {
                id: RoleId::new(),
                name: label("team"),
                system_permissions: system.to_vec(),
                custom_permissions: Vec::new(),
                assignment: DefaultAssignment::Manual,
            });
            let assignment = RoleAssignment::create(
                PrincipalRef::User(*account.id()),
                &role,
                anyone_holding(SystemPermission::all()),
            )
            .unwrap();
            Self {
                roles: vec![role],
                assignments: vec![assignment],
            }
        }

        fn access(&self) -> TenantAccess<'_, ResolvedTenant> {
            TenantAccess {
                tenant: TenantId::new(),
                grants: TenantGrants {
                    roles: &self.roles,
                    assignments: &self.assignments,
                    groups: &[] as &[Group<ResolvedTenant>],
                    memberships: &[] as &[GroupMembership<ResolvedTenant>],
                },
                catalogue: &[],
                break_glass: &[],
            }
        }
    }

    /// The account at `address`, which its owner proved.
    fn proven(address: &str) -> User<ResolvedTenant> {
        let mut account = user(UserId::new(), address);
        account.verify_email(&proof_of(account.email())).unwrap();
        account
    }

    /// The link from `subject` at Okta to `account`.
    fn link(subject: &str, account: &User<ResolvedTenant>) -> FederatedLink<ResolvedTenant> {
        let now = crate::shared::clock::now();
        FederatedLink::reconstitute(FederatedLinkRow {
            connection_id: okta(),
            subject: FederatedSubject::new(subject).unwrap(),
            user_id: *account.id(),
            linked_at: now,
            confirmed_at: now,
        })
        .unwrap()
    }

    /// Standing derived from the CEO's user-management role makes admission
    /// refuse linking that privileged account through an authoritative
    /// provider.
    #[test]
    fn the_standing_reads_what_the_address_holder_holds_from_the_records() {
        let ceo = proven("ceo@acme.com");
        let records = Records::holding(&ceo, &[SystemPermission::ManageUsers]);
        let access = records.access();
        let identity = identity("ceo@acme.com", ProviderEmailVerification::Confirmed);

        let standing = Standing::of(
            &identity,
            &KnownRecords {
                subject_link: None,
                address_holder: Some(&ceo),
                holder_link: None,
                access: &access,
            },
            crate::shared::clock::now(),
        )
        .unwrap();
        let result = admission(
            &authoritative(JitProvisioning::Disabled),
            &identity,
            standing,
        );

        assert_eq!(result, Err(AdmissionRefusal::PrivilegedAccount));
    }

    /// Alice holds no built-in permission and is linked to her Okta subject.
    /// Her standing names her account, linked and ordinary, so she comes
    /// back to it.
    #[test]
    fn the_standing_of_a_linked_subject_names_its_account() {
        let alice = proven("alice@acme.com");
        let records = Records::holding(&alice, &[]);
        let access = records.access();
        let linked = link("00u8x", &alice);
        let identity = identity("alice@acme.com", ProviderEmailVerification::Unstated);

        let standing = Standing::of(
            &identity,
            &KnownRecords {
                subject_link: Some(&linked),
                address_holder: Some(&alice),
                holder_link: Some(&linked),
                access: &access,
            },
            crate::shared::clock::now(),
        )
        .unwrap();

        assert_eq!(
            outcome(admission(
                &connection(JitProvisioning::Disabled),
                &identity,
                standing
            )),
            Ok(AdmissionOutcome::Returning(*alice.id()))
        );
    }

    /// Building Mallory's standing from Bob's subject link is forbidden
    /// because the link names a different provider subject.
    #[test]
    fn a_link_loaded_for_another_subject_is_refused() {
        let bob = proven("bob@acme.com");
        let records = Records::holding(&bob, &[]);
        let access = records.access();
        let bobs_link = link("00u-bob", &bob);
        let mallory = VouchedIdentity::new(VouchedFacts {
            connection_id: okta(),
            subject: FederatedSubject::new("00u-mallory").unwrap(),
            email: Email::new("mallory@acme.com").unwrap(),
            email_verification: ProviderEmailVerification::Confirmed,
            factor: ProviderFactor::NotPerformed,
        });

        let standing = Standing::of(
            &mallory,
            &KnownRecords {
                subject_link: Some(&bobs_link),
                address_holder: None,
                holder_link: None,
                access: &access,
            },
            crate::shared::clock::now(),
        );

        assert!(matches!(standing, Err(DomainError::Forbidden(_))));
    }

    /// Building Mallory's standing with Bob as the address holder is
    /// forbidden because his account has a different email address.
    #[test]
    fn an_account_with_another_address_is_refused() {
        let bob = proven("bob@acme.com");
        let records = Records::holding(&bob, &[]);
        let access = records.access();

        let standing = Standing::of(
            &identity("mallory@acme.com", ProviderEmailVerification::Confirmed),
            &KnownRecords {
                subject_link: None,
                address_holder: Some(&bob),
                holder_link: None,
                access: &access,
            },
            crate::shared::clock::now(),
        );

        assert!(matches!(standing, Err(DomainError::Forbidden(_))));
    }

    /// Alice's account is linked to another Okta subject. Her standing says
    /// so, and a second subject with her address is refused.
    #[test]
    fn an_address_holder_linked_at_the_connection_is_linked_to_another() {
        let alice = proven("alice@acme.com");
        let records = Records::holding(&alice, &[]);
        let access = records.access();
        let first = link("00u-first", &alice);
        let identity = identity("alice@acme.com", ProviderEmailVerification::Confirmed);

        let standing = Standing::of(
            &identity,
            &KnownRecords {
                subject_link: None,
                address_holder: Some(&alice),
                holder_link: Some(&first),
                access: &access,
            },
            crate::shared::clock::now(),
        )
        .unwrap();

        assert_eq!(
            admission(&connection(JitProvisioning::Enabled), &identity, standing),
            Err(AdmissionRefusal::LinkedToAnother)
        );
    }
}
