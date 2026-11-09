//! The organization's own identity provider: the company directory its
//! members sign in to the dashboard through, over SAML or OIDC.
//!
//! A tenant's connections sign in that tenant's users; this one signs in
//! the organization's members. It vouches only for members the
//! organization already has, by the address the provider proves: members
//! are invited or added by an owner, never created by a sign-in.

use time::OffsetDateTime;

use crate::domains::authentication::sessions::mfa_factor::FactorProved;
use crate::domains::authentication::sessions::sign_in_progress::ProviderSignIn;
use crate::domains::federation::connection::{
    AssuranceTrust, AuthnRequestSigning, ConnectionConfig, EmailTrust, FederationProtocol,
};
use crate::domains::federation::connection_status::ConnectionStatus;
use crate::domains::federation::vouched_identity::{ProviderEmailVerification, VouchedIdentity};
use crate::domains::identity::account::verified_email::VerifiedEmail;
use crate::domains::organization::events::access::identity_provider::{
    OrgIdentityProviderAdded, OrgIdentityProviderChanged, OrgIdentityProviderRemoved,
};
use crate::domains::organization::members::control::OrgControl;
use crate::domains::organization::members::membership::OrgRole;
use crate::domains::organization::members::org_user::OrgUser;
use crate::domains::organization::members::permission::{OrgPermission, OrganizationAction};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete};
use crate::shared::model::row_check::RowCheck;
use crate::types::{ConnectionId, Label, OrganizationId};

/// The right every change to the organization's identity provider needs:
/// it decides who can reach the management plane.
const SIGN_IN_SETTINGS: OrgPermission = OrgPermission::Organization(OrganizationAction::AuthConfig);

/// The organization's identity provider.
#[derive(Debug)]
pub struct OrgIdentityProvider {
    id: ConnectionId,
    organization_id: OrganizationId,
    name: Label,
    config: ConnectionConfig,
    email_trust: EmailTrust,
    assurance_trust: AssuranceTrust,
    status: ConnectionStatus,
    created_at: OffsetDateTime,
    raised: RaisedEvents,
}

/// What a new organization identity provider is made from.
pub struct NewOrgIdentityProvider {
    /// The identity used to correlate federation requests with this connection.
    pub id: ConnectionId,
    /// The organization it signs members in for.
    pub organization_id: OrganizationId,
    /// The name members see on the sign-in page.
    pub name: Label,
    /// How it is reached: SAML or OIDC.
    pub config: ConnectionConfig,
}

/// An organization identity provider as storage keeps it.
pub struct OrgIdentityProviderRow {
    /// The persisted identity used to correlate federation requests with this connection.
    pub id: ConnectionId,
    /// The organization it signs members in for.
    pub organization_id: OrganizationId,
    /// The name members see.
    pub name: Label,
    /// How it is reached.
    pub config: ConnectionConfig,
    /// Whether its addresses are taken on its word.
    pub email_trust: EmailTrust,
    /// Whether its report of factors is taken on its word.
    pub assurance_trust: AssuranceTrust,
    /// Whether members may sign in through it.
    pub status: ConnectionStatus,
    /// When it was added.
    pub created_at: OffsetDateTime,
}

/// One change to the organization's identity provider.
#[derive(Debug)]
pub enum OrgIdentityProviderChange {
    /// A new name.
    Rename(Label),
    /// New settings for reaching it.
    Reconfigure(ConnectionConfig),
    /// Whether its addresses are taken on its word.
    TrustEmail(EmailTrust),
    /// Whether its report of factors is taken on its word.
    TrustAssurance(AssuranceTrust),
}

/// What the organization's provider vouched for a member: the sign-in, and
/// the address it proved. Only [`OrgIdentityProvider::vouch`] makes one, so
/// a member's account is never opened on a caller's word.
#[derive(Debug)]
pub struct OrgProviderProof {
    sign_in: ProviderSignIn,
    address: VerifiedEmail,
}

impl OrgProviderProof {
    /// The sign-in the provider vouched for.
    #[must_use]
    pub fn sign_in(&self) -> &ProviderSignIn {
        &self.sign_in
    }

    /// The address the provider proved.
    #[must_use]
    pub fn address(&self) -> &VerifiedEmail {
        &self.address
    }

    /// The sign-in and the address, for the sign-in to begin with.
    #[must_use]
    pub fn into_parts(self) -> (ProviderSignIn, VerifiedEmail) {
        (self.sign_in, self.address)
    }

    /// A proof as a test says the provider gave it.
    #[cfg(test)]
    pub(crate) fn assumed(sign_in: ProviderSignIn, address: VerifiedEmail) -> Self {
        Self { sign_in, address }
    }
}

impl OrgIdentityProvider {
    /// Adds the organization's identity provider, as `by` may: it starts
    /// switched off, so nobody is signed in through it before it is checked.
    /// Its addresses and factors start untrusted. Raises
    /// `organization.org_identity_provider_added`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the
    ///   organization's sign-in settings.
    /// - [`DomainError::Validation`] when SAML settings ask for signed
    ///   sign-in requests.
    pub fn add(new: NewOrgIdentityProvider, by: &OrgControl<'_>) -> Result<Self, DomainError> {
        by.ensure_may(&new.organization_id, SIGN_IN_SETTINGS)?;
        ensure_requests_unsigned(&new.config)?;
        let mut provider = Self {
            id: new.id,
            organization_id: new.organization_id,
            name: new.name,
            config: new.config,
            email_trust: EmailTrust::Unverified,
            assurance_trust: AssuranceTrust::Untrusted,
            status: ConnectionStatus::Disabled,
            created_at: crate::shared::clock::now(),
            raised: RaisedEvents::default(),
        };
        provider
            .raised
            .raise_organization(OrgIdentityProviderAdded {
                organization_id: provider.organization_id,
                connection_id: provider.id,
                name: provider.name.clone(),
                occurred_at: provider.created_at,
            });
        Ok(provider)
    }

    /// Rebuilds the provider from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row is dated after now, or
    ///   asks for signed sign-in requests.
    pub fn reconstitute(row: OrgIdentityProviderRow) -> Result<Self, DomainError> {
        RowCheck::of("organization identity provider")
            .holds(
                row.created_at <= crate::shared::clock::now(),
                "added in the future",
            )
            .holds(
                !asks_for_signed_requests(&row.config),
                "settings asking for signed sign-in requests",
            )
            .finish()?;
        Ok(Self {
            id: row.id,
            organization_id: row.organization_id,
            name: row.name,
            config: row.config,
            email_trust: row.email_trust,
            assurance_trust: row.assurance_trust,
            status: row.status,
            created_at: row.created_at,
            raised: RaisedEvents::default(),
        })
    }

    /// The stable identity used to correlate federation requests with this connection.
    #[must_use]
    pub fn id(&self) -> &ConnectionId {
        &self.id
    }

    /// The organization it signs members in for.
    #[must_use]
    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// The name members see.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// How it is reached.
    #[must_use]
    pub fn config(&self) -> &ConnectionConfig {
        &self.config
    }

    /// The protocol it speaks.
    #[must_use]
    pub fn protocol(&self) -> FederationProtocol {
        self.config.protocol()
    }

    /// Whether its addresses are taken on its word.
    #[must_use]
    pub fn email_trust(&self) -> EmailTrust {
        self.email_trust
    }

    /// Whether its report of factors is taken on its word.
    #[must_use]
    pub fn assurance_trust(&self) -> AssuranceTrust {
        self.assurance_trust
    }

    /// Whether members may sign in through it.
    #[must_use]
    pub fn status(&self) -> ConnectionStatus {
        self.status
    }

    /// When it was added.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Makes every change in `changes`, as `by` may. Raises one
    /// `organization.org_identity_provider_changed`; no change raises
    /// nothing.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the
    ///   organization's sign-in settings.
    /// - [`DomainError::Validation`] when new SAML settings ask for signed
    ///   sign-in requests. Nothing changes then.
    pub fn change(
        &mut self,
        changes: Vec<OrgIdentityProviderChange>,
        by: &OrgControl<'_>,
    ) -> Result<(), DomainError> {
        by.ensure_may(&self.organization_id, SIGN_IN_SETTINGS)?;
        changes.iter().try_for_each(ensure_change_fits)?;
        if changes.is_empty() {
            return Ok(());
        }
        for change in changes {
            match change {
                OrgIdentityProviderChange::Rename(name) => self.name = name,
                OrgIdentityProviderChange::Reconfigure(config) => self.config = config,
                OrgIdentityProviderChange::TrustEmail(trust) => self.email_trust = trust,
                OrgIdentityProviderChange::TrustAssurance(trust) => self.assurance_trust = trust,
            }
        }
        self.record_change();
        Ok(())
    }

    /// Switches it on or off, as `by` may.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the
    ///   organization's sign-in settings.
    /// - [`DomainError::InvalidTransition`] when it is already so.
    pub fn switch(&mut self, to: ConnectionStatus, by: &OrgControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(&self.organization_id, SIGN_IN_SETTINGS)?;
        self.status = self.status.try_transition(to)?;
        self.record_change();
        Ok(())
    }

    /// Removes it, as `by` may. Raises
    /// `organization.org_identity_provider_removed`; the caller deletes it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not change the
    ///   organization's sign-in settings.
    pub fn remove(&mut self, by: &OrgControl<'_>) -> Result<(), DomainError> {
        by.ensure_may(&self.organization_id, SIGN_IN_SETTINGS)?;
        self.raised.raise_organization(OrgIdentityProviderRemoved {
            organization_id: self.organization_id,
            connection_id: self.id,
            name: self.name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Raises the provider's change.
    fn record_change(&mut self) {
        self.raised.raise_organization(OrgIdentityProviderChanged {
            organization_id: self.organization_id,
            connection_id: self.id,
            name: self.name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// What the provider vouched for `member`, through `identity`.
    ///
    /// The provider must be switched on, and the identity must have come
    /// through it. The address must be `member`'s and proven: the provider
    /// said it verified it, or it is trusted as the authority for its
    /// addresses. Mallory points a provider of her own at a sign-in naming
    /// Ann's address; without these checks it would open Ann's account. A
    /// factor the provider reports counts only when it is trusted to report
    /// one, and never for an owner, so nobody skips an owner's second factor
    /// through a directory they run.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the provider is switched off, the
    ///   identity came through another connection, the address is not
    ///   `member`'s, or it is not proven.
    pub fn vouch(
        &self,
        identity: &VouchedIdentity,
        member: &OrgUser,
    ) -> Result<OrgProviderProof, DomainError> {
        if !self.status.is_active() || identity.connection_id() != &self.id {
            return Err(DomainError::forbidden(message!(
                "organization-this-identity-provider-does-not-sign",
                "this identity provider does not sign members in now"
            )));
        }
        if identity.email() != member.email() || !self.proves_address(identity) {
            return Err(DomainError::forbidden(message!(
                "organization-the-provider-did-not-prove-this",
                "the provider did not prove this member's address"
            )));
        }
        Ok(OrgProviderProof {
            sign_in: ProviderSignIn::new(self.protocol().into(), self.factor_for(identity, member)),
            address: VerifiedEmail::proven(identity.email().clone()),
        })
    }

    /// Whether the provider proved the address `identity` names.
    fn proves_address(&self, identity: &VouchedIdentity) -> bool {
        identity.email_verification() == ProviderEmailVerification::Confirmed
            || self.email_trust == EmailTrust::Authoritative
    }

    /// The factor the provider's report counts as, for `member`.
    fn factor_for(&self, identity: &VouchedIdentity, member: &OrgUser) -> FactorProved {
        if member.role() == OrgRole::Owner {
            return FactorProved::NoneYet;
        }
        self.assurance_trust.proves(identity.factor())
    }
}

impl RaisesComplete for OrgIdentityProvider {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

/// Refuses a change whose new settings ask for signed sign-in requests.
fn ensure_change_fits(change: &OrgIdentityProviderChange) -> Result<(), DomainError> {
    match change {
        OrgIdentityProviderChange::Reconfigure(config) => ensure_requests_unsigned(config),
        OrgIdentityProviderChange::Rename(_)
        | OrgIdentityProviderChange::TrustEmail(_)
        | OrgIdentityProviderChange::TrustAssurance(_) => Ok(()),
    }
}

/// Refuses settings that ask for signed sign-in requests.
///
/// An organization holds no signing key of its own: its members sign in to
/// the platform's own service provider, whose metadata says its requests go
/// unsigned. The answer is what the sign-in rests on, and it is signed and
/// bound to the request and the browser. Without this, Acme saves Okta
/// settings that want signed requests, and no member signs in until
/// someone finds out why.
fn ensure_requests_unsigned(config: &ConnectionConfig) -> Result<(), DomainError> {
    if asks_for_signed_requests(config) {
        return Err(DomainError::invalid(message!(
            "organization-an-organization-s-provider-takes-its",
            "an organization's provider takes its sign-in requests unsigned"
        )));
    }
    Ok(())
}

/// Whether `config` asks for signed sign-in requests.
fn asks_for_signed_requests(config: &ConnectionConfig) -> bool {
    match config {
        ConnectionConfig::Saml(saml) => saml.request_signing == AuthnRequestSigning::Signed,
        ConnectionConfig::Oidc(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::federation::fixtures::saml_config;
    use crate::domains::federation::vouched_identity::{ProviderFactor, VouchedFacts};
    use crate::domains::organization::members::control::tests::{
        acting, founder, member_of, session_of,
    };
    use crate::types::{Email, FederatedSubject};

    /// Acme's directory, added by Ann, its owner, and switched on.
    fn acme_directory(ann: &OrgUser) -> OrgIdentityProvider {
        let session = session_of(ann);
        let by = acting(ann, &session);
        let mut provider = OrgIdentityProvider::add(
            NewOrgIdentityProvider {
                id: ConnectionId::new(),
                organization_id: *ann.organization_id(),
                name: Label::new("name", "Acme Okta").unwrap(),
                config: saml_config(),
            },
            &by,
        )
        .unwrap();
        provider.switch(ConnectionStatus::Active, &by).unwrap();
        provider
    }

    /// What `provider` says about `email`, verified as `verification` says,
    /// reporting `factor`.
    fn identity(
        provider: &OrgIdentityProvider,
        email: &Email,
        verification: ProviderEmailVerification,
        factor: ProviderFactor,
    ) -> VouchedIdentity {
        VouchedIdentity::new(VouchedFacts {
            connection_id: *provider.id(),
            subject: FederatedSubject::new("okta|bob").unwrap(),
            email: email.clone(),
            email_verification: verification,
            factor,
        })
    }

    /// An owner adds the directory. It starts switched off, its addresses
    /// and factors untrusted, and the addition is recorded.
    #[test]
    fn a_new_directory_starts_off_and_untrusted() {
        let ann = founder();
        let session = session_of(&ann);

        let mut provider = OrgIdentityProvider::add(
            NewOrgIdentityProvider {
                id: ConnectionId::new(),
                organization_id: *ann.organization_id(),
                name: Label::new("name", "Acme Okta").unwrap(),
                config: saml_config(),
            },
            &acting(&ann, &session),
        )
        .unwrap();

        assert_eq!(provider.status(), ConnectionStatus::Disabled);
        assert_eq!(provider.email_trust(), EmailTrust::Unverified);
        assert_eq!(provider.assurance_trust(), AssuranceTrust::Untrusted);
        assert_eq!(provider.take_events().len(), 1);
    }

    /// Okta's SAML settings, asking for signed sign-in requests.
    fn asking_for_signed_requests() -> ConnectionConfig {
        let ConnectionConfig::Saml(mut saml) = saml_config() else {
            panic!("the fixture is a SAML configuration");
        };
        saml.request_signing = AuthnRequestSigning::Signed;
        ConnectionConfig::Saml(saml)
    }

    /// Adding a provider that requires signed sign-in requests returns a validation error.
    #[test]
    fn settings_asking_for_signed_requests_are_refused() {
        let ann = founder();
        let session = session_of(&ann);

        let added = OrgIdentityProvider::add(
            NewOrgIdentityProvider {
                id: ConnectionId::new(),
                organization_id: *ann.organization_id(),
                name: Label::new("name", "Acme Okta").unwrap(),
                config: asking_for_signed_requests(),
            },
            &acting(&ann, &session),
        );

        assert!(matches!(added, Err(DomainError::Validation(_))));
    }

    /// Requiring signed requests is rejected during reconfiguration and preserves the provider name.
    #[test]
    fn a_reconfiguration_asking_for_signed_requests_changes_nothing() {
        let ann = founder();
        let mut provider = acme_directory(&ann);
        let session = session_of(&ann);
        let changes = vec![
            OrgIdentityProviderChange::Rename(Label::new("name", "Okta").unwrap()),
            OrgIdentityProviderChange::Reconfigure(asking_for_signed_requests()),
        ];

        let refused = provider.change(changes, &acting(&ann, &session));

        assert!(matches!(refused, Err(DomainError::Validation(_))));
        assert_eq!(provider.name().as_str(), "Acme Okta");
    }

    /// A plain member lacks authority to add an organization identity provider.
    #[test]
    fn a_member_without_the_sign_in_right_cannot_add_one() {
        let bob = member_of(&founder());
        let session = session_of(&bob);

        let result = OrgIdentityProvider::add(
            NewOrgIdentityProvider {
                id: ConnectionId::new(),
                organization_id: *bob.organization_id(),
                name: Label::new("name", "Bob's IdP").unwrap(),
                config: saml_config(),
            },
            &acting(&bob, &session),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// The directory proves Bob's address. Bob's sign-in is vouched for.
    #[test]
    fn a_proven_address_of_the_member_is_vouched_for() {
        let ann = founder();
        let bob = member_of(&ann);
        let provider = acme_directory(&ann);
        let bobs = identity(
            &provider,
            bob.email(),
            ProviderEmailVerification::Confirmed,
            ProviderFactor::NotPerformed,
        );

        let proof = provider.vouch(&bobs, &bob).unwrap();

        assert_eq!(proof.address().as_email(), bob.email());
    }

    /// A provider cannot vouch for an unverified address or one belonging to another member.
    #[test]
    fn an_unproven_or_foreign_address_is_not_vouched_for() {
        let ann = founder();
        let bob = member_of(&ann);
        let provider = acme_directory(&ann);
        let mallory = Email::new("mallory@evil.test").unwrap();
        let foreign = identity(
            &provider,
            &mallory,
            ProviderEmailVerification::Confirmed,
            ProviderFactor::NotPerformed,
        );
        let unstated = identity(
            &provider,
            bob.email(),
            ProviderEmailVerification::Unstated,
            ProviderFactor::NotPerformed,
        );

        assert!(provider.vouch(&foreign, &bob).is_err());
        assert!(provider.vouch(&unstated, &bob).is_err());
    }

    /// A provider-reported factor gives an organization owner no second-factor proof.
    #[test]
    fn a_reported_factor_never_counts_for_an_owner() {
        let ann = founder();
        let session = session_of(&ann);
        let mut provider = acme_directory(&ann);
        provider
            .change(
                vec![OrgIdentityProviderChange::TrustAssurance(
                    AssuranceTrust::Trusted,
                )],
                &acting(&ann, &session),
            )
            .unwrap();
        let anns = identity(
            &provider,
            ann.email(),
            ProviderEmailVerification::Confirmed,
            ProviderFactor::Performed,
        );

        let proof = provider.vouch(&anns, &ann).unwrap();

        assert_eq!(proof.sign_in().factor(), FactorProved::NoneYet);
    }
}
