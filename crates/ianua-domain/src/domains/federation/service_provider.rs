//! A SAML app of a tenant: an outside service its people sign in to, with
//! this platform as the identity provider.
//!
//! Okta and Entra call these SAML apps. Each names the app by its entity
//! id, the addresses its assertions may be posted to, how people are named
//! to it, what it is sent about them, and how its answers are signed and
//! sealed. A sign-in request is answered only as the app was set up: to a
//! registered address, in its `NameID` format, signed when it must be.
//!
//! Every change names who makes it, through
//! [`FederationControl`](crate::domains::federation::control::FederationControl).
//! A change that sends more of a person, or to more places, needs the full
//! federation right; one that only narrows what the app gets needs the
//! update right.

mod attributes;
mod requests;
mod settings;

use std::marker::PhantomData;

pub use attributes::{
    AccountAttribute, AttributeNameFormat, AttributeStatement, AttributeStatements, HeldNames,
    ReleasedAttribute, SamlAttributeName,
};
pub use requests::{AcceptedAuthnRequest, Answering};
pub use settings::{
    AcsUrls, AssertionEncryption, RequestSigningRule, SamlServiceProviderChange,
    SamlServiceProviderSettings, SignedParts,
};
use time::OffsetDateTime;

use crate::domains::federation::connection_status::ConnectionStatus;
use crate::domains::federation::control::{FederationControl, FederationRight};
use crate::domains::federation::events::{
    ServiceProviderCreated, ServiceProviderDeleted, ServiceProviderUpdated,
};
use crate::domains::federation::saml::authn_request::{
    InboundAuthnRequest, Reauthentication, RequestSignature,
};
use crate::domains::federation::saml::logout::{
    LogoutAnswer, LogoutPeer, LogoutSubject, SamlLogoutRequest, SentLogoutRequest,
};
use crate::domains::federation::saml::name_id::{IssuedNameId, NameIdMint};
use crate::domains::identity::account::user::User;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::types::event_type::FederationEvent;
use crate::types::{
    EventType, HttpsUrl, Label, SamlEntityId, SamlNameIdFormat, SamlServiceProviderId,
};

/// The event a new app's creation is recorded by.
const CREATED: EventType = EventType::Federation(FederationEvent::ServiceProviderCreated);

/// A SAML app of one tenant, with this platform as its identity provider.
///
/// Tenant-scoped: read and written only through stores opened for the
/// resolved tenant (see [`crate::isolation`]).
#[derive(Debug)]
pub struct SamlServiceProvider<T: TenantScope> {
    id: SamlServiceProviderId,
    name: Label,
    entity_id: SamlEntityId,
    status: ConnectionStatus,
    settings: SamlServiceProviderSettings,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// What a new SAML app is added with.
#[derive(Debug)]
pub struct NewSamlServiceProvider {
    /// The internal identity referenced by grants and audit records for this app.
    pub id: SamlServiceProviderId,
    /// The name shown in the app list.
    pub name: Label,
    /// The app's entity id, which its requests name as their issuer.
    pub entity_id: SamlEntityId,
    /// How it is answered.
    pub settings: SamlServiceProviderSettings,
}

/// A SAML app as stored, for [`SamlServiceProvider::reconstitute`].
#[derive(Debug)]
pub struct SamlServiceProviderRow {
    /// The persisted identity referenced by grants and audit records for this app.
    pub id: SamlServiceProviderId,
    /// The name shown in the app list.
    pub name: Label,
    /// The app's entity id.
    pub entity_id: SamlEntityId,
    /// Whether it is on.
    pub status: ConnectionStatus,
    /// How it is answered.
    pub settings: SamlServiceProviderSettings,
    /// When it was added.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

impl<T: TenantScope> SamlServiceProvider<T> {
    /// Adds an active SAML app. Raises `federation.service_provider_created`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not create
    ///   connections, or may not trust a provider: an app is sent who people
    ///   are, so adding one needs both rights.
    pub fn create(
        app: NewSamlServiceProvider,
        control: &FederationControl<'_>,
    ) -> Result<Self, DomainError> {
        control.ensure_may(FederationRight::CreateConnection)?;
        control.ensure_may(FederationRight::TrustConnection)?;
        let now = crate::shared::clock::now();
        let mut provider = Self {
            id: app.id,
            name: app.name,
            entity_id: app.entity_id,
            status: ConnectionStatus::Active,
            settings: app.settings,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        provider.raised.raise(ServiceProviderCreated {
            provider_id: provider.id,
            name: provider.name.clone(),
            occurred_at: now,
        });
        Ok(provider)
    }

    /// Rebuilds a SAML app from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says it changed
    ///   before it was added.
    pub fn reconstitute(row: SamlServiceProviderRow) -> Result<Self, DomainError> {
        RowCheck::of("SAML app")
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was added",
            )
            .finish()?;
        Ok(Self {
            id: row.id,
            name: row.name,
            entity_id: row.entity_id,
            status: row.status,
            settings: row.settings,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The stable internal identity, distinct from the peer's SAML entity identifier.
    #[must_use]
    pub fn id(&self) -> &SamlServiceProviderId {
        &self.id
    }

    /// The name shown in the app list.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// The app's entity id, written as the audience of every assertion.
    #[must_use]
    pub fn entity_id(&self) -> &SamlEntityId {
        &self.entity_id
    }

    /// Whether it is on.
    #[must_use]
    pub fn status(&self) -> ConnectionStatus {
        self.status
    }

    /// How it is answered.
    #[must_use]
    pub fn settings(&self) -> &SamlServiceProviderSettings {
        &self.settings
    }

    /// When it was added.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When it last changed.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// The sign-in `request` asks for, once it meets this app's rules.
    ///
    /// The request must name this app as issuer, be signed when the app
    /// requires it, ask for a registered address or none, and ask for the
    /// app's `NameID` format or none.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the app is switched off.
    /// - [`DomainError::Forbidden`] when the request names no issuer, or
    ///   another app.
    /// - [`DomainError::Forbidden`] when the app requires signed requests
    ///   and this one came unsigned.
    /// - [`DomainError::Forbidden`] when it asks for an address the app did
    ///   not register.
    /// - [`DomainError::Validation`] when it asks for another `NameID`
    ///   format.
    pub fn accept_request(
        &self,
        request: &InboundAuthnRequest,
    ) -> Result<AcceptedAuthnRequest, DomainError> {
        self.ensure_active()?;
        if request.issuer() != Some(&self.entity_id) {
            return Err(DomainError::forbidden(message!(
                "federation-this-request-does-not-name-the",
                "this request does not name the app as its issuer"
            )));
        }
        self.ensure_signed_as_required(request.signature())?;
        if !self
            .settings
            .name_id_format
            .answers(request.name_id_policy())
        {
            return Err(DomainError::invalid(message!(
                "federation-this-request-asks-for-a-nameid",
                "this request asks for a NameID format the app is not set up for"
            )));
        }
        Ok(AcceptedAuthnRequest {
            provider: self.id,
            acs_url: self.assertion_address(request)?.clone(),
            name_id_format: self.settings.name_id_format,
            answering: Answering::Request(request.id().clone()),
            reauthentication: request.force_authn(),
        })
    }

    /// A sign-in started here that the app never asked for, answered at its
    /// default address.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the app is switched off.
    pub fn unsolicited_sign_in(&self) -> Result<AcceptedAuthnRequest, DomainError> {
        self.ensure_active()?;
        Ok(AcceptedAuthnRequest {
            provider: self.id,
            acs_url: self.settings.acs_urls.default_url().clone(),
            name_id_format: self.settings.name_id_format,
            answering: Answering::Unsolicited,
            reauthentication: Reauthentication::NotForced,
        })
    }

    fn ensure_active(&self) -> Result<(), DomainError> {
        if !self.status.is_active() {
            return Err(DomainError::forbidden(message!(
                "federation-this-saml-app-is-switched-off",
                "this SAML app is switched off"
            )));
        }
        Ok(())
    }

    fn ensure_signed_as_required(&self, signature: RequestSignature) -> Result<(), DomainError> {
        match (&self.settings.request_signing, signature) {
            (RequestSigningRule::Required(_), RequestSignature::Absent) => {
                Err(DomainError::forbidden(message!(
                    "federation-this-app-signs-its-requests-and",
                    "this app signs its requests, and this one is unsigned"
                )))
            }
            (RequestSigningRule::Required(_), RequestSignature::Verified)
            | (RequestSigningRule::NotRequired, _) => Ok(()),
        }
    }

    /// The address the answer to `request` goes to: the one it asked for,
    /// when the app registered it, or the default when it asked for none.
    fn assertion_address<'a>(
        &'a self,
        request: &'a InboundAuthnRequest,
    ) -> Result<&'a HttpsUrl, DomainError> {
        let Some(asked) = request.acs_url() else {
            return Ok(self.settings.acs_urls.default_url());
        };
        if !self.settings.acs_urls.registered(asked) {
            return Err(DomainError::forbidden(message!(
                "federation-the-app-did-not-register-this",
                "the app did not register this address for its assertions"
            )));
        }
        Ok(asked)
    }

    /// The `NameID` `user` goes out as, for a sign-in this app accepted.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `accepted` is for another app.
    /// - [`DomainError::Conflict`] when the app names people by address and
    ///   `user`'s address is not verified.
    /// - [`DomainError::Infrastructure`] when `mint` fails.
    pub fn name_id_for(
        &self,
        accepted: &AcceptedAuthnRequest,
        user: &User<T>,
        mint: &impl NameIdMint,
    ) -> Result<IssuedNameId, DomainError> {
        if accepted.provider != self.id {
            return Err(DomainError::forbidden(message!(
                "federation-this-sign-in-was-accepted-for",
                "this sign-in was accepted for another app"
            )));
        }
        accepted.name_id_format.issue(&self.id, user, mint)
    }

    /// What `user` is sent, by this app's attribute statements. `held`
    /// names their roles and groups.
    #[must_use]
    pub fn released_attributes(
        &self,
        user: &User<T>,
        held: &HeldNames<'_>,
    ) -> Vec<ReleasedAttribute> {
        self.settings.attributes.released(user, held)
    }

    /// The answer owed to this app's logout `request`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the request names another app as
    ///   its issuer.
    /// - [`DomainError::Conflict`] when the app has no logout address to
    ///   answer at.
    pub fn accept_logout(&self, request: &SamlLogoutRequest) -> Result<LogoutAnswer, DomainError> {
        if *request.issuer() != self.entity_id {
            return Err(DomainError::forbidden(message!(
                "federation-this-logout-request-does-not-come-2",
                "this logout request does not come from the app"
            )));
        }
        Ok(request.answered_at(self.logout_url()?.clone()))
    }

    /// A logout request asking this app to end `subject`'s session, to keep
    /// until the app answers.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the app has no logout address.
    pub fn logout_request(&self, subject: LogoutSubject) -> Result<SentLogoutRequest, DomainError> {
        let to = LogoutPeer {
            peer: self.entity_id.clone(),
            destination: self.logout_url()?.clone(),
            name_id_format: SamlNameIdFormat::new(self.settings.name_id_format.urn())?,
        };
        Ok(SentLogoutRequest::sent(to, subject))
    }

    fn logout_url(&self) -> Result<&HttpsUrl, DomainError> {
        self.settings.logout_url.value().ok_or_else(|| {
            DomainError::conflict(message!(
                "federation-this-app-has-no-logout-address",
                "this app has no logout address"
            ))
        })
    }

    /// Makes every change in `changes`, as `control` allows. Raises one
    /// `federation.service_provider_updated` per save, naming the app as
    /// saved; a list with no change raises nothing.
    ///
    /// All of them are checked first, so a refused change leaves the app as
    /// it was.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person lacks the right a change
    ///   needs. See [`SamlServiceProviderChange`].
    pub fn update(
        &mut self,
        changes: Vec<SamlServiceProviderChange>,
        control: &FederationControl<'_>,
    ) -> Result<(), DomainError> {
        for change in &changes {
            control.ensure_may(change.needs(&self.settings))?;
        }
        if changes.is_empty() {
            return Ok(());
        }
        for change in changes {
            self.apply(change);
        }
        self.record_change();
        Ok(())
    }

    fn apply(&mut self, change: SamlServiceProviderChange) {
        let settings = &mut self.settings;
        match change {
            SamlServiceProviderChange::Rename(name) => self.name = name,
            SamlServiceProviderChange::AcsUrls(urls) => settings.acs_urls = urls,
            SamlServiceProviderChange::LogoutUrl(url) => settings.logout_url = url,
            SamlServiceProviderChange::NameIdFormat(format) => settings.name_id_format = format,
            SamlServiceProviderChange::Attributes(attributes) => settings.attributes = attributes,
            SamlServiceProviderChange::Signing(signing) => settings.signing = signing,
            SamlServiceProviderChange::Encryption(encryption) => settings.encryption = encryption,
            SamlServiceProviderChange::RequestSigning(rule) => settings.request_signing = rule,
        }
    }

    /// Switches the app back on. It was off for a reason, so this needs the
    /// full federation right. Raises `federation.service_provider_updated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not manage
    ///   federation.
    /// - [`DomainError::InvalidTransition`] when it is already on.
    pub fn activate(&mut self, control: &FederationControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(FederationRight::TrustConnection)?;
        self.status = self.status.try_transition(ConnectionStatus::Active)?;
        self.record_change();
        Ok(())
    }

    /// Switches the app off: no sign-in to it is answered. Anyone who may
    /// edit connections may, in an incident. Raises
    /// `federation.service_provider_updated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not update
    ///   connections.
    /// - [`DomainError::InvalidTransition`] when it is already off.
    pub fn disable(&mut self, control: &FederationControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(FederationRight::EditConnection)?;
        self.status = self.status.try_transition(ConnectionStatus::Disabled)?;
        self.record_change();
        Ok(())
    }

    /// Deletes the app. Raises `federation.service_provider_deleted`, taken
    /// once it is removed from storage. People keep their accounts; they
    /// only stop signing in to the app through this platform.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not delete
    ///   connections.
    pub fn delete(&mut self, control: &FederationControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(FederationRight::DeleteConnection)?;
        self.raised.raise(ServiceProviderDeleted {
            provider_id: self.id,
            name: self.name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Records a change: touches the app, and raises one update per save in
    /// place of any raised since the last save. A new app's changes are
    /// part of its creation.
    fn record_change(&mut self) {
        self.updated_at = crate::shared::clock::now();
        if self.raised.holds(CREATED) {
            return;
        }
        self.raised.raise_latest(ServiceProviderUpdated {
            provider_id: self.id,
            name: self.name.clone(),
            occurred_at: self.updated_at,
        });
    }
}

impl<T: TenantScope> Raises for SamlServiceProvider<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::{FederationAction, SystemPermission};
    use crate::domains::federation::fixtures::{federation_admin, holding};
    use crate::domains::federation::saml::authn_request::{InboundAuthnRequestRow, NameIdAsked};
    use crate::domains::federation::saml::logout::LogoutRequestParts;
    use crate::domains::federation::saml::name_id::{NameIdFormat, SamlNameIdValue};
    use crate::domains::identity::account::verified_email::proof_of;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::builders::{label, user};
    use crate::test_support::events::raised_names;
    use crate::types::{CertificatePem, SamlRequestId, SessionIndex, Setting, UserId};

    const EDITOR: [SystemPermission; 1] = [SystemPermission::Federation(FederationAction::Update)];

    /// A mint with fixed values, so a test can tell which one went out.
    struct FixedMint;

    impl NameIdMint for FixedMint {
        fn pairwise(
            &self,
            provider: &SamlServiceProviderId,
            account: &UserId,
        ) -> Result<SamlNameIdValue, DomainError> {
            Ok(SamlNameIdValue::new(format!("{provider}:{account}"))?)
        }

        fn transient(&self) -> Result<SamlNameIdValue, DomainError> {
            Ok(SamlNameIdValue::new("_transient_1")?)
        }
    }

    fn url(s: &str) -> HttpsUrl {
        HttpsUrl::new(s).unwrap()
    }

    fn certificate() -> CertificatePem {
        CertificatePem::new("-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----").unwrap()
    }

    fn settings(format: NameIdFormat) -> SamlServiceProviderSettings {
        SamlServiceProviderSettings {
            acs_urls: AcsUrls::new(
                url("https://app.acme.com/acs"),
                vec![url("https://app.acme.com/acs/eu")],
            )
            .unwrap(),
            logout_url: Setting::Set(url("https://app.acme.com/slo")),
            name_id_format: format,
            attributes: AttributeStatements::standard().unwrap(),
            signing: SignedParts::Assertion,
            encryption: AssertionEncryption::Plain,
            request_signing: RequestSigningRule::NotRequired,
        }
    }

    fn salesforce_with(
        settings: SamlServiceProviderSettings,
    ) -> SamlServiceProvider<ResolvedTenant> {
        SamlServiceProvider::create(
            NewSamlServiceProvider {
                id: SamlServiceProviderId::new(),
                name: label("Salesforce"),
                entity_id: SamlEntityId::new("https://app.acme.com").unwrap(),
                settings,
            },
            &federation_admin(),
        )
        .unwrap()
    }

    fn salesforce() -> SamlServiceProvider<ResolvedTenant> {
        salesforce_with(settings(NameIdFormat::Persistent))
    }

    /// Salesforce as stored, with nothing raised.
    fn stored() -> SamlServiceProvider<ResolvedTenant> {
        let mut app = salesforce();
        raised_names(&mut app);
        app
    }

    fn request(edit: impl FnOnce(&mut InboundAuthnRequestRow)) -> InboundAuthnRequest {
        let mut row = InboundAuthnRequestRow {
            id: SamlRequestId::new("_req_1").unwrap(),
            issuer: Some(SamlEntityId::new("https://app.acme.com").unwrap()),
            acs_url: None,
            force_authn: Reauthentication::NotForced,
            name_id_policy: NameIdAsked::AnyFormat,
            signature: RequestSignature::Absent,
        };
        edit(&mut row);
        InboundAuthnRequest::reconstitute(row).unwrap()
    }

    /// Ann adds Salesforce. It starts on and its addition is raised.
    #[test]
    fn adding_an_app_raises_its_creation() {
        let mut app = salesforce();

        assert!(app.status().is_active());
        assert_eq!(
            raised_names(&mut app),
            ["federation.service_provider_created"]
        );
    }

    /// Connection creation permission alone does not authorize adding a
    /// SAML app; the attempted creation is forbidden.
    #[test]
    fn adding_an_app_needs_the_full_right() {
        let create = [SystemPermission::Federation(FederationAction::Create)];

        let result = SamlServiceProvider::<ResolvedTenant>::create(
            NewSamlServiceProvider {
                id: SamlServiceProviderId::new(),
                name: label("Sam's app"),
                entity_id: SamlEntityId::new("https://sam.example.com").unwrap(),
                settings: settings(NameIdFormat::Persistent),
            },
            &holding(&create),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Salesforce asks for no address. Its assertion goes to its default
    /// address, answering its request.
    #[test]
    fn a_request_naming_no_address_is_answered_at_the_default() {
        let accepted = salesforce().accept_request(&request(|_| {})).unwrap();

        assert_eq!(accepted.acs_url().as_str(), "https://app.acme.com/acs");
        assert_eq!(
            accepted.in_response_to().map(SamlRequestId::as_str),
            Some("_req_1")
        );
    }

    /// Salesforce asks for its EU address, which it registered. The
    /// assertion goes there.
    #[test]
    fn a_registered_address_asked_for_is_used() {
        let accepted = salesforce()
            .accept_request(&request(|row| {
                row.acs_url = Some(url("https://app.acme.com/acs/eu"));
            }))
            .unwrap();

        assert_eq!(accepted.acs_url().as_str(), "https://app.acme.com/acs/eu");
    }

    /// Salesforce forbids a sign-in request that asks for its assertion at
    /// an unregistered address.
    #[test]
    fn an_unregistered_address_is_refused() {
        let result = salesforce().accept_request(&request(|row| {
            row.acs_url = Some(url("https://evil.example.com/acs"));
        }));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Salesforce forbids requests naming another issuer or omitting the
    /// issuer entirely.
    #[test]
    fn a_request_from_another_app_or_none_is_refused() {
        let other = salesforce().accept_request(&request(|row| {
            row.issuer = Some(SamlEntityId::new("https://other.example.com").unwrap());
        }));
        let none = salesforce().accept_request(&request(|row| row.issuer = None));

        assert!(matches!(other, Err(DomainError::Forbidden(_))));
        assert!(matches!(none, Err(DomainError::Forbidden(_))));
    }

    /// An app requiring request signatures forbids an unsigned request
    /// and accepts one with a verified signature.
    #[test]
    fn an_app_that_signs_its_requests_is_answered_only_when_signed() {
        let app = salesforce_with(SamlServiceProviderSettings {
            request_signing: RequestSigningRule::Required(certificate()),
            ..settings(NameIdFormat::Persistent)
        });

        let unsigned = app.accept_request(&request(|_| {}));
        let signed = app.accept_request(&request(|row| {
            row.signature = RequestSignature::Verified;
        }));

        assert!(matches!(unsigned, Err(DomainError::Forbidden(_))));
        assert!(signed.is_ok());
    }

    /// An app configured for persistent identifiers rejects a request for
    /// an email NameID with a validation error.
    #[test]
    fn a_request_for_another_name_id_format_is_refused() {
        let result = salesforce().accept_request(&request(|row| {
            row.name_id_policy = NameIdAsked::Format(
                SamlNameIdFormat::new(NameIdFormat::EmailAddress.urn()).unwrap(),
            );
        }));

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A disabled SAML app forbids both requested and unsolicited sign-ins.
    #[test]
    fn a_switched_off_app_is_not_answered() {
        let mut app = salesforce();
        app.disable(&federation_admin()).unwrap();

        assert!(matches!(
            app.accept_request(&request(|_| {})),
            Err(DomainError::Forbidden(_))
        ));
        assert!(matches!(
            app.unsolicited_sign_in(),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A sign-in started here goes to Salesforce's default address and
    /// answers no request.
    #[test]
    fn an_unsolicited_sign_in_goes_to_the_default_address() {
        let accepted = salesforce().unsolicited_sign_in().unwrap();

        assert_eq!(accepted.acs_url().as_str(), "https://app.acme.com/acs");
        assert_eq!(accepted.answering(), &Answering::Unsolicited);
    }

    /// Ann signs in to two apps set up for pairwise ids. Each is sent the
    /// mint's id for that app and her, never her account id.
    #[test]
    fn a_persistent_name_id_is_pairwise_per_app() {
        let ann = user(UserId::new(), "ann@acme.com");
        let (first, second) = (salesforce(), salesforce());

        let at_first = first
            .name_id_for(&first.unsolicited_sign_in().unwrap(), &ann, &FixedMint)
            .unwrap();
        let at_second = second
            .name_id_for(&second.unsolicited_sign_in().unwrap(), &ann, &FixedMint)
            .unwrap();

        assert_eq!(at_first.format(), NameIdFormat::Persistent);
        assert_ne!(at_first.value(), at_second.value());
        assert_ne!(at_first.value().as_str(), ann.id().to_string());
    }

    /// An app using email NameIDs refuses Ann's unverified address, then
    /// issues that address after mailbox verification.
    #[test]
    fn an_unverified_address_is_never_sent_as_the_name_id() {
        let app = salesforce_with(settings(NameIdFormat::EmailAddress));
        let mut ann = user(UserId::new(), "ann@acme.com");
        let accepted = app.unsolicited_sign_in().unwrap();

        let before = app.name_id_for(&accepted, &ann, &FixedMint);
        let proof = proof_of(ann.email());
        ann.verify_email(&proof).unwrap();
        let after = app.name_id_for(&accepted, &ann, &FixedMint).unwrap();

        assert!(matches!(before, Err(DomainError::Conflict(_))));
        assert_eq!(after.value().as_str(), "ann@acme.com");
    }

    /// An app set up for transient ids is sent the mint's fresh value.
    #[test]
    fn a_transient_name_id_comes_from_the_mint() {
        let app = salesforce_with(settings(NameIdFormat::Transient));
        let ann = user(UserId::new(), "ann@acme.com");

        let issued = app
            .name_id_for(&app.unsolicited_sign_in().unwrap(), &ann, &FixedMint)
            .unwrap();

        assert_eq!(issued.value().as_str(), "_transient_1");
    }

    /// Issuing a NameID is forbidden when the accepted sign-in belongs to
    /// another app.
    #[test]
    fn a_sign_in_accepted_for_another_app_is_refused() {
        let ann = user(UserId::new(), "ann@acme.com");
        let other = salesforce().unsolicited_sign_in().unwrap();

        let result = salesforce().name_id_for(&other, &ann, &FixedMint);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An editor renames the app and drops its EU address. Both take
    /// effect, and one update is raised.
    #[test]
    fn an_editor_may_narrow_an_app() {
        let mut app = stored();
        let fewer = AcsUrls::new(url("https://app.acme.com/acs"), Vec::new()).unwrap();

        app.update(
            vec![
                SamlServiceProviderChange::Rename(label("Salesforce EU")),
                SamlServiceProviderChange::AcsUrls(fewer),
            ],
            &holding(&EDITOR),
        )
        .unwrap();

        assert_eq!(app.name().as_str(), "Salesforce EU");
        assert!(app.settings().acs_urls.others().is_empty());
        assert_eq!(
            raised_names(&mut app),
            ["federation.service_provider_updated"]
        );
    }

    /// An editor cannot add an assertion destination, release roles or
    /// configure encryption. Each forbidden update also leaves its paired
    /// rename unapplied and raises no event.
    #[test]
    fn widening_an_app_needs_the_full_right() {
        let mut app = stored();
        let more = AcsUrls::new(
            url("https://app.acme.com/acs"),
            vec![url("https://sam.example.com/acs")],
        )
        .unwrap();
        let roles = AttributeStatements::new(vec![AttributeStatement {
            source: AccountAttribute::Roles,
            name: SamlAttributeName::new("roles").unwrap(),
            name_format: AttributeNameFormat::Basic,
        }])
        .unwrap();

        for change in [
            SamlServiceProviderChange::AcsUrls(more),
            SamlServiceProviderChange::Attributes(roles),
            SamlServiceProviderChange::Encryption(AssertionEncryption::EncryptedFor(certificate())),
        ] {
            let result = app.update(
                vec![SamlServiceProviderChange::Rename(label("Renamed")), change],
                &holding(&EDITOR),
            );

            assert!(matches!(result, Err(DomainError::Forbidden(_))));
        }
        assert_eq!(app.name().as_str(), "Salesforce");
        assert!(raised_names(&mut app).is_empty());
    }

    /// An editor is forbidden from dropping response signatures or the
    /// requirement for signed requests.
    #[test]
    fn checking_less_needs_the_full_right() {
        let mut app = salesforce_with(SamlServiceProviderSettings {
            signing: SignedParts::AssertionAndResponse,
            request_signing: RequestSigningRule::Required(certificate()),
            ..settings(NameIdFormat::Persistent)
        });

        let unsigned_response = app.update(
            vec![SamlServiceProviderChange::Signing(SignedParts::Assertion)],
            &holding(&EDITOR),
        );
        let unsigned_requests = app.update(
            vec![SamlServiceProviderChange::RequestSigning(
                RequestSigningRule::NotRequired,
            )],
            &holding(&EDITOR),
        );

        assert!(matches!(unsigned_response, Err(DomainError::Forbidden(_))));
        assert!(matches!(unsigned_requests, Err(DomainError::Forbidden(_))));
    }

    /// An editor switches the app off in an incident and may not switch it
    /// back on; a federation manager may. Each switch raises an update.
    #[test]
    fn switching_an_app_back_on_needs_the_full_right() {
        let mut app = stored();

        app.disable(&holding(&EDITOR)).unwrap();
        let by_editor = app.activate(&holding(&EDITOR));
        app.activate(&federation_admin()).unwrap();

        assert!(matches!(by_editor, Err(DomainError::Forbidden(_))));
        assert!(app.status().is_active());
        assert_eq!(
            raised_names(&mut app),
            ["federation.service_provider_updated"]
        );
    }

    /// An editor cannot delete the SAML app; a caller with deletion
    /// permission succeeds and raises one deletion event.
    #[test]
    fn deleting_an_app_needs_the_delete_right() {
        let mut app = stored();
        let deleter = [SystemPermission::Federation(FederationAction::Delete)];

        let by_editor = app.delete(&holding(&EDITOR));
        app.delete(&holding(&deleter)).unwrap();

        assert!(matches!(by_editor, Err(DomainError::Forbidden(_))));
        assert_eq!(
            raised_names(&mut app),
            ["federation.service_provider_deleted"]
        );
    }

    fn logout_from(issuer: &str) -> SamlLogoutRequest {
        SamlLogoutRequest::new(LogoutRequestParts {
            id: SamlRequestId::new("_their_logout").unwrap(),
            issuer: SamlEntityId::new(issuer).unwrap(),
            issued_at: crate::shared::clock::now(),
            name_id: SamlNameIdValue::new("p-123").unwrap(),
            session_indexes: Vec::new(),
        })
    }

    /// Salesforce asks to log Ann out. The answer goes to its logout
    /// address and names its request.
    #[test]
    fn an_apps_logout_request_is_answered_at_its_logout_address() {
        let answer = salesforce()
            .accept_logout(&logout_from("https://app.acme.com"))
            .unwrap();

        assert_eq!(answer.destination().as_str(), "https://app.acme.com/slo");
        assert_eq!(answer.in_response_to().as_str(), "_their_logout");
    }

    /// Salesforce forbids a logout request naming another app as issuer.
    #[test]
    fn a_logout_request_from_another_app_is_refused() {
        let result = salesforce().accept_logout(&logout_from("https://evil.example.com"));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An app with no logout address is never sent a logout request, and
    /// its own requests have nowhere to be answered.
    #[test]
    fn an_app_without_a_logout_address_takes_no_logout() {
        let app = salesforce_with(SamlServiceProviderSettings {
            logout_url: Setting::Unset,
            ..settings(NameIdFormat::Persistent)
        });

        let asked = app.logout_request(LogoutSubject {
            request_id: SamlRequestId::new("_logout_1").unwrap(),
            name_id: SamlNameIdValue::new("p-123").unwrap(),
            session_index: SessionIndex::new("_s1").unwrap(),
        });
        let answered = app.accept_logout(&logout_from("https://app.acme.com"));

        assert!(matches!(asked, Err(DomainError::Conflict(_))));
        assert!(matches!(answered, Err(DomainError::Conflict(_))));
    }

    /// A logout request to Salesforce goes to its logout address, in its
    /// `NameID` format, and is kept waiting for Salesforce's answer.
    #[test]
    fn a_logout_request_to_an_app_waits_for_that_app() {
        let sent = salesforce()
            .logout_request(LogoutSubject {
                request_id: SamlRequestId::new("_logout_1").unwrap(),
                name_id: SamlNameIdValue::new("p-123").unwrap(),
                session_index: SessionIndex::new("_s1").unwrap(),
            })
            .unwrap();

        assert_eq!(sent.peer().as_str(), "https://app.acme.com");
        assert_eq!(sent.destination().as_str(), "https://app.acme.com/slo");
        assert_eq!(sent.name_id_format().as_str(), SamlNameIdFormat::PERSISTENT);
    }

    /// A stored row that changed before it was added is refused as corrupt.
    #[test]
    fn a_stored_app_changed_before_it_was_added_is_refused() {
        let now = crate::shared::clock::now();

        let read = SamlServiceProvider::<ResolvedTenant>::reconstitute(SamlServiceProviderRow {
            id: SamlServiceProviderId::new(),
            name: label("Salesforce"),
            entity_id: SamlEntityId::new("https://app.acme.com").unwrap(),
            status: ConnectionStatus::Active,
            settings: settings(NameIdFormat::Persistent),
            created_at: now,
            updated_at: now - time::Duration::minutes(1),
        });

        assert!(refused_as_corrupt(&read));
    }
}
