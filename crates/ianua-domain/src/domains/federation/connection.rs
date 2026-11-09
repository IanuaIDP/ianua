//! A tenant's connection to an external identity provider, over SAML or
//! OIDC.
//!
//! Every change names who makes it, through
//! [`FederationControl`](crate::domains::federation::control::FederationControl).
//! A change that lets the provider speak for more people, or be believed
//! more, needs the full federation right. A change that only stops it needs the update
//! right, so anyone who may edit a connection can switch it off in an
//! incident.

mod config;
mod domains;
mod group_mapping;
mod mapped_holdings;
mod metadata;
mod provisioning;
mod saml;
mod saml_keys;
mod settings;
mod trust;

use std::collections::HashMap;
use std::marker::PhantomData;

pub use config::{ConnectionConfig, FederationProtocol, OidcConfig, SamlConfig};
pub use domains::{ConnectionDomains, DomainHolders};
#[cfg(test)]
pub(crate) use domains::{own_tenant, owned_domain};
pub use group_mapping::{
    GrantedThrough, GroupMapping, GroupRule, GroupRules, MappedGrant, MappedGrants, MappingRule,
    ProviderGroupName,
};
pub use mapped_holdings::{MappedHoldings, MappedHoldingsRow, MappedPerson, MappedWithdrawal};
pub use metadata::{IdpMetadataFacts, ImportedIdpMetadata};
pub use saml::ProviderLogout;
pub use saml_keys::{AssertionDecryption, AuthnRequestSigning, IdpCertificates, SpEncryptionKey};
pub use settings::{AssuranceTrust, EmailTrust, JitProvisioning, ProfileField};
use time::OffsetDateTime;

use crate::domains::federation::connection::domains::hint_is_allowed;
use crate::domains::federation::connection_status::ConnectionStatus;
use crate::domains::federation::control::{FederationControl, FederationRight};
use crate::domains::federation::events::{
    ConnectionActivated, ConnectionCreated, ConnectionDeleted, ConnectionDisabled,
    ConnectionUpdated,
};
pub use crate::domains::federation::scope_token::ScopeToken;
use crate::domains::tenant::custom_domains::owned_domain::OwnedDomain;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::distinct::first_repeat;
use crate::types::event_type::FederationEvent;
use crate::types::{ConnectionId, DomainName, Email, EventType, Label, RoleId, Setting};

/// A tenant's connection to an external identity provider.
///
/// Tenant-scoped: read and written only through stores opened for the
/// resolved tenant (see [`crate::isolation`]).
///
/// Each tenant sets, per connection:
/// - which external `IdP` it signs in through, over SAML or OIDC
/// - whether an account is created on someone's first sign-in
/// - which provider claims fill which profile fields
/// - which of the provider's groups bring which roles and groups here
/// - the email domain that is sent straight to this `IdP`
/// - the email domains this `IdP` may vouch for, each one the tenant owns
///
/// Settings changes are recorded once per save. An admin who renames Okta
/// and adds a domain in one request leaves one `federation.connection_updated`
/// naming the connection as saved, not one record per setting. Settings
/// given to a new connection before its first save are part of its
/// creation, which `federation.connection_created` records.
#[derive(Debug)]
pub struct FederatedIdpConnection<T: TenantScope> {
    id: ConnectionId,
    provider_name: Label,
    status: ConnectionStatus,
    config: ConnectionConfig,
    jit_provisioning: JitProvisioning,
    jit_default_role_id: Setting<RoleId>,
    email_trust: EmailTrust,
    assurance_trust: AssuranceTrust,
    domain_hint: Setting<DomainName>,
    allowed_domains: Vec<DomainName>,
    attribute_mapping: HashMap<Label, ProfileField>,
    group_mapping: GroupMapping,
    created_at: OffsetDateTime,
    keyed_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// The event a new connection's creation is recorded by.
const CREATED: EventType = EventType::Federation(FederationEvent::ConnectionCreated);

/// A connection as stored, for rebuilding it with
/// [`FederatedIdpConnection::reconstitute`].
pub struct ConnectionRow {
    /// Internal connection identifier.
    pub id: ConnectionId,
    /// Provider name shown in connection settings.
    pub provider_name: Label,
    /// Whether the connection is active or disabled.
    pub status: ConnectionStatus,
    /// Protocol-specific configuration (SAML or OIDC).
    pub config: ConnectionConfig,
    /// Whether JIT provisioning is enabled.
    pub jit_provisioning: JitProvisioning,
    /// Default role for JIT-provisioned users.
    pub jit_default_role_id: Setting<RoleId>,
    /// Whether the provider's addresses are taken on its word.
    pub email_trust: EmailTrust,
    /// Whether the provider's report of factors is taken on its word.
    pub assurance_trust: AssuranceTrust,
    /// Email domain that routes to this connection.
    pub domain_hint: Setting<DomainName>,
    /// Email domains this connection may vouch for.
    pub allowed_domains: Vec<DomainName>,
    /// Which provider claim fills which profile field.
    pub attribute_mapping: HashMap<Label, ProfileField>,
    /// Which of the provider's groups bring which roles and groups.
    pub group_mapping: GroupMapping,
    /// When this connection was created.
    pub created_at: OffsetDateTime,
    /// When what checks the provider's answers, its SAML signing
    /// certificate, last changed. It is when the connection was created
    /// until then.
    pub keyed_at: OffsetDateTime,
}

impl<T: TenantScope> FederatedIdpConnection<T> {
    /// Creates a new active connection. It makes no accounts and vouches for
    /// no domain until an admin sets that up. Raises
    /// `federation.connection_created`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not create
    ///   connections.
    /// - [`DomainError::Validation`] when a SAML configuration's `NameID`
    ///   format does not name one person for good.
    pub fn create(
        id: ConnectionId,
        provider_name: Label,
        config: ConnectionConfig,
        control: &FederationControl<'_>,
    ) -> Result<Self, DomainError> {
        control.ensure_may(FederationRight::CreateConnection)?;
        config.ensure_stable_subject()?;
        let now = crate::shared::clock::now();
        let mut connection = Self {
            id,
            provider_name,
            status: ConnectionStatus::Active,
            config,
            jit_provisioning: JitProvisioning::Disabled,
            jit_default_role_id: Setting::Unset,
            email_trust: EmailTrust::Unverified,
            assurance_trust: AssuranceTrust::Untrusted,
            domain_hint: Setting::Unset,
            allowed_domains: Vec::new(),
            attribute_mapping: HashMap::new(),
            group_mapping: GroupMapping::Off,
            created_at: now,
            keyed_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        connection.raised.raise(ConnectionCreated {
            connection_id: connection.id,
            provider_name: connection.provider_name.clone(),
            protocol: connection.protocol(),
            occurred_at: now,
        });
        Ok(connection)
    }

    /// Rebuilds a connection from storage. It checks the same rules a live
    /// connection keeps and refuses a row that breaks one.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Infrastructure`] for duplicate or wildcard allowed
    /// domains, a hint outside them, a default role without account creation,
    /// an unstable SAML `NameID`, duplicate profile-field mappings,
    /// or a re-key time before creation.
    pub fn reconstitute(row: ConnectionRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            provider_name: row.provider_name,
            status: row.status,
            config: row.config,
            jit_provisioning: row.jit_provisioning,
            jit_default_role_id: row.jit_default_role_id,
            email_trust: row.email_trust,
            assurance_trust: row.assurance_trust,
            domain_hint: row.domain_hint,
            allowed_domains: row.allowed_domains,
            attribute_mapping: row.attribute_mapping,
            group_mapping: row.group_mapping,
            created_at: row.created_at,
            keyed_at: row.keyed_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &ConnectionRow) -> Result<(), DomainError> {
        RowCheck::of("federated connection")
            .in_order(
                row.created_at,
                row.keyed_at,
                "re-keyed before it was created",
            )
            .holds(
                row.jit_provisioning == JitProvisioning::Enabled
                    || row.jit_default_role_id.is_unset(),
                "a role for new accounts while none are made",
            )
            .holds(
                row.config.ensure_stable_subject().is_ok(),
                "a SAML NameID format that does not name one person for good",
            )
            .holds(
                first_repeat(row.attribute_mapping.values()).is_none(),
                "a profile field filled by two claims",
            )
            .finish()?;
        Self::ensure_domains_consistent(row)
    }

    /// Refuses a stored row whose allowed domains break a rule this keeps.
    fn ensure_domains_consistent(row: &ConnectionRow) -> Result<(), DomainError> {
        RowCheck::of("federated connection")
            .holds(
                first_repeat(&row.allowed_domains).is_none(),
                "an allowed domain named twice",
            )
            .holds(
                !row.allowed_domains.iter().any(DomainName::is_wildcard),
                "a wildcard as an allowed domain",
            )
            .holds(
                hint_is_allowed(&row.domain_hint, &row.allowed_domains),
                "a domain hint that is not an allowed domain",
            )
            .finish()
    }

    /// Internal connection identifier.
    #[must_use]
    pub fn id(&self) -> &ConnectionId {
        &self.id
    }

    /// Provider name (e.g. `"Okta"`, `"Azure AD"`, `"Google Workspace"`).
    #[must_use]
    pub fn provider_name(&self) -> &Label {
        &self.provider_name
    }

    /// Whether the connection is active or disabled.
    #[must_use]
    pub fn status(&self) -> ConnectionStatus {
        self.status
    }

    /// The full protocol-specific configuration.
    #[must_use]
    pub fn config(&self) -> &ConnectionConfig {
        &self.config
    }

    /// The federation protocol derived from the config.
    #[must_use]
    pub fn protocol(&self) -> FederationProtocol {
        self.config.protocol()
    }

    /// Whether users authenticating through this `IdP` are automatically
    /// created in the tenant if they don't already exist.
    #[must_use]
    pub fn jit_provisioning(&self) -> JitProvisioning {
        self.jit_provisioning
    }

    /// The role automatically assigned to JIT-provisioned users.
    #[must_use]
    pub fn jit_default_role_id(&self) -> Option<&RoleId> {
        self.jit_default_role_id.value()
    }

    /// Email domain that routes to this connection.
    ///
    /// When a user enters `alice@acme.com` and `"acme.com"` is the
    /// domain hint for this connection, the login flow redirects
    /// to this `IdP` automatically.
    #[must_use]
    pub fn domain_hint(&self) -> Option<&DomainName> {
        self.domain_hint.value()
    }

    /// The email domains this connection may vouch for. Empty means it
    /// vouches for nobody.
    #[must_use]
    pub fn allowed_domains(&self) -> &[DomainName] {
        &self.allowed_domains
    }

    /// Whether `email` is at one of the domains this connection may vouch
    /// for. Only an exact domain matches: `acme.com` does not vouch for
    /// `eu.acme.com`.
    #[must_use]
    pub fn vouches_for(&self, email: &Email) -> bool {
        self.allowed_domains
            .iter()
            .any(|domain| domain.as_str() == email.domain())
    }

    /// Which provider claim fills which profile field.
    ///
    /// Example: `{"given_name": DisplayName, "zoneinfo": Timezone}`.
    #[must_use]
    pub fn attribute_mapping(&self) -> &HashMap<Label, ProfileField> {
        &self.attribute_mapping
    }

    /// When this connection was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Whether this connection can accept authentication requests.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == ConnectionStatus::Active
    }

    /// Turns the connection back on. It was off for a reason, such as an
    /// incident, so this needs the full federation right. Raises
    /// `federation.connection_activated`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not manage
    ///   federation.
    /// - [`DomainError::InvalidTransition`] when it is already active.
    pub fn activate(&mut self, control: &FederationControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(FederationRight::TrustConnection)?;
        self.status = self.status.try_transition(ConnectionStatus::Active)?;
        self.raised.raise(ConnectionActivated {
            connection_id: self.id,
            provider_name: self.provider_name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Disables the connection. Users can no longer authenticate through it.
    /// Raises `federation.connection_disabled`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not update
    ///   connections.
    /// - [`DomainError::InvalidTransition`] when it is already disabled.
    pub fn disable(&mut self, control: &FederationControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(FederationRight::EditConnection)?;
        self.status = self.status.try_transition(ConnectionStatus::Disabled)?;
        self.raised.raise(ConnectionDisabled {
            connection_id: self.id,
            provider_name: self.provider_name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Raises `federation.connection_updated` for a setting that changed,
    /// in place of any update raised since the last save, so the save
    /// records one update naming the connection as it is saved. A new
    /// connection's settings are part of its creation, which records them.
    fn settings_changed(&mut self) {
        if self.raised.holds(CREATED) {
            return;
        }
        self.raised.raise_latest(ConnectionUpdated {
            connection_id: self.id,
            provider_name: self.provider_name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
    }

    /// Updates secrets, endpoints, certificates and scopes for the same provider.
    /// Protocol, OIDC issuer and SAML entity ID stay fixed because subject IDs belong
    /// to that provider. A newly accepted current or next SAML certificate records re-keying;
    /// privileged linked accounts must then reconfirm through
    /// [`FederatedLink::reconfirm`](crate::domains::federation::link::FederatedLink::reconfirm).
    /// Scopes, client-secret rotation and endpoint moves do not change signing authority.
    /// Raises `federation.connection_updated` once per save across setting changes.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] without federation-management rights.
    /// [`DomainError::Conflict`] for a different provider.
    /// [`DomainError::Validation`] for a SAML `NameID` format lacking stable identity.
    pub fn update_config(
        &mut self,
        config: ConnectionConfig,
        control: &FederationControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(FederationRight::TrustConnection)?;
        if config.provider() != self.config.provider() {
            return Err(DomainError::conflict(message!(
                "federation-a-connection-keeps-its-provider-add",
                "a connection keeps its provider; add a new connection for another one"
            )));
        }
        config.ensure_stable_subject()?;
        if config.brings_new_signer(&self.config) {
            self.keyed_at = crate::shared::clock::now();
        }
        self.config = config;
        self.settings_changed();
        Ok(())
    }

    /// When what checks the provider's answers, its SAML signing
    /// certificate, last changed. A link confirmed before then no longer
    /// signs in an account holding built-in permissions.
    #[must_use]
    pub fn keyed_at(&self) -> OffsetDateTime {
        self.keyed_at
    }

    /// Replaces the email domains this connection may vouch for, and the
    /// one among them that sends people straight to it.
    ///
    /// Each domain must be one this tenant, or another tenant of its
    /// organization in `holders`, proved it owns. An address the
    /// provider vouches for becomes a verified address here, which tokens
    /// this platform issues pass on to apps. Without the proof, Fay binds
    /// `globex.com` to a provider she runs, and apps trust her as Globex's
    /// CEO.
    ///
    /// The two change together because the hint must be an allowed domain:
    /// sending `alice@acme.com` to a provider that may not vouch for
    /// `acme.com` is a sign-in that always fails.
    ///
    /// Adding a domain needs the full federation right. Keeping or dropping
    /// domains already bound, or moving the hint among them, needs the
    /// update right.
    ///
    /// Raises `federation.connection_updated`, once per save however many
    /// settings change. Domains bound to a new connection before its first
    /// save are part of its creation.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when a domain was proved by a tenant
    ///   outside `holders`.
    /// - [`DomainError::Forbidden`] when the person lacks the right the change
    ///   needs.
    /// - [`DomainError::Validation`] when a domain is listed twice.
    /// - [`DomainError::Conflict`] when the hint is not an allowed domain.
    pub fn change_domains(
        &mut self,
        domains: ConnectionDomains,
        control: &FederationControl<'_>,
        holders: DomainHolders<'_>,
    ) -> Result<(), DomainError> {
        for owned in &domains.allowed {
            holders.ensure_may_bind(owned)?;
        }
        let allowed: Vec<DomainName> = domains
            .allowed
            .into_iter()
            .map(OwnedDomain::into_domain)
            .collect();
        control.ensure_may(self.right_to_bind(&allowed))?;
        if let Some(twice) = first_repeat(&allowed) {
            return Err(DomainError::invalid(message!(
                "federation-the-allowed-domain-is-listed-twice",
                format!("the allowed domain {} is listed twice", twice.as_str())
            )));
        }
        if !hint_is_allowed(&domains.hint, &allowed) {
            return Err(DomainError::conflict(message!(
                "federation-the-domain-hint-must-be-one",
                "the domain hint must be one of the allowed domains"
            )));
        }
        self.allowed_domains = allowed;
        self.domain_hint = domains.hint;
        self.settings_changed();
        Ok(())
    }

    /// The right binding `allowed` needs: the full one when it adds a
    /// domain, the update one when it keeps or drops domains already bound.
    fn right_to_bind(&self, allowed: &[DomainName]) -> FederationRight {
        if allowed
            .iter()
            .all(|domain| self.allowed_domains.contains(domain))
        {
            return FederationRight::EditConnection;
        }
        FederationRight::TrustConnection
    }

    /// Replaces which provider claim fills which profile field. Raises
    /// `federation.connection_updated`, once per save however many settings
    /// change.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not update
    ///   connections.
    /// - [`DomainError::Validation`] when two claims fill the same field,
    ///   which would leave the field to whichever is read last.
    pub fn replace_attribute_mapping(
        &mut self,
        mapping: HashMap<Label, ProfileField>,
        control: &FederationControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(FederationRight::EditConnection)?;
        if let Some(field) = first_repeat(mapping.values()) {
            return Err(DomainError::invalid(message!(
                "federation-two-claims-fill-map-one-claim",
                format!(
                    "two claims fill {}; map one claim to each field",
                    field.as_str()
                )
            )));
        }
        self.attribute_mapping = mapping;
        self.settings_changed();
        Ok(())
    }

    /// Updates the provider display name. Raises
    /// `federation.connection_updated`, once per save however many settings
    /// change, naming the connection as saved.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not update
    ///   connections.
    pub fn rename(
        &mut self,
        name: Label,
        control: &FederationControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(FederationRight::EditConnection)?;
        self.provider_name = name;
        self.settings_changed();
        Ok(())
    }

    /// Deletes this connection, once the person may delete connections and
    /// it is switched off. Raises `federation.connection_deleted`, taken
    /// once the connection is removed from storage.
    ///
    /// Deleting it deletes every link to it. The accounts it made often
    /// have no password, so their holders lose their only way in. The
    /// update right, which may only switch it off, is not enough. And it is
    /// switched off first, so people stop signing in through it before
    /// their links are gone, and nobody is cut off in the middle of a
    /// sign-in by one slip.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the person may not delete
    ///   connections.
    /// - [`DomainError::Forbidden`] while the connection is active.
    pub fn delete(&mut self, control: &FederationControl<'_>) -> Result<(), DomainError> {
        control.ensure_may(FederationRight::DeleteConnection)?;
        if self.is_active() {
            return Err(DomainError::forbidden(message!(
                "federation-a-connection-is-switched-off-before",
                "a connection is switched off before it is deleted"
            )));
        }
        self.raised.raise(ConnectionDeleted {
            connection_id: self.id,
            provider_name: self.provider_name.clone(),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }
}

impl<T: TenantScope> Raises for FederatedIdpConnection<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::methods::AuthMethod;
    use crate::domains::authentication::sessions::mfa_factor::{FactorProved, MfaFactor};
    use crate::domains::authorization::permission::{
        FederationAction, SystemPermission, UserAction,
    };
    use crate::domains::authorization::role::{DefaultAssignment, NewRole, Role};
    use crate::domains::federation::account_privilege::AccountPrivilege;
    use crate::domains::federation::fixtures::{
        federation_admin, holding, saml_config, saml_config_signed_by,
    };
    use crate::domains::federation::vouched_identity::{
        ProviderEmailVerification, ProviderFactor, VouchedFacts, VouchedIdentity,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::builders::label;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{HttpsUrl, PrincipalRef, SamlNameIdFormat, SealedSecret, UserId};

    fn url(s: &str) -> HttpsUrl {
        HttpsUrl::new(s).unwrap()
    }

    const EDITOR: [SystemPermission; 1] = [SystemPermission::Federation(FederationAction::Update)];

    fn oidc_config() -> ConnectionConfig {
        ConnectionConfig::Oidc(OidcConfig {
            issuer: url("https://accounts.google.com"),
            client_id: label("client_123"),
            encrypted_client_secret: SealedSecret::new("encrypted_secret_xyz").unwrap(),
            scopes: vec![
                ScopeToken::new("openid").unwrap(),
                ScopeToken::new("email").unwrap(),
                ScopeToken::new("profile").unwrap(),
            ],
        })
    }

    fn saml_connection() -> FederatedIdpConnection<ResolvedTenant> {
        FederatedIdpConnection::create(
            ConnectionId::new(),
            label("Okta"),
            saml_config(),
            &federation_admin(),
        )
        .unwrap()
    }

    fn oidc_connection() -> FederatedIdpConnection<ResolvedTenant> {
        FederatedIdpConnection::create(
            ConnectionId::new(),
            label("Google Workspace"),
            oidc_config(),
            &federation_admin(),
        )
        .unwrap()
    }

    fn saml_naming(format: &str) -> ConnectionConfig {
        let ConnectionConfig::Saml(saml) = saml_config() else {
            panic!("a SAML configuration");
        };
        ConnectionConfig::Saml(Box::new(SamlConfig {
            name_id_format: SamlNameIdFormat::new(format).unwrap(),
            ..*saml
        }))
    }

    /// Creating or updating a SAML connection rejects email, transient and
    /// unspecified NameID formats because they do not provide a stable
    /// identity for each person.
    #[test]
    fn a_saml_connection_must_name_each_person_for_good() {
        for format in [
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
            "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        ] {
            let created = FederatedIdpConnection::<ResolvedTenant>::create(
                ConnectionId::new(),
                label("Okta"),
                saml_naming(format),
                &federation_admin(),
            );
            let mut conn = saml_connection();
            let changed = conn.update_config(saml_naming(format), &federation_admin());

            assert!(
                matches!(created, Err(DomainError::Validation(_))),
                "{format}"
            );
            assert!(
                matches!(changed, Err(DomainError::Validation(_))),
                "{format}"
            );
        }
    }

    /// An admin adds Okta over SAML. It starts active, makes no accounts,
    /// names no role, hint or claim mapping.
    #[test]
    fn create_saml_connection() {
        let conn = saml_connection();

        assert_eq!(conn.provider_name().as_str(), "Okta");
        assert_eq!(conn.protocol(), FederationProtocol::Saml);
        assert!(conn.is_active());
        assert_eq!(conn.jit_provisioning(), JitProvisioning::Disabled);
        assert!(conn.jit_default_role_id().is_none());
        assert!(conn.domain_hint().is_none());
        assert!(conn.attribute_mapping().is_empty());
    }

    /// An admin adds Google Workspace over OIDC. It starts active and reports
    /// OIDC as its protocol.
    #[test]
    fn create_oidc_connection() {
        let conn = oidc_connection();

        assert_eq!(conn.provider_name().as_str(), "Google Workspace");
        assert_eq!(conn.protocol(), FederationProtocol::Oidc);
        assert!(conn.is_active());
    }

    /// Sam's federation viewing permission does not authorize creating a
    /// provider connection; creation is forbidden.
    #[test]
    fn creating_a_connection_needs_the_create_right() {
        let view = [SystemPermission::Federation(FederationAction::View)];

        let result = FederatedIdpConnection::<ResolvedTenant>::create(
            ConnectionId::new(),
            label("Sam's IdP"),
            saml_config(),
            &holding(&view),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An editor switches a connection off during an incident. It no longer
    /// takes sign-ins.
    #[test]
    fn an_editor_can_switch_a_connection_off() {
        let mut conn = saml_connection();

        conn.disable(&holding(&EDITOR)).unwrap();

        assert!(!conn.is_active());
        assert_eq!(conn.status(), ConnectionStatus::Disabled);
    }

    /// An editor cannot activate a disabled connection, which stays off
    /// until a federation administrator activates it.
    #[test]
    fn turning_a_connection_back_on_needs_the_full_right() {
        let mut conn = saml_connection();
        conn.disable(&federation_admin()).unwrap();

        let by_editor = conn.activate(&holding(&EDITOR));

        assert!(matches!(by_editor, Err(DomainError::Forbidden(_))));
        assert!(!conn.is_active());
        conn.activate(&federation_admin()).unwrap();
        assert!(conn.is_active());
    }

    fn domains(allowed: &[&str], hint: Setting<&str>) -> ConnectionDomains {
        ConnectionDomains {
            allowed: allowed.iter().map(|name| owned_domain(name)).collect(),
            hint: match hint {
                Setting::Set(name) => Setting::Set(domain(name)),
                Setting::Unset => Setting::Unset,
            },
        }
    }

    /// An admin allows `acme.com` and makes it the hint. People with an
    /// `acme.com` address are then sent to this connection.
    #[test]
    fn an_allowed_domain_can_be_the_hint() {
        let mut conn = saml_connection();

        conn.change_domains(
            domains(&["acme.com"], Setting::Set("acme.com")),
            &federation_admin(),
            own_tenant(),
        )
        .unwrap();

        assert_eq!(conn.domain_hint().map(DomainName::as_str), Some("acme.com"));
    }

    /// An editor keeps `acme.com` allowed but clears it as the hint. The
    /// connection then has no hint at all.
    #[test]
    fn a_cleared_hint_sends_nobody_to_the_connection() {
        let mut conn = saml_connection();
        conn.change_domains(
            domains(&["acme.com"], Setting::Set("acme.com")),
            &federation_admin(),
            own_tenant(),
        )
        .unwrap();

        conn.change_domains(
            domains(&["acme.com"], Setting::Unset),
            &holding(&EDITOR),
            own_tenant(),
        )
        .unwrap();

        assert!(conn.domain_hint().is_none());
    }

    /// Adding an allowed domain is forbidden for a connection editor,
    /// leaving the allowed domain list empty.
    #[test]
    fn adding_a_domain_needs_the_full_right() {
        let mut conn = saml_connection();

        let result = conn.change_domains(
            domains(&["acme.com"], Setting::Unset),
            &holding(&EDITOR),
            own_tenant(),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(conn.allowed_domains().is_empty());
    }

    /// An admin allows `acme.com` but sets `globex.com` as the hint. It is
    /// refused and nothing changes, since Globex people would be sent to a
    /// sign-in that always fails.
    #[test]
    fn a_hint_outside_the_allowed_domains_is_refused() {
        let mut conn = saml_connection();

        let result = conn.change_domains(
            domains(&["acme.com"], Setting::Set("globex.com")),
            &federation_admin(),
            own_tenant(),
        );

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert!(conn.allowed_domains().is_empty());
    }

    fn role_granting(system: Vec<SystemPermission>) -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id: RoleId::new(),
            name: label("member"),
            system_permissions: system,
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        })
    }

    /// An admin who holds every permission turns on account creation with a
    /// "member" role that grants no built-in permission. New accounts are
    /// made and get that role.
    #[test]
    fn provisioning_gives_new_accounts_the_named_role() {
        let mut conn = saml_connection();
        let role = role_granting(Vec::new());

        conn.provision_new_accounts(Setting::Set(&role), &federation_admin())
            .unwrap();

        assert_eq!(conn.jit_provisioning(), JitProvisioning::Enabled);
        assert_eq!(conn.jit_default_role_id(), Some(role.id()));
    }

    /// Even an administrator cannot enable account provisioning with a
    /// role that grants a built-in permission; provisioning stays disabled.
    #[test]
    fn provisioning_never_gives_built_in_permissions() {
        let mut conn = saml_connection();
        let role = role_granting(vec![SystemPermission::Users(UserAction::View)]);

        let result = conn.provision_new_accounts(Setting::Set(&role), &federation_admin());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(conn.jit_provisioning(), JitProvisioning::Disabled);
    }

    /// Sam manages federation and views users, but provisioning with a
    /// user-management role is forbidden, leaving provisioning disabled
    /// and its default role unset.
    #[test]
    fn provisioning_with_a_role_beyond_the_granter_is_refused() {
        let mut conn = saml_connection();
        let admin_role = role_granting(vec![SystemPermission::ManageUsers]);
        let sam = [
            SystemPermission::ManageFederation,
            SystemPermission::Users(UserAction::View),
        ];

        let result = conn.provision_new_accounts(Setting::Set(&admin_role), &holding(&sam));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(conn.jit_provisioning(), JitProvisioning::Disabled);
        assert!(conn.jit_default_role_id().is_none());
    }

    /// A connection editor cannot enable account provisioning, which
    /// remains disabled after the forbidden attempt.
    #[test]
    fn turning_on_account_creation_needs_the_full_right() {
        let mut conn = saml_connection();

        let result = conn.provision_new_accounts(Setting::Unset, &holding(&EDITOR));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(conn.jit_provisioning(), JitProvisioning::Disabled);
    }

    /// Account creation with a role is turned off by an editor. The role is
    /// cleared too, so turning creation back on later does not hand out a
    /// stale role.
    #[test]
    fn stopping_provisioning_forgets_the_role() {
        let mut conn = saml_connection();
        let role = role_granting(Vec::new());
        conn.provision_new_accounts(Setting::Set(&role), &federation_admin())
            .unwrap();

        conn.stop_provisioning(&holding(&EDITOR)).unwrap();

        assert_eq!(conn.jit_provisioning(), JitProvisioning::Disabled);
        assert!(conn.jit_default_role_id().is_none());
    }

    /// A connection viewer cannot disable provisioning; the enabled
    /// setting and its default role remain intact.
    #[test]
    fn stopping_provisioning_needs_the_right_to_edit_connections() {
        let mut conn = saml_connection();
        let role = role_granting(Vec::new());
        conn.provision_new_accounts(Setting::Set(&role), &federation_admin())
            .unwrap();
        let view = [SystemPermission::Federation(FederationAction::View)];

        let result = conn.stop_provisioning(&holding(&view));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(conn.jit_provisioning(), JitProvisioning::Enabled);
        assert_eq!(conn.jit_default_role_id(), Some(role.id()));
    }

    /// Okta makes an account for Ann on her first sign-in. She is given the
    /// "member" role the connection names for new accounts.
    #[test]
    fn a_new_account_is_given_the_connections_default_role() {
        let mut conn = saml_connection();
        let member = role_granting(Vec::new());
        conn.provision_new_accounts(Setting::Set(&member), &federation_admin())
            .unwrap();
        let ann = UserId::new();

        let given = conn.default_assignment(ann, &member).unwrap();

        assert_eq!(given.principal(), &PrincipalRef::User(ann));
        assert_eq!(given.role_id(), member.id());
    }

    /// A connection configured with the member role forbids assigning a
    /// different role through its default-assignment operation.
    #[test]
    fn a_connection_gives_new_accounts_only_its_default_role() {
        let mut conn = saml_connection();
        let member = role_granting(Vec::new());
        let billing = role_granting(Vec::new());
        conn.provision_new_accounts(Setting::Set(&member), &federation_admin())
            .unwrap();

        let result = conn.default_assignment(UserId::new(), &billing);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Deleting a disabled connection is forbidden for an editor and
    /// succeeds for a caller holding the deletion permission.
    #[test]
    fn the_update_right_does_not_delete_a_connection() {
        let mut conn = saml_connection();
        conn.disable(&federation_admin()).unwrap();
        let deleter = [SystemPermission::Federation(FederationAction::Delete)];

        let by_editor = conn.delete(&holding(&EDITOR));
        let by_deleter = conn.delete(&holding(&deleter));

        assert!(matches!(by_editor, Err(DomainError::Forbidden(_))));
        assert!(by_deleter.is_ok());
    }

    /// Deleting an active connection is forbidden even for a federation
    /// administrator.
    #[test]
    fn an_active_connection_is_not_deleted() {
        let mut conn = saml_connection();

        let result = conn.delete(&federation_admin());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An editor cannot trust a provider's addresses or factors, but can
    /// remove address trust after an administrator grants it.
    #[test]
    fn trusting_a_provider_needs_the_full_right() {
        let mut conn = saml_connection();
        let editor = holding(&EDITOR);

        let email = conn.change_email_trust(EmailTrust::Authoritative, &editor);
        let factors = conn.change_assurance_trust(AssuranceTrust::Trusted, &editor);

        assert!(matches!(email, Err(DomainError::Forbidden(_))));
        assert!(matches!(factors, Err(DomainError::Forbidden(_))));
        conn.change_email_trust(EmailTrust::Authoritative, &federation_admin())
            .unwrap();
        conn.change_email_trust(EmailTrust::Unverified, &editor)
            .unwrap();
        assert_eq!(conn.email_trust(), EmailTrust::Unverified);
    }

    /// An admin maps the provider's `given_name` to the display name. The
    /// connection then reports that mapping.
    #[test]
    fn a_replaced_attribute_mapping_takes_effect() {
        let mut conn = saml_connection();
        let mapping = HashMap::from([(label("given_name"), ProfileField::DisplayName)]);

        conn.replace_attribute_mapping(mapping.clone(), &holding(&EDITOR))
            .unwrap();

        assert_eq!(conn.attribute_mapping(), &mapping);
    }

    /// An admin maps both `name` and `given_name` to the display name. Which
    /// one wins would depend on reading order, so it is refused.
    #[test]
    fn two_claims_for_one_profile_field_are_refused() {
        let mut conn = saml_connection();
        let mapping = HashMap::from([
            (label("name"), ProfileField::DisplayName),
            (label("given_name"), ProfileField::DisplayName),
        ]);

        let result = conn.replace_attribute_mapping(mapping, &federation_admin());

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert!(conn.attribute_mapping().is_empty());
    }

    /// A disabled OIDC connection with account creation, a role, a hint and a
    /// mapping is loaded from storage. Every field comes back as stored.
    #[test]
    fn reconstitute_preserves_all_fields() {
        let id = ConnectionId::new();
        let role_id = RoleId::new();
        let now = crate::shared::clock::now();
        let mapping = HashMap::from([(label("zoneinfo"), ProfileField::Timezone)]);

        let conn = FederatedIdpConnection::<ResolvedTenant>::reconstitute(provisioning_row(
            id,
            role_id,
            now,
            mapping.clone(),
        ))
        .unwrap();

        assert_eq!(*conn.id(), id);
        assert_eq!(conn.provider_name().as_str(), "Azure AD");
        assert_eq!(conn.status(), ConnectionStatus::Disabled);
        assert_eq!(conn.protocol(), FederationProtocol::Oidc);
        assert_eq!(conn.jit_provisioning(), JitProvisioning::Enabled);
        assert_eq!(conn.jit_default_role_id(), Some(&role_id));
        assert_eq!(
            conn.domain_hint().map(DomainName::as_str),
            Some("globex.com")
        );
        assert_eq!(conn.attribute_mapping(), &mapping);
        assert_eq!(conn.created_at(), now);
    }

    /// Stores a disabled OIDC provider that provisions a role and maps a profile field.
    fn provisioning_row(
        id: ConnectionId,
        role_id: RoleId,
        now: OffsetDateTime,
        mapping: HashMap<Label, ProfileField>,
    ) -> ConnectionRow {
        ConnectionRow {
            id,
            provider_name: label("Azure AD"),
            status: ConnectionStatus::Disabled,
            config: oidc_config(),
            jit_provisioning: JitProvisioning::Enabled,
            jit_default_role_id: Setting::Set(role_id),
            email_trust: EmailTrust::Unverified,
            assurance_trust: AssuranceTrust::Untrusted,
            domain_hint: Setting::Set(domain("globex.com")),
            allowed_domains: vec![domain("globex.com")],
            attribute_mapping: mapping,
            group_mapping: GroupMapping::Off,
            created_at: now,
            keyed_at: now,
        }
    }

    /// Acme moves its SSO endpoint to `/sso/v2` at the same provider. The new
    /// configuration is kept, so sign-ins go to the new endpoint.
    #[test]
    fn replacing_the_configuration_takes_effect() {
        let mut conn = saml_connection();
        let ConnectionConfig::Saml(mut moved) = saml_config() else {
            panic!("a SAML configuration");
        };
        moved.sso_url = url("https://idp.acme.com/sso/v2");

        conn.update_config(ConnectionConfig::Saml(moved), &federation_admin())
            .unwrap();

        let ConnectionConfig::Saml(saml) = conn.config() else {
            panic!("expected the replacement configuration");
        };
        assert_eq!(saml.sso_url.as_str(), "https://idp.acme.com/sso/v2");
    }

    /// An editor cannot replace the signing certificate; the forbidden
    /// update leaves the original SAML configuration intact.
    #[test]
    fn changing_the_configuration_needs_the_full_right() {
        let mut conn = saml_connection();

        let result = conn.update_config(rekeyed(), &holding(&EDITOR));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(conn.config(), &saml_config());
    }

    fn rekeyed() -> ConnectionConfig {
        saml_config_signed_by("-----BEGIN CERTIFICATE-----\nMIID\n-----END CERTIFICATE-----")
    }

    /// Replacing the signing certificate advances the connection's key
    /// timestamp to the time of the update.
    #[test]
    fn a_new_certificate_re_keys_the_connection() {
        let start = crate::shared::clock::now();
        let _then = crate::shared::clock::freeze(start);
        let mut conn = saml_connection();
        let _later = crate::shared::clock::freeze(start + time::Duration::minutes(1));

        conn.update_config(rekeyed(), &federation_admin()).unwrap();

        assert_eq!(conn.keyed_at(), start + time::Duration::minutes(1));
    }

    /// Acme moves its SSO URL, and its Google connection asks for one more
    /// scope. Nobody new may sign answers, so neither re-keys the
    /// connection, and no admin is asked to confirm their link.
    #[test]
    fn a_new_sso_url_or_scope_does_not_re_key_the_connection() {
        let start = crate::shared::clock::now();
        let _then = crate::shared::clock::freeze(start);
        let mut saml = saml_connection();
        let mut oidc = oidc_connection();
        let _later = crate::shared::clock::freeze(start + time::Duration::minutes(1));
        let ConnectionConfig::Saml(mut moved) = saml_config() else {
            panic!("a SAML configuration");
        };
        moved.sso_url = url("https://idp.acme.com/sso/v2");
        let ConnectionConfig::Oidc(mut wider) = oidc_config() else {
            panic!("an OIDC configuration");
        };
        wider.scopes.push(ScopeToken::new("groups").unwrap());

        saml.update_config(ConnectionConfig::Saml(moved), &federation_admin())
            .unwrap();
        oidc.update_config(ConnectionConfig::Oidc(wider), &federation_admin())
            .unwrap();

        assert_eq!(saml.keyed_at(), start);
        assert_eq!(oidc.keyed_at(), start);
    }

    /// Changing an OIDC connection's issuer or replacing it with SAML
    /// conflicts, leaving its protocol as OIDC.
    #[test]
    fn a_connection_cannot_be_pointed_at_another_provider() {
        let mut conn = oidc_connection();
        let ConnectionConfig::Oidc(mut elsewhere) = oidc_config() else {
            panic!("an OIDC configuration");
        };
        elsewhere.issuer = url("https://login.microsoftonline.com/other");

        let other_issuer =
            conn.update_config(ConnectionConfig::Oidc(elsewhere), &federation_admin());
        let other_protocol = conn.update_config(saml_config(), &federation_admin());

        assert!(matches!(other_issuer, Err(DomainError::Conflict(_))));
        assert!(matches!(other_protocol, Err(DomainError::Conflict(_))));
        assert_eq!(conn.protocol(), FederationProtocol::Oidc);
    }

    /// An editor renames "Okta" to "Okta (Production)". The new name is the
    /// one shown on the sign-in page and in the connection list.
    #[test]
    fn renaming_a_connection_changes_what_it_is_listed_as() {
        let mut conn = saml_connection();

        conn.rename(label("Okta (Production)"), &holding(&EDITOR))
            .unwrap();

        assert_eq!(conn.provider_name().as_str(), "Okta (Production)");
    }

    fn domain(name: &str) -> DomainName {
        DomainName::new(name).unwrap()
    }

    fn email(address: &str) -> Email {
        Email::new(address).unwrap()
    }

    /// A connection with no allowed domains is asked about `alice@acme.com`.
    /// It does not vouch for her until an admin allows `acme.com`.
    #[test]
    fn a_new_connection_vouches_for_nobody() {
        let conn = saml_connection();

        assert!(!conn.vouches_for(&email("alice@acme.com")));
    }

    /// A connection allowing acme.com vouches for that exact email domain,
    /// but neither its subdomains nor a hostname extending its name.
    #[test]
    fn a_connection_vouches_only_for_its_exact_domains() {
        let mut conn = saml_connection();

        conn.change_domains(
            domains(&["acme.com"], Setting::Unset),
            &federation_admin(),
            own_tenant(),
        )
        .unwrap();

        assert!(conn.vouches_for(&email("alice@acme.com")));
        assert!(!conn.vouches_for(&email("alice@eu.acme.com")));
        assert!(!conn.vouches_for(&email("alice@acme.com.evil.io")));
    }

    /// An admin lists `b.com` twice in the allowed domains. The change is
    /// refused and the list stays as it was.
    #[test]
    fn an_allowed_domain_listed_twice_is_refused() {
        let mut conn = saml_connection();

        let result = conn.change_domains(
            domains(&["b.com", "a.com", "b.com"], Setting::Unset),
            &federation_admin(),
            own_tenant(),
        );

        assert!(matches!(result, Err(DomainError::Validation(_))));
        assert!(conn.allowed_domains().is_empty());
    }

    /// An OIDC configuration is printed with `{:?}`, as a log line would.
    /// The client secret shows as redacted, so it never reaches the logs.
    #[test]
    fn debug_output_never_carries_the_client_secret() {
        let rendered = format!("{:?}", oidc_config());

        assert!(!rendered.contains("encrypted_secret_xyz"));
        assert!(rendered.contains("redacted"));
    }

    fn vouched(
        conn: &FederatedIdpConnection<ResolvedTenant>,
        factor: ProviderFactor,
    ) -> VouchedIdentity {
        VouchedIdentity::new(VouchedFacts {
            connection_id: *conn.id(),
            subject: crate::types::FederatedSubject::new("sub-1").unwrap(),
            email: email("alice@acme.com"),
            email_verification: ProviderEmailVerification::Confirmed,
            factor,
        })
    }

    fn trusted_for_factors() -> FederatedIdpConnection<ResolvedTenant> {
        let mut conn = saml_connection();
        conn.change_assurance_trust(AssuranceTrust::Trusted, &federation_admin())
            .unwrap();
        conn
    }

    /// An untrusted connection establishes no factor for an ordinary
    /// account, whatever factor its provider reports.
    #[test]
    fn an_untrusted_provider_proves_no_factor() {
        let conn = saml_connection();

        for factor in [
            ProviderFactor::HardwareKey,
            ProviderFactor::Performed,
            ProviderFactor::NotPerformed,
        ] {
            assert_eq!(
                conn.vouched_sign_in(&vouched(&conn, factor), AccountPrivilege::Ordinary)
                    .factor(),
                FactorProved::NoneYet,
                "{factor:?}"
            );
        }
    }

    /// A trusted connection establishes no factor for an identity vouched
    /// through another connection, even when it reports a hardware key.
    #[test]
    fn a_trusted_connection_proves_nothing_for_another_connections_identity() {
        let trusted = trusted_for_factors();
        let elsewhere = saml_connection();

        let sign_in = trusted.vouched_sign_in(
            &vouched(&elsewhere, ProviderFactor::HardwareKey),
            AccountPrivilege::Ordinary,
        );

        assert_eq!(sign_in.factor(), FactorProved::NoneYet);
    }

    /// A trusted connection reports a hardware key, then another factor, then
    /// none. Each is recorded as the matching provider factor, and none as none.
    #[test]
    fn a_trusted_provider_proves_what_it_reports() {
        let conn = trusted_for_factors();

        let proved = |factor| {
            conn.vouched_sign_in(&vouched(&conn, factor), AccountPrivilege::Ordinary)
                .factor()
        };

        assert_eq!(
            proved(ProviderFactor::HardwareKey),
            FactorProved::Proved(MfaFactor::ProviderHardwareKey)
        );
        assert_eq!(
            proved(ProviderFactor::Performed),
            FactorProved::Proved(MfaFactor::ProviderMultiFactor)
        );
        assert_eq!(proved(ProviderFactor::NotPerformed), FactorProved::NoneYet);
    }

    /// A trusted connection establishes no provider factor for a privileged
    /// account, whether the provider reports MFA or a hardware key.
    #[test]
    fn a_trusted_provider_proves_no_factor_for_a_privileged_account() {
        let conn = trusted_for_factors();

        for factor in [ProviderFactor::HardwareKey, ProviderFactor::Performed] {
            let sign_in =
                conn.vouched_sign_in(&vouched(&conn, factor), AccountPrivilege::Privileged);

            assert_eq!(sign_in.factor(), FactorProved::NoneYet, "{factor:?}");
        }
    }

    /// Someone signs in through a SAML connection. The sign-in is recorded
    /// with SAML as its method.
    #[test]
    fn a_sign_in_is_vouched_through_the_connections_protocol() {
        let conn = saml_connection();

        let sign_in = conn.vouched_sign_in(
            &vouched(&conn, ProviderFactor::NotPerformed),
            AccountPrivilege::Ordinary,
        );

        assert_eq!(sign_in.method(), AuthMethod::Saml);
    }

    fn stored_row() -> ConnectionRow {
        ConnectionRow {
            id: ConnectionId::new(),
            provider_name: label("Azure AD"),
            status: ConnectionStatus::Active,
            config: oidc_config(),
            jit_provisioning: JitProvisioning::Disabled,
            jit_default_role_id: Setting::Unset,
            email_trust: EmailTrust::Unverified,
            assurance_trust: AssuranceTrust::Untrusted,
            domain_hint: Setting::Unset,
            allowed_domains: vec![domain("globex.com")],
            attribute_mapping: HashMap::new(),
            group_mapping: GroupMapping::Off,
            created_at: crate::shared::clock::now(),
            keyed_at: crate::shared::clock::now(),
        }
    }

    /// A stored row lists `globex.com` twice. Loading it is refused as a
    /// corrupt row.
    #[test]
    fn a_stored_connection_allowing_a_domain_twice_is_refused() {
        let conn = FederatedIdpConnection::<ResolvedTenant>::reconstitute(ConnectionRow {
            allowed_domains: vec![domain("globex.com"), domain("globex.com")],
            ..stored_row()
        });

        assert!(refused_as_corrupt(&conn));
    }

    /// A stored row allows `*.globex.com`, which no address is at. Loading
    /// it is refused as a corrupt row.
    #[test]
    fn a_stored_wildcard_domain_is_refused() {
        let conn = FederatedIdpConnection::<ResolvedTenant>::reconstitute(ConnectionRow {
            allowed_domains: vec![domain("*.globex.com")],
            ..stored_row()
        });

        assert!(refused_as_corrupt(&conn));
    }

    /// A stored row allows only `globex.com` but hints `acme.com`. Loading it
    /// is refused as a corrupt row.
    #[test]
    fn a_stored_hint_outside_the_allowed_domains_is_refused() {
        let conn = FederatedIdpConnection::<ResolvedTenant>::reconstitute(ConnectionRow {
            domain_hint: Setting::Set(domain("acme.com")),
            ..stored_row()
        });

        assert!(refused_as_corrupt(&conn));
    }

    /// A stored row names a role for new accounts while account creation is
    /// off. Loading it is refused as a corrupt row.
    #[test]
    fn a_stored_role_for_new_accounts_without_provisioning_is_refused() {
        let conn = FederatedIdpConnection::<ResolvedTenant>::reconstitute(ConnectionRow {
            jit_default_role_id: Setting::Set(RoleId::new()),
            ..stored_row()
        });

        assert!(refused_as_corrupt(&conn));
    }

    /// A stored row fills the display name from two claims. Loading it is
    /// refused as a corrupt row.
    #[test]
    fn a_stored_mapping_filling_one_field_twice_is_refused() {
        let conn = FederatedIdpConnection::<ResolvedTenant>::reconstitute(ConnectionRow {
            attribute_mapping: HashMap::from([
                (label("name"), ProfileField::DisplayName),
                (label("given_name"), ProfileField::DisplayName),
            ]),
            ..stored_row()
        });

        assert!(refused_as_corrupt(&conn));
    }

    /// A stored row says the connection was re-keyed a minute before it was
    /// created. Loading it is refused as a corrupt row.
    #[test]
    fn a_stored_connection_re_keyed_before_it_was_made_is_refused() {
        let row = stored_row();
        let keyed_at = row.created_at - time::Duration::minutes(1);

        let conn = FederatedIdpConnection::<ResolvedTenant>::reconstitute(ConnectionRow {
            keyed_at,
            ..row
        });

        assert!(refused_as_corrupt(&conn));
    }

    /// Azure AD as stored, active, with nothing raised.
    fn stored_connection() -> FederatedIdpConnection<ResolvedTenant> {
        FederatedIdpConnection::reconstitute(stored_row()).unwrap()
    }

    fn connection_label(event: &DomainEvent) -> String {
        match event.payload().value("connection") {
            Some(FieldValue::Reference(reference)) => reference.label().to_owned(),
            other => panic!("the connection is not referenced: {other:?}"),
        }
    }

    /// Ann creates the Okta connection. The creation is raised for the
    /// audit trail.
    #[test]
    fn creating_raises_federation_connection_created() {
        let mut conn = saml_connection();

        assert_eq!(raised_names(&mut conn), ["federation.connection_created"]);
    }

    /// Ann creates the Okta connection and binds `acme.com` to it before it
    /// is saved. Binding is part of making it, so only the creation is
    /// raised.
    #[test]
    fn settings_given_before_the_first_save_are_part_of_the_creation() {
        let mut conn = saml_connection();

        conn.change_domains(
            domains(&["acme.com"], Setting::Unset),
            &federation_admin(),
            own_tenant(),
        )
        .unwrap();

        assert_eq!(raised_names(&mut conn), ["federation.connection_created"]);
    }

    /// Azure AD is read back from storage. Loading it is no change, so it
    /// has raised nothing.
    #[test]
    fn a_connection_read_back_from_storage_has_raised_nothing() {
        let mut stored = stored_connection();

        assert!(raised_names(&mut stored).is_empty());
    }

    /// Ann switches Azure AD off in an incident and back on once it is
    /// over. Each switch is raised, in order.
    #[test]
    fn switching_raises_federation_connection_disabled_and_activated() {
        let mut conn = stored_connection();

        conn.disable(&federation_admin()).unwrap();
        conn.activate(&federation_admin()).unwrap();

        assert_eq!(
            raised_names(&mut conn),
            [
                "federation.connection_disabled",
                "federation.connection_activated"
            ]
        );
    }

    /// Ann renames Azure AD to Entra ID and trusts its addresses in one
    /// request. One update is raised, naming the connection as saved.
    #[test]
    fn settings_changed_together_raise_one_federation_connection_updated() {
        let mut conn = stored_connection();

        conn.rename(label("Entra ID"), &federation_admin()).unwrap();
        conn.change_email_trust(EmailTrust::Authoritative, &federation_admin())
            .unwrap();

        let events = raised(&mut conn);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "federation.connection_updated"
        );
        assert_eq!(connection_label(&events[0]), "Entra ID");
    }

    /// Ann's rename is saved and taken. Nothing more is owed, so taking
    /// again finds nothing, and her next change raises its own update.
    #[test]
    fn a_taken_update_is_not_raised_again() {
        let mut conn = stored_connection();
        conn.rename(label("Entra ID"), &federation_admin()).unwrap();
        raised_names(&mut conn);

        let nothing_more = raised_names(&mut conn);
        conn.rename(label("Azure"), &federation_admin()).unwrap();

        assert!(nothing_more.is_empty());
        assert_eq!(raised_names(&mut conn), ["federation.connection_updated"]);
    }

    /// Ann deletes Azure AD once it is switched off. The deletion is
    /// raised.
    #[test]
    fn deleting_raises_federation_connection_deleted() {
        let mut conn = stored_connection();
        conn.disable(&federation_admin()).unwrap();
        raised_names(&mut conn);

        conn.delete(&federation_admin()).unwrap();

        assert_eq!(raised_names(&mut conn), ["federation.connection_deleted"]);
    }

    /// Activating or deleting an active connection and renaming it without
    /// permission all fail, leaving no raised events.
    #[test]
    fn a_refused_change_raises_nothing() {
        let mut conn = stored_connection();

        let activated = conn.activate(&federation_admin());
        let deleted = conn.delete(&federation_admin());
        let renamed = conn.rename(label("Entra ID"), &holding(&[]));

        assert!(activated.is_err());
        assert!(deleted.is_err());
        assert!(renamed.is_err());
        assert!(raised_names(&mut conn).is_empty());
    }
}
