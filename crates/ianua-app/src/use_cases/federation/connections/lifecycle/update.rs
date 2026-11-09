//! Update connection: change a federation connection's settings.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::federation::connection::{AssuranceTrust, EmailTrust, ProfileField};
use ianua_domain::domains::federation::control::{FederationControl, FederationRight};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ConnectionId, DomainName, Label, RoleId, Setting};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::authorization::RoleStore;
use crate::ports::domain::RegisteredDomainStore;
use crate::ports::federation::{ConnectionStore, OidcValidator, SamlMetadataReader};
use crate::ports::tenant::TenantStore;
use crate::use_case::Command;
use crate::use_cases::federation::connections::ProviderConfig;
use crate::use_cases::federation::connections::lifecycle::change::ChangeSources;
use crate::use_cases::federation::connections::settings::allowed_domains::{
    DomainProofs, own_tenant,
};
use crate::use_cases::federation::connections::settings::issuer;
use crate::use_cases::federation::connections::settings::stored_config::ConfigSources;
use crate::use_cases::federation::lookup::existing_connection;

/// Whether a connection makes an account on someone's first sign-in.
pub enum AccountProvisioning {
    /// It makes one, giving it the role named, if any.
    Enabled(Setting<RoleId>),
    /// It refuses a sign-in that matches no account.
    Disabled,
}

/// What to change. `None` leaves a setting as it is.
pub struct UpdateRequest {
    /// The connection to change.
    pub connection_id: ConnectionId,
    /// A new provider name.
    pub provider_name: Option<Label>,
    /// A new configuration, at the same provider.
    pub config: Option<ProviderConfig>,
    /// Whether accounts are made on a first sign-in.
    pub provisioning: Option<AccountProvisioning>,
    /// The allowed domain that sends people straight to this connection.
    pub domain_hint: Option<Setting<DomainName>>,
    /// The email domains the provider may sign in.
    pub allowed_domains: Option<Vec<DomainName>>,
    /// Which provider claim fills which profile field.
    pub attribute_mapping: Option<HashMap<Label, ProfileField>>,
    /// Whether the provider's addresses are taken on its word.
    pub email_trust: Option<EmailTrust>,
    /// Whether the provider's report of factors is taken on its word.
    pub assurance_trust: Option<AssuranceTrust>,
}

impl UpdateRequest {
    /// Whether the request names no setting to change.
    fn changes_nothing(&self) -> bool {
        self.provider_name.is_none()
            && self.config.is_none()
            && self.provisioning.is_none()
            && self.domain_hint.is_none()
            && self.allowed_domains.is_none()
            && self.attribute_mapping.is_none()
            && self.email_trust.is_none()
            && self.assurance_trust.is_none()
    }
}

/// The ports [`UpdateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdatePorts {
    /// Loads and saves connections.
    pub connection_store: Arc<dyn ConnectionStore>,
    /// Loads the role accounts the connection makes start with.
    pub role_store: Arc<dyn RoleStore>,
    /// Encrypts a new client secret before it is stored.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// The tenant registry, for the tenant whose domains are bound.
    pub tenant_store: Arc<dyn TenantStore>,
    /// The domains the tenant registered and proved.
    pub domain_store: Arc<dyn RegisteredDomainStore>,
    /// Checks a new OIDC issuer publishes its configuration.
    pub oidc_validator: Arc<dyn OidcValidator>,
    /// Fetches and reads a SAML provider's metadata.
    pub metadata_reader: Arc<dyn SamlMetadataReader>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes a federation connection's settings.
pub struct UpdateUseCase {
    ports: UpdatePorts,
}

impl UpdateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UpdatePorts) -> Self {
        Self { ports }
    }

    /// Where the parts of a change are read and sealed.
    fn sources(&self) -> ChangeSources<'_> {
        ChangeSources {
            config: ConfigSources {
                encryptor: self.ports.encryptor.as_ref(),
                metadata: self.ports.metadata_reader.as_ref(),
            },
            role_store: self.ports.role_store.as_ref(),
            proofs: DomainProofs {
                tenant_store: self.ports.tenant_store.as_ref(),
                domain_store: self.ports.domain_store.as_ref(),
            },
        }
    }

    /// Refuses a new config unless `control` may trust connections, and
    /// then a new OIDC config whose issuer publishes no usable
    /// configuration. The right comes first, so a caller without it never
    /// has the server fetch an issuer they name. A request that leaves the
    /// config alone passes.
    async fn ensure_new_config_admitted(
        &self,
        request: &UpdateRequest,
        control: &FederationControl<'_>,
    ) -> Result<(), AppError> {
        let Some(config) = &request.config else {
            return Ok(());
        };
        control
            .ensure_may(FederationRight::TrustConnection)
            .map_err(AppError::from_domain)?;
        issuer::ensure_published(self.ports.oidc_validator.as_ref(), config).await
    }
}

impl Command for UpdateUseCase {
    type Caller = CallerContext;
    type Input = UpdateRequest;
    type Output = Result<(), AppError>;

    /// Changes the settings `request` names and records
    /// `federation.connection_updated`. A request naming none changes and
    /// records nothing.
    ///
    /// The connection decides what each change needs: renaming, filling
    /// profile fields or stopping the provider needs the update right, and
    /// anything that lets it speak for more people or be believed more needs
    /// the full federation right.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` for missing change rights or a new-account role with built-in/ungrantable permissions.
    /// - `AppError::NotFound` for a missing connection/role; `Conflict` for another provider, a hint outside allowed domains or an unverified domain.
    /// - `AppError::Domain` for an unregistered domain, unusable OIDC issuer configuration or competing claims for one field.
    /// - `AppError::Internal` on encryption, audit or persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: UpdateRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let tenant = ctx.tenant();
        let store = self.ports.connection_store.as_ref();
        let control = FederationControl::new(&authority);
        self.ensure_new_config_admitted(&request, &control).await?;
        let mut conn = existing_connection(store, &tenant, &request.connection_id).await?;
        if request.changes_nothing() {
            return Ok(());
        }
        let change = self.sources().prepare(&tenant, request, &conn).await?;
        change
            .apply_to(&mut conn, &control, own_tenant(&tenant))
            .map_err(AppError::from_domain)?;
        store.save(&tenant, &conn).await.or_internal()?;
        auditor
            .dispatch_by(&ctx.actor(), conn.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{FederationAction, SystemPermission};
    use ianua_domain::domains::authorization::role::{DefaultAssignment, NewRole, Role};
    use ianua_domain::domains::federation::connection::{
        ConnectionConfig, FederatedIdpConnection, IdpCertificates, OidcConfig, ScopeToken,
    };
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::domains::tenant::custom_domains::registered_domain::{
        DomainConnection, DomainProof, DomainVerificationToken, RegisteredDomain,
        RegisteredDomainRow,
    };
    use ianua_domain::domains::tenant::custom_domains::verification_status::TlsStatus;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{CertificatePem, DomainId, HttpsUrl, SamlNameIdFormat, SealedSecret};

    use super::*;
    use crate::ports::federation::MetadataSource;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authorization::FakeRoleStore;
    use crate::test_support::domain::FakeDomainStore;
    use crate::test_support::federation::{
        FakeConnectionStore, FakeOidcValidator, FakeSamlMetadataReader, TEST_IDP_CERTIFICATE,
        UnpublishedIssuer, test_connection, test_saml_provider_config,
    };
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::federation::connections::{OidcProviderConfig, SamlProviderConfig};

    const ISSUER: &str = "https://idp.acme.com";

    struct Harness {
        use_case: UpdateUseCase,
        store: Arc<FakeConnectionStore>,
        audit: Arc<FakeEventDispatcher>,
        id: ConnectionId,
    }

    fn engineer() -> RoleId {
        RoleId::from_uuid(uuid::Uuid::from_u128(11))
    }

    fn admin() -> RoleId {
        RoleId::from_uuid(uuid::Uuid::from_u128(12))
    }

    fn role(id: RoleId, system_permissions: Vec<SystemPermission>) -> Role<ResolvedTenant> {
        Role::provisioned(NewRole {
            id,
            name: Label::new("name", "Role").unwrap(),
            system_permissions,
            custom_permissions: Vec::new(),
            assignment: DefaultAssignment::Manual,
        })
    }

    fn verified_acme() -> Arc<FakeDomainStore> {
        let domains = Arc::new(FakeDomainStore::empty());
        let acme = RegisteredDomain::reconstitute(RegisteredDomainRow {
            id: DomainId::new(),
            domain: DomainName::new("acme.com").unwrap(),
            connection: DomainConnection::SelfManaged,
            proof: DomainProof::Verified { at: clock::now() },
            dns_challenge_token: DomainVerificationToken::new("token").unwrap(),
            tls_status: TlsStatus::NotRequired,
            created_at: clock::now() - time::Duration::days(1),
        })
        .unwrap();
        block_on(domains.save(&test_ctx().tenant(), &acme)).unwrap();
        domains
    }

    fn ports_over(
        connection: FederatedIdpConnection<ResolvedTenant>,
        authorities: FakeTenantAuthorities,
    ) -> (UpdatePorts, Arc<FakeConnectionStore>) {
        let tenant = test_ctx().tenant();
        let store = Arc::new(FakeConnectionStore::holding(&tenant, [connection]));
        let roles = [
            role(engineer(), Vec::new()),
            role(admin(), vec![SystemPermission::ManageUsers]),
        ];
        let ports = UpdatePorts {
            connection_store: store.clone(),
            role_store: Arc::new(FakeRoleStore::holding(*tenant, roles)),
            tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
            domain_store: verified_acme(),
            tenant_authorities: Arc::new(authorities),
            ..UpdatePorts::fakes()
        };
        (ports, store)
    }

    fn harness(authorities: FakeTenantAuthorities) -> Harness {
        let id = ConnectionId::new();
        let (ports, store) = ports_over(test_connection(id, ConnectionStatus::Active), authorities);
        Harness {
            use_case: UpdateUseCase::new(ports),
            store,
            audit: Arc::new(FakeEventDispatcher::new()),
            id,
        }
    }

    fn admin_harness() -> Harness {
        harness(FakeTenantAuthorities::holding_everything())
    }

    fn empty_req(id: ConnectionId) -> UpdateRequest {
        UpdateRequest {
            connection_id: id,
            provider_name: None,
            config: None,
            provisioning: None,
            domain_hint: None,
            allowed_domains: None,
            attribute_mapping: None,
            email_trust: None,
            assurance_trust: None,
        }
    }

    fn update(h: &Harness, request: UpdateRequest) -> Result<(), AppError> {
        block_on(
            h.use_case
                .execute(&test_ctx(), &test_auditor(h.audit.clone()), request),
        )
    }

    fn saved(h: &Harness) -> FederatedIdpConnection<ResolvedTenant> {
        block_on(h.store.find_by_id(&test_ctx().tenant(), &h.id))
            .unwrap()
            .unwrap()
    }

    /// Acme's Okta settings as an administrator gives them by hand.
    fn given_saml() -> SamlProviderConfig {
        let ProviderConfig::Saml(saml) = test_saml_provider_config() else {
            unreachable!("the test config is SAML");
        };
        *saml
    }

    fn saml_with_certificate(body: &str) -> ProviderConfig {
        let certificate = CertificatePem::new(format!(
            "-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----"
        ))
        .unwrap();
        ProviderConfig::Saml(Box::new(SamlProviderConfig {
            certificates: IdpCertificates::single(certificate),
            ..given_saml()
        }))
    }

    fn oidc(secret: &str) -> ProviderConfig {
        ProviderConfig::Oidc(OidcProviderConfig {
            issuer: HttpsUrl::new(ISSUER).unwrap(),
            client_id: Label::new("client_id", "ianua").unwrap(),
            client_secret: Secret::new(secret),
            scopes: vec![ScopeToken::new("openid").unwrap()],
        })
    }

    /// Acme's Google connection over OIDC, its secret already sealed.
    fn oidc_harness(validator: Arc<dyn OidcValidator>) -> Harness {
        oidc_harness_for(validator, FakeTenantAuthorities::holding_everything())
    }

    /// The Google connection, changed by someone holding what
    /// `authorities` says, its issuer checked by `validator`.
    fn oidc_harness_for(
        validator: Arc<dyn OidcValidator>,
        authorities: FakeTenantAuthorities,
    ) -> Harness {
        let id = ConnectionId::new();
        let authority =
            block_on(FakeTenantAuthorities::holding_everything().authority(&test_ctx())).unwrap();
        let connection = FederatedIdpConnection::create(
            id,
            Label::new("name", "Google").unwrap(),
            ConnectionConfig::Oidc(OidcConfig {
                issuer: HttpsUrl::new(ISSUER).unwrap(),
                client_id: Label::new("client_id", "ianua").unwrap(),
                encrypted_client_secret: SealedSecret::new("enc_1,2,3").unwrap(),
                scopes: vec![ScopeToken::new("openid").unwrap()],
            }),
            &FederationControl::new(&authority),
        )
        .unwrap();
        let (ports, store) = ports_over(connection, authorities);
        Harness {
            use_case: UpdateUseCase::new(UpdatePorts {
                oidc_validator: validator,
                ..ports
            }),
            store,
            audit: Arc::new(FakeEventDispatcher::new()),
            id,
        }
    }

    /// Fay renames Acme's Okta. The new name is saved and the change is
    /// recorded.
    #[test]
    fn a_rename_is_saved_and_recorded() {
        let h = admin_harness();

        update(
            &h,
            UpdateRequest {
                provider_name: Some(Label::new("name", "Azure AD").unwrap()),
                ..empty_req(h.id)
            },
        )
        .unwrap();

        assert_eq!(saved(&h).provider_name().as_str(), "Azure AD");
        assert_eq!(
            h.audit.records.lock().unwrap().as_slice(),
            ["federation.connection_updated"]
        );
    }

    /// Settings whose presence alone must count as an update.
    #[derive(Clone, Copy, Debug)]
    enum SingleChange {
        Provisioning,
        DomainHint,
        AttributeMapping,
        Config,
        EmailTrust,
    }

    impl SingleChange {
        /// Names only this setting, leaving every other change absent.
        fn request(self, id: ConnectionId) -> UpdateRequest {
            let mut request = empty_req(id);
            match self {
                Self::Provisioning => {
                    request.provisioning = Some(AccountProvisioning::Enabled(Setting::Unset));
                }
                Self::DomainHint => request.domain_hint = Some(Setting::Unset),
                Self::AttributeMapping => {
                    request.attribute_mapping = Some(HashMap::from([(
                        Label::new("claim", "name").unwrap(),
                        ProfileField::DisplayName,
                    )]));
                }
                Self::Config => request.config = Some(saml_with_certificate("TkVX")),
                Self::EmailTrust => request.email_trust = Some(EmailTrust::Authoritative),
            }
            request
        }
    }

    /// Each setting is a change on its own: a request naming only one is
    /// applied, not read as nothing to do.
    #[test]
    fn a_single_changed_setting_is_applied_on_its_own() {
        for setting in [
            SingleChange::Provisioning,
            SingleChange::DomainHint,
            SingleChange::AttributeMapping,
            SingleChange::Config,
            SingleChange::EmailTrust,
        ] {
            let h = admin_harness();

            update(&h, setting.request(h.id)).unwrap();

            assert_eq!(
                h.audit.records.lock().unwrap().as_slice(),
                ["federation.connection_updated"],
                "changing {setting:?} alone must count as a change"
            );
        }
    }

    /// Fay sends a request that names nothing to change. Nothing is saved or
    /// recorded.
    #[test]
    fn a_request_naming_nothing_changes_nothing() {
        let h = admin_harness();

        update(&h, empty_req(h.id)).unwrap();

        assert!(h.audit.records.lock().unwrap().is_empty());
    }

    /// Fay names a connection her tenant does not have. It is not found.
    #[test]
    fn an_unknown_connection_is_not_found() {
        let h = admin_harness();

        let result = update(
            &h,
            UpdateRequest {
                provider_name: Some(Label::new("name", "Ghost").unwrap()),
                ..empty_req(ConnectionId::new())
            },
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Fay has the connection make accounts with the Engineer role, which
    /// holds no built-in permission. It is saved.
    #[test]
    fn accounts_are_made_with_a_role_of_app_permissions_only() {
        let h = admin_harness();

        update(
            &h,
            UpdateRequest {
                provisioning: Some(AccountProvisioning::Enabled(Setting::Set(engineer()))),
                ..empty_req(h.id)
            },
        )
        .unwrap();

        assert_eq!(saved(&h).jit_default_role_id(), Some(&engineer()));
    }

    /// A role carrying user-management permission cannot be assigned to new
    /// federated accounts by default. The refusal leaves the role unset.
    #[test]
    fn a_role_with_built_in_permissions_is_refused_for_new_accounts() {
        let h = admin_harness();

        let result = update(
            &h,
            UpdateRequest {
                provisioning: Some(AccountProvisioning::Enabled(Setting::Set(admin()))),
                ..empty_req(h.id)
            },
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(saved(&h).jit_default_role_id().is_none());
    }

    /// Fay names a role her tenant does not have for new accounts. It is
    /// not found.
    #[test]
    fn a_role_that_does_not_exist_is_not_found() {
        let h = admin_harness();

        let result = update(
            &h,
            UpdateRequest {
                provisioning: Some(AccountProvisioning::Enabled(Setting::Set(RoleId::new()))),
                ..empty_req(h.id)
            },
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Fay manages federation and Acme proved it owns `acme.com`. She binds
    /// it to the connection and makes it the hint. Both are saved.
    #[test]
    fn a_federation_admin_binds_a_verified_domain() {
        let h = admin_harness();
        let acme = DomainName::new("acme.com").unwrap();

        update(
            &h,
            UpdateRequest {
                allowed_domains: Some(vec![acme.clone()]),
                domain_hint: Some(Setting::Set(acme.clone())),
                ..empty_req(h.id)
            },
        )
        .unwrap();

        assert_eq!(saved(&h).allowed_domains(), std::slice::from_ref(&acme));
        assert_eq!(saved(&h).domain_hint(), Some(&acme));
    }

    /// The update right does not permit binding a domain to a connection.
    /// The permission refusal leaves its allowed domains empty.
    #[test]
    fn binding_a_domain_needs_the_federation_admin_right() {
        let update_only = [SystemPermission::Federation(FederationAction::Update)];
        let h = harness(FakeTenantAuthorities::holding(&update_only));

        let result = update(
            &h,
            UpdateRequest {
                allowed_domains: Some(vec![DomainName::new("acme.com").unwrap()]),
                ..empty_req(h.id)
            },
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(saved(&h).allowed_domains().is_empty());
    }

    /// Replacing a SAML connection's provider entity returns a conflict.
    #[test]
    fn a_connection_keeps_its_provider() {
        let h = admin_harness();
        let elsewhere = ProviderConfig::Saml(Box::new(SamlProviderConfig {
            entity_id: HttpsUrl::new("https://idp.evil.example").unwrap(),
            ..given_saml()
        }));

        let result = update(
            &h,
            UpdateRequest {
                config: Some(elsewhere),
                ..empty_req(h.id)
            },
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// Okta publishes its next certificate ahead of a key rollover. Fay
    /// imports its metadata again: the connection takes both certificates
    /// and the new sign-in address, and keeps its own `NameID` format.
    #[test]
    fn imported_metadata_brings_the_next_certificate_and_keeps_the_format() {
        let id = ConnectionId::new();
        let (ports, store) = ports_over(
            test_connection(id, ConnectionStatus::Active),
            FakeTenantAuthorities::holding_everything(),
        );
        let next = "-----BEGIN CERTIFICATE-----\nTkVYVA==\n-----END CERTIFICATE-----";
        let reader = FakeSamlMetadataReader::listing(&[TEST_IDP_CERTIFICATE, next]);
        let h = Harness {
            use_case: UpdateUseCase::new(UpdatePorts {
                metadata_reader: Arc::new(reader),
                ..ports
            }),
            store,
            audit: Arc::new(FakeEventDispatcher::new()),
            id,
        };
        let document = MetadataSource::Document(FakeSamlMetadataReader::DOCUMENT.to_owned());

        let request = UpdateRequest {
            config: Some(ProviderConfig::SamlMetadata(document)),
            ..empty_req(id)
        };
        update(&h, request).unwrap();

        let ConnectionConfig::Saml(saml) = saved(&h).config().clone() else {
            panic!("expected a SAML connection");
        };
        assert_eq!(saml.sso_url.as_str(), "https://idp.acme.com/sso/new");
        assert!(saml.certificates.upcoming().is_some());
        assert_eq!(saml.name_id_format.as_str(), SamlNameIdFormat::PERSISTENT);
    }

    /// Replacing an OIDC client secret saves a sealed value that does not
    /// contain the supplied plaintext.
    #[test]
    fn a_new_oidc_client_secret_is_never_stored_as_typed() {
        let h = oidc_harness(Arc::new(FakeOidcValidator::signing_in("ada@acme.com")));

        update(
            &h,
            UpdateRequest {
                config: Some(oidc("plain-idp-secret")),
                ..empty_req(h.id)
            },
        )
        .unwrap();

        let ConnectionConfig::Oidc(config) = saved(&h).config().clone() else {
            panic!("the connection keeps its OIDC config");
        };
        assert!(
            !config
                .encrypted_client_secret
                .as_str()
                .contains("plain-idp-secret")
        );
    }

    /// Updating OIDC settings fails when the issuer publishes no configuration.
    /// The saved client secret remains unchanged.
    #[test]
    fn a_config_whose_issuer_publishes_nothing_is_refused() {
        let h = oidc_harness(Arc::new(UnpublishedIssuer));

        let result = update(
            &h,
            UpdateRequest {
                config: Some(oidc("new-secret")),
                ..empty_req(h.id)
            },
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        let ConnectionConfig::Oidc(config) = saved(&h).config().clone() else {
            panic!("the connection keeps its OIDC config");
        };
        assert_eq!(config.encrypted_client_secret.as_str(), "enc_1,2,3");
    }

    /// The update right does not permit replacing OIDC configuration. The
    /// permission refusal occurs without fetching the issuer.
    #[test]
    fn a_caller_who_may_not_trust_connections_makes_the_server_fetch_nothing() {
        let validator = Arc::new(FakeOidcValidator::signing_in("ada@acme.com"));
        let edits_only = [SystemPermission::Federation(FederationAction::Update)];
        let h = oidc_harness_for(
            validator.clone(),
            FakeTenantAuthorities::holding(&edits_only),
        );

        let result = update(
            &h,
            UpdateRequest {
                config: Some(oidc("new-secret")),
                ..empty_req(h.id)
            },
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(validator.issuers_fetched().is_empty());
    }

    /// Renaming a connection without tenant rights is forbidden and preserves
    /// its stored provider name.
    #[test]
    fn a_caller_without_the_right_is_refused() {
        let h = harness(FakeTenantAuthorities::holding(&[]));

        let result = update(
            &h,
            UpdateRequest {
                provider_name: Some(Label::new("name", "Mallory's").unwrap()),
                ..empty_req(h.id)
            },
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(saved(&h).provider_name().as_str(), "Okta");
    }

    /// A signed-out session is refused even when its update names no changes.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let h = harness(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = update(&h, empty_req(h.id));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
