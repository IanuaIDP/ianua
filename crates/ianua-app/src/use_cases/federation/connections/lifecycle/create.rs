//! Create connection: register a new SAML or OIDC federation connection.

use std::sync::Arc;

use ianua_domain::domains::federation::connection::{
    AssertionDecryption, ConnectionDomains, FederatedIdpConnection,
};
use ianua_domain::domains::federation::control::{FederationControl, FederationRight};
use ianua_domain::domains::tenant::custom_domains::owned_domain::OwnedDomain;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ConnectionId, DomainName, Label, Setting};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::domain::RegisteredDomainStore;
use crate::ports::federation::{ConnectionStore, OidcValidator, SamlMetadataReader};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::tenant::TenantStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::federation::lookup::client_secret_place;
use crate::use_cases::federation::connections::ProviderConfig;
use crate::use_cases::federation::connections::settings::allowed_domains::{
    DomainProofs, own_tenant,
};
use crate::use_cases::federation::connections::settings::issuer;
use crate::use_cases::federation::connections::settings::stored_config::ConfigSources;

/// Request to create a new federation connection.
pub struct CreateRequest {
    /// Display name for the provider (e.g. `"Okta"`, `"Azure AD"`).
    pub provider_name: Label,
    /// How the connection reaches its provider, over SAML or OIDC.
    pub config: ProviderConfig,
    /// The email domains the provider may sign in. Empty signs in nobody.
    pub allowed_domains: Vec<DomainName>,
}

/// The ports [`CreateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreatePorts {
    /// Saves connections.
    pub connection_store: Arc<dyn ConnectionStore>,
    /// Checks the plan has room for another connection.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// Encrypts an OIDC client secret before it is stored.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// The tenant registry, for the tenant whose domains are bound.
    pub tenant_store: Arc<dyn TenantStore>,
    /// The domains the tenant registered and proved.
    pub domain_store: Arc<dyn RegisteredDomainStore>,
    /// Checks an OIDC issuer publishes its configuration.
    pub oidc_validator: Arc<dyn OidcValidator>,
    /// Fetches and reads a SAML provider's metadata.
    pub metadata_reader: Arc<dyn SamlMetadataReader>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Registers a new federation connection.
pub struct CreateUseCase {
    ports: CreatePorts,
}

impl CreateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CreatePorts) -> Self {
        Self { ports }
    }

    /// Refuses a connection beyond the plan's ceiling.
    async fn ensure_within_limit(&self, ctx: &CallerContext) -> Result<(), AppError> {
        self.ports
            .limit_enforcer
            .check_tenant_limit(
                ctx.plan_limits(),
                &ctx.tenant(),
                ResourceKind::FederationConnections,
            )
            .await
            .map_err(AppError::from_domain)
    }

    /// Where the configuration's secret is sealed and its metadata read.
    fn config_sources(&self) -> ConfigSources<'_> {
        ConfigSources {
            encryptor: self.ports.encryptor.as_ref(),
            metadata: self.ports.metadata_reader.as_ref(),
        }
    }

    /// The proof the tenant owns each of `domains`.
    async fn owned(
        &self,
        ctx: &CallerContext,
        domains: &[DomainName],
    ) -> Result<Vec<OwnedDomain>, AppError> {
        DomainProofs {
            tenant_store: self.ports.tenant_store.as_ref(),
            domain_store: self.ports.domain_store.as_ref(),
        }
        .owned(&ctx.tenant(), domains)
        .await
    }

    /// The new connection, as `control` makes it, vouching for `owned`.
    async fn connection(
        &self,
        ctx: &CallerContext,
        request: CreateRequest,
        control: &FederationControl<'_>,
    ) -> Result<FederatedIdpConnection<ResolvedTenant>, AppError> {
        let owned = self.owned(ctx, &request.allowed_domains).await?;
        issuer::ensure_published(self.ports.oidc_validator.as_ref(), &request.config).await?;
        let id = ConnectionId::new();
        let place = client_secret_place(&ctx.tenant(), &id);
        let config = self
            .config_sources()
            .stored(request.config, AssertionDecryption::NotExpected, &place)
            .await?
            .into_new()?;
        let mut connection =
            FederatedIdpConnection::create(id, request.provider_name, config, control)
                .map_err(AppError::from_domain)?;
        bind(&mut connection, owned, control, &ctx.tenant())?;
        Ok(connection)
    }
}

impl Command for CreateUseCase {
    type Caller = CallerContext;
    type Input = CreateRequest;
    type Output = Result<ConnectionId, AppError>;

    /// Creates a new, active connection for the caller's tenant and records
    /// `federation.connection_created`.
    ///
    /// The right to create connections is checked before anything else, so
    /// a caller without it never has the server fetch an issuer they name.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` if the caller may not create connections, or
    ///   allowed domains are named and they may not manage federation, or
    ///   the plan's connection limit is reached.
    /// - `AppError::Domain` if an allowed domain was never registered, or an
    ///   OIDC issuer publishes no usable configuration, or a SAML `NameID`
    ///   format does not name one person for good.
    /// - `AppError::Conflict` if an allowed domain is not verified now.
    /// - `AppError::Internal` on encryption, audit or persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        auditor: &RequestAuditor,
        request: CreateRequest,
    ) -> Result<ConnectionId, AppError> {
        let authority = self.ports.tenant_authorities.authority(ctx).await?;
        let control = FederationControl::new(&authority);
        control
            .ensure_may(FederationRight::CreateConnection)
            .map_err(AppError::from_domain)?;
        self.ensure_within_limit(ctx).await?;
        let mut connection = self.connection(ctx, request, &control).await?;
        let tenant = ctx.tenant();

        self.ports
            .connection_store
            .save(&tenant, &connection)
            .await
            .or_internal()?;

        auditor
            .dispatch_by(&ctx.actor(), connection.take_events(&tenant))
            .await
            .or_internal()?;

        Ok(*connection.id())
    }
}

/// Lets `connection` vouch for `owned`. A connection made with no domain
/// vouches for nobody, so it asks for nothing more.
fn bind(
    connection: &mut FederatedIdpConnection<ResolvedTenant>,
    owned: Vec<OwnedDomain>,
    control: &FederationControl<'_>,
    tenant: &ScopedTenant,
) -> Result<(), AppError> {
    if owned.is_empty() {
        return Ok(());
    }
    let domains = ConnectionDomains {
        allowed: owned,
        hint: Setting::Unset,
    };
    connection
        .change_domains(domains, control, own_tenant(tenant))
        .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authorization::permission::{FederationAction, SystemPermission};
    use ianua_domain::domains::federation::connection::{ConnectionConfig, ScopeToken};
    use ianua_domain::domains::tenant::custom_domains::registered_domain::{
        DomainConnection, DomainProof, DomainVerificationToken, RegisteredDomain,
        RegisteredDomainRow,
    };
    use ianua_domain::domains::tenant::custom_domains::verification_status::TlsStatus;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{DomainId, HttpsUrl, PublicHttpsUrl};

    use super::*;
    use crate::ports::federation::MetadataSource;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::domain::FakeDomainStore;
    use crate::test_support::federation::{
        FakeConnectionStore, FakeOidcValidator, FakeSamlMetadataReader, TEST_IDP_CERTIFICATE,
        UnpublishedIssuer, test_saml_provider_config,
    };
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_for_ctx};
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };
    use crate::use_cases::federation::connections::OidcProviderConfig;

    fn label(s: &str) -> Label {
        Label::new("name", s).unwrap()
    }

    fn acme() -> DomainName {
        DomainName::new("acme.com").unwrap()
    }

    fn saml_req() -> CreateRequest {
        CreateRequest {
            provider_name: label("Okta"),
            config: test_saml_provider_config(),
            allowed_domains: Vec::new(),
        }
    }

    fn metadata_req(source: MetadataSource) -> CreateRequest {
        CreateRequest {
            config: ProviderConfig::SamlMetadata(source),
            ..saml_req()
        }
    }

    fn oidc_req(issuer: &str, secret: &str) -> CreateRequest {
        CreateRequest {
            provider_name: label("Google"),
            config: ProviderConfig::Oidc(OidcProviderConfig {
                issuer: HttpsUrl::new(issuer).unwrap(),
                client_id: label("client_123"),
                client_secret: Secret::new(secret),
                scopes: vec![ScopeToken::new("openid").unwrap()],
            }),
            allowed_domains: Vec::new(),
        }
    }

    /// The test tenant's registration of `acme.com`, proved or not.
    fn acme_registration(proof: DomainProof) -> RegisteredDomain<ResolvedTenant> {
        RegisteredDomain::reconstitute(RegisteredDomainRow {
            id: DomainId::new(),
            domain: acme(),
            connection: DomainConnection::SelfManaged,
            proof,
            dns_challenge_token: DomainVerificationToken::new("token").unwrap(),
            tls_status: TlsStatus::NotRequired,
            created_at: clock::now() - time::Duration::days(1),
        })
        .unwrap()
    }

    /// Keeps the supplied registration under the test tenant.
    fn domains_holding(registration: &RegisteredDomain<ResolvedTenant>) -> Arc<FakeDomainStore> {
        let domains = Arc::new(FakeDomainStore::empty());
        block_on(domains.save(&test_ctx().tenant(), registration)).unwrap();
        domains
    }

    fn verified_acme() -> Arc<FakeDomainStore> {
        domains_holding(&acme_registration(DomainProof::Verified {
            at: clock::now(),
        }))
    }

    fn use_case(
        store: Arc<FakeConnectionStore>,
        authorities: FakeTenantAuthorities,
        domains: Arc<FakeDomainStore>,
    ) -> CreateUseCase {
        CreateUseCase::new(CreatePorts {
            connection_store: store,
            tenant_authorities: Arc::new(authorities),
            tenant_store: Arc::new(FakeTenantStore::holding(test_tenant_for_ctx())),
            domain_store: domains,
            ..CreatePorts::fakes()
        })
    }

    fn create(use_case: &CreateUseCase, request: CreateRequest) -> Result<ConnectionId, AppError> {
        block_on(use_case.execute(
            &test_ctx(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            request,
        ))
    }

    fn binding_acme(
        authorities: FakeTenantAuthorities,
        domains: Arc<FakeDomainStore>,
    ) -> (Arc<FakeConnectionStore>, Result<ConnectionId, AppError>) {
        let store = Arc::new(FakeConnectionStore::empty());
        let use_case = use_case(store.clone(), authorities, domains);
        let request = CreateRequest {
            allowed_domains: vec![acme()],
            ..saml_req()
        };
        let result = create(&use_case, request);
        (store, result)
    }

    fn stored(
        store: &FakeConnectionStore,
        id: &ConnectionId,
    ) -> FederatedIdpConnection<ResolvedTenant> {
        block_on(store.find_by_id(&test_ctx().tenant(), id))
            .unwrap()
            .unwrap()
    }

    /// Fay manages federation and Acme proved it owns `acme.com`. She binds
    /// it to the new Okta connection, which then vouches for it.
    #[test]
    fn a_federation_admin_binds_a_verified_domain() {
        let (store, result) =
            binding_acme(FakeTenantAuthorities::holding_everything(), verified_acme());

        let id = result.unwrap();

        assert_eq!(stored(&store, &id).allowed_domains(), &[acme()]);
    }

    /// Two proved domains are bound to one connection after one domain
    /// lookup, preserving the names the federation administrator requested.
    #[test]
    fn trusted_domains_share_one_registration_read() {
        let domains = verified_acme();
        let example = DomainName::new("example.com").unwrap();
        let registration = RegisteredDomain::reconstitute(RegisteredDomainRow {
            id: DomainId::new(),
            domain: example.clone(),
            connection: DomainConnection::SelfManaged,
            proof: DomainProof::Verified { at: clock::now() },
            dns_challenge_token: DomainVerificationToken::new("token").unwrap(),
            tls_status: TlsStatus::NotRequired,
            created_at: clock::now() - time::Duration::days(1),
        })
        .unwrap();
        block_on(domains.save(&test_ctx().tenant(), &registration)).unwrap();
        let store = Arc::new(FakeConnectionStore::empty());
        let uc = use_case(
            store.clone(),
            FakeTenantAuthorities::holding_everything(),
            domains.clone(),
        );

        let id = create(
            &uc,
            CreateRequest {
                allowed_domains: vec![acme(), example.clone()],
                ..saml_req()
            },
        )
        .unwrap();

        assert_eq!(stored(&store, &id).allowed_domains(), &[acme(), example]);
        assert_eq!(domains.name_reads(), 1);
    }

    /// The create right does not permit binding a verified domain to a new
    /// connection. The refusal leaves the connection store empty.
    #[test]
    fn binding_a_domain_needs_the_federation_admin_right() {
        let creates_only = [SystemPermission::Federation(FederationAction::Create)];

        let (store, result) = binding_acme(
            FakeTenantAuthorities::holding(&creates_only),
            verified_acme(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
    }

    /// Binding an unverified domain returns a conflict and saves no connection.
    #[test]
    fn a_domain_the_tenant_has_not_verified_cannot_be_bound() {
        let unproved = domains_holding(&acme_registration(DomainProof::Unproved));

        let (store, result) = binding_acme(FakeTenantAuthorities::holding_everything(), unproved);

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(store.count(), 0);
    }

    /// Binding a domain the tenant has not registered fails and saves no connection.
    #[test]
    fn a_domain_the_tenant_never_registered_cannot_be_bound() {
        let none = Arc::new(FakeDomainStore::empty());

        let (store, result) = binding_acme(FakeTenantAuthorities::holding_everything(), none);

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(store.count(), 0);
    }

    /// With both an unproved and a missing domain, the first requested name
    /// determines the refusal. Neither ordering saves a connection or records
    /// a creation event.
    #[test]
    fn domain_batches_preserve_the_first_refusal_and_write_nothing() {
        for missing_first in [false, true] {
            let domains = domains_holding(&acme_registration(DomainProof::Unproved));
            let store = Arc::new(FakeConnectionStore::empty());
            let audit = Arc::new(FakeEventDispatcher::new());
            let uc = use_case(
                store.clone(),
                FakeTenantAuthorities::holding_everything(),
                domains,
            );
            let missing = DomainName::new("missing.example").unwrap();
            let allowed_domains = if missing_first {
                vec![missing, acme()]
            } else {
                vec![acme(), missing]
            };

            let result = block_on(uc.execute(
                &test_ctx(),
                &test_auditor(audit.clone()),
                CreateRequest {
                    allowed_domains,
                    ..saml_req()
                },
            ));

            match missing_first {
                true => assert!(matches!(result, Err(AppError::Domain(_)))),
                false => assert!(matches!(result, Err(AppError::Conflict(_)))),
            }
            assert_eq!(store.count(), 0);
            assert!(audit.records.lock().unwrap().is_empty());
        }
    }

    /// Ann adds Acme's Okta over SAML. It is saved active and the creation
    /// is recorded.
    #[test]
    fn a_saml_connection_is_created_and_recorded() {
        let store = Arc::new(FakeConnectionStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = use_case(
            store.clone(),
            FakeTenantAuthorities::holding_everything(),
            Arc::new(FakeDomainStore::empty()),
        );

        let id = block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), saml_req()))
            .unwrap();

        assert!(stored(&store, &id).is_active());
        assert_eq!(stored(&store, &id).provider_name().as_str(), "Okta");
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["federation.connection_created"]
        );
    }

    /// Ann adds Google over OIDC. The connection is saved.
    #[test]
    fn an_oidc_connection_is_created() {
        let store = Arc::new(FakeConnectionStore::empty());
        let use_case = use_case(
            store.clone(),
            FakeTenantAuthorities::holding_everything(),
            Arc::new(FakeDomainStore::empty()),
        );

        create(&use_case, oidc_req("https://accounts.google.com", "secret")).unwrap();

        assert_eq!(store.count(), 1);
    }

    /// Ann adds Acme's Okta by its metadata address instead of copying each
    /// setting. The connection takes the endpoints and certificate the
    /// metadata lists.
    #[test]
    fn a_saml_connection_is_created_from_its_metadata_address() {
        let store = Arc::new(FakeConnectionStore::empty());
        let reader = Arc::new(FakeSamlMetadataReader::listing(&[TEST_IDP_CERTIFICATE]));
        let use_case = CreateUseCase::new(CreatePorts {
            connection_store: store.clone(),
            metadata_reader: reader.clone(),
            ..CreatePorts::fakes()
        });
        let url = PublicHttpsUrl::new("https://idp.acme.com/metadata").unwrap();

        let id = create(&use_case, metadata_req(MetadataSource::Url(url))).unwrap();

        let ConnectionConfig::Saml(saml) = stored(&store, &id).config().clone() else {
            panic!("expected a SAML connection");
        };
        assert_eq!(saml.sso_url.as_str(), "https://idp.acme.com/sso/new");
        assert_eq!(reader.fetched(), ["https://idp.acme.com/metadata"]);
    }

    /// Ann pastes a document that is not identity provider metadata. The
    /// connection is refused and nothing is saved.
    #[test]
    fn a_document_that_is_not_metadata_is_refused() {
        let store = Arc::new(FakeConnectionStore::empty());
        let use_case = CreateUseCase::new(CreatePorts {
            connection_store: store.clone(),
            ..CreatePorts::fakes()
        });

        let result = create(
            &use_case,
            metadata_req(MetadataSource::Document("<html/>".to_owned())),
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(store.count(), 0);
    }

    /// A caller with only the viewing right cannot create a SAML connection.
    /// The permission refusal occurs without fetching its metadata address.
    #[test]
    fn a_caller_who_may_not_create_has_no_metadata_fetched() {
        let reader = Arc::new(FakeSamlMetadataReader::listing(&[TEST_IDP_CERTIFICATE]));
        let viewer = [SystemPermission::Federation(FederationAction::View)];
        let use_case = CreateUseCase::new(CreatePorts {
            metadata_reader: reader.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&viewer)),
            ..CreatePorts::fakes()
        });
        let url = PublicHttpsUrl::new("https://idp.acme.com/metadata").unwrap();

        let result = create(&use_case, metadata_req(MetadataSource::Url(url)));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(reader.fetched().is_empty());
    }

    /// An issuer without published configuration causes a validation refusal
    /// and leaves the connection store empty.
    #[test]
    fn an_issuer_that_publishes_no_configuration_is_refused() {
        let store = Arc::new(FakeConnectionStore::empty());
        let use_case = CreateUseCase::new(CreatePorts {
            connection_store: store.clone(),
            oidc_validator: Arc::new(UnpublishedIssuer),
            ..CreatePorts::fakes()
        });

        let result = create(&use_case, oidc_req("https://acounts.google.com", "secret"));

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
        assert_eq!(store.count(), 0);
    }

    /// Creating an OIDC connection saves a sealed client secret whose stored
    /// value does not contain the supplied plaintext.
    #[test]
    fn the_client_secret_never_reaches_storage_in_the_clear() {
        let store = Arc::new(FakeConnectionStore::empty());
        let use_case = use_case(
            store.clone(),
            FakeTenantAuthorities::holding_everything(),
            Arc::new(FakeDomainStore::empty()),
        );

        let id = create(&use_case, oidc_req("https://accounts.google.com", "s3cret")).unwrap();

        let ConnectionConfig::Oidc(config) = stored(&store, &id).config().clone() else {
            panic!("expected an OIDC connection");
        };
        assert!(!config.encrypted_client_secret.as_str().contains("s3cret"));
    }

    /// Creating a connection without tenant rights is forbidden and saves nothing.
    #[test]
    fn a_caller_without_the_create_right_is_refused() {
        let store = Arc::new(FakeConnectionStore::empty());
        let use_case = use_case(
            store.clone(),
            FakeTenantAuthorities::holding(&[]),
            Arc::new(FakeDomainStore::empty()),
        );

        let result = create(&use_case, saml_req());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
    }

    /// A caller without the create right cannot create an OIDC connection.
    /// The permission refusal occurs without fetching the requested issuer.
    #[test]
    fn a_caller_without_the_create_right_makes_the_server_fetch_nothing() {
        let validator = Arc::new(FakeOidcValidator::signing_in("ada@acme.com"));
        let use_case = CreateUseCase::new(CreatePorts {
            oidc_validator: validator.clone(),
            tenant_authorities: Arc::new(FakeTenantAuthorities::holding(&[])),
            ..CreatePorts::fakes()
        });

        let result = create(
            &use_case,
            oidc_req("https://probe.mallory.example", "secret"),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(validator.issuers_fetched().is_empty());
    }

    /// A signed-out session cannot create a connection and leaves the store empty.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let store = Arc::new(FakeConnectionStore::empty());
        let use_case = use_case(
            store.clone(),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            Arc::new(FakeDomainStore::empty()),
        );

        let result = create(&use_case, saml_req());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(store.count(), 0);
    }

    /// A plan-limit refusal prevents saving the requested connection.
    #[test]
    fn a_connection_beyond_the_plan_limit_is_refused() {
        let store = Arc::new(FakeConnectionStore::empty());
        let use_case = CreateUseCase::new(CreatePorts {
            connection_store: store.clone(),
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..CreatePorts::fakes()
        });

        let result = create(&use_case, saml_req());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
    }
}
