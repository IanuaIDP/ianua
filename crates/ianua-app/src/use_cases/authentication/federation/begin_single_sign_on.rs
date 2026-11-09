//! Begin single sign-on: sends the browser to a connection's identity
//! provider, remembering the request so only its answer, brought back by the
//! same browser, is accepted.
//!
//! For OIDC the pending flow keeps the `state`, nonce and PKCE verifier. For
//! SAML it keeps the sign-in request's ID, which the answer must name.

use std::sync::Arc;

use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::sessions::sign_in_progress::FederatedMethod;
use ianua_domain::domains::crypto::signing_key::SigningKeySet;
use ianua_domain::domains::federation::connection::{
    AuthnRequestSigning, ConnectionConfig, FederatedIdpConnection, OidcConfig, SamlConfig,
};
use ianua_domain::domains::federation::sign_in_start::SingleSignOnStart;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ConnectionId, HttpsUrl, TokenHash};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::crypto::SigningKeyStore;
use crate::ports::federation::{
    ConnectionStore, OidcFlowStore, OidcLoginFlow, OidcValidator, RequestSigningKey,
    SamlLoginRequest, SamlRequestStore, SamlServiceProviderMessages, ServiceProvider,
};
use crate::ports::oauth::CodeHasher;
use crate::ports::tenant::TenantStore;
use crate::services::authentication::sign_in_gate::{self, ClientOrigin};
use crate::services::lookup::existing_key_set;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::federation::lookup::{
    client_secret_place, existing_active_connection, opened_oidc_config,
};
use crate::use_cases::authentication::federation::single_sign_on::{SsoStart, bind_browser};
use crate::use_cases::federation::lookup::{active_signing_key, xml_signing_key};

/// The ports [`BeginSingleSignOnUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct BeginSingleSignOnPorts {
    /// Opens an OIDC connection's client secret.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// The tenant's federation connections.
    pub connection_store: Arc<dyn ConnectionStore>,
    /// Builds the OIDC authorization address.
    pub oidc_validator: Arc<dyn OidcValidator>,
    /// Keeps pending OIDC flows.
    pub flow_store: Arc<dyn OidcFlowStore>,
    /// Builds the SAML sign-in request.
    pub saml_messages: Arc<dyn SamlServiceProviderMessages>,
    /// Keeps SAML requests awaiting their answer.
    pub saml_requests: Arc<dyn SamlRequestStore>,
    /// The tenant's signing keys, for a connection that signs its requests.
    pub key_store: Arc<dyn SigningKeyStore>,
    /// Makes the secret that binds the sign-in to the browser.
    pub code_hasher: Arc<dyn CodeHasher>,
    /// The tenant, whose say on the sign-in comes first.
    pub tenant_store: Arc<dyn TenantStore>,
}

/// Where the identity provider must send its answer.
pub struct SsoReturn {
    /// The OIDC redirect address.
    pub oidc_callback: HttpsUrl,
    /// This platform as a SAML service provider.
    pub service_provider: ServiceProvider,
}

/// The provider connection and return destination for a new authentication exchange.
pub struct BeginSingleSignOnRequest {
    /// The connection to sign in through.
    pub connection_id: ConnectionId,
    /// Where the answer goes.
    pub returns_to: SsoReturn,
    /// Where the request came from.
    pub origin: ClientOrigin,
    /// A value the dashboard made and keeps to itself, shown again with the
    /// one-time code so the code works only for this dashboard.
    pub dashboard_state: Secret,
}

/// Sends the browser to an identity provider and remembers why.
pub struct BeginSingleSignOnUseCase {
    ports: BeginSingleSignOnPorts,
}

/// What a pending sign-in remembers besides what the provider's redirect
/// gives.
struct PendingSignIn {
    connection_id: ConnectionId,
    binding_hash: TokenHash,
    dashboard_hash: TokenHash,
}

impl BeginSingleSignOnUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: BeginSingleSignOnPorts) -> Self {
        Self { ports }
    }

    /// The secret the browser keeps for the way back, and the pending
    /// sign-in bound to it and to the dashboard that asked.
    async fn pending_sign_in(
        &self,
        begin: &BeginSingleSignOnRequest,
    ) -> Result<(Secret, PendingSignIn), AppError> {
        let hasher = self.ports.code_hasher.as_ref();
        let (binding, binding_hash) = bind_browser(hasher).await?;
        let dashboard_hash = hasher
            .hash_code(&begin.dashboard_state)
            .await
            .or_internal()?;
        let pending = PendingSignIn {
            connection_id: begin.connection_id,
            binding_hash,
            dashboard_hash,
        };
        Ok((binding, pending))
    }

    /// Where to send the browser for the connection's protocol, with the
    /// request remembered against the browser's binding.
    async fn provider_url(
        &self,
        tenant: &ScopedTenant,
        connection: &FederatedIdpConnection<ResolvedTenant>,
        returns_to: &SsoReturn,
        pending: PendingSignIn,
    ) -> Result<HttpsUrl, AppError> {
        match connection.config() {
            ConnectionConfig::Oidc(config) => {
                self.begin_oidc(tenant, config, &returns_to.oidc_callback, pending)
                    .await
            }
            ConnectionConfig::Saml(config) => {
                self.begin_saml(tenant, config, &returns_to.service_provider, pending)
                    .await
            }
        }
    }

    async fn begin_oidc(
        &self,
        tenant: &ScopedTenant,
        config: &OidcConfig,
        redirect_uri: &HttpsUrl,
        pending: PendingSignIn,
    ) -> Result<HttpsUrl, AppError> {
        let place = client_secret_place(tenant, &pending.connection_id);
        let opened = opened_oidc_config(self.ports.encryptor.as_ref(), config, &place).await?;
        let redirect = self
            .ports
            .oidc_validator
            .build_authorization_url(&opened, redirect_uri)
            .await
            .or_internal()?;
        let flow = OidcLoginFlow {
            connection_id: pending.connection_id,
            nonce: redirect.nonce,
            pkce_verifier: redirect.pkce_verifier,
            redirect_uri: redirect_uri.clone(),
            binding_hash: pending.binding_hash,
            dashboard_hash: pending.dashboard_hash,
        };
        self.ports
            .flow_store
            .save(tenant, &redirect.state, &flow)
            .await
            .or_internal()?;
        Ok(redirect.url)
    }

    /// The tenant's signing keys, when `config` signs the requests it sends.
    async fn request_keys(
        &self,
        tenant: &ScopedTenant,
        config: &SamlConfig,
    ) -> Result<Option<SigningKeySet<ResolvedTenant>>, AppError> {
        if config.request_signing == AuthnRequestSigning::Unsigned {
            return Ok(None);
        }
        existing_key_set(self.ports.key_store.as_ref(), tenant)
            .await
            .map(Some)
    }

    async fn begin_saml(
        &self,
        tenant: &ScopedTenant,
        config: &SamlConfig,
        service_provider: &ServiceProvider,
        pending: PendingSignIn,
    ) -> Result<HttpsUrl, AppError> {
        let keys = self.request_keys(tenant, config).await?;
        let redirect = self
            .ports
            .saml_messages
            .sign_in_request(config, service_provider, request_key(keys.as_ref())?)
            .or_internal()?;
        let request = SamlLoginRequest {
            connection_id: pending.connection_id,
            binding_hash: pending.binding_hash,
            dashboard_hash: pending.dashboard_hash,
        };
        self.ports
            .saml_requests
            .save(tenant, &redirect.request_id, &request)
            .await
            .or_internal()?;
        Ok(redirect.url)
    }
}

impl Command for BeginSingleSignOnUseCase {
    type Caller = ScopedTenant;
    type Input = BeginSingleSignOnRequest;
    type Output = Result<SsoStart, AppError>;

    /// Returns where to send the browser, and the secret it keeps until it
    /// comes back. Nobody is signed in yet: `tenant` is the one the request's
    /// address names. Records `authentication.single_sign_on_started`; the
    /// sign-in itself is recorded when the provider answers.
    ///
    /// # Errors
    ///
    /// - `AppError::TenantUnavailable` or `AppError::Forbidden` if the tenant
    ///   does not accept the connection's protocol from where the request
    ///   came from.
    /// - `AppError::NotFound` if the connection or the tenant doesn't exist,
    ///   or the tenant has no signing keys for a connection that signs its
    ///   requests.
    /// - `AppError::Forbidden` if the connection is turned off.
    /// - `AppError::Internal` on discovery, encoding or persistence failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        begin: BeginSingleSignOnRequest,
    ) -> Result<SsoStart, AppError> {
        let connection = existing_active_connection(
            self.ports.connection_store.as_ref(),
            tenant,
            &begin.connection_id,
        )
        .await?;
        let tenants = self.ports.tenant_store.as_ref();
        let client_ip = begin.origin.ip_address.as_ref();
        sign_in_gate::admit(tenants, tenant, protocol_of(&connection), client_ip).await?;
        let (binding, pending) = self.pending_sign_in(&begin).await?;
        let url = self
            .provider_url(tenant, &connection, &begin.returns_to, pending)
            .await?;
        let mut start = SingleSignOnStart::through(&connection).map_err(AppError::from_domain)?;
        auditor
            .dispatch(&start.take_events(tenant))
            .await
            .or_internal()?;
        Ok(SsoStart { url, binding })
    }
}

/// The key a sign-in request is signed with: the one `keys` signs with now,
/// or none when the connection sends its requests unsigned.
///
/// # Errors
///
/// - `AppError::Internal` if the set holds no key that signs now.
fn request_key(
    keys: Option<&SigningKeySet<ResolvedTenant>>,
) -> Result<RequestSigningKey<'_>, AppError> {
    let Some(keys) = keys else {
        return Ok(RequestSigningKey::Unsigned);
    };
    let key = active_signing_key(keys)?;
    Ok(RequestSigningKey::SignedWith(xml_signing_key(key)))
}

/// The sign-in method a connection's protocol is.
fn protocol_of(connection: &FederatedIdpConnection<ResolvedTenant>) -> AuthMethod {
    AuthMethod::from(FederatedMethod::from(connection.protocol()))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ianua_domain::domains::federation::connection::{
        AssuranceTrust, ConnectionRow, EmailTrust, GroupMapping, JitProvisioning, ScopeToken,
    };
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{Label, SamlEntityId, SamlRequestId, SealedSecret, Setting};

    use super::*;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::federation::{
        FakeConnectionStore, FakeOidcFlowStore, FakeOidcValidator, FakeSamlRequests,
        FixedSamlMessages, OIDC_NONCE, OIDC_STATE, test_saml_config,
    };
    use crate::test_support::oauth::{FakeCodeHasher, hash_of};
    use crate::test_support::tenant::tenant_store_signing_in_with;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Okta over OIDC, its client secret sealed once [`connection`] holds
    /// it.
    fn oidc_config() -> ConnectionConfig {
        ConnectionConfig::Oidc(OidcConfig {
            issuer: HttpsUrl::new("https://idp.acme.com").unwrap(),
            client_id: Label::new("client_id", "client-123").unwrap(),
            encrypted_client_secret: SealedSecret::new("sealed-once-held").unwrap(),
            scopes: vec![ScopeToken::new("openid").unwrap()],
        })
    }

    /// `config` with an OIDC client secret sealed for the test tenant's
    /// connection `id`.
    fn sealed_for_connection(config: ConnectionConfig, id: &ConnectionId) -> ConnectionConfig {
        let place = client_secret_place(&test_ctx().tenant(), id);
        match config {
            ConnectionConfig::Oidc(oidc) => ConnectionConfig::Oidc(OidcConfig {
                encrypted_client_secret: FakeEncryptor::sealed_for("client-secret", &place),
                ..oidc
            }),
            ConnectionConfig::Saml(saml) => ConnectionConfig::Saml(saml),
        }
    }

    fn connection(
        id: ConnectionId,
        status: ConnectionStatus,
        config: ConnectionConfig,
    ) -> FederatedIdpConnection<ResolvedTenant> {
        let now = clock::now();
        FederatedIdpConnection::reconstitute(ConnectionRow {
            id,
            provider_name: Label::new("name", "Okta").unwrap(),
            status,
            config: sealed_for_connection(config, &id),
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
        })
        .unwrap()
    }

    struct Harness {
        use_case: BeginSingleSignOnUseCase,
        flows: Arc<FakeOidcFlowStore>,
        saml_requests: Arc<FakeSamlRequests>,
        connection_id: ConnectionId,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Harness {
        fn new(status: ConnectionStatus, config: ConnectionConfig, method: AuthMethod) -> Self {
            let connection_id = ConnectionId::new();
            let flows = Arc::new(FakeOidcFlowStore::new());
            let saml_requests = Arc::new(FakeSamlRequests::empty());
            let held = connection(connection_id, status, config);
            let use_case = BeginSingleSignOnUseCase::new(BeginSingleSignOnPorts {
                encryptor: Arc::new(FakeEncryptor),
                connection_store: Arc::new(FakeConnectionStore::holding(
                    &test_ctx().tenant(),
                    [held],
                )),
                oidc_validator: Arc::new(FakeOidcValidator::signing_in("ada@acme.com")),
                flow_store: flows.clone(),
                saml_messages: Arc::new(FixedSamlMessages),
                saml_requests: saml_requests.clone(),
                code_hasher: Arc::new(FakeCodeHasher::new()),
                tenant_store: tenant_store_signing_in_with(TenantAuthSettings {
                    enabled_methods: vec![AuthMethod::Password, method],
                    ..TenantAuthSettings::default()
                }),
                ..BeginSingleSignOnPorts::fakes()
            });
            Self {
                use_case,
                flows,
                saml_requests,
                connection_id,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn begin(&self, connection_id: ConnectionId) -> Result<SsoStart, AppError> {
            let service_provider = ServiceProvider {
                entity_id: SamlEntityId::new("https://ianua.example.com").unwrap(),
                acs_url: HttpsUrl::new("https://ianua.example.com/acs").unwrap(),
            };
            block_on(self.use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.audit.clone()),
                BeginSingleSignOnRequest {
                    connection_id,
                    returns_to: SsoReturn {
                        oidc_callback: HttpsUrl::new("https://ianua.example.com/callback").unwrap(),
                        service_provider,
                    },
                    origin: ClientOrigin::default(),
                    dashboard_state: Secret::new("dashboard-state"),
                },
            ))
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann starts signing in through Acme's OIDC provider. The flow is kept
    /// under its `state`, bound to her browser's secret, and the start is
    /// recorded.
    #[test]
    fn oidc_remembers_the_flow_and_who_started_it() {
        let harness = Harness::new(ConnectionStatus::Active, oidc_config(), AuthMethod::Oidc);

        let start = harness.begin(harness.connection_id).unwrap();

        let state = Secret::new(OIDC_STATE);
        let flow = block_on(harness.flows.consume(&test_ctx().tenant(), &state))
            .unwrap()
            .unwrap();
        assert_eq!(flow.connection_id, harness.connection_id);
        assert_eq!(flow.nonce.as_str(), OIDC_NONCE);
        assert_eq!(flow.binding_hash, hash_of(start.binding.expose()));
        assert_eq!(flow.dashboard_hash, hash_of("dashboard-state"));
        assert_eq!(
            harness.recorded(),
            vec!["authentication.single_sign_on_started"]
        );
    }

    /// Ann starts signing in through Acme's SAML provider. The request is
    /// kept under its ID, bound to her browser's secret.
    #[test]
    fn saml_remembers_the_request_and_who_started_it() {
        let harness = Harness::new(
            ConnectionStatus::Active,
            test_saml_config(),
            AuthMethod::Saml,
        );

        let start = harness.begin(harness.connection_id).unwrap();

        assert!(start.url.as_str().starts_with("https://idp.acme.com/sso"));
        let request_id = SamlRequestId::new(FixedSamlMessages::REQUEST_ID).unwrap();
        let request = block_on(
            harness
                .saml_requests
                .take(&test_ctx().tenant(), &request_id),
        )
        .unwrap()
        .unwrap();
        assert_eq!(request.connection_id, harness.connection_id);
        assert_eq!(request.binding_hash, hash_of(start.binding.expose()));
        assert_eq!(request.dashboard_hash, hash_of("dashboard-state"));
    }

    /// A tenant with SAML disabled refuses the sign-in and stores no SAML request.
    #[test]
    fn nothing_starts_while_the_tenant_has_the_protocol_off() {
        let harness = Harness::new(
            ConnectionStatus::Active,
            test_saml_config(),
            AuthMethod::Oidc,
        );

        let result = harness.begin(harness.connection_id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(harness.saml_requests.count(), 0);
    }

    /// A disabled OIDC connection refuses sign-in without storing a flow.
    #[test]
    fn a_disabled_connection_starts_nothing() {
        let harness = Harness::new(ConnectionStatus::Disabled, oidc_config(), AuthMethod::Oidc);

        let result = harness.begin(harness.connection_id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(harness.flows.count(), 0);
    }

    /// An unknown connection returns not found without recording a sign-in start.
    #[test]
    fn an_unknown_connection_is_not_found() {
        let harness = Harness::new(ConnectionStatus::Active, oidc_config(), AuthMethod::Oidc);

        let result = harness.begin(ConnectionId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(harness.recorded().is_empty());
    }
}
