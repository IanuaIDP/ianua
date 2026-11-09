//! An app registering itself as a client (RFC 7591), with an initial
//! access token the tenant handed out.
//!
//! Nobody registers without one: an open registration endpoint would let
//! anyone put a consent screen in the tenant's name in front of its people.
//! What an app registers is held to more than an admin's client: it asks
//! people for consent, and it never acts as itself.

use std::sync::Arc;

use ianua_domain::domains::oauth::clients::client::{GrantType, NewOAuthClient, OAuthClient};
use ianua_domain::domains::oauth::clients::credential::ClientCredential;
use ianua_domain::domains::oauth::clients::registration::{
    ClientRegistration, InitialAccessToken, RegistrationAdmission,
};
use ianua_domain::domains::oauth::clients::settings::ClientSettings;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ActorRef, ClientId, Label, OAuthClientId, RedirectUri, Scope};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::input::validate_token;
use crate::ports::limits::{LimitEnforcer, PlanLimitsSource, ResourceKind};
use crate::ports::oauth::{
    ClientSecretGenerator, CodeHasher, InitialAccessTokenStore, OAuthClientStore,
};
use crate::services::limits::room::{PlanSources, ensure_room_for_tenant};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::oauth::clients::credentials::{
    ClientProving, ShownSecret, fresh_credentials,
};

/// What an app registers itself with (RFC 7591 2).
pub struct ClientMetadata {
    /// Its name (`client_name`).
    pub name: Label,
    /// Where codes may be sent (`redirect_uris`).
    pub redirect_uris: Vec<RedirectUri>,
    /// Where a person may be sent back to after signing out
    /// (`post_logout_redirect_uris`).
    pub post_logout_redirect_uris: Vec<RedirectUri>,
    /// The grants it asks for (`grant_types`).
    pub grant_types: Vec<GrantType>,
    /// The scopes it may ask for (`scope`).
    pub scopes: Vec<Scope>,
    /// How it proves itself (`token_endpoint_auth_method`, with its `jwks`
    /// or certificate subject).
    pub proving: ClientProving,
    /// The rest of its settings: links, token form, logout, binding.
    pub settings: ClientSettings,
}

/// An app's registration request.
pub struct RegisterClientRequest {
    /// The initial access token it presents.
    pub initial_access_token: Secret,
    /// What it registers itself with.
    pub metadata: ClientMetadata,
}

/// An app just registered, with what it was handed.
pub struct RegisteredClient {
    /// The client as kept.
    pub client: OAuthClient<ResolvedTenant>,
    /// Its secret, for a client holding one, shown once.
    pub secret: ShownSecret,
    /// The registration access token it manages itself with, shown once.
    pub registration_access_token: Secret,
}

/// The ports [`RegisterClientUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RegisterClientPorts {
    /// Where initial access tokens are kept.
    pub token_store: Arc<dyn InitialAccessTokenStore>,
    /// Where clients are kept.
    pub client_store: Arc<dyn OAuthClientStore>,
    /// Hashes the initial access token, and makes the registration token.
    pub code_hasher: Arc<dyn CodeHasher>,
    /// Makes the client id and secret.
    pub secret_generator: Arc<dyn ClientSecretGenerator>,
    /// Reads the tenant's plan; no caller brings it.
    pub plan_limits: Arc<dyn PlanLimitsSource>,
    /// Whether the plan has room for another client.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
}

impl PlanSources for RegisterClientPorts {
    fn plan_limits(&self) -> &dyn PlanLimitsSource {
        self.plan_limits.as_ref()
    }

    fn limit_enforcer(&self) -> &dyn LimitEnforcer {
        self.limit_enforcer.as_ref()
    }
}

/// Registers an app as a client of the tenant.
pub struct RegisterClientUseCase {
    ports: RegisterClientPorts,
}

impl RegisterClientUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RegisterClientPorts) -> Self {
        Self { ports }
    }

    /// The live initial access token `raw`.
    async fn presented_token(
        &self,
        tenant: &ScopedTenant,
        raw: &Secret,
    ) -> Result<InitialAccessToken<ResolvedTenant>, AppError> {
        validate_token("initial_access_token", raw.expose())
            .map_err(|_| AppError::Unauthenticated)?;
        let hash = self.ports.code_hasher.hash_code(raw).await.or_internal()?;
        self.ports
            .token_store
            .find_by_hash(tenant, &hash)
            .await
            .or_internal()?
            .ok_or(AppError::Unauthenticated)
    }

    /// Refuses a registration the tenant's plan has no room for.
    async fn ensure_plan_has_room(&self, tenant: &ScopedTenant) -> Result<(), AppError> {
        ensure_room_for_tenant(self.ports.plan_room(), tenant, ResourceKind::OAuthClients).await
    }

    /// Spends the use `token` gave up in memory, in one step with the
    /// store: of two apps registering with its last use, only one does.
    async fn ensure_use_spent(
        &self,
        tenant: &ScopedTenant,
        token: &InitialAccessToken<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let spent = self
            .ports
            .token_store
            .spend_use(tenant, token)
            .await
            .or_internal()?;
        if !spent {
            return Err(AppError::Unauthenticated);
        }
        Ok(())
    }

    /// The client `metadata` describes, registered on `admission`, with
    /// its secret and registration access token.
    async fn registered(
        &self,
        metadata: ClientMetadata,
        admission: RegistrationAdmission,
    ) -> Result<RegisteredClient, AppError> {
        let generator = self.ports.secret_generator.as_ref();
        let (client_id_value, credential, secret) =
            fresh_credentials(generator, metadata.proving.clone()).await?;
        let hasher = self.ports.code_hasher.as_ref();
        let (registration_access_token, registration_token) =
            hasher.generate_code().await.or_internal()?;
        let registration = ClientRegistration {
            client: new_client(metadata, client_id_value, credential),
            registration_token,
        };
        let client =
            OAuthClient::register(registration, admission).map_err(AppError::from_domain)?;
        Ok(RegisteredClient {
            client,
            secret,
            registration_access_token,
        })
    }
}

impl Command for RegisterClientUseCase {
    type Caller = ScopedTenant;
    type Input = RegisterClientRequest;
    type Output = Result<RegisteredClient, AppError>;

    /// Registers the app `req` describes in `tenant`, spending one use of
    /// the initial access token it presents, and records
    /// `oauth.client_registered`, with the new client as actor. Its secret
    /// and registration access token come back once.
    ///
    /// What it registers is checked before the use is spent, so a request
    /// the client rules refuse leaves the token as it was.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the initial access token is
    ///   unknown, revoked, expired or used up.
    /// - `AppError::Forbidden` when the plan has no room for another client,
    ///   or the app asks to skip consent or to act as itself.
    /// - `AppError::Domain` when what it registers breaks a client rule.
    /// - `AppError::Internal` when a lookup, the credentials, the save or
    ///   the audit fails.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        req: RegisterClientRequest,
    ) -> Result<RegisteredClient, AppError> {
        let mut token = self
            .presented_token(tenant, &req.initial_access_token)
            .await?;
        self.ensure_plan_has_room(tenant).await?;
        let admission = token
            .admit(clock::now())
            .map_err(|_| AppError::Unauthenticated)?;
        let mut registered = self.registered(req.metadata, admission).await?;
        self.ensure_use_spent(tenant, &token).await?;
        let client = &mut registered.client;
        self.ports
            .client_store
            .save(tenant, client)
            .await
            .or_internal()?;
        let actor = ActorRef::OAuthClient(*client.id());
        auditor
            .dispatch_by(&actor, client.take_events(tenant))
            .await
            .or_internal()?;
        Ok(registered)
    }
}

/// The client `metadata` describes, under the fresh `client_id_value`,
/// proving itself as `credential`.
fn new_client(
    metadata: ClientMetadata,
    client_id_value: ClientId,
    credential: ClientCredential,
) -> NewOAuthClient {
    NewOAuthClient {
        id: OAuthClientId::new(),
        client_id_value,
        credential,
        name: metadata.name,
        redirect_uris: metadata.redirect_uris,
        post_logout_redirect_uris: metadata.post_logout_redirect_uris,
        grant_types: metadata.grant_types,
        scopes: metadata.scopes,
        settings: metadata.settings,
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::registration::{
        ClientManagement, NewInitialAccessToken,
    };
    use ianua_domain::domains::oauth::clients::settings::ConsentPrompt;
    use ianua_domain::domains::oauth::control::OAuthControl;
    use ianua_domain::types::{InitialAccessTokenId, Lifetime};

    use super::*;
    use crate::acting::TenantAuthorities;
    use crate::test_support::acting::FakeTenantAuthorities;
    use crate::test_support::oauth::{
        FakeInitialAccessTokenStore, FakeOAuthClientStore, TEST_REDIRECT, hash_of,
    };
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };

    /// The raw initial access token the tenant handed out.
    const INITIAL: &str = "initial-token";

    /// The tenant, having handed out a token good for `uses` registrations.
    struct Fixture {
        tokens: Arc<FakeInitialAccessTokenStore>,
        clients: Arc<FakeOAuthClientStore>,
        token_id: InitialAccessTokenId,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        /// A token good for `uses` registrations.
        fn handing_out(uses: u32) -> Self {
            let tokens = Arc::new(FakeInitialAccessTokenStore::empty());
            let authority =
                block_on(FakeTenantAuthorities::holding_everything().authority(&test_ctx()))
                    .unwrap();
            let token = InitialAccessToken::issue(
                NewInitialAccessToken {
                    id: InitialAccessTokenId::new(),
                    name: Label::new("name", "MCP clients").unwrap(),
                    token_hash: hash_of(INITIAL),
                    uses,
                    lifetime: Lifetime::seconds(3600).unwrap(),
                },
                &OAuthControl::new(&authority),
            )
            .unwrap();
            block_on(tokens.save(&test_ctx().tenant(), &token)).unwrap();
            Self {
                token_id: *token.id(),
                tokens,
                clients: Arc::new(FakeOAuthClientStore::empty()),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// What registering `metadata` with `initial`, through `ports`,
        /// answers.
        fn register_through(
            &self,
            ports: RegisterClientPorts,
            initial: &str,
            metadata: ClientMetadata,
        ) -> Result<RegisteredClient, AppError> {
            let use_case = RegisterClientUseCase::new(ports);
            let req = RegisterClientRequest {
                initial_access_token: Secret::new(initial),
                metadata,
            };
            let auditor = test_auditor(self.audit.clone());
            block_on(use_case.execute(&test_ctx().tenant(), &auditor, req))
        }

        /// The ports registering goes through.
        fn ports(&self) -> RegisterClientPorts {
            RegisterClientPorts {
                token_store: self.tokens.clone(),
                client_store: self.clients.clone(),
                ..RegisterClientPorts::fakes()
            }
        }

        /// What registering `metadata` with the handed-out token answers.
        fn register(&self, metadata: ClientMetadata) -> Result<RegisteredClient, AppError> {
            self.register_through(self.ports(), INITIAL, metadata)
        }
    }

    /// An MCP client registering for the code flow, holding no secret.
    fn mcp_client() -> ClientMetadata {
        ClientMetadata {
            name: Label::new("name", "Claude").unwrap(),
            redirect_uris: vec![RedirectUri::new(TEST_REDIRECT).unwrap()],
            post_logout_redirect_uris: Vec::new(),
            grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            scopes: vec![Scope::new("read").unwrap()],
            proving: ClientProving::Nothing,
            settings: ClientSettings::platform_defaults(),
        }
    }

    /// An MCP client registers itself with the token. It is kept, managing
    /// itself, gets a registration access token, the token has one use
    /// fewer, and the registration is recorded.
    #[test]
    fn an_app_registers_itself() {
        let fixture = Fixture::handing_out(2);

        let registered = fixture.register(mcp_client()).unwrap();

        assert!(matches!(
            registered.client.management(),
            ClientManagement::ByItself { .. }
        ));
        assert!(!registered.registration_access_token.expose().is_empty());
        assert_eq!(fixture.clients.count(), 1);
        assert_eq!(fixture.tokens.uses_left(&fixture.token_id), Some(1));
        assert_eq!(
            fixture.audit.records.lock().unwrap().as_slice(),
            ["oauth.client_registered"]
        );
    }

    /// An unknown initial access token cannot authenticate registration.
    /// No client is stored.
    #[test]
    fn an_unknown_token_is_refused() {
        let fixture = Fixture::handing_out(2);

        let result = fixture.register_through(fixture.ports(), "guessed", mcp_client());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.clients.count(), 0);
    }

    /// A token exhausted by its first registration refuses a second app.
    /// Only the first client remains stored.
    #[test]
    fn a_used_up_token_is_refused() {
        let fixture = Fixture::handing_out(1);
        fixture.register(mcp_client()).unwrap();

        let result = fixture.register(mcp_client());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.clients.count(), 1);
    }

    /// An app cannot register itself with first-party consent. The request
    /// is forbidden and no client is stored.
    #[test]
    fn an_app_may_not_make_itself_first_party() {
        let fixture = Fixture::handing_out(2);
        let mut metadata = mcp_client();
        metadata.settings.consent = ConsentPrompt::FirstParty;

        let result = fixture.register(metadata);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.clients.count(), 0);
    }

    /// A refused first-party registration preserves the token's last use.
    /// A valid registration then succeeds and consumes that use.
    #[test]
    fn a_refused_registration_keeps_the_tokens_use() {
        let fixture = Fixture::handing_out(1);
        let mut refused = mcp_client();
        refused.settings.consent = ConsentPrompt::FirstParty;

        let first = fixture.register(refused);
        let left = fixture.tokens.uses_left(&fixture.token_id);
        let second = fixture.register(mcp_client());

        assert!(matches!(first, Err(AppError::Forbidden(_))));
        assert_eq!(left, Some(1));
        assert!(second.is_ok());
        assert_eq!(fixture.tokens.uses_left(&fixture.token_id), Some(0));
    }

    /// Self-registration cannot request the client-credentials grant, even
    /// when the app offers secret authentication.
    #[test]
    fn an_app_may_not_act_as_itself() {
        let fixture = Fixture::handing_out(2);
        let metadata = ClientMetadata {
            grant_types: vec![GrantType::ClientCredentials],
            proving: ClientProving::SecretInHeader,
            ..mcp_client()
        };

        let result = fixture.register(metadata);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A plan-limit refusal prevents client registration. The token retains
    /// both uses and no client is stored.
    #[test]
    fn a_full_plan_refuses_the_registration() {
        let fixture = Fixture::handing_out(2);
        let ports = RegisterClientPorts {
            limit_enforcer: Arc::new(RejectingLimitEnforcer),
            ..fixture.ports()
        };

        let result = fixture.register_through(ports, INITIAL, mcp_client());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.tokens.uses_left(&fixture.token_id), Some(2));
        assert_eq!(fixture.clients.count(), 0);
    }
}
