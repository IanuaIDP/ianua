//! Registering an OAuth client for the tenant. A secret, for a client that
//! holds one, is shown once.

use std::sync::Arc;

use ianua_domain::domains::oauth::clients::client::{GrantType, NewOAuthClient, OAuthClient};
use ianua_domain::domains::oauth::clients::settings::ClientSettings;
use ianua_domain::domains::oauth::control::OAuthControl;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ClientId, Label, OAuthClientId, RedirectUri, Scope};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::limits::{LimitEnforcer, ResourceKind};
use crate::ports::oauth::{ClientSecretGenerator, OAuthClientStore};
use crate::use_case::Command;
use crate::use_cases::oauth::clients::credentials::{
    ClientProving, ShownSecret, fresh_credentials,
};

/// The client to register.
pub struct CreateRequest {
    /// The name shown in the OAuth settings.
    pub name: Label,
    /// Where the authorization code flow may send codes.
    pub redirect_uris: Vec<RedirectUri>,
    /// Where a person may be sent back to after signing out.
    pub post_logout_redirect_uris: Vec<RedirectUri>,
    /// The grants the client may use.
    pub grant_types: Vec<GrantType>,
    /// The scopes the client may ask for.
    pub scopes: Vec<Scope>,
    /// How it proves itself at the token endpoint.
    pub proving: ClientProving,
    /// What it is set up with beyond those: lifetimes, links, consent,
    /// token format, logout, sender constraint.
    pub settings: ClientSettings,
}

/// The ports [`CreateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct CreatePorts {
    /// Where clients are kept.
    pub client_store: Arc<dyn OAuthClientStore>,
    /// Makes the client id and secret.
    pub secret_generator: Arc<dyn ClientSecretGenerator>,
    /// Whether the tenant's plan has room for another client.
    pub limit_enforcer: Arc<dyn LimitEnforcer>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// A client just registered, with its credentials.
pub struct CreateResult {
    /// The client's internal id.
    pub client_id: OAuthClientId,
    /// The public client id sent in OAuth requests.
    pub client_id_value: ClientId,
    /// The raw client secret, for a client holding one, shown once and
    /// never stored.
    pub secret: ShownSecret,
}

/// Registers an OAuth client.
pub struct CreateUseCase {
    ports: CreatePorts,
}

impl CreateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: CreatePorts) -> Self {
        Self { ports }
    }

    /// The client `req` describes, registered by the person `control`
    /// names, with its raw secret, which exists only here.
    async fn new_client(
        &self,
        req: CreateRequest,
        control: &OAuthControl<'_>,
    ) -> Result<(OAuthClient<ResolvedTenant>, ShownSecret), AppError> {
        let generator = self.ports.secret_generator.as_ref();
        let (client_id_value, credential, secret) =
            fresh_credentials(generator, req.proving).await?;
        let client = OAuthClient::create(
            NewOAuthClient {
                id: OAuthClientId::new(),
                client_id_value,
                credential,
                name: req.name,
                redirect_uris: req.redirect_uris,
                post_logout_redirect_uris: req.post_logout_redirect_uris,
                grant_types: req.grant_types,
                scopes: req.scopes,
                settings: req.settings,
            },
            control,
        )
        .map_err(AppError::from_domain)?;
        Ok((client, secret))
    }
}

impl Command for CreateUseCase {
    type Caller = CallerContext;
    type Input = CreateRequest;
    type Output = Result<CreateResult, AppError>;

    /// Registers the client `req` describes for `caller` and returns its
    /// credentials. Records `oauth.client_created`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not create clients, or the
    ///   plan has no room for another client.
    /// - `AppError::Domain` when the client has no grant, uses the code flow
    ///   without a redirect, names a redirect, sign-out address or scope
    ///   twice, or is public and asks for client credentials or token
    ///   exchange.
    /// - `AppError::Internal` when the credentials cannot be made, or the
    ///   client cannot be saved or audited.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        req: CreateRequest,
    ) -> Result<CreateResult, AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        self.ports
            .limit_enforcer
            .check_tenant_limit(
                caller.plan_limits(),
                &caller.tenant(),
                ResourceKind::OAuthClients,
            )
            .await
            .map_err(AppError::from_domain)?;
        let (mut client, secret) = self.new_client(req, &OAuthControl::new(&authority)).await?;
        let tenant = caller.tenant();
        self.ports
            .client_store
            .save(&tenant, &client)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), client.take_events(&tenant))
            .await
            .or_internal()?;
        Ok(CreateResult {
            client_id: *client.id(),
            client_id_value: client.client_id_value().clone(),
            secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::credential::ClientCredential;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::oauth::{FakeOAuthClientStore, TEST_REDIRECT};
    use crate::test_support::{
        FakeEventDispatcher, RejectingLimitEnforcer, block_on, test_auditor, test_ctx,
    };

    /// The portal as Ann registers it: the code flow, one redirect, `read`,
    /// a secret in the header, the platform's settings.
    fn portal() -> CreateRequest {
        CreateRequest {
            name: Label::new("name", "Portal").unwrap(),
            redirect_uris: vec![RedirectUri::new(TEST_REDIRECT).unwrap()],
            post_logout_redirect_uris: Vec::new(),
            grant_types: vec![GrantType::AuthorizationCode],
            scopes: vec![Scope::new("read").unwrap()],
            proving: ClientProving::SecretInHeader,
            settings: ClientSettings::platform_defaults(),
        }
    }

    /// What registering `req` through `ports` answers.
    fn create(ports: CreatePorts, req: CreateRequest) -> Result<CreateResult, AppError> {
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        block_on(CreateUseCase::new(ports).execute(&test_ctx(), &auditor, req))
    }

    /// What registering the portal answers for a caller `authorities`
    /// describe.
    fn refused_by(authorities: FakeTenantAuthorities) -> Result<CreateResult, AppError> {
        create(
            CreatePorts {
                tenant_authorities: Arc::new(authorities),
                ..CreatePorts::fakes()
            },
            portal(),
        )
    }

    /// Ann registers the portal. She gets its secret once, the client is
    /// kept and its registration is recorded.
    #[test]
    fn a_client_is_registered_kept_and_recorded() {
        let store = Arc::new(FakeOAuthClientStore::empty());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = CreateUseCase::new(CreatePorts {
            client_store: store.clone(),
            ..CreatePorts::fakes()
        });

        let created =
            block_on(use_case.execute(&test_ctx(), &test_auditor(audit.clone()), portal()))
                .unwrap();

        assert!(matches!(created.secret, ShownSecret::Shown(_)));
        assert_eq!(store.count(), 1);
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["oauth.client_created"]
        );
    }

    /// Ann registers the portal. The kept client carries the public id she
    /// was handed, its name, and is active.
    #[test]
    fn the_kept_client_matches_the_credentials() {
        let store = Arc::new(FakeOAuthClientStore::empty());
        let created = create(
            CreatePorts {
                client_store: store.clone(),
                ..CreatePorts::fakes()
            },
            portal(),
        )
        .unwrap();

        let saved = block_on(store.find_by_id(&test_ctx().tenant(), &created.client_id))
            .unwrap()
            .unwrap();
        assert_eq!(saved.client_id_value(), &created.client_id_value);
        assert_eq!(saved.name().as_str(), "Portal");
        assert!(saved.is_active());
    }

    /// Ann registers a single-page app. It holds no secret, so none is
    /// shown, and it is kept as public.
    #[test]
    fn a_public_client_gets_no_secret() {
        let store = Arc::new(FakeOAuthClientStore::empty());

        let created = create(
            CreatePorts {
                client_store: store.clone(),
                ..CreatePorts::fakes()
            },
            CreateRequest {
                proving: ClientProving::Nothing,
                ..portal()
            },
        )
        .unwrap();

        assert!(matches!(created.secret, ShownSecret::NotIssued));
        let saved = block_on(store.find_by_id(&test_ctx().tenant(), &created.client_id))
            .unwrap()
            .unwrap();
        assert_eq!(saved.credential(), &ClientCredential::Public);
    }

    /// Registering a public client for client-credentials grants is refused
    /// and stores no client.
    #[test]
    fn a_public_machine_client_is_refused() {
        let store = Arc::new(FakeOAuthClientStore::empty());

        let result = create(
            CreatePorts {
                client_store: store.clone(),
                ..CreatePorts::fakes()
            },
            CreateRequest {
                grant_types: vec![GrantType::ClientCredentials],
                proving: ClientProving::Nothing,
                ..portal()
            },
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(store.count(), 0);
    }

    /// Registering an authorization-code client without a redirect is
    /// refused and stores no client.
    #[test]
    fn a_code_client_without_a_redirect_is_refused() {
        let store = Arc::new(FakeOAuthClientStore::empty());

        let result = create(
            CreatePorts {
                client_store: store.clone(),
                ..CreatePorts::fakes()
            },
            CreateRequest {
                redirect_uris: Vec::new(),
                ..portal()
            },
        );

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(store.count(), 0);
    }

    /// A rejected client limit refuses registration and stores no client.
    #[test]
    fn a_full_plan_refuses_the_client() {
        let store = Arc::new(FakeOAuthClientStore::empty());

        let result = create(
            CreatePorts {
                client_store: store.clone(),
                limit_enforcer: Arc::new(RejectingLimitEnforcer),
                ..CreatePorts::fakes()
            },
            portal(),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(store.count(), 0);
    }

    /// A signed-out caller receives unauthenticated when registering a client.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = refused_by(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// A caller with no permissions is forbidden from registering a client.
    #[test]
    fn a_caller_without_the_create_right_is_refused() {
        let result = refused_by(FakeTenantAuthorities::holding(&[]));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
