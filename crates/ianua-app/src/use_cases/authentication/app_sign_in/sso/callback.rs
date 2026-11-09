//! Finishing single sign-on at an app's address: the outside identity
//! provider sent the browser back to the app's return address, and the
//! person it vouched for is signed in on the app's host.

use std::sync::Arc;

use ianua_domain::domains::routing::sign_in::return_path::ReturnPath;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::SamlRequestId;

use crate::auditor::RequestAuditor;
use crate::error::AppError;
use crate::use_case::Command;
use crate::use_cases::authentication::app_sign_in::relay::common::{
    AppSignInCommon, OnTarget, Proved, without_mailed_link,
};
use crate::use_cases::authentication::app_sign_in::{AppSignInContext, AppSignInOutcome};
use crate::use_cases::authentication::federation::single_sign_on::SsoSignIn;
use crate::use_cases::authentication::federation::{
    ExchangeSignInCodeRequest, ExchangeSignInCodeUseCase, ExchangedSession, OidcLoginRequest,
    OidcLoginUseCase, SamlCallbackRequest, SamlLoginUseCase,
};

/// What the outside identity provider sent the browser back with. Holds
/// credentials, so it has no `Debug`.
pub enum AppSsoAnswer {
    /// An OIDC redirect.
    Oidc {
        /// The `state` the flow was started with.
        state: Secret,
        /// The authorization code to swap.
        code: Secret,
    },
    /// A SAML response, posted.
    Saml {
        /// The `RelayState`: the ID of the request being answered.
        relay_state: SamlRequestId,
        /// The base64 `SAMLResponse`.
        saml_response: String,
    },
}

/// The provider's answer, with the secrets the browser kept since the
/// sign-in started. Holds credentials, so it has no `Debug`.
pub struct AppSsoCallbackRequest {
    /// What the provider answered with.
    pub answer: AppSsoAnswer,
    /// The secret the answer is accepted only with.
    pub binding: Secret,
    /// The secret the session is handed back against.
    pub hand_back: Secret,
    /// Where to send them once they are in, as kept since the start.
    pub return_to: Option<ReturnPath>,
}

/// The dashboard's own ways of finishing a single sign-on, which the app's
/// host goes through.
pub struct AppSsoFinishFlows {
    /// Finishing from an OIDC provider's answer.
    pub oidc: Arc<OidcLoginUseCase>,
    /// Finishing from a SAML provider's answer.
    pub saml: Arc<SamlLoginUseCase>,
    /// Swapping the one-time code for the session.
    pub exchange: Arc<ExchangeSignInCodeUseCase>,
}

/// Signs in on an app's host the person an outside identity provider
/// vouched for.
pub struct AppSsoCallbackUseCase {
    common: Arc<AppSignInCommon>,
    flows: AppSsoFinishFlows,
}

impl AppSsoCallbackUseCase {
    /// A use case finishing sign-ins through the dashboard's own `flows`.
    pub(in crate::use_cases::authentication::app_sign_in) fn new(
        common: Arc<AppSignInCommon>,
        flows: AppSsoFinishFlows,
    ) -> Self {
        Self { common, flows }
    }

    /// The sign-in the provider's `answer` vouches for, accepted only with
    /// the browser's `binding`, as a one-time code for its session.
    async fn vouched(
        &self,
        on: &OnTarget<'_>,
        auditor: &RequestAuditor,
        answer: AppSsoAnswer,
        binding: Secret,
    ) -> Result<SsoSignIn, AppError> {
        let tenant = &on.ctx.tenant;
        match answer {
            AppSsoAnswer::Oidc { state, code } => {
                let callback = OidcLoginRequest {
                    state,
                    code,
                    binding,
                    origin: on.ctx.origin(),
                };
                self.flows.oidc.execute(tenant, auditor, callback).await
            }
            AppSsoAnswer::Saml {
                relay_state,
                saml_response,
            } => {
                let callback = SamlCallbackRequest {
                    relay_state,
                    saml_response,
                    binding,
                    service_provider: self.common.sso_return(on.target)?.service_provider,
                    origin: on.ctx.origin(),
                };
                self.flows.saml.execute(tenant, auditor, callback).await
            }
        }
    }

    /// The session the one-time `code` stands for, handed back against
    /// `hand_back`, the secret made when the sign-in started.
    async fn handed_back(
        &self,
        ctx: &AppSignInContext,
        auditor: &RequestAuditor,
        code: Secret,
        hand_back: Secret,
    ) -> Result<ExchangedSession, AppError> {
        let exchange = ExchangeSignInCodeRequest {
            code,
            dashboard_state: hand_back,
        };
        self.flows
            .exchange
            .execute(&ctx.tenant, auditor, exchange)
            .await
    }
}

impl Command for AppSsoCallbackUseCase {
    type Caller = AppSignInContext;
    type Input = AppSsoCallbackRequest;
    type Output = Result<AppSignInOutcome, AppError>;

    /// Finishes the sign-in through the dashboard's own single sign-on: the
    /// answer is taken once and only from the browser that started it, the
    /// account is found, linked or made as the connection allows, and its
    /// session handed back against the second secret. The person is then
    /// signed in on the app's host, or asked for their second factor.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the app has no sign-in here, or the
    ///   connection, tenant or linked account does not exist.
    /// - `AppError::Forbidden` if the answer is unknown, used, or brought
    ///   back by another browser; the provider may not vouch for the
    ///   person; the account may not sign in; the plan has no room for a new
    ///   account; the sign-in falls short of what the tenant requires; or it
    ///   owes a step an app's host does not take.
    /// - `AppError::TenantUnavailable`, `AppError::Domain` and
    ///   `AppError::Conflict` as the dashboard's own single sign-on reports
    ///   them.
    /// - `AppError::Internal` on persistence or signing failure.
    async fn execute(
        &self,
        ctx: &AppSignInContext,
        auditor: &RequestAuditor,
        request: AppSsoCallbackRequest,
    ) -> Result<AppSignInOutcome, AppError> {
        let (target, auditor) = self.common.resolved(ctx, auditor).await?;
        let AppSsoCallbackRequest {
            answer,
            binding,
            hand_back,
            return_to,
        } = request;
        let on = OnTarget {
            ctx,
            target: &target,
        };
        let signed_in = self.vouched(&on, &auditor, answer, binding).await?;
        let session = self
            .handed_back(ctx, &auditor, signed_in.code, hand_back)
            .await?;
        let proved = Proved {
            session_id: session.session_id,
            owed: without_mailed_link(session.second_factor)?,
            return_to,
        };
        self.common.onward(&on, proved).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ianua_domain::domains::authentication::methods::{AuthMethod, MfaPolicy};
    use ianua_domain::domains::federation::connection::{
        AssuranceTrust, ConnectionConfig, ConnectionRow, EmailTrust, FederatedIdpConnection,
        GroupMapping, JitProvisioning, OidcConfig, ScopeToken,
    };
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::domains::federation::link::{FederatedLink, FederatedLinkRow};
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::config::DisplayNameLimits;
    use ianua_domain::types::{
        ConnectionId, DomainName, FederatedSubject, HttpsUrl, Label, Lifetime, Nonce, ServiceId,
        Setting, UserId,
    };

    use super::*;
    use crate::ports::federation::{FederatedLinkStore, OidcFlowStore, OidcLoginFlow};
    use crate::ports::tenant::TenantStore;
    use crate::test_support::authentication::{
        FakeAppSessionTokens, FakeEncryptor, FakeSessionStore, FakeSignInCodes, SHOP_HOST,
        app_sign_in_lifetimes, app_sign_in_services, app_sign_in_target_ports, cross_host_ctx,
        shop_with_app_sign_in,
    };
    use crate::test_support::federation::{
        FakeConnectionStore, FakeFederatedLinkStore, FakeOidcFlowStore, FakeOidcValidator,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::oauth::{FakeCodeHasher, hash_of};
    use crate::test_support::tenant::tenant_store_signing_in_with;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::authentication::app_sign_in::SignInPorts;
    use crate::use_cases::authentication::federation::completion::{
        SsoAccountPorts, SsoCompletionPorts, SsoSessionPorts,
    };
    use crate::use_cases::authentication::federation::lookup::client_secret_place;
    use crate::use_cases::authentication::federation::single_sign_on::SsoPolicy;
    use crate::use_cases::authentication::federation::{
        ExchangeSignInCodePorts, OidcLoginPorts, SamlLoginPorts,
    };

    const ANN: &str = "ann@acme.com";
    const STATE: &str = "state-from-the-redirect";
    const BINDING: &str = "the-browsers-secret";
    const HAND_BACK: &str = "the-hand-back-secret";

    /// The shop, Ann linked to Acme's OIDC provider, and what was opened and
    /// minted.
    struct Fixture {
        use_case: AppSsoCallbackUseCase,
        shop: ServiceId,
        sessions: Arc<FakeSessionStore>,
        tokens: Arc<FakeAppSessionTokens>,
    }

    /// Acme's provider over OIDC, vouching for `acme.com`.
    fn acme_oidc(id: ConnectionId) -> FederatedIdpConnection<ResolvedTenant> {
        let now = clock::now();
        FederatedIdpConnection::reconstitute(ConnectionRow {
            id,
            provider_name: Label::new("name", "Acme OIDC").unwrap(),
            status: ConnectionStatus::Active,
            config: ConnectionConfig::Oidc(OidcConfig {
                issuer: HttpsUrl::new("https://idp.acme.com").unwrap(),
                client_id: Label::new("client_id", "client-123").unwrap(),
                encrypted_client_secret: FakeEncryptor::sealed_for(
                    "the-client-secret",
                    &client_secret_place(&test_ctx().tenant(), &id),
                ),
                scopes: vec![ScopeToken::new("openid").unwrap()],
            }),
            jit_provisioning: JitProvisioning::Disabled,
            jit_default_role_id: Setting::Unset,
            email_trust: EmailTrust::Unverified,
            assurance_trust: AssuranceTrust::Untrusted,
            domain_hint: Setting::Unset,
            allowed_domains: vec![DomainName::new("acme.com").unwrap()],
            attribute_mapping: HashMap::new(),
            group_mapping: GroupMapping::Off,
            created_at: now,
            keyed_at: now,
        })
        .unwrap()
    }

    /// One-time codes good for a minute, and the default name limits.
    fn policy() -> SsoPolicy {
        SsoPolicy {
            code_lifetime: Lifetime::seconds(60).unwrap(),
            display_names: DisplayNameLimits::default(),
        }
    }

    /// The flow the shop's start kept for Ann's browser, bound to both of
    /// its secrets.
    fn started_flow(connection_id: ConnectionId) -> FakeOidcFlowStore {
        let flows = FakeOidcFlowStore::new();
        let flow = OidcLoginFlow {
            connection_id,
            nonce: Nonce::new("nonce-of-sixteen-chars").unwrap(),
            pkce_verifier: Secret::new("verifier"),
            redirect_uri: HttpsUrl::new("https://shop.example.com/.ianua/sso-callback").unwrap(),
            binding_hash: hash_of(BINDING),
            dashboard_hash: hash_of(HAND_BACK),
        };
        block_on(flows.save(&test_ctx().tenant(), &Secret::new(STATE), &flow)).unwrap();
        flows
    }

    /// Ann's account, linked to who she is at Acme's provider.
    fn ann_linked_to(connection_id: ConnectionId) -> (Arc<FakeUserStore>, FakeFederatedLinkStore) {
        let ann = UserId::new();
        let links = FakeFederatedLinkStore::empty();
        let now = clock::now();
        let link = FederatedLink::reconstitute(FederatedLinkRow {
            connection_id,
            subject: FederatedSubject::new("ada").unwrap(),
            user_id: ann,
            linked_at: now,
            confirmed_at: now,
        })
        .unwrap();
        block_on(links.save(&test_ctx().tenant(), &link)).unwrap();
        (Arc::new(FakeUserStore::with_user(ann, ANN)), links)
    }

    /// The shop signing people in on [`SHOP_HOST`], over a workspace taking
    /// OIDC sign-in, where Ann's browser started a sign-in through Acme's
    /// provider.
    fn fixture() -> Fixture {
        let shop = shop_with_app_sign_in();
        let shop_id = *shop.id();
        let connection_id = ConnectionId::new();
        let sessions = Arc::new(FakeSessionStore::empty());
        let stores = SsoStores::new(connection_id, &sessions);
        let tokens = Arc::new(FakeAppSessionTokens::default());
        let ports = SignInPorts {
            target: app_sign_in_target_ports(app_sign_in_services([shop])),
            session_store: sessions.clone(),
            tokens: tokens.clone(),
            ..SignInPorts::fakes()
        };
        let base = HttpsUrl::new("https://ianua.example.com").unwrap();
        let common = AppSignInCommon::new(ports, base, app_sign_in_lifetimes());
        let flows = AppSsoFinishFlows {
            oidc: Arc::new(stores.oidc(connection_id)),
            saml: Arc::new(SamlLoginUseCase::new(policy(), SamlLoginPorts::fakes())),
            exchange: Arc::new(stores.exchange()),
        };
        Fixture {
            use_case: AppSsoCallbackUseCase::new(Arc::new(common), flows),
            shop: shop_id,
            sessions,
            tokens,
        }
    }

    /// Provider completion and code exchange share Ann's account and issued sessions.
    struct SsoStores {
        users: Arc<FakeUserStore>,
        links: Arc<FakeFederatedLinkStore>,
        tenants: Arc<dyn TenantStore>,
        sessions: Arc<FakeSessionStore>,
        codes: Arc<FakeSignInCodes>,
        hasher: Arc<FakeCodeHasher>,
    }

    impl SsoStores {
        /// Links Ann to the provider in a tenant accepting OIDC without mandatory MFA.
        fn new(connection_id: ConnectionId, sessions: &Arc<FakeSessionStore>) -> Self {
            let (users, links) = ann_linked_to(connection_id);
            let tenants: Arc<dyn TenantStore> = tenant_store_signing_in_with(TenantAuthSettings {
                enabled_methods: vec![AuthMethod::Password, AuthMethod::Oidc],
                mfa_policy: MfaPolicy::Optional,
                ..TenantAuthSettings::default()
            });
            Self {
                users,
                links: Arc::new(links),
                tenants,
                sessions: sessions.clone(),
                codes: Arc::new(FakeSignInCodes::empty()),
                hasher: Arc::new(FakeCodeHasher::new()),
            }
        }

        /// Completes the provider flow against the shared account and session stores.
        fn oidc(&self, connection_id: ConnectionId) -> OidcLoginUseCase {
            OidcLoginUseCase::new(
                policy(),
                OidcLoginPorts {
                    encryptor: Arc::new(FakeEncryptor),
                    connection_store: Arc::new(FakeConnectionStore::holding(
                        &test_ctx().tenant(),
                        [acme_oidc(connection_id)],
                    )),
                    oidc_validator: Arc::new(FakeOidcValidator::signing_in(ANN)),
                    flow_store: Arc::new(started_flow(connection_id)),
                    tenant_store: self.tenants.clone(),
                    completion: SsoCompletionPorts {
                        accounts: SsoAccountPorts {
                            users: self.users.clone(),
                            links: self.links.clone(),
                            ..SsoAccountPorts::fakes()
                        },
                        session: SsoSessionPorts {
                            sessions: self.sessions.clone(),
                            code_hasher: self.hasher.clone(),
                            sign_in_codes: self.codes.clone(),
                            ..SsoSessionPorts::fakes()
                        },
                        ..SsoCompletionPorts::fakes()
                    },
                },
            )
        }

        /// Exchanges only codes issued by this fixture's provider completion.
        fn exchange(&self) -> ExchangeSignInCodeUseCase {
            ExchangeSignInCodeUseCase::new(ExchangeSignInCodePorts {
                code_hasher: self.hasher.clone(),
                codes: self.codes.clone(),
                sessions: self.sessions.clone(),
                users: self.users.clone(),
                tenants: self.tenants.clone(),
                ..ExchangeSignInCodePorts::fakes()
            })
        }
    }

    /// The provider's answer arriving at `service`'s sign-in on the shop's
    /// host, from a browser holding `binding` and `hand_back`.
    fn come_back(
        f: &Fixture,
        service: ServiceId,
        binding: &str,
        hand_back: &str,
    ) -> Result<AppSignInOutcome, AppError> {
        let request = AppSsoCallbackRequest {
            answer: AppSsoAnswer::Oidc {
                state: Secret::new(STATE),
                code: Secret::new("authorization-code"),
            },
            binding: Secret::new(binding),
            hand_back: Secret::new(hand_back),
            return_to: Some(ReturnPath::new("/orders").unwrap()),
        };
        block_on(f.use_case.execute(
            &cross_host_ctx(service, SHOP_HOST),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            request,
        ))
    }

    /// Ann comes back from Acme's provider to the shop. A session cookie is
    /// minted for the shop's host and she lands where she was going.
    #[test]
    fn the_providers_answer_signs_in_on_the_host() {
        let f = fixture();

        let outcome = come_back(&f, f.shop, BINDING, HAND_BACK).unwrap();

        let AppSignInOutcome::SignedIn { return_to, .. } = outcome else {
            panic!("Ann is signed in");
        };
        assert_eq!(return_to.as_str(), "/orders");
        assert_eq!(
            f.tokens.minted.lock().unwrap().as_slice(),
            [format!("session:{SHOP_HOST}:shop")]
        );
    }

    /// A provider callback with another browser's binding secret is refused
    /// and mints no session cookie.
    #[test]
    fn an_answer_from_another_browser_is_refused() {
        let f = fixture();

        let outcome = come_back(&f, f.shop, "another-browser", HAND_BACK);

        assert!(matches!(outcome, Err(AppError::Forbidden(_))));
        assert!(f.tokens.minted.lock().unwrap().is_empty());
    }

    /// A correct browser binding cannot finish sign-in with the wrong
    /// hand-back secret, and no session cookie is minted.
    #[test]
    fn a_session_is_not_handed_back_against_another_secret() {
        let f = fixture();

        let outcome = come_back(&f, f.shop, BINDING, "another-hand-back");

        assert!(outcome.is_err());
        assert!(f.tokens.minted.lock().unwrap().is_empty());
    }

    /// A provider callback for an unknown service returns not found and
    /// opens no session.
    #[test]
    fn a_service_without_app_sign_in_here_is_not_found() {
        let f = fixture();

        let outcome = come_back(&f, ServiceId::new(), BINDING, HAND_BACK);

        assert!(matches!(outcome, Err(AppError::NotFound(_))));
        assert_eq!(f.sessions.session_count(), 0);
    }
}
