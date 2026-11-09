//! The organization's identity provider answering a member's dashboard
//! sign-in: the answer is checked, the member the provider proved is found,
//! and their session opens.
//!
//! Every step refuses by default. An answer to no request started here, one
//! brought back by another browser, one from a provider switched off or
//! replaced since, a forged or replayed assertion, an address that matches
//! no member, and an address the provider did not prove all open nothing.
//! The provider vouches only for members the organization already has:
//! nobody becomes a member by signing in.
//!
//! The answer arrives at the dashboard, which hands it on here; the
//! session's token goes back to the dashboard in the answer, never in an
//! address.

use std::sync::Arc;

use ianua_domain::domains::federation::connection::{ConnectionConfig, OidcConfig, SamlConfig};
use ianua_domain::domains::federation::vouched_identity::VouchedIdentity;
use ianua_domain::domains::organization::access::identity_provider::OrgIdentityProvider;
use ianua_domain::domains::organization::access::sign_in_start::OrgSignInStart;
use ianua_domain::domains::organization::events::access::OrgSignInMethod;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{SamlAssertionId, SamlRequestId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{SealOwner, SecretEncryptor};
use crate::ports::federation::{
    OidcCodeExchange, OidcValidator, SamlAnswer, SamlConnection, SamlValidator, ServiceProvider,
};
use crate::ports::oauth::CodeHasher;
use crate::ports::organization::{
    OrgIdentityProviderStore, OrgSamlAssertionLedger, OrgSsoAwaiting, OrgSsoKey, OrgSsoRequest,
    OrgSsoRequestStore, OrgUserStore, OrganizationStore,
};
use crate::services::authentication::assertion_refusal::{rejected_assertion, unchecked_assertion};
use crate::services::authentication::sign_in_gate::ClientOrigin;
use crate::use_case::Command;
use crate::use_cases::authentication::federation::lookup::opened_oidc_config;
use crate::use_cases::authentication::federation::single_sign_on::ensure_same_browser;
use crate::use_cases::organization::identity_providers::provider_config::provider_secret_place;
use crate::use_cases::organization::lookup::existing_organization;
use crate::use_cases::organization::sign_in::OrgLoginSuccess;
use crate::use_cases::organization::sign_in::sso::single_sign_on::{
    ensure_admitted, switched_on_provider, unavailable,
};
use crate::use_cases::organization::sign_in::steps::finishing::{
    Arrival, FinishingPorts, start_refused,
};
use crate::use_cases::organization::sign_in_record::org_sign_in_record;

/// How long a spent assertion is remembered: longer than any sane
/// `NotOnOrAfter`, so a replay is refused for as long as it would verify.
const ASSERTION_MEMORY: time::Duration = time::Duration::hours(24);

/// What the provider sent the browser back with.
pub enum OrgSsoAnswer {
    /// An OIDC provider's redirect.
    Oidc {
        /// The `state` the sign-in was started with.
        state: Secret,
        /// The authorization code to swap.
        code: Secret,
    },
    /// A SAML provider's posted response.
    Saml {
        /// The request it answers, carried back as `RelayState`.
        relay_state: SamlRequestId,
        /// The base64 `SAMLResponse`.
        saml_response: String,
        /// This platform as the service provider the response must be for.
        service_provider: ServiceProvider,
    },
}

/// The provider's answer, with the secret the browser kept since the
/// sign-in began. Holds secrets, so it has no `Debug`.
pub struct OrgSsoCallbackRequest {
    /// What the provider sent.
    pub answer: OrgSsoAnswer,
    /// The secret the browser kept.
    pub binding: Secret,
    /// Where the request came from.
    pub origin: ClientOrigin,
}

/// The ports [`OrgSsoCallbackUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OrgSsoCallbackPorts {
    /// The sign-ins waiting on a provider's answer.
    pub requests: Arc<dyn OrgSsoRequestStore>,
    /// Organizations, which set the sign-in's rules.
    pub organizations: Arc<dyn OrganizationStore>,
    /// Organizations' identity providers.
    pub providers: Arc<dyn OrgIdentityProviderStore>,
    /// The members a provider may vouch for.
    pub members: Arc<dyn OrgUserStore>,
    /// Opens an OIDC provider's client secret.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Swaps an OIDC code and checks the ID token.
    pub oidc_validator: Arc<dyn OidcValidator>,
    /// Checks a SAML response.
    pub saml_validator: Arc<dyn SamlValidator>,
    /// Remembers the SAML assertions spent.
    pub assertion_ledger: Arc<dyn OrgSamlAssertionLedger>,
    /// Hashes the browser's secret.
    pub code_hasher: Arc<dyn CodeHasher>,
    /// What finishes the sign-in.
    pub finish: FinishingPorts,
}

/// Signs a member in to the dashboard from their organization's provider's
/// answer.
pub struct OrgSsoCallbackUseCase {
    ports: OrgSsoCallbackPorts,
}

/// The organization a sign-in is for, and its provider.
struct Through {
    organization: Organization,
    provider: OrgIdentityProvider,
}

impl OrgSsoCallbackUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: OrgSsoCallbackPorts) -> Self {
        Self { ports }
    }

    /// Takes the sign-in the answer names, refusing an answer nobody here
    /// asked for, one already answered, or one brought back by another
    /// browser.
    async fn awaited(&self, callback: &OrgSsoCallbackRequest) -> Result<OrgSsoRequest, AppError> {
        let key = match &callback.answer {
            OrgSsoAnswer::Oidc { state, .. } => OrgSsoKey::OidcState(state),
            OrgSsoAnswer::Saml { relay_state, .. } => OrgSsoKey::SamlRequest(relay_state),
        };
        let request = self
            .ports
            .requests
            .take(key)
            .await
            .or_internal()?
            .ok_or_else(|| {
                AppError::Forbidden(message!(
                    "organization-no-sign-in-awaits-this-answer",
                    "no sign-in awaits this answer"
                ))
            })?;
        let hasher = self.ports.code_hasher.as_ref();
        ensure_same_browser(hasher, &callback.binding, &request.binding_hash).await?;
        Ok(request)
    }

    /// The organization the sign-in is for and its provider, provided it is
    /// still the one the browser was sent to, switched on, and allowed from
    /// where the answer came.
    async fn through(
        &self,
        request: &OrgSsoRequest,
        origin: &ClientOrigin,
    ) -> Result<Through, AppError> {
        let organization =
            existing_organization(self.ports.organizations.as_ref(), &request.organization_id)
                .await?;
        let provider = switched_on_provider(self.ports.providers.as_ref(), &organization).await?;
        if provider.id() != &request.connection_id {
            return Err(unavailable());
        }
        ensure_admitted(&organization, provider.protocol(), origin)?;
        Ok(Through {
            organization,
            provider,
        })
    }

    /// Who the provider says signed in, from an answer of the kind the
    /// sign-in waits for.
    async fn vouched(
        &self,
        provider: &OrgIdentityProvider,
        awaiting: OrgSsoAwaiting,
        answer: OrgSsoAnswer,
    ) -> Result<VouchedIdentity, AppError> {
        match (provider.config(), awaiting, answer) {
            (ConnectionConfig::Oidc(config), awaiting, OrgSsoAnswer::Oidc { code, .. }) => {
                self.oidc_identity(provider, config, awaiting, &code).await
            }
            (ConnectionConfig::Saml(config), OrgSsoAwaiting::Saml, answer) => {
                self.saml_identity(provider, config, answer).await
            }
            _ => Err(mismatched_answer()),
        }
    }

    /// Who the OIDC provider says signed in, in exchange for `code`, checked
    /// against the nonce and PKCE verifier the sign-in was started with.
    async fn oidc_identity(
        &self,
        provider: &OrgIdentityProvider,
        config: &OidcConfig,
        awaiting: OrgSsoAwaiting,
        code: &Secret,
    ) -> Result<VouchedIdentity, AppError> {
        let OrgSsoAwaiting::Oidc {
            nonce,
            pkce_verifier,
            redirect_uri,
        } = awaiting
        else {
            return Err(mismatched_answer());
        };
        let place = provider_secret_place(provider.organization_id(), provider.id());
        let opened = opened_oidc_config(self.ports.encryptor.as_ref(), config, &place).await?;
        let exchange = OidcCodeExchange {
            code,
            nonce: &nonce,
            pkce_verifier: &pkce_verifier,
            redirect_uri: &redirect_uri,
        };
        let claims = self
            .ports
            .oidc_validator
            .exchange_code(&opened, &exchange, provider.id())
            .await
            .map_err(AppError::from_domain)?;
        Ok(claims.vouched())
    }

    /// Who the SAML provider's response says signed in, once it checks out
    /// against the request it answers and its assertion is spent.
    async fn saml_identity(
        &self,
        provider: &OrgIdentityProvider,
        config: &SamlConfig,
        answer: OrgSsoAnswer,
    ) -> Result<VouchedIdentity, AppError> {
        let OrgSsoAnswer::Saml {
            relay_state,
            saml_response,
            service_provider,
        } = answer
        else {
            return Err(mismatched_answer());
        };
        let saml_answer = SamlAnswer {
            response: &saml_response,
            in_response_to: &relay_state,
        };
        let through = SamlConnection {
            owner: SealOwner::Organization(*provider.organization_id()),
            id: *provider.id(),
        };
        let assertion = self
            .ports
            .saml_validator
            .validate(&saml_answer, config, &through, &service_provider)
            .await
            .map_err(|error| rejected_assertion(&error))?;
        self.spend(assertion.assertion_id()).await?;
        Ok(assertion.vouched())
    }

    /// Spends the assertion, refusing one already answered. A ledger that
    /// cannot answer counts as a replay.
    async fn spend(&self, assertion_id: &SamlAssertionId) -> Result<(), AppError> {
        let remembered_until = clock::now().saturating_add(ASSERTION_MEMORY);
        let spent = self
            .ports
            .assertion_ledger
            .spend(assertion_id, remembered_until)
            .await
            .map_err(|error| unchecked_assertion(&error))?;
        if !spent {
            return Err(AppError::Forbidden(message!(
                "authentication-this-assertion-has-already-been-used",
                "this assertion has already been used"
            )));
        }
        Ok(())
    }

    /// The member of the organization the provider's address names.
    async fn member_named(
        &self,
        organization: &Organization,
        identity: &VouchedIdentity,
    ) -> Result<OrgUser, AppError> {
        self.ports
            .members
            .find_by_email(organization.id(), identity.email())
            .await
            .or_internal()?
            .ok_or_else(|| {
                AppError::Forbidden(message!(
                    "organization-the-provider-s-sign-in-matches",
                    "the provider's sign-in matches no member"
                ))
            })
    }

    /// The sign-in the provider's word begins for `member`, owing what the
    /// organization asks of them.
    async fn begun(
        &self,
        through: &Through,
        identity: &VouchedIdentity,
        member: &OrgUser,
    ) -> Result<OrgSignInStart, AppError> {
        let proof = through
            .provider
            .vouch(identity, member)
            .map_err(AppError::from_domain)?;
        let owed = self
            .ports
            .finish
            .owed(member, &through.organization)
            .await?;
        let config = through.organization.auth_config();
        OrgSignInStart::through_provider(member, proof, owed, config).map_err(start_refused)
    }

    /// Opens the session of the member `arrival` names, once the
    /// provider's word for them begins their sign-in.
    async fn session_opened(
        &self,
        through: &Through,
        identity: &VouchedIdentity,
        arrival: Arrival<'_>,
    ) -> Result<OrgLoginSuccess, AppError> {
        let start = self.begun(through, identity, arrival.member).await?;
        self.ports.finish.finish(arrival, start).await
    }
}

impl Command for OrgSsoCallbackUseCase {
    type Caller = ();
    type Input = OrgSsoCallbackRequest;
    type Output = Result<OrgLoginSuccess, AppError>;

    /// Signs in the member the provider's answer proved, and opens their
    /// session in the tenant they asked for, or the first they reach. The
    /// session owes the member's own second factor when they set one up,
    /// unless the provider is trusted to report one; an owner always owes
    /// their own. Records `organization.org_login_succeeded` through single
    /// sign-on, or `organization.org_login_failed` once the provider named
    /// a member whose sign-in is then refused. An answer naming no member
    /// records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when no sign-in awaits the answer, the
    ///   browser is not the one that started it, the provider is gone,
    ///   switched off or replaced, the organization does not allow its
    ///   protocol from where the answer came, the answer is forged, replayed
    ///   or of the wrong kind, no member holds the address, the provider did
    ///   not prove it, the organization signs the member in another way, the
    ///   member may not sign in or named a tenant they do not reach.
    /// - `AppError::NotFound` when the organization is gone, or no tenant of
    ///   it has the slug the member asked for.
    /// - `AppError::Domain` when the OIDC code swap or ID token check fails,
    ///   or the organization's session lifetime is out of range.
    /// - `AppError::Internal` on storage, secret, token or audit failure.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        callback: OrgSsoCallbackRequest,
    ) -> Result<OrgLoginSuccess, AppError> {
        let request = self.awaited(&callback).await?;
        let through = self.through(&request, &callback.origin).await?;
        let OrgSsoRequest {
            tenant_slug,
            awaiting,
            ..
        } = request;
        let identity = self
            .vouched(&through.provider, awaiting, callback.answer)
            .await?;
        let member = self.member_named(&through.organization, &identity).await?;
        let arrival = Arrival {
            member: &member,
            organization: &through.organization,
            tenant_slug: tenant_slug.as_ref(),
            origin: &callback.origin,
        };
        let outcome = self.session_opened(&through, &identity, arrival).await;
        if let Some(event) = org_sign_in_record(&member, OrgSignInMethod::SingleSignOn, &outcome) {
            auditor.dispatch(&[event]).await.or_internal()?;
        }
        outcome
    }
}

/// The refusal for an answer of another kind than the sign-in waits for.
fn mismatched_answer() -> AppError {
    AppError::Forbidden(message!(
        "organization-the-answer-does-not-fit-the",
        "the answer does not fit the sign-in it names"
    ))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::authentication::risk_engine::step_up::StepUpPolicy;
    use ianua_domain::domains::federation::connection::EmailTrust;
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::domains::organization::access::auth_config::OrganizationAuthSettings;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::status::Suspension;
    use ianua_domain::types::{
        ConnectionId, Fact, HttpsUrl, Nonce, OrganizationId, SamlEntityId, TenantId,
    };

    use super::*;
    use crate::test_support::federation::{FakeOidcValidator, FakeSamlValidator, OIDC_STATE};
    use crate::test_support::oauth::hash_of;
    use crate::test_support::organization::{
        FakeOrgIdentityProviderStore, FakeOrgSsoRequests, OrgProviderShape, OrgShape,
        RecordingOrgSessionStore, org_shaped, org_store_with, org_user_store_with,
        stored_org_provider, test_org_user,
    };
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_in};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    const BINDING: &str = "the-browsers-secret";
    const REQUEST_ID: &str = "_request-1";
    const ALICE: &str = "alice@acme.com";

    /// Acme, its owner Alice, its `production` tenant and its provider, as
    /// a test arranges them.
    struct Scene {
        acme: OrganizationId,
        shape: OrgProviderShape,
        members: Vec<OrgUser>,
        oidc: FakeOidcValidator,
        saml: FakeSamlValidator,
    }

    struct Setup {
        uc: OrgSsoCallbackUseCase,
        requests: Arc<FakeOrgSsoRequests>,
        sessions: Arc<RecordingOrgSessionStore>,
        audit: Arc<FakeEventDispatcher>,
        provider: ConnectionId,
        acme: OrganizationId,
    }

    impl Scene {
        fn with(shape: OrgProviderShape) -> Self {
            let acme = OrganizationId::new();
            Self {
                acme,
                shape,
                members: vec![test_org_user(acme, ALICE, OrgRole::Owner)],
                oidc: FakeOidcValidator::signing_in(ALICE),
                saml: FakeSamlValidator::succeeding(),
            }
        }

        fn saml() -> Self {
            Self::with(OrgProviderShape::saml())
        }

        fn build(self) -> Setup {
            let tenant = test_tenant_in(self.acme, "production", "production.com");
            let organization = organization_with(self.acme, *tenant.id());
            let provider = stored_org_provider(self.acme, self.shape);
            let provider_id = *provider.id();
            let requests = Arc::new(FakeOrgSsoRequests::empty());
            let sessions = Arc::new(RecordingOrgSessionStore::new());
            let ports = OrgSsoCallbackPorts {
                requests: requests.clone(),
                organizations: org_store_with([organization]),
                providers: Arc::new(FakeOrgIdentityProviderStore::holding(provider)),
                members: Arc::new(org_user_store_with(self.members)),
                oidc_validator: Arc::new(self.oidc),
                saml_validator: Arc::new(self.saml),
                finish: FinishingPorts {
                    tenants: Arc::new(FakeTenantStore::holding_all([tenant])),
                    sessions: sessions.clone(),
                    ..FinishingPorts::fakes()
                },
                ..OrgSsoCallbackPorts::fakes()
            };
            Setup {
                uc: OrgSsoCallbackUseCase::new(ports),
                requests,
                sessions,
                audit: Arc::new(FakeEventDispatcher::new()),
                provider: provider_id,
                acme: self.acme,
            }
        }
    }

    impl Setup {
        /// A sign-in Acme's provider is waiting to answer, started in the
        /// browser holding [`BINDING`].
        fn waiting(&self, awaiting: OrgSsoAwaiting) -> OrgSsoRequest {
            OrgSsoRequest {
                organization_id: self.acme,
                connection_id: self.provider,
                binding_hash: hash_of(BINDING),
                tenant_slug: None,
                awaiting,
            }
        }

        fn awaits_saml(&self) {
            let id = SamlRequestId::new(REQUEST_ID).unwrap();
            let request = self.waiting(OrgSsoAwaiting::Saml);
            block_on(self.requests.save(OrgSsoKey::SamlRequest(&id), &request)).unwrap();
        }

        fn awaits_oidc(&self) {
            let request = self.waiting(OrgSsoAwaiting::Oidc {
                nonce: Nonce::new("nonce-0123456789ab").unwrap(),
                pkce_verifier: Secret::new("verifier-1"),
                redirect_uri: HttpsUrl::new("https://app.ianua.test/sso/oidc").unwrap(),
            });
            let state = Secret::new(OIDC_STATE);
            block_on(self.requests.save(OrgSsoKey::OidcState(&state), &request)).unwrap();
        }

        fn answer(&self, answer: OrgSsoAnswer, binding: &str) -> Result<OrgLoginSuccess, AppError> {
            block_on(self.uc.execute(
                &(),
                &test_auditor(self.audit.clone()),
                OrgSsoCallbackRequest {
                    answer,
                    binding: Secret::new(binding),
                    origin: ClientOrigin {
                        ip_address: Fact::Unknown,
                        user_agent: None,
                    },
                },
            ))
        }

        fn saml_answer(&self) -> Result<OrgLoginSuccess, AppError> {
            self.answer(saml_response(), BINDING)
        }
    }

    /// Allows both provider protocols in Acme's single tenant without suspension.
    fn organization_with(acme: OrganizationId, tenant: TenantId) -> Organization {
        org_shaped(
            acme,
            OrgShape {
                tenants: vec![tenant],
                settings: settings(),
                suspension: Suspension::NotSuspended,
            },
        )
    }

    fn settings() -> OrganizationAuthSettings {
        OrganizationAuthSettings {
            enabled_methods: vec![AuthMethod::Password, AuthMethod::Saml, AuthMethod::Oidc],
            step_up_policy: StepUpPolicy::relaxed(),
            ..OrganizationAuthSettings::default()
        }
    }

    fn saml_response() -> OrgSsoAnswer {
        OrgSsoAnswer::Saml {
            relay_state: SamlRequestId::new(REQUEST_ID).unwrap(),
            saml_response: "PHNhbWxwOlJlc3BvbnNlLz4=".to_owned(),
            service_provider: ServiceProvider {
                entity_id: SamlEntityId::new("https://app.ianua.test").unwrap(),
                acs_url: HttpsUrl::new("https://app.ianua.test/sso/saml").unwrap(),
            },
        }
    }

    fn oidc_redirect() -> OrgSsoAnswer {
        OrgSsoAnswer::Oidc {
            state: Secret::new(OIDC_STATE),
            code: Secret::new("code-from-okta"),
        }
    }

    /// Alice signs in to Acme's dashboard through Okta over SAML. Okta is
    /// the authority for Acme's addresses, so her session opens in the
    /// `production` tenant.
    #[test]
    fn a_saml_answer_for_a_member_opens_her_session() {
        let setup = Scene::saml().build();
        setup.awaits_saml();

        let success = setup.saml_answer().unwrap();

        assert_eq!(success.organization_id, setup.acme);
        assert_eq!(success.tenant.slug().unwrap().as_str(), "production");
        assert_eq!(setup.sessions.count(), 1);
        assert_eq!(
            *setup.audit.records.lock().unwrap(),
            ["organization.org_login_succeeded"]
        );
    }

    /// A SAML answer without a pending sign-in records no audit event.
    #[test]
    fn an_answer_naming_nobody_records_nothing() {
        let setup = Scene::saml().build();

        let _ = setup.saml_answer();

        assert!(setup.audit.records.lock().unwrap().is_empty());
    }

    /// Alice signs in through Okta over OIDC, which says it verified her
    /// address. Her session opens.
    #[test]
    fn an_oidc_answer_for_a_verified_address_opens_her_session() {
        let setup = Scene::with(OrgProviderShape::oidc()).build();
        setup.awaits_oidc();

        let success = setup.answer(oidc_redirect(), BINDING).unwrap();

        assert_eq!(success.organization_id, setup.acme);
        assert_eq!(setup.sessions.count(), 1);
    }

    /// A SAML answer without a pending sign-in returns a forbidden error and
    /// opens no session.
    #[test]
    fn an_answer_nobody_asked_for_opens_nothing() {
        let setup = Scene::saml().build();

        let result = setup.saml_answer();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.sessions.count(), 0);
    }

    /// An answer carrying a different browser secret returns a forbidden
    /// error and opens no session.
    #[test]
    fn an_answer_from_another_browser_opens_nothing() {
        let setup = Scene::saml().build();
        setup.awaits_saml();

        let result = setup.answer(saml_response(), "another-browser");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.sessions.count(), 0);
    }

    /// An answer from a disabled provider returns a forbidden error and
    /// opens no session.
    #[test]
    fn an_answer_from_a_switched_off_provider_opens_nothing() {
        let shape = OrgProviderShape::saml().in_status(ConnectionStatus::Disabled);
        let setup = Scene::with(shape).build();
        setup.awaits_saml();

        let result = setup.saml_answer();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.sessions.count(), 0);
    }

    /// A pending request naming a different provider from Acme's current one
    /// returns a forbidden error and opens no session.
    #[test]
    fn an_answer_for_a_replaced_provider_opens_nothing() {
        let setup = Scene::saml().build();
        let id = SamlRequestId::new(REQUEST_ID).unwrap();
        let request = OrgSsoRequest {
            connection_id: ConnectionId::new(),
            ..setup.waiting(OrgSsoAwaiting::Saml)
        };
        block_on(setup.requests.save(OrgSsoKey::SamlRequest(&id), &request)).unwrap();

        let result = setup.saml_answer();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.sessions.count(), 0);
    }

    /// A provider identity whose address matches no member returns a
    /// forbidden error and opens no session.
    #[test]
    fn an_unknown_subject_opens_nothing() {
        let mut scene = Scene::saml();
        scene.members = vec![test_org_user(scene.acme, "bob@acme.com", OrgRole::Owner)];
        let setup = scene.build();
        setup.awaits_saml();

        let result = setup.saml_answer();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.sessions.count(), 0);
    }

    /// A SAML provider without email trust cannot prove the member's address;
    /// its answer returns a forbidden error and opens no session.
    #[test]
    fn an_unproven_address_opens_nothing() {
        let shape = OrgProviderShape::saml().trusting_email(EmailTrust::Unverified);
        let setup = Scene::with(shape).build();
        setup.awaits_saml();

        let result = setup.saml_answer();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.sessions.count(), 0);
    }

    /// Validator failure returns the generic SAML assertion rejection and
    /// opens no session.
    #[test]
    fn a_forged_response_opens_nothing() {
        let mut scene = Scene::saml();
        scene.saml = FakeSamlValidator::failing();
        let setup = scene.build();
        setup.awaits_saml();

        let result = setup.saml_answer();

        assert!(
            matches!(&result, Err(AppError::Forbidden(message)) if message == "SAML assertion rejected")
        );
        assert_eq!(setup.sessions.count(), 0);
    }

    /// Reusing an assertion for another pending sign-in returns a forbidden
    /// error and leaves only the session opened by its first use.
    #[test]
    fn a_replayed_assertion_opens_nothing() {
        let setup = Scene::saml().build();
        setup.awaits_saml();
        setup.saml_answer().unwrap();
        setup.awaits_saml();

        let replayed = setup.saml_answer();

        assert!(matches!(replayed, Err(AppError::Forbidden(_))));
        assert_eq!(setup.sessions.count(), 1);
    }

    /// A SAML answer for an OIDC provider returns a forbidden error and
    /// opens no session.
    #[test]
    fn an_answer_of_the_wrong_kind_opens_nothing() {
        let setup = Scene::with(OrgProviderShape::oidc()).build();
        let id = SamlRequestId::new(REQUEST_ID).unwrap();
        let request = setup.waiting(OrgSsoAwaiting::Saml);
        block_on(setup.requests.save(OrgSsoKey::SamlRequest(&id), &request)).unwrap();

        let result = setup.saml_answer();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.sessions.count(), 0);
    }
}
