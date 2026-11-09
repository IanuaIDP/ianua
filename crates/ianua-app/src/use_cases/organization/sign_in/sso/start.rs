//! A member starting a sign-in to the dashboard through their
//! organization's identity provider.
//!
//! The browser is sent to the provider, and the request is remembered
//! against a secret the browser keeps, so only the provider's answer to
//! this request, brought back by the same browser, is accepted. For OIDC
//! the request keeps the nonce and PKCE verifier; for SAML, the request's
//! ID, which the answer must name.
//!
//! SAML requests go unsigned. An organization holds no signing key of its
//! own: its members sign in to the platform's own service provider, whose
//! metadata says so, and the domain refuses provider settings that ask for
//! signed requests when they are saved. What the sign-in rests on is the
//! provider's signed answer, bound to this request and this browser.

use std::sync::Arc;

use ianua_domain::domains::federation::connection::{ConnectionConfig, OidcConfig, SamlConfig};
use ianua_domain::domains::organization::access::identity_provider::OrgIdentityProvider;
use ianua_domain::domains::organization::events::access::OrgSsoSignInStarted;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::types::{ActorRef, HttpsUrl, TenantSlug};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::federation::{
    OidcValidator, RequestSigningKey, SamlServiceProviderMessages, ServiceProvider,
};
use crate::ports::oauth::CodeHasher;
use crate::ports::organization::{
    OrgIdentityProviderStore, OrgSsoAwaiting, OrgSsoKey, OrgSsoRequest, OrgSsoRequestStore,
    OrganizationStore,
};
use crate::services::authentication::sign_in_gate::ClientOrigin;
use crate::use_case::Command;
use crate::use_cases::authentication::federation::SsoReturn;
use crate::use_cases::authentication::federation::lookup::opened_oidc_config;
use crate::use_cases::authentication::federation::single_sign_on::{SsoStart, bind_browser};
use crate::use_cases::organization::identity_providers::provider_config::provider_secret_place;
use crate::use_cases::organization::sign_in::sso::single_sign_on::{
    ensure_admitted, switched_on_provider, unavailable,
};

/// A member's request to sign in through their organization's provider.
pub struct OrgSsoStartRequest {
    /// The organization signing in.
    pub organization: TenantSlug,
    /// The tenant to land in. Without it the session lands in the first
    /// active tenant the member reaches.
    pub tenant_slug: Option<TenantSlug>,
    /// Where the provider must send its answer.
    pub returns_to: SsoReturn,
    /// Where the request came from.
    pub origin: ClientOrigin,
}

/// The ports [`OrgSsoStartUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OrgSsoStartPorts {
    /// Organizations, found by slug.
    pub organizations: Arc<dyn OrganizationStore>,
    /// Organizations' identity providers.
    pub providers: Arc<dyn OrgIdentityProviderStore>,
    /// Opens an OIDC provider's client secret.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// Builds the OIDC authorization address.
    pub oidc_validator: Arc<dyn OidcValidator>,
    /// Builds the SAML sign-in request.
    pub saml_messages: Arc<dyn SamlServiceProviderMessages>,
    /// Keeps the sign-in until the provider answers.
    pub requests: Arc<dyn OrgSsoRequestStore>,
    /// Makes the secret that binds the sign-in to the browser.
    pub code_hasher: Arc<dyn CodeHasher>,
}

/// Sends a member's browser to their organization's identity provider.
pub struct OrgSsoStartUseCase {
    ports: OrgSsoStartPorts,
}

impl OrgSsoStartUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: OrgSsoStartPorts) -> Self {
        Self { ports }
    }

    /// The organization `slug` names, or the refusal an organization
    /// without single sign-on gets, so the answer tells nobody which
    /// organizations exist.
    async fn organization_named(&self, slug: &TenantSlug) -> Result<Organization, AppError> {
        let found = self
            .ports
            .organizations
            .find_by_slug(slug)
            .await
            .or_internal()?;
        found
            .map(|organization| Organization::clone(&organization))
            .ok_or_else(unavailable)
    }

    /// Where to send the browser for `provider`'s protocol, with `pending`
    /// remembered.
    async fn provider_url(
        &self,
        provider: &OrgIdentityProvider,
        returns_to: &SsoReturn,
        pending: OrgSsoRequest,
    ) -> Result<HttpsUrl, AppError> {
        match provider.config() {
            ConnectionConfig::Oidc(config) => {
                self.begin_oidc(config, &returns_to.oidc_callback, pending)
                    .await
            }
            ConnectionConfig::Saml(config) => {
                self.begin_saml(config, &returns_to.service_provider, pending)
                    .await
            }
        }
    }

    /// The provider's authorization address, with the nonce and PKCE
    /// verifier remembered under the request's `state`.
    async fn begin_oidc(
        &self,
        config: &OidcConfig,
        redirect_uri: &HttpsUrl,
        pending: OrgSsoRequest,
    ) -> Result<HttpsUrl, AppError> {
        let place = provider_secret_place(&pending.organization_id, &pending.connection_id);
        let opened = opened_oidc_config(self.ports.encryptor.as_ref(), config, &place).await?;
        let redirect = self
            .ports
            .oidc_validator
            .build_authorization_url(&opened, redirect_uri)
            .await
            .or_internal()?;
        let request = OrgSsoRequest {
            awaiting: OrgSsoAwaiting::Oidc {
                nonce: redirect.nonce,
                pkce_verifier: redirect.pkce_verifier,
                redirect_uri: redirect_uri.clone(),
            },
            ..pending
        };
        self.ports
            .requests
            .save(OrgSsoKey::OidcState(&redirect.state), &request)
            .await
            .or_internal()?;
        Ok(redirect.url)
    }

    /// The provider's sign-in address carrying a SAML request, remembered
    /// under the request's ID.
    async fn begin_saml(
        &self,
        config: &SamlConfig,
        service_provider: &ServiceProvider,
        pending: OrgSsoRequest,
    ) -> Result<HttpsUrl, AppError> {
        let redirect = self
            .ports
            .saml_messages
            .sign_in_request(config, service_provider, RequestSigningKey::Unsigned)
            .or_internal()?;
        self.ports
            .requests
            .save(OrgSsoKey::SamlRequest(&redirect.request_id), &pending)
            .await
            .or_internal()?;
        Ok(redirect.url)
    }
}

impl Command for OrgSsoStartUseCase {
    type Caller = ();
    type Input = OrgSsoStartRequest;
    type Output = Result<SsoStart, AppError>;

    /// Sends the browser to the organization's provider, remembering the
    /// request against the secret the browser is handed, and records
    /// `organization.org_sso_sign_in_started`. The sign-in itself is
    /// recorded when the provider's answer opens a session.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the organization does not exist, has no
    ///   provider, the provider is switched off, or the organization does
    ///   not allow its protocol from where the request came, all alike.
    /// - `AppError::Internal` on storage, secret, encoding or audit failure.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        request: OrgSsoStartRequest,
    ) -> Result<SsoStart, AppError> {
        let organization = self.organization_named(&request.organization).await?;
        let provider = switched_on_provider(self.ports.providers.as_ref(), &organization).await?;
        ensure_admitted(&organization, provider.protocol(), &request.origin)?;
        let (binding, binding_hash) = bind_browser(self.ports.code_hasher.as_ref()).await?;
        let pending = OrgSsoRequest {
            organization_id: *organization.id(),
            connection_id: *provider.id(),
            binding_hash,
            tenant_slug: request.tenant_slug,
            awaiting: OrgSsoAwaiting::Saml,
        };
        let url = self
            .provider_url(&provider, &request.returns_to, pending)
            .await?;
        auditor
            .with_organization(*organization.id())
            .dispatch_by(
                &ActorRef::System,
                vec![OrgSsoSignInStarted::observed(&organization)],
            )
            .await
            .or_internal()?;
        Ok(SsoStart { url, binding })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::authentication::risk_engine::step_up::StepUpPolicy;
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::domains::organization::access::auth_config::OrganizationAuthSettings;
    use ianua_domain::domains::organization::status::Suspension;
    use ianua_domain::shared::config::SlugLimits;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{Fact, OrganizationId, SamlEntityId, SamlRequestId};

    use super::*;
    use crate::test_support::federation::{FixedSamlMessages, OIDC_STATE};
    use crate::test_support::organization::{
        FakeOrgIdentityProviderStore, FakeOrgSsoRequests, OrgProviderShape, OrgShape, org_shaped,
        org_store_with, stored_org_provider,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    /// Acme, which allows passwords, SAML and OIDC, connected to Okta as
    /// `shape` says.
    struct Setup {
        uc: OrgSsoStartUseCase,
        requests: Arc<FakeOrgSsoRequests>,
        audit: Arc<FakeEventDispatcher>,
    }

    fn settings() -> OrganizationAuthSettings {
        OrganizationAuthSettings {
            enabled_methods: vec![AuthMethod::Password, AuthMethod::Saml, AuthMethod::Oidc],
            step_up_policy: StepUpPolicy::relaxed(),
            ..OrganizationAuthSettings::default()
        }
    }

    fn setup_with(settings: OrganizationAuthSettings, shape: Option<OrgProviderShape>) -> Setup {
        let acme = OrganizationId::new();
        let organization = org_shaped(
            acme,
            OrgShape {
                tenants: Vec::new(),
                settings,
                suspension: Suspension::NotSuspended,
            },
        );
        let providers = shape.map_or_else(FakeOrgIdentityProviderStore::empty, |shape| {
            FakeOrgIdentityProviderStore::holding(stored_org_provider(acme, shape))
        });
        let requests = Arc::new(FakeOrgSsoRequests::empty());
        Setup {
            uc: OrgSsoStartUseCase::new(OrgSsoStartPorts {
                organizations: org_store_with([organization]),
                providers: Arc::new(providers),
                requests: requests.clone(),
                ..OrgSsoStartPorts::fakes()
            }),
            requests,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn setup(shape: OrgProviderShape) -> Setup {
        setup_with(settings(), Some(shape))
    }

    fn returns_to() -> SsoReturn {
        SsoReturn {
            oidc_callback: HttpsUrl::new("https://app.ianua.test/sso/oidc").unwrap(),
            service_provider: ServiceProvider {
                entity_id: SamlEntityId::new("https://app.ianua.test").unwrap(),
                acs_url: HttpsUrl::new("https://app.ianua.test/sso/saml").unwrap(),
            },
        }
    }

    fn start_at(setup: &Setup, slug: &str) -> Result<SsoStart, AppError> {
        block_on(setup.uc.execute(
            &(),
            &test_auditor(setup.audit.clone()),
            OrgSsoStartRequest {
                organization: TenantSlug::new(slug, &SlugLimits::default()).unwrap(),
                tenant_slug: None,
                returns_to: returns_to(),
                origin: ClientOrigin {
                    ip_address: Fact::Unknown,
                    user_agent: None,
                },
            },
        ))
    }

    fn start(setup: &Setup) -> Result<SsoStart, AppError> {
        start_at(setup, "acme-corp")
    }

    fn awaits_saml(setup: &Setup) -> bool {
        let id = SamlRequestId::new(FixedSamlMessages::REQUEST_ID).unwrap();
        block_on(setup.requests.take(OrgSsoKey::SamlRequest(&id)))
            .unwrap()
            .is_some()
    }

    /// Bob of Acme signs in through Okta over SAML. His browser is sent to
    /// Okta with a secret of its own, and the request waits for the answer.
    #[test]
    fn a_saml_start_sends_the_browser_and_remembers_the_request() {
        let setup = setup(OrgProviderShape::saml());

        let started = start(&setup).unwrap();

        assert!(started.url.as_str().starts_with("https://idp.acme.com/sso"));
        assert!(!started.binding.is_empty());
        assert!(awaits_saml(&setup));
        assert_eq!(
            *setup.audit.records.lock().unwrap(),
            ["organization.org_sso_sign_in_started"]
        );
    }

    /// Starting SSO for an organization without a provider records no audit
    /// event.
    #[test]
    fn a_refused_start_records_nothing() {
        let setup = setup_with(settings(), None);

        let _ = start(&setup);

        assert!(setup.audit.records.lock().unwrap().is_empty());
    }

    /// Bob signs in through Okta over OIDC. The request waits under the
    /// `state` the redirect carries, with its nonce and PKCE verifier.
    #[test]
    fn an_oidc_start_remembers_the_state() {
        let setup = setup(OrgProviderShape::oidc());

        start(&setup).unwrap();

        let state = Secret::new(OIDC_STATE);
        let request = block_on(setup.requests.take(OrgSsoKey::OidcState(&state)))
            .unwrap()
            .unwrap();
        assert!(matches!(request.awaiting, OrgSsoAwaiting::Oidc { .. }));
    }

    /// A disabled provider returns a forbidden error and stores no pending
    /// sign-in request.
    #[test]
    fn a_switched_off_provider_starts_nothing() {
        let setup = setup(OrgProviderShape::saml().in_status(ConnectionStatus::Disabled));

        let result = start(&setup);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.requests.count(), 0);
    }

    /// Unknown organizations and organizations without a provider both return
    /// forbidden errors when SSO starts.
    #[test]
    fn an_unknown_organization_answers_as_one_without_a_provider() {
        let unknown = start_at(&setup(OrgProviderShape::saml()), "globex");
        let without = start(&setup_with(settings(), None));

        assert!(matches!(unknown, Err(AppError::Forbidden(_))));
        assert!(matches!(without, Err(AppError::Forbidden(_))));
    }

    /// When Acme disables SAML, its connected SAML provider returns a
    /// forbidden error and stores no pending sign-in request.
    #[test]
    fn a_protocol_the_organization_does_not_allow_starts_nothing() {
        let passwords_only = OrganizationAuthSettings {
            enabled_methods: vec![AuthMethod::Password],
            ..settings()
        };
        let setup = setup_with(passwords_only, Some(OrgProviderShape::saml()));

        let result = start(&setup);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.requests.count(), 0);
    }
}
