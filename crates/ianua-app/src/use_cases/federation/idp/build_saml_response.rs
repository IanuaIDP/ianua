//! Build SAML response: this platform, as an identity provider, answers one
//! of the tenant's SAML apps for the person signed in.
//!
//! 1. The person must be signed in to their own tenant session; the
//!    assertion is about them, never about an account the request names.
//! 2. An app's request is read from where it was held on arrival, within
//!    ten minutes, so when it arrived is the server's record and never the
//!    browser's word.
//! 3. The app's sign-in request must meet the app's rules: it names the app,
//!    is signed when the app must sign, and asks for a registered address
//!    and the app's `NameID` format. A sign-in started here goes to the
//!    app's default address.
//! 4. The person is named in the app's format, sent what its attribute
//!    statements release, and the assertion is signed, sealed when the app
//!    asked for that, and wrapped in a response signed when it asked for
//!    that.
//! 5. The sign-in is kept against the person's session, so a logout reaches
//!    the app, and the held request is let go, so it is answered once.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ianua_domain::domains::federation::saml::assertion_builder::AssertionParams;
use ianua_domain::domains::federation::saml::authn_request::Reauthentication;
use ianua_domain::domains::federation::saml::name_id::{IssuedNameId, NameIdMint, SamlNameIdValue};
use ianua_domain::domains::federation::saml::trail::SamlTrail;
use ianua_domain::domains::federation::service_provider::{
    AcceptedAuthnRequest, HeldNames, SamlServiceProvider,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{
    ActorRef, HttpsUrl, Lifetime, SamlArrivalId, SamlAssertionId, SamlEntityId,
    SamlServiceProviderId, SessionIndex, UserId,
};
use time::Duration;
use uuid::Uuid;

use crate::acting::TenantAuthorities;
use crate::acting::tenant::SignedInAccount;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::authorization::{GroupMembershipStore, GroupStore, RoleStore};
use crate::ports::crypto::{SigningKeyStore, XmlSigner};
use crate::ports::federation::{
    AssertionEncrypter, HeldSamlSignIn, HeldSamlSignInStore, SamlAppSession, SamlAppSessionStore,
    SamlMessageReader, SamlNameIds, SamlServiceProviderStore,
};
use crate::services::lookup::existing_key_set;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::federation::idp::held_names::{Held, HeldNameSources};
use crate::use_cases::federation::idp::lookup::{
    existing_service_provider, sending_service_provider, signature_trust,
};
use crate::use_cases::federation::idp::signed_answer::{AnswerSigner, AnswerTerms};
use crate::use_cases::federation::lookup::active_signing_key;

/// How long after it reached this platform a sign-in request may still be
/// answered.
const ANSWER_WINDOW: Duration = Duration::minutes(10);

/// What a sign-in to an app answers.
pub enum SamlSignInTrigger {
    /// A sign-in request the app sent, held on the server since it arrived
    /// under this id. The message and when it arrived are read from there,
    /// never from the browser.
    Request(SamlArrivalId),
    /// A sign-in started here, to the app with this id.
    Initiated(SamlServiceProviderId),
}

/// What to answer an app with.
pub struct BuildSamlResponseRequest {
    /// This identity provider's entity id, written as the issuer.
    pub issuer: SamlEntityId,
    /// What the answer is for.
    pub trigger: SamlSignInTrigger,
    /// How long the assertion is good for.
    pub lifetime: Lifetime,
}

/// The answer, and where the browser posts it.
pub struct SamlResponseOutput {
    /// The app's address the answer is posted to.
    pub acs_url: HttpsUrl,
    /// The `Response` XML, base64-encoded for the HTTP-POST binding.
    pub base64_response: String,
    /// What the app sent to have back with the answer, if anything.
    pub relay_state: Option<String>,
}

/// The ports [`BuildSamlResponseUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct BuildSamlResponsePorts {
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// The app asking: its registration, its request read back, and the name it knows the person by.
    pub provider: SamlProviderPorts,
    /// What the answer says the person holds: their roles and groups.
    pub claims: SamlClaimPorts,
    /// What signs, and encrypts when asked, the answer.
    pub signing: SamlSigningPorts,
    /// Keeps the apps each session signed in to.
    pub app_sessions: Arc<dyn SamlAppSessionStore>,
    /// The sign-in requests held since they arrived.
    pub held: Arc<dyn HeldSamlSignInStore>,
}

/// The app asking: its registration, its request read back, and the name it knows the person by.
#[derive(ianua_macros::Fakes)]
pub struct SamlProviderPorts {
    /// The tenant's SAML apps.
    pub service_providers: Arc<dyn SamlServiceProviderStore>,
    /// Reads the app's sign-in request and checks its signature.
    pub message_reader: Arc<dyn SamlMessageReader>,
    /// Makes pairwise and transient `NameID`s.
    pub name_ids: Arc<dyn SamlNameIds>,
}

/// What the answer says the person holds: their roles and groups.
#[derive(ianua_macros::Fakes)]
pub struct SamlClaimPorts {
    /// The roles each person holds, for statements that send them.
    pub roles: Arc<dyn RoleStore>,
    /// Who sits in which group, for statements that send groups.
    pub memberships: Arc<dyn GroupMembershipStore>,
    /// The tenant's groups, for their names.
    pub groups: Arc<dyn GroupStore>,
}

/// What signs, and encrypts when asked, the answer.
#[derive(ianua_macros::Fakes)]
pub struct SamlSigningPorts {
    /// The tenant's signing keys.
    pub key_store: Arc<dyn SigningKeyStore>,
    /// Signs XML.
    pub xml_signer: Arc<dyn XmlSigner>,
    /// Seals an assertion to an app's key.
    pub encrypter: Arc<dyn AssertionEncrypter>,
}

/// Builds a signed SAML response about the person signed in.
pub struct BuildSamlResponseUseCase {
    ports: BuildSamlResponsePorts,
}

/// `NameID` values made through the [`SamlNameIds`] port, as the domain's
/// mint asks for them.
struct MintThrough<'a>(&'a dyn SamlNameIds);

impl NameIdMint for MintThrough<'_> {
    fn pairwise(
        &self,
        provider: &SamlServiceProviderId,
        account: &UserId,
    ) -> Result<SamlNameIdValue, DomainError> {
        self.0.pairwise(provider, account)
    }

    fn transient(&self) -> Result<SamlNameIdValue, DomainError> {
        self.0.transient()
    }
}

/// An app's sign-in, accepted by the app's rules, and where it began.
struct Accepted {
    app: SamlServiceProvider<ResolvedTenant>,
    sign_in: AcceptedAuthnRequest,
    origin: Origin,
}

/// Where a sign-in to an app began.
enum Origin {
    /// At a request the app sent, held since it arrived.
    Asked(HeldSamlSignIn),
    /// Here, with no request from the app.
    Here,
}

impl Origin {
    /// What the app sent to have back with the answer, if anything.
    fn relay_state(&self) -> Option<String> {
        match self {
            Self::Asked(held) => held.relay_state.clone(),
            Self::Here => None,
        }
    }
}

impl BuildSamlResponseUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: BuildSamlResponsePorts) -> Self {
        Self { ports }
    }

    /// The app `trigger` names and the sign-in it may be answered for.
    async fn accepted(
        &self,
        tenant: &ScopedTenant,
        trigger: &SamlSignInTrigger,
    ) -> Result<Accepted, AppError> {
        match trigger {
            SamlSignInTrigger::Request(id) => {
                let held = self.held_request(tenant, id).await?;
                self.requested(tenant, held).await
            }
            SamlSignInTrigger::Initiated(id) => self.initiated(tenant, id).await,
        }
    }

    /// The request held as `id` in `tenant`, still within the window it is
    /// answered in.
    ///
    /// # Errors
    ///
    /// - `AppError::LinkExpired` when no request is held as `id` in the
    ///   tenant, or it arrived longer ago than the window.
    /// - `AppError::Internal` on storage failure.
    async fn held_request(
        &self,
        tenant: &ScopedTenant,
        id: &SamlArrivalId,
    ) -> Result<HeldSamlSignIn, AppError> {
        let held = self.ports.held.find(tenant, id).await.or_internal()?;
        let Some(held) = held else {
            return Err(start_again());
        };
        if clock::now() - held.arrived_at > ANSWER_WINDOW {
            return Err(start_again());
        }
        Ok(held)
    }

    /// The app that sent the `held` request and the sign-in it asks for,
    /// once the request meets the app's rules.
    async fn requested(
        &self,
        tenant: &ScopedTenant,
        held: HeldSamlSignIn,
    ) -> Result<Accepted, AppError> {
        let store = self.ports.provider.service_providers.as_ref();
        let reader = self.ports.provider.message_reader.as_ref();
        let issuer = reader
            .issuer(&held.message)
            .map_err(AppError::from_domain)?;
        let app = sending_service_provider(store, tenant, &issuer).await?;
        let trust = signature_trust(&app.settings().request_signing);
        let request = reader
            .authn_request(&held.message, &trust)
            .map_err(AppError::from_domain)?;
        let sign_in = app
            .accept_request(&request)
            .map_err(AppError::from_domain)?;
        Ok(Accepted {
            app,
            sign_in,
            origin: Origin::Asked(held),
        })
    }

    /// The app with `id` and a sign-in started here to it.
    async fn initiated(
        &self,
        tenant: &ScopedTenant,
        id: &SamlServiceProviderId,
    ) -> Result<Accepted, AppError> {
        let store = self.ports.provider.service_providers.as_ref();
        let app = existing_service_provider(store, tenant, id).await?;
        let sign_in = app.unsolicited_sign_in().map_err(AppError::from_domain)?;
        Ok(Accepted {
            app,
            sign_in,
            origin: Origin::Here,
        })
    }

    /// What `user` holds, by name.
    async fn held(&self, tenant: &ScopedTenant, user: UserId) -> Result<Held, AppError> {
        HeldNameSources {
            roles: self.ports.claims.roles.as_ref(),
            memberships: self.ports.claims.memberships.as_ref(),
            groups: self.ports.claims.groups.as_ref(),
        }
        .of(tenant, user)
        .await
    }

    /// The signed answer carrying `assertion` to the app `accepted` names,
    /// base64-encoded.
    async fn answer(
        &self,
        tenant: &ScopedTenant,
        request: &BuildSamlResponseRequest,
        accepted: &Accepted,
        assertion: AssertionParams,
    ) -> Result<String, AppError> {
        let key_set = existing_key_set(self.ports.signing.key_store.as_ref(), tenant).await?;
        let signer = AnswerSigner {
            xml_signer: self.ports.signing.xml_signer.as_ref(),
            encrypter: self.ports.signing.encrypter.as_ref(),
            key: active_signing_key(&key_set)?,
        };
        let settings = accepted.app.settings();
        let signed = signer.assertion(&assertion, &settings.encryption).await?;
        let terms = AnswerTerms {
            issuer: &request.issuer,
            accepted: &accepted.sign_in,
            settings,
        };
        let response = signer.response(signed, &terms).await?;
        Ok(STANDARD.encode(response.as_bytes()))
    }

    /// Keeps that `person`'s session signed in to the app under the name
    /// and session index `terms` gave the assertion.
    async fn keep_app_session(
        &self,
        tenant: &ScopedTenant,
        person: &SignedInAccount,
        accepted: &Accepted,
        terms: &AssertionTerms,
    ) -> Result<(), AppError> {
        let AssertionTerms {
            name_id,
            session_index,
        } = terms;
        let app_session = SamlAppSession {
            session_id: *person.session.id(),
            provider_id: *accepted.app.id(),
            name_id: name_id.value().clone(),
            session_index: session_index.clone(),
        };
        self.ports
            .app_sessions
            .save(tenant, &app_session)
            .await
            .or_internal()
    }

    /// Lets go of the request `origin` held, now that it is answered.
    async fn release(&self, tenant: &ScopedTenant, origin: &Origin) -> Result<(), AppError> {
        let Origin::Asked(held) = origin else {
            return Ok(());
        };
        self.ports
            .held
            .release(tenant, &held.id)
            .await
            .or_internal()
    }
}

impl Command for BuildSamlResponseUseCase {
    type Caller = CallerContext;
    type Input = BuildSamlResponseRequest;
    type Output = Result<SamlResponseOutput, AppError>;

    /// A signed SAML response about the person signed in to `caller`'s
    /// session, for the app `request` names, and where to post it. The
    /// sign-in is kept against the session for single logout, a held
    /// request is let go so it is answered once, and the answer is recorded
    /// as `federation.saml_assertion_issued`, done by the person.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for no valid own tenant session or an insufficiently fresh sign-in; `LinkExpired` for an unknown, answered or ten-minute-old request.
    /// - `AppError::Forbidden` for a foreign/disabled app, missing required signature, invalid signature or unregistered address.
    /// - `AppError::NotFound` for a missing app/key set; `Conflict` for an unverified address used as the name.
    /// - `AppError::Domain` for a malformed request, unsupported NameID format or unrepresentable time.
    /// - `AppError::Internal` for no active signing key or signing, sealing or storage failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: BuildSamlResponseRequest,
    ) -> Result<SamlResponseOutput, AppError> {
        let person = self.ports.tenant_authorities.signed_in(caller).await?;
        let tenant = caller.tenant();
        let accepted = self.accepted(&tenant, &request.trigger).await?;
        ensure_fresh_enough(&accepted, &person)?;
        let mint = MintThrough(self.ports.provider.name_ids.as_ref());
        let name_id = accepted
            .app
            .name_id_for(&accepted.sign_in, &person.account, &mint)
            .map_err(AppError::from_domain)?;
        let held = self.held(&tenant, *person.account.id()).await?;
        let terms = AssertionTerms {
            name_id,
            session_index: fresh_session_index()?,
        };
        let assertion = assertion_params(&request, &accepted, &person, &held, &terms);
        let base64_response = self.answer(&tenant, &request, &accepted, assertion).await?;
        self.keep_app_session(&tenant, &person, &accepted, &terms)
            .await?;
        record_issued(auditor, &tenant, &accepted.app, &person).await?;
        self.release(&tenant, &accepted.origin).await?;
        Ok(SamlResponseOutput {
            acs_url: accepted.sign_in.acs_url().clone(),
            base64_response,
            relay_state: accepted.origin.relay_state(),
        })
    }
}

/// Refuses an answer to an app that asked for a fresh sign-in when the
/// person signed in before the request arrived, as the server recorded
/// it. They sign in again first.
///
/// # Errors
///
/// - `AppError::Unauthenticated` when the sign-in is older than the request
///   that asked for a fresh one.
fn ensure_fresh_enough(accepted: &Accepted, person: &SignedInAccount) -> Result<(), AppError> {
    let Origin::Asked(held) = &accepted.origin else {
        return Ok(());
    };
    let stale = person.session.signed_in_at() < held.arrived_at;
    match (accepted.sign_in.reauthentication(), stale) {
        (Reauthentication::Forced, true) => Err(AppError::Unauthenticated),
        (Reauthentication::Forced, false) | (Reauthentication::NotForced, _) => Ok(()),
    }
}

/// The refusal for a request no longer held: it is unknown here, was
/// answered already, or arrived too long ago.
fn start_again() -> AppError {
    AppError::LinkExpired(message!(
        "federation-the-sign-in-request-is-no",
        "the sign-in request is no longer open; start again at the app"
    ))
}

/// Records that `person` was signed in to `app`, as done by them.
///
/// # Errors
///
/// - `AppError::Internal` when the record cannot be written.
async fn record_issued(
    auditor: &RequestAuditor,
    tenant: &ScopedTenant,
    app: &SamlServiceProvider<ResolvedTenant>,
    person: &SignedInAccount,
) -> Result<(), AppError> {
    let mut trail = SamlTrail::default();
    trail.assertion_issued(app, &person.account);
    auditor
        .dispatch_by(
            &ActorRef::User(*person.account.id()),
            trail.take_events(tenant),
        )
        .await
        .or_internal()
}

/// How the person is named in the assertion, and the session the app is
/// told of.
struct AssertionTerms {
    name_id: IssuedNameId,
    session_index: SessionIndex,
}

/// What the assertion says about `person`, who holds `held`, for the app
/// `accepted` names.
fn assertion_params(
    request: &BuildSamlResponseRequest,
    accepted: &Accepted,
    person: &SignedInAccount,
    held: &Held,
    terms: &AssertionTerms,
) -> AssertionParams {
    let names = HeldNames {
        roles: &held.roles,
        groups: &held.groups,
    };
    AssertionParams {
        assertion_id: SamlAssertionId::fresh(),
        issuer: request.issuer.clone(),
        sp_entity_id: accepted.app.entity_id().clone(),
        acs_url: accepted.sign_in.acs_url().clone(),
        authenticated_at: person.session.signed_in_at(),
        assurance: person.signed_in.progress().assurance_level(),
        name_id: terms.name_id.clone(),
        attributes: accepted.app.released_attributes(&person.account, &names),
        lifetime: request.lifetime,
        session_index: terms.session_index.clone(),
        in_response_to: accepted.sign_in.in_response_to().cloned(),
    }
}

/// A new, unique session index.
///
/// # Errors
///
/// - `AppError::Internal` if the index is refused, which it never is.
fn fresh_session_index() -> Result<SessionIndex, AppError> {
    SessionIndex::new(format!("_s{}", Uuid::now_v7().simple())).or_internal()
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use ianua_domain::domains::crypto::signing_key::{
        NewSigningKey, SigningAlgorithm, SigningKey, SigningKeySet,
    };
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::domains::federation::service_provider::{
        AssertionEncryption, RequestSigningRule, SamlServiceProviderSettings, SignedParts,
    };
    use ianua_domain::shared::clock;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{CertificatePem, Expiry, KeyId, PublicKeyPem, TenantId};

    use super::*;
    use crate::ports::crypto::XmlSigningKey;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::crypto::{FakeSigningKeyStore, FakeXmlSigner};
    use crate::test_support::domain::TEST_CERTIFICATE_PEM;
    use crate::test_support::federation::{
        FakeHeldSamlSignIns, FakeSamlAppSessions, FakeSamlMessageReader,
        FakeSamlServiceProviderStore, FakeSignature, TEST_APP_ACS_URL, TEST_APP_ENTITY_ID,
        posted_message, test_app_settings, test_service_provider_with,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct FailingXmlSigner;

    #[async_trait]
    impl XmlSigner for FailingXmlSigner {
        async fn sign_xml(
            &self,
            _xml: &str,
            _key: &XmlSigningKey<'_>,
        ) -> Result<String, DomainError> {
            Err(DomainError::infra_msg("signing failed"))
        }
    }

    fn key_store() -> Arc<FakeSigningKeyStore> {
        let key = SigningKey::create(NewSigningKey {
            kid: KeyId::new("key-1").unwrap(),
            algorithm: SigningAlgorithm::Rs256,
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n",
            )
            .unwrap(),
            private_key: Secret::new("private-key"),
            expires_at: Expiry::Never,
        });
        Arc::new(FakeSigningKeyStore::holding(SigningKeySet::new(key)))
    }

    /// Acme's Salesforce app, answered by `settings`, in `status`.
    fn apps_holding(
        status: ConnectionStatus,
        settings: SamlServiceProviderSettings,
    ) -> (Arc<FakeSamlServiceProviderStore>, SamlServiceProviderId) {
        let id = SamlServiceProviderId::new();
        let app = test_service_provider_with(id, status, settings);
        let store = FakeSamlServiceProviderStore::holding(&test_ctx().tenant(), [app]);
        (Arc::new(store), id)
    }

    struct Harness {
        ports: BuildSamlResponsePorts,
        app_id: SamlServiceProviderId,
        app_sessions: Arc<FakeSamlAppSessions>,
        held: Arc<FakeHeldSamlSignIns>,
    }

    /// The id the test request is held by.
    fn arrival() -> SamlArrivalId {
        SamlArrivalId::from_uuid(Uuid::from_u128(1))
    }

    /// Salesforce's request, held since `offset` from now.
    fn held_at(offset: Duration) -> HeldSamlSignIn {
        HeldSamlSignIn {
            id: arrival(),
            message: posted_message(),
            relay_state: Some("back-to-salesforce".to_owned()),
            arrived_at: clock::now() + offset,
        }
    }

    fn harness_holding(
        settings: SamlServiceProviderSettings,
        held: FakeHeldSamlSignIns,
    ) -> Harness {
        let (apps, app_id) = apps_holding(ConnectionStatus::Active, settings);
        let app_sessions = Arc::new(FakeSamlAppSessions::empty());
        let held = Arc::new(held);
        let ports = BuildSamlResponsePorts {
            app_sessions: app_sessions.clone(),
            held: held.clone(),
            provider: SamlProviderPorts {
                service_providers: apps,
                ..SamlProviderPorts::fakes()
            },
            signing: SamlSigningPorts {
                key_store: key_store(),
                xml_signer: Arc::new(FakeXmlSigner),
                ..SamlSigningPorts::fakes()
            },
            ..BuildSamlResponsePorts::fakes()
        };
        Harness {
            ports,
            app_id,
            app_sessions,
            held,
        }
    }

    fn harness_with(settings: SamlServiceProviderSettings) -> Harness {
        let held =
            FakeHeldSamlSignIns::holding(test_ctx().tenant_id(), held_at(-Duration::minutes(1)));
        harness_holding(settings, held)
    }

    fn harness() -> Harness {
        harness_with(test_app_settings())
    }

    fn requested() -> BuildSamlResponseRequest {
        BuildSamlResponseRequest {
            issuer: SamlEntityId::new("https://auth.acme.com").unwrap(),
            trigger: SamlSignInTrigger::Request(arrival()),
            lifetime: Lifetime::seconds(300).unwrap(),
        }
    }

    fn answer(
        ports: BuildSamlResponsePorts,
        request: BuildSamlResponseRequest,
    ) -> Result<SamlResponseOutput, AppError> {
        answer_recorded(ports, request, &Arc::new(FakeEventDispatcher::new()))
    }

    fn answer_recorded(
        ports: BuildSamlResponsePorts,
        request: BuildSamlResponseRequest,
        audit: &Arc<FakeEventDispatcher>,
    ) -> Result<SamlResponseOutput, AppError> {
        let auditor = test_auditor(audit.clone());
        block_on(BuildSamlResponseUseCase::new(ports).execute(&test_ctx(), &auditor, request))
    }

    fn xml_of(output: &SamlResponseOutput) -> String {
        String::from_utf8(STANDARD.decode(&output.base64_response).unwrap()).unwrap()
    }

    fn reading(
        reader: FakeSamlMessageReader,
        ports: BuildSamlResponsePorts,
    ) -> BuildSamlResponsePorts {
        BuildSamlResponsePorts {
            provider: SamlProviderPorts {
                message_reader: Arc::new(reader),
                ..ports.provider
            },
            ..ports
        }
    }

    /// Ann, signed in, opens Salesforce, which asks Acme to sign her in.
    /// Salesforce gets a signed answer at its address, naming her by her
    /// pairwise id and sending her address, and the sign-in is kept against
    /// her session and recorded.
    #[test]
    fn a_requested_sign_in_is_answered_and_kept() {
        let h = harness();
        let audit = Arc::new(FakeEventDispatcher::new());

        let output = answer_recorded(h.ports, requested(), &audit).unwrap();

        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["federation.saml_assertion_issued"]
        );
        assert_eq!(output.acs_url.as_str(), TEST_APP_ACS_URL);
        let xml = xml_of(&output);
        assert!(xml.contains("<Signed><saml:Assertion"));
        assert!(xml.contains("pairwise:"));
        assert!(xml.contains("caller@example.test"));
        assert!(xml.contains(FakeSamlMessageReader::AUTHN_REQUEST_ID));
        assert_eq!(output.relay_state.as_deref(), Some("back-to-salesforce"));
        let kept = h.app_sessions.all();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].provider_id, h.app_id);
        assert!(h.held.all().is_empty());
    }

    /// Ann opens Salesforce from Acme's app list. Salesforce never asked,
    /// so the answer goes to its default address and answers no request.
    #[test]
    fn a_sign_in_started_here_answers_no_request() {
        let h = harness();
        let request = BuildSamlResponseRequest {
            trigger: SamlSignInTrigger::Initiated(h.app_id),
            ..requested()
        };

        let output = answer(h.ports, request).unwrap();

        assert_eq!(output.acs_url.as_str(), TEST_APP_ACS_URL);
        assert!(!xml_of(&output).contains("InResponseTo"));
    }

    /// Salesforce asked for its assertions sealed and its responses signed.
    /// The assertion inside goes sealed, and the response around it is
    /// signed.
    #[test]
    fn an_app_gets_its_assertion_sealed_and_its_response_signed() {
        let h = harness_with(SamlServiceProviderSettings {
            encryption: AssertionEncryption::EncryptedFor(
                CertificatePem::new(TEST_CERTIFICATE_PEM).unwrap(),
            ),
            signing: SignedParts::AssertionAndResponse,
            ..test_app_settings()
        });

        let xml = xml_of(&answer(h.ports, requested()).unwrap());

        assert!(xml.starts_with("<Signed><samlp:Response"));
        assert!(xml.contains("<Sealed><Signed><saml:Assertion"));
    }

    /// Acme has no signing key yet. Nothing can be signed, and the answer is
    /// not found.
    #[test]
    fn a_tenant_without_signing_keys_is_not_found() {
        let h = harness();
        let ports = BuildSamlResponsePorts {
            signing: SamlSigningPorts {
                key_store: Arc::new(FakeSigningKeyStore::empty()),
                ..h.ports.signing
            },
            ..h.ports
        };

        let result = answer(ports, requested());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(h.app_sessions.all().is_empty());
    }

    /// The signer fails. The answer fails rather than go out unsigned.
    #[test]
    fn a_signing_failure_is_internal() {
        let h = harness();
        let ports = BuildSamlResponsePorts {
            signing: SamlSigningPorts {
                xml_signer: Arc::new(FailingXmlSigner),
                ..h.ports.signing
            },
            ..h.ports
        };

        let result = answer(ports, requested());

        assert!(matches!(result, Err(AppError::Internal(_))));
    }

    /// A sign-in request whose issuer names an unknown app is forbidden.
    #[test]
    fn a_request_from_an_unknown_app_is_refused() {
        let h = harness();
        let reader = FakeSamlMessageReader::from_issuer("https://evil.example");

        let result = answer(reading(reader, h.ports), requested());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An app requiring signed requests cannot obtain an answer to an
    /// unsigned sign-in request.
    #[test]
    fn an_unsigned_request_is_refused_where_the_app_signs() {
        let h = harness_with(SamlServiceProviderSettings {
            request_signing: RequestSigningRule::Required(
                CertificatePem::new(TEST_CERTIFICATE_PEM).unwrap(),
            ),
            ..test_app_settings()
        });

        let result = answer(h.ports, requested());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A sign-in request with a forged signature is forbidden when the app
    /// requires signatures from its registered key.
    #[test]
    fn a_request_signed_by_another_key_is_refused() {
        let h = harness_with(SamlServiceProviderSettings {
            request_signing: RequestSigningRule::Required(
                CertificatePem::new(TEST_CERTIFICATE_PEM).unwrap(),
            ),
            ..test_app_settings()
        });
        let reader =
            FakeSamlMessageReader::from_issuer(TEST_APP_ENTITY_ID).signed(FakeSignature::Forged);

        let result = answer(reading(reader, h.ports), requested());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Asking for an assertion at an unregistered address is forbidden and
    /// leaves the app-session store empty.
    #[test]
    fn an_unregistered_address_is_refused() {
        let h = harness();
        let reader = FakeSamlMessageReader::from_issuer(TEST_APP_ENTITY_ID)
            .asking_for("https://evil.example/acs");

        let result = answer(reading(reader, h.ports), requested());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(h.app_sessions.all().is_empty());
    }

    /// A request from a disabled app is forbidden.
    #[test]
    fn a_switched_off_app_is_sent_no_assertion() {
        let (apps, _) = apps_holding(ConnectionStatus::Disabled, test_app_settings());
        let ports = {
            let base = harness().ports;
            BuildSamlResponsePorts {
                provider: SamlProviderPorts {
                    service_providers: apps,
                    ..base.provider
                },
                ..base
            }
        };

        let result = answer(ports, requested());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A forced sign-in request newer than the caller's session requires
    /// authentication again and remains held for a later attempt.
    #[test]
    fn a_forced_sign_in_is_not_answered_with_an_older_one() {
        let held =
            FakeHeldSamlSignIns::holding(test_ctx().tenant_id(), held_at(Duration::minutes(1)));
        let h = harness_holding(test_app_settings(), held);
        let reader = FakeSamlMessageReader::from_issuer(TEST_APP_ENTITY_ID).forcing_sign_in();

        let result = answer(reading(reader, h.ports), requested());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(h.held.all().len(), 1);
    }

    /// An unknown request identifier is treated as expired and creates no
    /// app-session record.
    #[test]
    fn an_unknown_request_id_is_refused() {
        let h = harness_holding(test_app_settings(), FakeHeldSamlSignIns::empty());

        let result = answer(h.ports, requested());

        assert!(matches!(result, Err(AppError::LinkExpired(_))));
        assert!(h.app_sessions.all().is_empty());
    }

    /// A request held by another tenant is treated as expired in the caller's tenant.
    #[test]
    fn a_request_held_in_another_tenant_is_refused() {
        let held = FakeHeldSamlSignIns::holding(TenantId::new(), held_at(-Duration::minutes(1)));
        let h = harness_holding(test_app_settings(), held);

        let result = answer(h.ports, requested());

        assert!(matches!(result, Err(AppError::LinkExpired(_))));
    }

    /// A held request that arrived eleven minutes ago is refused as expired.
    #[test]
    fn a_request_older_than_the_window_is_refused() {
        let held =
            FakeHeldSamlSignIns::holding(test_ctx().tenant_id(), held_at(-Duration::minutes(11)));
        let h = harness_holding(test_app_settings(), held);

        let result = answer(h.ports, requested());

        assert!(matches!(result, Err(AppError::LinkExpired(_))));
    }

    /// After a held request is answered successfully, using its identifier
    /// again returns an expired-link refusal.
    #[test]
    fn a_request_is_answered_once() {
        let h = harness();
        let use_case = BuildSamlResponseUseCase::new(h.ports);
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        block_on(use_case.execute(&test_ctx(), &auditor, requested())).unwrap();

        let again = block_on(use_case.execute(&test_ctx(), &auditor, requested()));

        assert!(matches!(again, Err(AppError::LinkExpired(_))));
    }

    /// A signed-out session cannot obtain a SAML answer and creates no
    /// app-session record.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let h = harness();
        let ports = BuildSamlResponsePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..h.ports
        };

        let result = answer(ports, requested());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(h.app_sessions.all().is_empty());
    }
}
