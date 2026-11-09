//! SAML sign-in, the assertion consumer: the identity provider posts the
//! browser back with a signed response and the `RelayState` naming the
//! request it answers. Only an answer to a request sent from here, brought
//! back by the browser that started it, is accepted, each assertion once.
//! The session goes back as a one-time code.

use std::sync::Arc;
use std::time::Instant;

use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::federation::connection::{ConnectionConfig, FederatedIdpConnection};
use ianua_domain::domains::federation::saml::assertion::SamlAssertion;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{SamlRequestId, Setting, TokenHash};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SealOwner;
use crate::ports::federation::{
    ConnectionStore, SamlAnswer, SamlAssertionLedger, SamlConnection, SamlLoginRequest,
    SamlRequestStore, SamlValidator, ServiceProvider,
};
use crate::ports::tenant::TenantStore;
use crate::services::authentication::assertion_refusal::{rejected_assertion, unchecked_assertion};
use crate::services::authentication::sign_in_gate::{self, ClientOrigin};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::federation::completion::{
    SignInCompletion, SsoCompletionPorts, VouchedSignIn,
};
use crate::use_cases::authentication::federation::lookup::existing_active_connection;
use crate::use_cases::authentication::federation::single_sign_on::{
    SsoPolicy, SsoSignIn, ensure_same_browser,
};

/// How long a spent assertion is remembered.
///
/// Longer than any sane `NotOnOrAfter`, so a replay is refused for the whole
/// time the assertion would otherwise still verify. Rows past this are swept.
const ASSERTION_MEMORY: time::Duration = time::Duration::hours(24);

/// The ports [`SamlLoginUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SamlLoginPorts {
    /// The tenant's federation connections.
    pub connection_store: Arc<dyn ConnectionStore>,
    /// Checks the SAML response.
    pub saml_validator: Arc<dyn SamlValidator>,
    /// Remembers which assertions were answered already.
    pub assertion_ledger: Arc<dyn SamlAssertionLedger>,
    /// Requests awaiting their answer.
    pub saml_requests: Arc<dyn SamlRequestStore>,
    /// The tenant, whose say on the sign-in comes first.
    pub tenant_store: Arc<dyn TenantStore>,
    /// What finishes the sign-in, the same for OIDC and SAML.
    pub completion: SsoCompletionPorts,
}

/// The identity provider's answer, as the browser posted it.
pub struct SamlCallbackRequest {
    /// The `RelayState`: the ID of the request being answered.
    pub relay_state: SamlRequestId,
    /// The base64 `SAMLResponse`.
    pub saml_response: String,
    /// The secret the browser kept since the request went out.
    pub binding: Secret,
    /// This service provider, as the response must name it.
    pub service_provider: ServiceProvider,
    /// Where the request came from.
    pub origin: ClientOrigin,
}

/// Signs a person in from a SAML provider's answer.
pub struct SamlLoginUseCase {
    policy: SsoPolicy,
    ports: SamlLoginPorts,
}

impl SamlLoginUseCase {
    /// A use case working through `ports` under `policy`.
    #[must_use]
    pub fn new(policy: SsoPolicy, ports: SamlLoginPorts) -> Self {
        Self { policy, ports }
    }

    /// The connection the response answers through and its assertion,
    /// checked and spent so it cannot be presented again.
    async fn vouched_assertion(
        &self,
        tenant: &ScopedTenant,
        callback: &SamlCallbackRequest,
    ) -> Result<
        (
            FederatedIdpConnection<ResolvedTenant>,
            SamlAssertion,
            TokenHash,
        ),
        AppError,
    > {
        let request = self.answered_request(tenant, callback).await?;
        let connection = existing_active_connection(
            self.ports.connection_store.as_ref(),
            tenant,
            &request.connection_id,
        )
        .await?;
        let assertion = self
            .validated_assertion(tenant, &connection, callback)
            .await?;
        connection
            .ensure_delivered_as_required(&assertion)
            .map_err(AppError::from_domain)?;
        self.spend_assertion(tenant, &assertion).await?;
        Ok((connection, assertion, request.dashboard_hash))
    }

    /// Takes the request the `RelayState` names, refusing an answer nobody
    /// here asked for, one already answered, or one brought back by another
    /// browser.
    async fn answered_request(
        &self,
        tenant: &ScopedTenant,
        callback: &SamlCallbackRequest,
    ) -> Result<SamlLoginRequest, AppError> {
        let request = self
            .ports
            .saml_requests
            .take(tenant, &callback.relay_state)
            .await
            .or_internal()?
            .ok_or_else(|| {
                AppError::Forbidden(message!(
                    "api-no-sign-in-request-awaits-this",
                    "no sign-in request awaits this answer"
                ))
            })?;
        let hasher = self.ports.completion.session.code_hasher.as_ref();
        ensure_same_browser(hasher, &callback.binding, &request.binding_hash).await?;
        Ok(request)
    }

    /// The assertion the provider's response carries, once its signature,
    /// expiry, audience, and answer to the request all check out.
    async fn validated_assertion(
        &self,
        tenant: &ScopedTenant,
        connection: &FederatedIdpConnection<ResolvedTenant>,
        callback: &SamlCallbackRequest,
    ) -> Result<SamlAssertion, AppError> {
        let ConnectionConfig::Saml(config) = connection.config() else {
            return Err(AppError::Forbidden(message!(
                "authentication-connection-is-not-saml",
                "connection is not SAML"
            )));
        };
        let answer = SamlAnswer {
            response: &callback.saml_response,
            in_response_to: &callback.relay_state,
        };
        let through = SamlConnection {
            owner: SealOwner::from(tenant),
            id: *connection.id(),
        };
        self.ports
            .saml_validator
            .validate(&answer, config, &through, &callback.service_provider)
            .await
            .map_err(|error| rejected_assertion(&error))
    }

    /// Spends the assertion, refusing one that was already answered.
    ///
    /// A valid signature says the provider wrote it, not that this is the
    /// first time it is shown. A ledger that cannot answer is treated as a
    /// replay: an assertion whose history is unknown is not one to trust.
    async fn spend_assertion(
        &self,
        tenant: &ScopedTenant,
        assertion: &SamlAssertion,
    ) -> Result<(), AppError> {
        let remembered_until = clock::now() + ASSERTION_MEMORY;
        let spent = self
            .ports
            .assertion_ledger
            .spend(tenant, assertion.assertion_id(), remembered_until)
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
}

impl Command for SamlLoginUseCase {
    type Caller = ScopedTenant;
    type Input = SamlCallbackRequest;
    type Output = Result<SsoSignIn, AppError>;

    /// Signs in the person a SAML provider's answer names, and hands their
    /// session back as a one-time code.
    ///
    /// The tenant admits SAML sign-in from where the request came first. The
    /// request answered is taken once, and only from the browser that sent
    /// it. The response is checked against the request, and its assertion
    /// spent. The account is found by its link, linked, or made, as the
    /// domain's admission allows, and the session owes what the tenant asks
    /// of the person.
    ///
    /// # Errors
    ///
    /// - `AppError::TenantUnavailable` or `AppError::Forbidden` if the tenant
    ///   does not accept SAML sign-in from where the request came from.
    /// - `AppError::Forbidden` if no request awaits this answer, the browser
    ///   is not the one that sent it, the connection is turned off or not
    ///   SAML, the response is invalid, its assertion came readable to a
    ///   connection that takes only sealed ones, was used or cannot be
    ///   checked for reuse, admission refuses the person, the account may
    ///   not sign in, the plan has no room for a new account, or the sign-in
    ///   falls short of what the tenant requires.
    /// - `AppError::NotFound` if the connection, the tenant or the linked
    ///   account doesn't exist.
    /// - `AppError::Conflict` if another sign-in linked the account first.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        callback: SamlCallbackRequest,
    ) -> Result<SsoSignIn, AppError> {
        let started = Instant::now();
        let tenants = self.ports.tenant_store.as_ref();
        let client_ip = callback.origin.ip_address.as_ref();
        let (record, _) = sign_in_gate::admit(tenants, tenant, AuthMethod::Saml, client_ip).await?;
        let (connection, assertion, dashboard_hash) =
            self.vouched_assertion(tenant, &callback).await?;
        let identity = assertion.vouched();
        let groups = connection.provider_groups(assertion.attributes());
        let completion = SignInCompletion {
            ports: &self.ports.completion,
            policy: &self.policy,
        };
        let vouched = VouchedSignIn {
            scope: tenant,
            tenant: &record,
            connection: &connection,
            identity: &identity,
            origin: &callback.origin,
            started,
            dashboard_hash,
            provider_groups: &groups,
            provider_session: Setting::from_stored(assertion.session_index().cloned()),
        };
        completion.complete(auditor, vouched).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use async_trait::async_trait;
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::federation::connection::{
        AssertionDecryption, AssuranceTrust, ConnectionRow, EmailTrust, GroupMapping,
        JitProvisioning, SamlConfig, SpEncryptionKey,
    };
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;
    use ianua_domain::shared::config::DisplayNameLimits;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::types::{
        CertificatePem, ConnectionId, DomainName, HttpsUrl, Label, Lifetime, SamlAssertionId,
        SamlEntityId, SealedSecret, Setting, UserId,
    };
    use time::OffsetDateTime;

    use super::*;
    use crate::ports::TenantScoped;
    use crate::test_support::authentication::FakeSessionStore;
    use crate::test_support::federation::{
        FakeConnectionStore, FakeSamlAssertionLedger, FakeSamlRequests, FakeSamlValidator,
        TEST_IDP_CERTIFICATE, test_saml_config, test_saml_settings,
    };
    use crate::test_support::identity::{FakeUserStore, stored_user};
    use crate::test_support::oauth::{FakeCodeHasher, hash_of};
    use crate::test_support::tenant::tenant_store_signing_in_with;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::authentication::federation::completion::{
        SsoAccountPorts, SsoSessionPorts,
    };

    const REQUEST: &str = "_request-1";
    const BINDING: &str = "the-browsers-secret";
    const ALICE: &str = "alice@acme.com";

    /// A ledger that cannot be reached.
    struct UnreachableLedger;

    impl TenantScoped for UnreachableLedger {}

    #[async_trait]
    impl SamlAssertionLedger for UnreachableLedger {
        async fn spend(
            &self,
            _: &ScopedTenant,
            _: &SamlAssertionId,
            _: OffsetDateTime,
        ) -> Result<bool, DomainError> {
            Err(DomainError::infra_msg("ledger unreachable"))
        }
    }

    fn saml_connection(
        id: ConnectionId,
        status: ConnectionStatus,
        provisioning: JitProvisioning,
    ) -> FederatedIdpConnection<ResolvedTenant> {
        saml_connection_reached_by(id, status, provisioning, test_saml_config())
    }

    fn saml_connection_reached_by(
        id: ConnectionId,
        status: ConnectionStatus,
        provisioning: JitProvisioning,
        config: ConnectionConfig,
    ) -> FederatedIdpConnection<ResolvedTenant> {
        let now = clock::now();
        FederatedIdpConnection::reconstitute(ConnectionRow {
            id,
            provider_name: Label::new("name", "Acme SAML").unwrap(),
            status,
            config,
            jit_provisioning: provisioning,
            jit_default_role_id: Setting::Unset,
            email_trust: EmailTrust::Authoritative,
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

    fn service_provider() -> ServiceProvider {
        ServiceProvider {
            entity_id: SamlEntityId::new("https://ianua.example.com").unwrap(),
            acs_url: HttpsUrl::new("https://ianua.example.com/acs").unwrap(),
        }
    }

    struct Harness {
        connection_id: ConnectionId,
        connections: Arc<FakeConnectionStore>,
        validator: Arc<FakeSamlValidator>,
        ledger: Arc<dyn SamlAssertionLedger>,
        requests: Arc<FakeSamlRequests>,
        users: Arc<FakeUserStore>,
        sessions: Arc<FakeSessionStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Harness {
        fn with(status: ConnectionStatus, provisioning: JitProvisioning) -> Self {
            let connection_id = ConnectionId::new();
            let tenant = test_ctx().tenant();
            let held = saml_connection(connection_id, status, provisioning);
            let harness = Self {
                connection_id,
                connections: Arc::new(FakeConnectionStore::holding(&tenant, [held])),
                validator: Arc::new(FakeSamlValidator::succeeding()),
                ledger: Arc::new(FakeSamlAssertionLedger::empty()),
                requests: Arc::new(FakeSamlRequests::empty()),
                users: Arc::new(FakeUserStore::empty()),
                sessions: Arc::new(FakeSessionStore::empty()),
                audit: Arc::new(FakeEventDispatcher::new()),
            };
            harness.send_request();
            harness
        }

        fn active() -> Self {
            Self::with(ConnectionStatus::Active, JitProvisioning::Disabled)
        }

        fn send_request(&self) {
            let request = SamlLoginRequest {
                connection_id: self.connection_id,
                binding_hash: hash_of(BINDING),
                dashboard_hash: hash_of("dashboard-state"),
            };
            let id = SamlRequestId::new(REQUEST).unwrap();
            block_on(self.requests.save(&test_ctx().tenant(), &id, &request)).unwrap();
        }

        fn with_alice(self, status: UserStatus) -> (Self, UserId) {
            let alice = UserId::new();
            self.users.add(stored_user(alice, ALICE, status));
            (self, alice)
        }

        fn answer(&self, relay_state: &str, binding: &str) -> Result<SsoSignIn, AppError> {
            let use_case = self.use_case();
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.audit.clone()),
                SamlCallbackRequest {
                    relay_state: SamlRequestId::new(relay_state).unwrap(),
                    saml_response: "PHNhbWxwOlJlc3BvbnNlLz4=".to_owned(),
                    binding: Secret::new(binding),
                    service_provider: service_provider(),
                    origin: ClientOrigin::default(),
                },
            ))
        }

        /// Resolves the provider answer using this harness's request and account stores.
        fn use_case(&self) -> SamlLoginUseCase {
            SamlLoginUseCase::new(
                SsoPolicy {
                    code_lifetime: Lifetime::seconds(60).unwrap(),
                    display_names: DisplayNameLimits::default(),
                },
                SamlLoginPorts {
                    connection_store: self.connections.clone(),
                    saml_validator: self.validator.clone(),
                    assertion_ledger: self.ledger.clone(),
                    saml_requests: self.requests.clone(),
                    tenant_store: tenant_store_signing_in_with(TenantAuthSettings {
                        enabled_methods: vec![AuthMethod::Password, AuthMethod::Saml],
                        ..TenantAuthSettings::default()
                    }),
                    completion: SsoCompletionPorts {
                        accounts: SsoAccountPorts {
                            users: self.users.clone(),
                            ..SsoAccountPorts::fakes()
                        },
                        session: SsoSessionPorts {
                            sessions: self.sessions.clone(),
                            code_hasher: Arc::new(FakeCodeHasher::new()),
                            ..SsoSessionPorts::fakes()
                        },
                        ..SsoCompletionPorts::fakes()
                    },
                },
            )
        }

        fn sign_in(&self) -> Result<SsoSignIn, AppError> {
            self.answer(REQUEST, BINDING)
        }
    }

    /// Alice has an account at Acme and answers the request her browser
    /// sent. She is signed in, with a SAML session.
    #[test]
    fn saml_login_creates_a_session_for_an_existing_user() {
        let (harness, alice) = Harness::active().with_alice(UserStatus::Active);

        let signed_in = harness.sign_in().unwrap();

        assert_eq!(signed_in.user_id, alice);
        assert_eq!(harness.sessions.session_count(), 1);
    }

    /// The validator is asked about the request the answer names, so an
    /// answer to some other request cannot pass for this one.
    #[test]
    fn the_answer_must_answer_the_request_sent() {
        let (harness, _) = Harness::active().with_alice(UserStatus::Active);

        harness.sign_in().unwrap();

        assert_eq!(
            harness.validator.answered(),
            vec![SamlRequestId::new(REQUEST).unwrap()]
        );
    }

    /// Replaying Alice's spent assertion is refused and leaves only her first session.
    #[test]
    fn a_replayed_assertion_is_refused() {
        let (harness, _) = Harness::active().with_alice(UserStatus::Active);
        harness.sign_in().unwrap();
        harness.send_request();

        let replayed = harness.sign_in();

        assert!(matches!(replayed, Err(AppError::Forbidden(_))));
        assert_eq!(harness.sessions.session_count(), 1);
    }

    /// A spent assertion is remembered for a full day, longer than it would
    /// still verify.
    #[test]
    fn a_spent_assertion_is_remembered_for_its_full_window() {
        let ledger = Arc::new(FakeSamlAssertionLedger::empty());
        let (harness, _) = Harness {
            ledger: ledger.clone(),
            ..Harness::active()
        }
        .with_alice(UserStatus::Active);
        let before = clock::now();

        harness.sign_in().unwrap();

        let until = ledger.remembered_until();
        assert_eq!(until.len(), 1);
        assert!(until[0] >= before + ASSERTION_MEMORY);
    }

    /// An unavailable assertion ledger refuses sign-in without opening a session.
    #[test]
    fn an_assertion_that_cannot_be_checked_for_reuse_is_refused() {
        let (harness, _) = Harness {
            ledger: Arc::new(UnreachableLedger),
            ..Harness::active()
        }
        .with_alice(UserStatus::Active);

        let result = harness.sign_in();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(harness.sessions.session_count(), 0);
    }

    /// An answer naming an unsent SAML request is forbidden.
    #[test]
    fn an_answer_nobody_here_asked_for_is_refused() {
        let (harness, _) = Harness::active().with_alice(UserStatus::Active);

        let result = harness.answer("_never-sent", BINDING);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An answer carrying another browser's binding is refused without opening a session.
    #[test]
    fn an_answer_brought_back_by_another_browser_opens_no_session() {
        let (harness, _) = Harness::active().with_alice(UserStatus::Active);

        let result = harness.answer(REQUEST, "another-browser");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(harness.sessions.session_count(), 0);
    }

    /// Alice has no account and the connection makes them. Hers is made
    /// active, so her next sign-in works too.
    #[test]
    fn saml_login_provisions_an_active_user() {
        let harness = Harness::with(ConnectionStatus::Active, JitProvisioning::Enabled);

        let signed_in = harness.sign_in().unwrap();

        assert!(signed_in.jit_provisioned);
        assert_eq!(
            harness.users.get_status(&signed_in.user_id),
            Some(UserStatus::Active)
        );
    }

    /// Alice's deactivated account cannot open a session through her SAML provider.
    #[test]
    fn saml_login_rejects_a_deactivated_user() {
        let (harness, _) = Harness::active().with_alice(UserStatus::Deactivated);

        let result = harness.sign_in();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(harness.sessions.session_count(), 0);
    }

    /// With provisioning disabled, an unknown SAML identity is refused and no user is saved.
    #[test]
    fn saml_login_rejects_an_unknown_user_without_provisioning() {
        let harness = Harness::active();

        let result = harness.sign_in();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(harness.users.count(), 0);
    }

    /// A disabled SAML connection refuses an otherwise active account's sign-in.
    #[test]
    fn saml_login_rejects_a_disabled_connection() {
        let (harness, _) = Harness::with(ConnectionStatus::Disabled, JitProvisioning::Disabled)
            .with_alice(UserStatus::Active);

        let result = harness.sign_in();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Failed assertion validation returns the generic SAML rejection message.
    #[test]
    fn saml_login_rejects_an_invalid_assertion() {
        let (harness, _) = Harness {
            validator: Arc::new(FakeSamlValidator::failing()),
            ..Harness::active()
        }
        .with_alice(UserStatus::Active);

        let result = harness.sign_in();

        let Err(AppError::Forbidden(message)) = result else {
            panic!("a forged response is refused");
        };
        assert_eq!(message, "SAML assertion rejected");
    }

    /// A SAML callback whose connection is absent returns not found.
    #[test]
    fn saml_login_for_a_connection_that_is_gone_is_not_found() {
        let (harness, _) = Harness {
            connections: Arc::new(FakeConnectionStore::empty()),
            ..Harness::active()
        }
        .with_alice(UserStatus::Active);

        let result = harness.sign_in();

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Alice has no second factor here and Acme asks for none. Her first
    /// SAML sign-in owes nothing more; it is recorded with the link it made
    /// to her account.
    #[test]
    fn a_saml_sign_in_without_a_factor_of_ones_own_owes_nothing() {
        let (harness, _) = Harness::active().with_alice(UserStatus::Active);

        let signed_in = harness.sign_in().unwrap();

        assert_eq!(signed_in.second_factor, SecondFactor::NotOwed);
        assert_eq!(
            harness.audit.records.lock().unwrap().clone(),
            vec![
                "authentication.login_succeeded",
                "federation.account_linked"
            ]
        );
    }

    /// A connection requiring encrypted assertions refuses a readable
    /// assertion without opening a session.
    #[test]
    fn a_readable_assertion_is_refused_where_only_sealed_ones_are_taken() {
        let key = SpEncryptionKey::new(
            CertificatePem::new(TEST_IDP_CERTIFICATE).unwrap(),
            SealedSecret::new("sealed-key").unwrap(),
        );
        let sealing = ConnectionConfig::Saml(Box::new(SamlConfig {
            assertion_decryption: AssertionDecryption::Required(key),
            ..test_saml_settings()
        }));
        let base = Harness::active();
        let held = saml_connection_reached_by(
            base.connection_id,
            ConnectionStatus::Active,
            JitProvisioning::Disabled,
            sealing,
        );
        let (harness, _) = Harness {
            connections: Arc::new(FakeConnectionStore::holding(&test_ctx().tenant(), [held])),
            ..base
        }
        .with_alice(UserStatus::Active);

        let result = harness.sign_in();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(harness.sessions.session_count(), 0);
    }
}
