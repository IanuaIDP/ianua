//! OIDC sign-in: the identity provider sends the browser back with an
//! authorization code, which is swapped for who the person is, and the
//! account they sign in to gets a session. The session goes back to the
//! browser as a one-time code, never as its token.

use std::sync::Arc;
use std::time::Instant;

use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::federation::connection::{ConnectionConfig, FederatedIdpConnection};
use ianua_domain::domains::federation::oidc::identity::OidcIdentityClaims;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Setting, TokenHash};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::ports::federation::{
    ConnectionStore, OidcCodeExchange, OidcFlowStore, OidcLoginFlow, OidcValidator,
};
use crate::ports::tenant::TenantStore;
use crate::services::authentication::sign_in_gate::{self, ClientOrigin};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::federation::completion::{
    SignInCompletion, SsoCompletionPorts, VouchedSignIn,
};
use crate::use_cases::authentication::federation::lookup::{
    client_secret_place, existing_active_connection, opened_oidc_config,
};
use crate::use_cases::authentication::federation::single_sign_on::{
    SsoPolicy, SsoSignIn, ensure_same_browser,
};

/// The ports [`OidcLoginUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OidcLoginPorts {
    /// Opens the connection's client secret.
    pub encryptor: Arc<dyn SecretEncryptor>,
    /// The tenant's federation connections.
    pub connection_store: Arc<dyn ConnectionStore>,
    /// Swaps the authorization code and checks the ID token.
    pub oidc_validator: Arc<dyn OidcValidator>,
    /// Pending flows, kept by their `state`.
    pub flow_store: Arc<dyn OidcFlowStore>,
    /// The tenant, whose say on the sign-in comes first.
    pub tenant_store: Arc<dyn TenantStore>,
    /// What finishes the sign-in, the same for OIDC and SAML.
    pub completion: SsoCompletionPorts,
}

/// What the identity provider sends the browser back with.
pub struct OidcLoginRequest {
    /// The `state` the flow was started with.
    pub state: Secret,
    /// The authorization code to swap.
    pub code: Secret,
    /// The secret the browser kept since the flow began.
    pub binding: Secret,
    /// Where the request came from.
    pub origin: ClientOrigin,
}

/// Signs a person in from an OIDC provider's answer.
pub struct OidcLoginUseCase {
    policy: SsoPolicy,
    ports: OidcLoginPorts,
}

impl OidcLoginUseCase {
    /// A use case working through `ports` under `policy`.
    #[must_use]
    pub fn new(policy: SsoPolicy, ports: OidcLoginPorts) -> Self {
        Self { policy, ports }
    }

    /// The connection the callback answers through and the identity it
    /// vouches for.
    async fn vouched_claims(
        &self,
        tenant: &ScopedTenant,
        callback: &OidcLoginRequest,
    ) -> Result<
        (
            FederatedIdpConnection<ResolvedTenant>,
            OidcIdentityClaims,
            TokenHash,
        ),
        AppError,
    > {
        let flow = self.answered_flow(tenant, callback).await?;
        let connection = existing_active_connection(
            self.ports.connection_store.as_ref(),
            tenant,
            &flow.connection_id,
        )
        .await?;
        let claims = self
            .exchanged_claims(tenant, &connection, &flow, &callback.code)
            .await?;
        Ok((connection, claims, flow.dashboard_hash))
    }

    /// Takes the flow the callback's `state` names, refusing one nobody here
    /// started, one already answered, or one brought back by another
    /// browser.
    async fn answered_flow(
        &self,
        tenant: &ScopedTenant,
        callback: &OidcLoginRequest,
    ) -> Result<OidcLoginFlow, AppError> {
        let flow = self
            .ports
            .flow_store
            .consume(tenant, &callback.state)
            .await
            .or_internal()?
            .ok_or_else(|| {
                AppError::Forbidden(message!(
                    "authentication-unknown-or-expired-oidc-state",
                    "unknown or expired OIDC state"
                ))
            })?;
        let hasher = self.ports.completion.session.code_hasher.as_ref();
        ensure_same_browser(hasher, &callback.binding, &flow.binding_hash).await?;
        Ok(flow)
    }

    /// Who the provider says signed in, in exchange for `code`, checked
    /// against the flow's nonce and PKCE verifier, through `tenant`'s
    /// `connection`.
    async fn exchanged_claims(
        &self,
        tenant: &ScopedTenant,
        connection: &FederatedIdpConnection<ResolvedTenant>,
        flow: &OidcLoginFlow,
        code: &Secret,
    ) -> Result<OidcIdentityClaims, AppError> {
        let ConnectionConfig::Oidc(config) = connection.config() else {
            return Err(AppError::Forbidden(message!(
                "authentication-connection-is-not-oidc",
                "connection is not OIDC"
            )));
        };
        let place = client_secret_place(tenant, connection.id());
        let opened = opened_oidc_config(self.ports.encryptor.as_ref(), config, &place).await?;
        let exchange = OidcCodeExchange {
            code,
            nonce: &flow.nonce,
            pkce_verifier: &flow.pkce_verifier,
            redirect_uri: &flow.redirect_uri,
        };
        self.ports
            .oidc_validator
            .exchange_code(&opened, &exchange, &flow.connection_id)
            .await
            .map_err(AppError::from_domain)
    }
}

impl Command for OidcLoginUseCase {
    type Caller = ScopedTenant;
    type Input = OidcLoginRequest;
    type Output = Result<SsoSignIn, AppError>;

    /// Signs in the person an OIDC provider's answer names, and hands their
    /// session back as a one-time code.
    ///
    /// The tenant admits OIDC sign-in from where the request came first.
    /// The flow the `state` names is taken once, and only from the browser
    /// that started it. The provider's code is swapped for an ID token, and
    /// the account is found by its link, linked, or made, as the domain's
    /// admission allows. The session owes what the tenant asks of the
    /// person, counting a factor the provider proved only when the
    /// connection is trusted to report one.
    ///
    /// # Errors
    ///
    /// - `AppError::TenantUnavailable` or `Forbidden` when the tenant rejects OIDC from this origin.
    /// - `AppError::Forbidden` for invalid/spent state, another browser, a disabled/non-OIDC connection, refused admission/account/assurance, or a full plan.
    /// - `AppError::Domain` for failed code exchange or ID-token validation.
    /// - `AppError::NotFound` for a missing connection, tenant or linked account; `Conflict` for a concurrent link.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        callback: OidcLoginRequest,
    ) -> Result<SsoSignIn, AppError> {
        let started = Instant::now();
        let tenants = self.ports.tenant_store.as_ref();
        let client_ip = callback.origin.ip_address.as_ref();
        let (record, _) = sign_in_gate::admit(tenants, tenant, AuthMethod::Oidc, client_ip).await?;
        let (connection, claims, dashboard_hash) = self.vouched_claims(tenant, &callback).await?;
        let identity = claims.vouched();
        let groups = connection.provider_groups(claims.claims());
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
            provider_session: Setting::Unset,
        };
        completion.complete(auditor, vouched).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ianua_domain::domains::authentication::methods::MfaPolicy;
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::authentication::risk_engine::step_up::StepUpPolicy;
    use ianua_domain::domains::branding::email_template::EmailTemplateType;
    use ianua_domain::domains::federation::connection::{
        AssuranceTrust, ConnectionRow, EmailTrust, GroupMapping, GroupRule, GroupRules,
        JitProvisioning, MappedGrant, OidcConfig, ProviderGroupName, ScopeToken,
    };
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::domains::federation::link::{FederatedLink, FederatedLinkRow};
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;
    use ianua_domain::domains::tenant::status::TenantStatus;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::config::DisplayNameLimits;
    use ianua_domain::types::{
        ConnectionId, DomainName, FederatedSubject, HttpsUrl, Label, Lifetime, Nonce, PrincipalRef,
        RoleId, Setting, UserId,
    };

    use super::*;
    use crate::ports::authentication::SignInCodeStore;
    use crate::ports::federation::FederatedLinkStore;
    use crate::ports::limits::LimitEnforcer;
    use crate::test_support::authentication::{
        FakeEncryptor, FakeMfaEnrollmentStore, FakeSessionStore, FakeSignInCodes,
    };
    use crate::test_support::authorization::{
        AccessSources, FakeAccessRecordStore, FakeRoleAssignmentStore, FakeRoleStore, stored_role,
    };
    use crate::test_support::federation::{
        FakeConnectionStore, FakeFederatedLinkStore, FakeOidcFlowStore, FakeOidcValidator,
    };
    use crate::test_support::identity::{FakeUserStore, stored_user};
    use crate::test_support::oauth::{FakeCodeHasher, hash_of};
    use crate::test_support::tenant::{tenant_store_in_status, tenant_store_signing_in_with};
    use crate::test_support::{
        FakeEventDispatcher, FakeLimitEnforcer, FakeMailer, RejectingLimitEnforcer, block_on,
        test_auditor, test_ctx,
    };
    use crate::use_cases::authentication::federation::completion::{
        SsoAccountPorts, SsoFactorPorts, SsoSessionPorts,
    };

    const STATE: &str = "state-from-the-redirect";
    const CLIENT_SECRET: &str = "The provider's client secret +%:&=";
    const EMAIL: &str = "ada@acme.com";
    const BINDING: &str = "the-browsers-secret";
    const SUBJECT: &str = "ada";

    /// How the connection is set up for a test.
    struct Setup {
        status: ConnectionStatus,
        provisioning: JitProvisioning,
        role: Setting<RoleId>,
        assurance: AssuranceTrust,
        groups: GroupMapping,
    }

    impl Setup {
        fn active() -> Self {
            Self {
                status: ConnectionStatus::Active,
                provisioning: JitProvisioning::Disabled,
                role: Setting::Unset,
                assurance: AssuranceTrust::Untrusted,
                groups: GroupMapping::Off,
            }
        }

        fn provisioning() -> Self {
            Self {
                provisioning: JitProvisioning::Enabled,
                ..Self::active()
            }
        }
    }

    fn oidc_connection(id: ConnectionId, setup: &Setup) -> FederatedIdpConnection<ResolvedTenant> {
        let now = clock::now();
        FederatedIdpConnection::reconstitute(ConnectionRow {
            id,
            provider_name: Label::new("name", "Acme OIDC").unwrap(),
            status: setup.status,
            config: ConnectionConfig::Oidc(OidcConfig {
                issuer: HttpsUrl::new("https://idp.acme.com").unwrap(),
                client_id: Label::new("client_id", "client-123").unwrap(),
                encrypted_client_secret: FakeEncryptor::sealed_for(
                    CLIENT_SECRET,
                    &client_secret_place(&test_ctx().tenant(), &id),
                ),
                scopes: vec![ScopeToken::new("openid").unwrap()],
            }),
            jit_provisioning: setup.provisioning,
            jit_default_role_id: setup.role,
            email_trust: EmailTrust::Unverified,
            assurance_trust: setup.assurance,
            domain_hint: Setting::Unset,
            allowed_domains: vec![DomainName::new("acme.com").unwrap()],
            attribute_mapping: HashMap::new(),
            group_mapping: setup.groups.clone(),
            created_at: now,
            keyed_at: now,
        })
        .unwrap()
    }

    fn accepting_oidc(mfa_policy: MfaPolicy) -> Arc<dyn TenantStore> {
        tenant_store_signing_in_with(TenantAuthSettings {
            enabled_methods: vec![AuthMethod::Password, AuthMethod::Oidc],
            mfa_policy,
            ..TenantAuthSettings::default()
        })
    }

    fn policy() -> SsoPolicy {
        SsoPolicy {
            code_lifetime: Lifetime::seconds(60).unwrap(),
            display_names: DisplayNameLimits::default(),
        }
    }

    struct Harness {
        connection_id: ConnectionId,
        flows: Arc<FakeOidcFlowStore>,
        connections: Arc<FakeConnectionStore>,
        validator: Arc<FakeOidcValidator>,
        tenants: Arc<dyn TenantStore>,
        users: Arc<FakeUserStore>,
        links: Arc<FakeFederatedLinkStore>,
        roles: Arc<FakeRoleStore>,
        assignments: Arc<FakeRoleAssignmentStore>,
        access: Arc<FakeAccessRecordStore>,
        enrollments: Arc<FakeMfaEnrollmentStore>,
        sessions: Arc<FakeSessionStore>,
        codes: Arc<FakeSignInCodes>,
        mailer: Arc<FakeMailer>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Harness {
        fn with(setup: &Setup) -> Self {
            let connection_id = ConnectionId::new();
            let tenant = test_ctx().tenant();
            let connections =
                FakeConnectionStore::holding(&tenant, [oidc_connection(connection_id, setup)]);
            let roles = Arc::new(FakeRoleStore::empty());
            let assignments = Arc::new(FakeRoleAssignmentStore::empty());
            let access = Arc::new(FakeAccessRecordStore::reading(AccessSources {
                roles: roles.clone(),
                assignments: assignments.clone(),
                ..AccessSources::default()
            }));
            let harness = Self {
                connection_id,
                flows: Arc::new(FakeOidcFlowStore::new()),
                connections: Arc::new(connections),
                validator: Arc::new(FakeOidcValidator::signing_in(EMAIL)),
                tenants: accepting_oidc(MfaPolicy::Optional),
                users: Arc::new(FakeUserStore::empty()),
                links: Arc::new(FakeFederatedLinkStore::empty()),
                roles,
                assignments,
                access,
                enrollments: Arc::new(FakeMfaEnrollmentStore::empty()),
                sessions: Arc::new(FakeSessionStore::empty()),
                codes: Arc::new(FakeSignInCodes::empty()),
                mailer: Arc::new(FakeMailer::new()),
                audit: Arc::new(FakeEventDispatcher::new()),
            };
            harness.start_flow();
            harness
        }

        fn start_flow(&self) {
            let flow = OidcLoginFlow {
                connection_id: self.connection_id,
                nonce: Nonce::new("nonce-of-sixteen-chars").unwrap(),
                pkce_verifier: Secret::new("verifier"),
                redirect_uri: HttpsUrl::new("https://ianua.example.com/callback").unwrap(),
                dashboard_hash: hash_of("dashboard-state"),
                binding_hash: hash_of(BINDING),
            };
            block_on(
                self.flows
                    .save(&test_ctx().tenant(), &Secret::new(STATE), &flow),
            )
            .unwrap();
        }

        fn with_user(self, status: UserStatus) -> (Self, UserId) {
            let ann = UserId::new();
            self.users.add(stored_user(ann, EMAIL, status));
            (self, ann)
        }

        fn linked(self, user_id: UserId, subject: &str) -> Self {
            let now = clock::now();
            let link = FederatedLink::reconstitute(FederatedLinkRow {
                connection_id: self.connection_id,
                subject: FederatedSubject::new(subject).unwrap(),
                user_id,
                linked_at: now,
                confirmed_at: now,
            })
            .unwrap();
            block_on(self.links.save(&test_ctx().tenant(), &link)).unwrap();
            self
        }

        fn sign_in_from(&self, binding: &str) -> Result<SsoSignIn, AppError> {
            self.sign_in_under(Arc::new(FakeLimitEnforcer), binding)
        }

        fn sign_in(&self) -> Result<SsoSignIn, AppError> {
            self.sign_in_from(BINDING)
        }

        fn sign_in_under(
            &self,
            limit_enforcer: Arc<dyn LimitEnforcer>,
            binding: &str,
        ) -> Result<SsoSignIn, AppError> {
            let use_case = OidcLoginUseCase::new(policy(), self.ports(limit_enforcer));
            block_on(use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.audit.clone()),
                OidcLoginRequest {
                    state: Secret::new(STATE),
                    code: Secret::new("authorization-code"),
                    binding: Secret::new(binding),
                    origin: ClientOrigin::default(),
                },
            ))
        }

        fn ports(&self, limit_enforcer: Arc<dyn LimitEnforcer>) -> OidcLoginPorts {
            OidcLoginPorts {
                encryptor: Arc::new(FakeEncryptor),
                connection_store: self.connections.clone(),
                oidc_validator: self.validator.clone(),
                flow_store: self.flows.clone(),
                tenant_store: self.tenants.clone(),
                completion: SsoCompletionPorts {
                    accounts: SsoAccountPorts {
                        users: self.users.clone(),
                        roles: self.roles.clone(),
                        assignments: self.assignments.clone(),
                        links: self.links.clone(),
                        access: self.access.clone(),
                        limit_enforcer,
                        ..SsoAccountPorts::fakes()
                    },
                    factors: SsoFactorPorts {
                        mfa_enrollments: self.enrollments.clone(),
                        mailer: self.mailer.clone(),
                        ..SsoFactorPorts::fakes()
                    },
                    session: SsoSessionPorts {
                        sessions: self.sessions.clone(),
                        code_hasher: Arc::new(FakeCodeHasher::new()),
                        sign_in_codes: self.codes.clone(),
                        ..SsoSessionPorts::fakes()
                    },
                    ..SsoCompletionPorts::fakes()
                },
            }
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }

        fn mails(&self) -> Vec<EmailTemplateType> {
            self.mailer
                .sent
                .lock()
                .unwrap()
                .iter()
                .map(|sent| sent.template)
                .collect()
        }
    }

    /// Ann, already linked, signs in through Acme's provider. She gets a
    /// session, and the sign-in is recorded.
    #[test]
    fn a_linked_person_signs_in_through_an_active_connection() {
        let (harness, ann) = Harness::with(&Setup::active()).with_user(UserStatus::Active);
        let harness = harness.linked(ann, SUBJECT);

        let signed_in = harness.sign_in().unwrap();

        assert_eq!(signed_in.user_id, ann);
        assert!(!signed_in.jit_provisioned);
        assert_eq!(harness.sessions.session_count(), 1);
        assert_eq!(harness.recorded(), vec!["authentication.login_succeeded"]);
    }

    /// Ann, already linked, signs in. What she holds is read from her own
    /// share of Acme's records; the rest of the tenant's are not read.
    #[test]
    fn a_sign_in_reads_only_the_persons_records() {
        let (harness, ann) = Harness::with(&Setup::active()).with_user(UserStatus::Active);
        let harness = harness.linked(ann, SUBJECT);

        harness.sign_in().unwrap();

        assert_eq!(harness.access.whole_reads(), 0);
    }

    /// Ann's session goes back to her browser as a one-time code, which
    /// stands in for the session just opened.
    #[test]
    fn the_session_goes_back_as_a_one_time_code_for_it() {
        let (harness, ann) = Harness::with(&Setup::active()).with_user(UserStatus::Active);
        let harness = harness.linked(ann, SUBJECT);

        let signed_in = harness.sign_in().unwrap();

        let code = block_on(
            harness
                .codes
                .take(&test_ctx().tenant(), &hash_of(signed_in.code.expose())),
        )
        .unwrap()
        .unwrap();
        let session = harness.sessions.get_session(code.session_id()).unwrap();
        assert_eq!(session.user_id(), &ann);
        assert_eq!(session.auth_method(), AuthMethod::Oidc);
    }

    /// An OIDC answer carrying another browser's binding is refused without opening a session.
    #[test]
    fn an_answer_brought_back_by_another_browser_opens_no_session() {
        let (harness, ann) = Harness::with(&Setup::active()).with_user(UserStatus::Active);
        let harness = harness.linked(ann, SUBJECT);

        let result = harness.sign_in_from("another-browser");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(harness.sessions.session_count(), 0);
    }

    /// Reusing consumed OIDC state is refused and leaves only the original session.
    #[test]
    fn a_replayed_state_is_refused() {
        let (harness, ann) = Harness::with(&Setup::active()).with_user(UserStatus::Active);
        let harness = harness.linked(ann, SUBJECT);
        harness.sign_in().unwrap();

        let replayed = harness.sign_in();

        assert!(matches!(replayed, Err(AppError::Forbidden(_))));
        assert_eq!(harness.sessions.session_count(), 1);
    }

    /// A tenant with OIDC disabled refuses the callback before completing sign-in.
    #[test]
    fn single_sign_on_is_refused_when_the_tenant_has_oidc_off() {
        let harness = Harness {
            tenants: tenant_store_signing_in_with(TenantAuthSettings::default()),
            ..Harness::with(&Setup::active())
        };

        let result = harness.sign_in();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A suspended tenant returns unavailable for an OIDC callback.
    #[test]
    fn single_sign_on_is_refused_while_the_tenant_is_suspended() {
        let harness = Harness {
            tenants: tenant_store_in_status(TenantStatus::Suspended),
            ..Harness::with(&Setup::active())
        };

        let result = harness.sign_in();

        assert!(matches!(result, Err(AppError::TenantUnavailable(_))));
    }

    /// A disabled connection refuses OIDC sign-in for its linked active user.
    #[test]
    fn a_disabled_connection_cannot_be_used_to_sign_in() {
        let setup = Setup {
            status: ConnectionStatus::Disabled,
            ..Setup::active()
        };
        let (harness, ann) = Harness::with(&setup).with_user(UserStatus::Active);
        let harness = harness.linked(ann, SUBJECT);

        let result = harness.sign_in();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Ann has no account and the connection makes none. She is refused.
    #[test]
    fn an_unknown_person_is_refused_when_provisioning_is_off() {
        let harness = Harness::with(&Setup::active());

        let result = harness.sign_in();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(harness.users.count(), 0);
    }

    /// Ann has no account and the connection makes them. Hers is made
    /// active, linked to her, and recorded as made by the provider.
    #[test]
    fn an_unknown_person_is_given_an_active_account_when_provisioning_is_on() {
        let harness = Harness::with(&Setup::provisioning());

        let signed_in = harness.sign_in().unwrap();

        assert!(signed_in.jit_provisioned);
        assert_eq!(
            harness.users.get_status(&signed_in.user_id),
            Some(UserStatus::Active)
        );
        assert_eq!(harness.links.count(), 1);
        assert_eq!(
            harness.recorded(),
            vec![
                "authentication.login_succeeded",
                "federation.jit_user_provisioned"
            ]
        );
    }

    /// A full user plan refuses first sign-in without creating an account or session.
    #[test]
    fn a_first_sign_in_past_the_user_limit_is_refused() {
        let harness = Harness::with(&Setup::provisioning());

        let result = harness.sign_in_under(Arc::new(RejectingLimitEnforcer), BINDING);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(harness.users.count(), 0);
        assert_eq!(harness.sessions.session_count(), 0);
    }

    /// Ann's account is made on her first sign-in through a connection that
    /// gives new accounts a role. She starts with it.
    #[test]
    fn a_made_account_starts_with_the_connections_role() {
        let role = stored_role("member", Vec::new(), Vec::new());
        let role_id = *role.id();
        let setup = Setup {
            role: Setting::Set(role_id),
            ..Setup::provisioning()
        };
        let harness = Harness::with(&setup);
        harness.roles.add(test_ctx().tenant_id(), [role]);

        let signed_in = harness.sign_in().unwrap();

        assert_eq!(
            harness
                .assignments
                .holders_of(test_ctx().tenant_id(), &role_id),
            vec![PrincipalRef::User(signed_in.user_id)]
        );
    }

    /// Acme's provider lists Ann's groups in its `groups` claim, and the
    /// connection maps `engineering` to the Engineer role. Her sign-in gives
    /// it to her, and the record says so.
    #[test]
    fn the_groups_claim_brings_the_role_its_group_maps_to() {
        let engineer = stored_role("engineer", Vec::new(), Vec::new());
        let rules = engineering_group(*engineer.id());
        let setup = Setup {
            groups: GroupMapping::On(rules),
            ..Setup::active()
        };
        let (harness, ann) = Harness::with(&setup).with_user(UserStatus::Active);
        let harness = Harness {
            validator: Arc::new(
                FakeOidcValidator::signing_in(EMAIL).with_claim("groups", &["engineering", "ops"]),
            ),
            ..harness.linked(ann, SUBJECT)
        };
        harness
            .roles
            .add(test_ctx().tenant_id(), [engineer.clone()]);

        harness.sign_in().unwrap();

        assert_eq!(
            harness
                .assignments
                .holders_of(test_ctx().tenant_id(), engineer.id()),
            vec![PrincipalRef::User(ann)]
        );
        assert!(
            harness
                .recorded()
                .contains(&"authorization.role_assigned".to_owned())
        );
    }

    /// The provider's engineering group grants the designated tenant role.
    fn engineering_group(role: RoleId) -> GroupRules {
        GroupRules::new(
            Label::new("claim", "groups").unwrap(),
            vec![GroupRule {
                provider_group: ProviderGroupName::new("engineering").unwrap(),
                grant: MappedGrant::Role(role),
            }],
        )
        .unwrap()
    }

    /// Ann's locked account is refused through its linked provider and gets no session.
    #[test]
    fn a_locked_person_cannot_sign_in_through_a_connection() {
        let (harness, ann) = Harness::with(&Setup::active()).with_user(UserStatus::Locked);
        let harness = harness.linked(ann, SUBJECT);

        let result = harness.sign_in();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(harness.sessions.session_count(), 0);
    }

    /// Ann's deactivated account is refused even when its linked provider vouches for her.
    #[test]
    fn a_deactivated_person_cannot_sign_in_through_a_connection() {
        let (harness, ann) = Harness::with(&Setup::active()).with_user(UserStatus::Deactivated);
        let harness = harness.linked(ann, SUBJECT);

        let result = harness.sign_in();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// The provider is sent the client secret opened, never the sealed form
    /// the connection keeps.
    #[test]
    fn the_identity_provider_is_sent_the_opened_client_secret() {
        let (harness, ann) = Harness::with(&Setup::active()).with_user(UserStatus::Active);
        let harness = harness.linked(ann, SUBJECT);

        harness.sign_in().unwrap();

        let seen = harness.validator.secrets_seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].expose(), CLIENT_SECRET);
    }

    /// Ann has an account with her address, which she confirmed, and signs
    /// in through the provider the first time. Her account is linked to her
    /// there, and she is told by mail.
    #[test]
    fn a_first_sign_in_links_the_account_with_the_address_and_tells_its_owner() {
        let (harness, ann) = Harness::with(&Setup::active()).with_user(UserStatus::Active);

        let signed_in = harness.sign_in().unwrap();

        assert_eq!(signed_in.user_id, ann);
        assert_eq!(harness.links.count(), 1);
        assert_eq!(harness.mails(), vec![EmailTemplateType::AccountLinked]);
        assert!(
            harness
                .recorded()
                .contains(&"federation.account_linked".to_owned())
        );
    }

    /// Acme asks every session for a second factor's strength, which this
    /// provider's word alone does not reach.
    fn asking_for_strength(harness: Harness) -> Harness {
        Harness {
            tenants: tenant_store_signing_in_with(TenantAuthSettings {
                enabled_methods: vec![AuthMethod::Password, AuthMethod::Oidc],
                mfa_policy: MfaPolicy::Disabled,
                step_up_policy: StepUpPolicy::strict(),
                ..TenantAuthSettings::default()
            }),
            ..harness
        }
    }

    /// Insufficient assurance refuses a first sign-in without opening a
    /// session, while still recording the account provisioning event.
    #[test]
    fn a_first_sign_in_refused_for_its_strength_records_the_account_it_made() {
        let harness = asking_for_strength(Harness::with(&Setup::provisioning()));

        let result = harness.sign_in();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(harness.sessions.session_count(), 0);
        assert_eq!(harness.recorded(), vec!["federation.jit_user_provisioned"]);
    }

    /// Insufficient assurance opens no session after first linking an
    /// account, but the link event and notification mail are still emitted.
    #[test]
    fn a_first_sign_in_refused_for_its_strength_still_tells_of_the_link() {
        let (harness, _) = Harness::with(&Setup::active()).with_user(UserStatus::Active);
        let harness = asking_for_strength(harness);

        let result = harness.sign_in();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(harness.sessions.session_count(), 0);
        assert_eq!(harness.recorded(), vec!["federation.account_linked"]);
        assert_eq!(harness.mails(), vec![EmailTemplateType::AccountLinked]);
    }

    /// Ann, linked already, signs in again. No new link is made and no mail
    /// goes out.
    #[test]
    fn a_linked_subject_returns_to_its_account_without_a_new_link_or_mail() {
        let (harness, ann) = Harness::with(&Setup::active()).with_user(UserStatus::Active);
        let harness = harness.linked(ann, SUBJECT);

        harness.sign_in().unwrap();

        assert_eq!(harness.links.count(), 1);
        assert!(harness.mails().is_empty());
    }

    /// An address outside the connection's allowed domains is refused without provisioning a user.
    #[test]
    fn a_provider_cannot_sign_in_an_address_outside_its_bound_domains() {
        let harness = Harness {
            validator: Arc::new(FakeOidcValidator::signing_in("mallory@evil.test")),
            ..Harness::with(&Setup::provisioning())
        };

        let result = harness.sign_in();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(harness.users.count(), 0);
    }

    /// A provider subject cannot use an address linked to another subject
    /// to open a session for that account.
    #[test]
    fn an_account_linked_to_someone_else_at_the_provider_is_not_taken_over() {
        let (harness, ann) = Harness::with(&Setup::active()).with_user(UserStatus::Active);
        let harness = harness.linked(ann, "ann-at-the-provider");

        let result = harness.sign_in();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(harness.sessions.session_count(), 0);
    }

    /// A provider's explicitly unverified address is refused without creating an account link.
    #[test]
    fn an_address_the_provider_calls_unverified_is_refused() {
        let (harness, _) = Harness::with(&Setup::active()).with_user(UserStatus::Active);
        let harness = Harness {
            validator: Arc::new(FakeOidcValidator::signing_in(EMAIL).with_unverified_email()),
            ..harness
        };

        let result = harness.sign_in();

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(harness.links.count(), 0);
    }

    /// Ann set up an authenticator app here and signs in at the provider
    /// with a password alone. Her session still owes her own factor.
    #[test]
    fn someone_with_a_factor_of_their_own_still_owes_it_after_a_password_at_the_provider() {
        let (harness, ann) = Harness::with(&Setup::active()).with_user(UserStatus::Active);
        let harness = Harness {
            enrollments: Arc::new(FakeMfaEnrollmentStore::active_for(ann)),
            ..harness.linked(ann, SUBJECT)
        };

        let signed_in = harness.sign_in().unwrap();

        assert_eq!(signed_in.second_factor, SecondFactor::Verify);
    }

    /// An untrusted provider's MFA claim does not satisfy Ann's own factor;
    /// her session still owes verification.
    #[test]
    fn an_untrusted_provider_claiming_a_second_factor_still_owes_the_own_one() {
        let (harness, ann) = Harness::with(&Setup::active()).with_user(UserStatus::Active);
        let harness = Harness {
            validator: Arc::new(FakeOidcValidator::signing_in(EMAIL).after_mfa()),
            enrollments: Arc::new(FakeMfaEnrollmentStore::active_for(ann)),
            ..harness.linked(ann, SUBJECT)
        };

        let signed_in = harness.sign_in().unwrap();

        assert_eq!(signed_in.second_factor, SecondFactor::Verify);
    }

    /// Ann signs in with a second factor at a provider Acme trusts to report
    /// one. Nothing more is owed.
    #[test]
    fn a_multi_factor_sign_in_at_a_trusted_provider_owes_nothing_more() {
        let setup = Setup {
            assurance: AssuranceTrust::Trusted,
            ..Setup::active()
        };
        let (harness, ann) = Harness::with(&setup).with_user(UserStatus::Active);
        let harness = Harness {
            validator: Arc::new(FakeOidcValidator::signing_in(EMAIL).after_mfa()),
            enrollments: Arc::new(FakeMfaEnrollmentStore::active_for(ann)),
            ..harness.linked(ann, SUBJECT)
        };

        let signed_in = harness.sign_in().unwrap();

        assert_eq!(signed_in.second_factor, SecondFactor::NotOwed);
    }
}
