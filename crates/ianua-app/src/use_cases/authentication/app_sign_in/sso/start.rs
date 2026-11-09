//! Starting single sign-on at an app's address: the browser is sent to one
//! of the tenant's outside identity providers, which sends it back to the
//! app's own return address.

use std::sync::Arc;

use ianua_domain::domains::routing::sign_in::return_path::ReturnPath;
use ianua_domain::types::ConnectionId;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::use_case::Command;
use crate::use_cases::authentication::app_sign_in::relay::common::AppSignInCommon;
use crate::use_cases::authentication::app_sign_in::{AppSignInContext, AppSignInOutcome};
use crate::use_cases::authentication::federation::{
    BeginSingleSignOnRequest, BeginSingleSignOnUseCase,
};

/// Which provider to sign in through, and where to land afterwards.
pub struct AppSsoStartRequest {
    /// The connection the person picked.
    pub connection_id: ConnectionId,
    /// Where to send them once they are in, if they came from somewhere.
    pub return_to: Option<ReturnPath>,
}

/// Sends the browser from an app's address to an outside identity provider.
pub struct AppSsoStartUseCase {
    common: Arc<AppSignInCommon>,
    begin: Arc<BeginSingleSignOnUseCase>,
}

impl AppSsoStartUseCase {
    /// A use case starting sign-ins through the dashboard's own `begin`.
    pub(in crate::use_cases::authentication::app_sign_in) fn new(
        common: Arc<AppSignInCommon>,
        begin: Arc<BeginSingleSignOnUseCase>,
    ) -> Self {
        Self { common, begin }
    }
}

impl Command for AppSsoStartUseCase {
    type Caller = AppSignInContext;
    type Input = AppSsoStartRequest;
    type Output = Result<AppSignInOutcome, AppError>;

    /// Starts the sign-in through the dashboard's own single sign-on, with
    /// the provider sending its answer to the app host's return address.
    /// Hands back where to send the browser and two secrets for the host's
    /// cookie: the one the answer is accepted only with, and the one the
    /// session is then handed back against. Both are made here and never
    /// stored, only their hashes.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the app has no sign-in here, or the tenant
    ///   has no such connection.
    /// - `AppError::Forbidden` or `AppError::TenantUnavailable` if the
    ///   connection is turned off, or the tenant does not take its protocol
    ///   from where the request came.
    /// - `AppError::Internal` on discovery, encoding or persistence failure.
    async fn execute(
        &self,
        ctx: &AppSignInContext,
        auditor: &RequestAuditor,
        request: AppSsoStartRequest,
    ) -> Result<AppSignInOutcome, AppError> {
        let (target, auditor) = self.common.resolved(ctx, auditor).await?;
        let (hand_back, _) = self
            .common
            .ports
            .code_hasher
            .generate_code()
            .await
            .or_internal()?;
        let begin = BeginSingleSignOnRequest {
            connection_id: request.connection_id,
            returns_to: self.common.sso_return(&target)?,
            origin: ctx.origin(),
            dashboard_state: hand_back.clone(),
        };
        let started = self.begin.execute(&ctx.tenant, &auditor, begin).await?;
        Ok(AppSignInOutcome::SsoRedirect {
            url: started.url,
            binding: started.binding,
            hand_back,
            return_to: request.return_to,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::federation::connection::{
        AssuranceTrust, ConnectionConfig, ConnectionRow, EmailTrust, FederatedIdpConnection,
        GroupMapping, JitProvisioning, OidcConfig, ScopeToken,
    };
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{HttpsUrl, Label, ServiceId, Setting};

    use super::*;
    use crate::ports::federation::OidcFlowStore;
    use crate::test_support::authentication::{
        FakeEncryptor, SHOP_HOST, app_sign_in_lifetimes, app_sign_in_services,
        app_sign_in_target_ports, cross_host_ctx, shop_with_app_sign_in,
    };
    use crate::test_support::federation::{
        FakeConnectionStore, FakeOidcFlowStore, FakeOidcValidator, OIDC_STATE,
    };
    use crate::test_support::oauth::{FakeCodeHasher, hash_of};
    use crate::test_support::tenant::tenant_store_signing_in_with;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::authentication::app_sign_in::SignInPorts;
    use crate::use_cases::authentication::federation::BeginSingleSignOnPorts;
    use crate::use_cases::authentication::federation::lookup::client_secret_place;

    /// The shop, Acme's OIDC provider, and the flows kept.
    struct Fixture {
        use_case: AppSsoStartUseCase,
        shop: ServiceId,
        okta: ConnectionId,
        flows: Arc<FakeOidcFlowStore>,
    }

    /// Acme's Okta over OIDC, in `status`.
    fn okta(id: ConnectionId, status: ConnectionStatus) -> FederatedIdpConnection<ResolvedTenant> {
        let now = clock::now();
        FederatedIdpConnection::reconstitute(ConnectionRow {
            id,
            provider_name: Label::new("name", "Okta").unwrap(),
            status,
            config: ConnectionConfig::Oidc(OidcConfig {
                issuer: HttpsUrl::new("https://idp.acme.com").unwrap(),
                client_id: Label::new("client_id", "client-123").unwrap(),
                encrypted_client_secret: FakeEncryptor::sealed_for(
                    "client-secret",
                    &client_secret_place(&test_ctx().tenant(), &id),
                ),
                scopes: vec![ScopeToken::new("openid").unwrap()],
            }),
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

    /// The shop signing people in on [`SHOP_HOST`], over a workspace taking
    /// OIDC sign-in through Okta in `status`.
    fn fixture(status: ConnectionStatus) -> Fixture {
        let shop = shop_with_app_sign_in();
        let shop_id = *shop.id();
        let okta_id = ConnectionId::new();
        let flows = Arc::new(FakeOidcFlowStore::new());
        let hasher = Arc::new(FakeCodeHasher::new());
        let begin = begin_sign_in(okta(okta_id, status), &flows, &hasher);
        let ports = SignInPorts {
            target: app_sign_in_target_ports(app_sign_in_services([shop])),
            code_hasher: hasher,
            ..SignInPorts::fakes()
        };
        let base = HttpsUrl::new("https://ianua.example.com").unwrap();
        let common = AppSignInCommon::new(ports, base, app_sign_in_lifetimes());
        Fixture {
            use_case: AppSsoStartUseCase::new(Arc::new(common), Arc::new(begin)),
            shop: shop_id,
            okta: okta_id,
            flows,
        }
    }

    /// Begins OIDC sign-in through the stored connection and shared flow secrets.
    fn begin_sign_in(
        connection: FederatedIdpConnection<ResolvedTenant>,
        flows: &Arc<FakeOidcFlowStore>,
        hasher: &Arc<FakeCodeHasher>,
    ) -> BeginSingleSignOnUseCase {
        BeginSingleSignOnUseCase::new(BeginSingleSignOnPorts {
            encryptor: Arc::new(FakeEncryptor),
            connection_store: Arc::new(FakeConnectionStore::holding(
                &test_ctx().tenant(),
                [connection],
            )),
            oidc_validator: Arc::new(FakeOidcValidator::signing_in("ann@acme.test")),
            flow_store: flows.clone(),
            code_hasher: hasher.clone(),
            tenant_store: tenant_store_signing_in_with(TenantAuthSettings {
                enabled_methods: vec![AuthMethod::Password, AuthMethod::Oidc],
                ..TenantAuthSettings::default()
            }),
            ..BeginSingleSignOnPorts::fakes()
        })
    }

    /// A start through `connection_id` at `service`'s sign-in on the shop's
    /// host.
    fn start(
        f: &Fixture,
        service: ServiceId,
        connection_id: ConnectionId,
    ) -> Result<AppSignInOutcome, AppError> {
        let request = AppSsoStartRequest {
            connection_id,
            return_to: Some(ReturnPath::new("/orders").unwrap()),
        };
        block_on(f.use_case.execute(
            &cross_host_ctx(service, SHOP_HOST),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            request,
        ))
    }

    /// Ann picks Okta on the shop's login page. Her browser is sent to Okta,
    /// which is told to send her back to the shop's own return address, and
    /// the flow is bound to both secrets her browser keeps.
    #[test]
    fn the_provider_is_told_to_answer_on_the_apps_host() {
        let f = fixture(ConnectionStatus::Active);

        let outcome = start(&f, f.shop, f.okta).unwrap();

        let AppSignInOutcome::SsoRedirect {
            binding,
            hand_back,
            return_to,
            ..
        } = outcome
        else {
            panic!("Ann is sent to Okta");
        };
        let state = Secret::new(OIDC_STATE);
        let flow = block_on(f.flows.consume(&test_ctx().tenant(), &state))
            .unwrap()
            .unwrap();
        assert_eq!(
            flow.redirect_uri.as_str(),
            "https://shop.example.com/.ianua/sso-callback"
        );
        assert_eq!(flow.binding_hash, hash_of(binding.expose()));
        assert_eq!(flow.dashboard_hash, hash_of(hand_back.expose()));
        assert_eq!(return_to.unwrap().as_str(), "/orders");
    }

    /// Starting sign-in through a disabled connection is refused and stores
    /// no flow.
    #[test]
    fn a_disabled_connection_is_refused() {
        let f = fixture(ConnectionStatus::Disabled);

        let outcome = start(&f, f.shop, f.okta);

        assert!(matches!(outcome, Err(AppError::Forbidden(_))));
        assert_eq!(f.flows.count(), 0);
    }

    /// Starting sign-in through an unknown connection returns not found and
    /// stores no flow.
    #[test]
    fn an_unknown_connection_is_not_found() {
        let f = fixture(ConnectionStatus::Active);

        let outcome = start(&f, f.shop, ConnectionId::new());

        assert!(matches!(outcome, Err(AppError::NotFound(_))));
        assert_eq!(f.flows.count(), 0);
    }

    /// Starting sign-in for an unknown service returns not found and stores
    /// no provider flow.
    #[test]
    fn a_service_without_app_sign_in_here_is_not_found() {
        let f = fixture(ConnectionStatus::Active);

        let outcome = start(&f, ServiceId::new(), f.okta);

        assert!(matches!(outcome, Err(AppError::NotFound(_))));
        assert_eq!(f.flows.count(), 0);
    }
}
