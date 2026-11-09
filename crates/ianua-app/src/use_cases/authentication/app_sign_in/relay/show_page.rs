//! Showing the page a person fills in at an app's sign-in address.

use std::sync::Arc;

use ianua_domain::domains::federation::connection::FederatedIdpConnection;
use ianua_domain::domains::routing::sign_in::app::SignInAction;
use ianua_domain::domains::routing::sign_in::return_path::ReturnPath;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::secret::Secret;

use crate::error::{AppError, OrInternal};
use crate::listing::{Limit, PageRequest, SortOrder};
use crate::use_case::Query;
use crate::use_cases::authentication::app_sign_in::relay::common::AppSignInCommon;
use crate::use_cases::authentication::app_sign_in::relay::page::{Dressing, PageAsk, page};
use crate::use_cases::authentication::app_sign_in::relay::target::resolve;
use crate::use_cases::authentication::app_sign_in::{
    AppSignInContext, AppSignInOutcome, SignInNote,
};

/// The most outside identity providers a login page offers.
const MOST_PROVIDERS_OFFERED: u32 = 20;

/// Which page to show, and what to show on it. Holds the token of a mailed
/// link, so it has no `Debug`.
pub struct AppSignInPageRequest {
    /// Which page.
    pub action: SignInAction,
    /// A note to show above the form.
    pub note: Option<SignInNote>,
    /// Where to send the person once they are in.
    pub return_to: Option<ReturnPath>,
    /// The token of the mailed link the reset or change page was opened
    /// from.
    pub link_token: Option<Secret>,
}

/// Renders an app's sign-in page in the workspace's branding.
pub struct PageUseCase {
    common: Arc<AppSignInCommon>,
}

impl PageUseCase {
    /// A use case reading through the shared app sign-in parts.
    pub(in crate::use_cases::authentication::app_sign_in) fn new(
        common: Arc<AppSignInCommon>,
    ) -> Self {
        Self { common }
    }

    /// The workspace's branding, and on the login page its outside
    /// identity providers.
    async fn dressing(
        &self,
        ctx: &AppSignInContext,
        action: SignInAction,
    ) -> Result<Dressing, AppError> {
        let ports = &self.common.ports;
        let branding = ports.branding_store.find(&ctx.tenant).await.or_internal()?;
        let connections = match action {
            SignInAction::LogIn => self.connections(ctx).await?,
            _ => Vec::new(),
        };
        Ok(Dressing {
            branding,
            connections,
        })
    }

    /// The workspace's outside identity providers, up to the most a page
    /// offers.
    async fn connections(
        &self,
        ctx: &AppSignInContext,
    ) -> Result<Vec<FederatedIdpConnection<ResolvedTenant>>, AppError> {
        let page = PageRequest::first(Limit::internal(MOST_PROVIDERS_OFFERED));
        let connections = self
            .common
            .ports
            .connection_store
            .list_all(&ctx.tenant, None, &SortOrder::default(), &page)
            .await
            .or_internal()?;
        Ok(connections.items)
    }
}

impl Query for PageUseCase {
    type Caller = AppSignInContext;
    type Input = AppSignInPageRequest;
    type Output = Result<AppSignInOutcome, AppError>;

    /// The page for `request.action`, wearing the workspace's branding.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the app has no sign-in here, or the page is
    ///   for an action the app does not offer.
    /// - `AppError::Forbidden` for the sign-up page of a workspace that takes
    ///   no sign-ups.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        ctx: &AppSignInContext,
        request: AppSignInPageRequest,
    ) -> Result<AppSignInOutcome, AppError> {
        let ports = &self.common.ports;
        let target = resolve(&ports.target, &ctx.tenant, &ctx.service_id, &ctx.host).await?;
        let AppSignInPageRequest {
            action,
            note,
            return_to,
            link_token,
        } = request;
        let dressing = self.dressing(ctx, action).await?;
        let ask = PageAsk {
            action,
            note,
            return_to,
            link_token,
        };
        let shown = page(&target, dressing, ask)?;
        Ok(AppSignInOutcome::Page(Box::new(shown)))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;
    use ianua_domain::types::{ConnectionId, HttpsUrl, ServiceId};

    use super::*;
    use crate::test_support::authentication::{
        SHOP_HOST, app_sign_in_lifetimes, app_sign_in_services, app_sign_in_target_ports,
        cross_host_ctx, shop_with_app_sign_in,
    };
    use crate::test_support::federation::{FakeConnectionStore, test_connection};
    use crate::test_support::tenant::tenant_store_signing_in_with;
    use crate::test_support::{block_on, test_ctx};
    use crate::use_cases::authentication::app_sign_in::{SignInPorts, TargetPorts};

    fn show(
        service_of: impl FnOnce(ServiceId) -> ServiceId,
        action: SignInAction,
    ) -> Result<AppSignInOutcome, AppError> {
        let shop = shop_with_app_sign_in();
        let shown_for = service_of(*shop.id());
        let ports = SignInPorts {
            target: app_sign_in_target_ports(app_sign_in_services([shop])),
            ..SignInPorts::fakes()
        };
        let use_case = page_use_case(ports);
        let request = page_request(action);
        block_on(use_case.execute(&cross_host_ctx(shown_for, SHOP_HOST), request))
    }

    /// Acme signs people in with passwords and through Okta over SAML, and
    /// has a second connection turned off. Ann opens the shop's login page:
    /// it offers Okta, and only Okta.
    #[test]
    fn the_login_page_offers_the_workspaces_providers() {
        let shop = shop_with_app_sign_in();
        let shop_id = *shop.id();
        let okta = ConnectionId::new();
        let connections = provider_connections(okta);
        let ports = SignInPorts {
            target: TargetPorts {
                tenant_store: tenant_store_signing_in_with(TenantAuthSettings {
                    enabled_methods: vec![AuthMethod::Password, AuthMethod::Saml],
                    ..TenantAuthSettings::default()
                }),
                ..app_sign_in_target_ports(app_sign_in_services([shop]))
            },
            connection_store: Arc::new(connections),
            ..SignInPorts::fakes()
        };
        let use_case = page_use_case(ports);
        let request = page_request(SignInAction::LogIn);

        let shown = block_on(use_case.execute(&cross_host_ctx(shop_id, SHOP_HOST), request));

        let Ok(AppSignInOutcome::Page(login)) = shown else {
            panic!("the login page is shown");
        };
        let offered: Vec<ConnectionId> = login
            .single_sign_on
            .iter()
            .map(|choice| choice.connection_id)
            .collect();
        assert_eq!(offered, [okta]);
        assert!(login.passkey_path.is_none());
    }

    /// Builds the page renderer with the fixture's sign-in stores and URL.
    fn page_use_case(ports: SignInPorts) -> PageUseCase {
        let base = HttpsUrl::new("https://ianua.example.com").unwrap();
        PageUseCase::new(Arc::new(AppSignInCommon::new(
            ports,
            base,
            app_sign_in_lifetimes(),
        )))
    }

    /// Opens an action's page without a note, return path or mailed token.
    fn page_request(action: SignInAction) -> AppSignInPageRequest {
        AppSignInPageRequest {
            action,
            note: None,
            return_to: None,
            link_token: None,
        }
    }

    /// The tenant has active Okta and a second disabled provider connection.
    fn provider_connections(okta: ConnectionId) -> FakeConnectionStore {
        FakeConnectionStore::holding(
            &test_ctx().tenant(),
            [
                test_connection(okta, ConnectionStatus::Active),
                test_connection(ConnectionId::new(), ConnectionStatus::Disabled),
            ],
        )
    }

    /// Ann opens the shop's login page. It is shown.
    #[test]
    fn the_login_page_is_shown() {
        let shown = show(|shop| shop, SignInAction::LogIn);

        assert!(matches!(shown, Ok(AppSignInOutcome::Page(_))));
    }

    /// A workspace with sign-ups closed refuses its sign-up page.
    #[test]
    fn the_sign_up_page_of_a_closed_workspace_is_refused() {
        let shown = show(|shop| shop, SignInAction::SignUp);

        assert!(matches!(shown, Err(AppError::Forbidden(_))));
    }

    /// Asking for an unknown service's login page on the shop's host returns
    /// not found.
    #[test]
    fn a_service_without_sign_in_here_shows_nothing() {
        let shown = show(|_| ServiceId::new(), SignInAction::LogIn);

        assert!(matches!(shown, Err(AppError::NotFound(_))));
    }
}
