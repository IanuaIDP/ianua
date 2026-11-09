//! What a tenant's sign-in page offers besides a password.
//!
//! Asked before anyone is signed in, so it says no more than the page needs:
//! whether magic links and passkeys are on, and for each identity provider
//! its ID, name and protocol. A disabled connection, or one whose protocol
//! the tenant has switched off, is not offered, and neither are magic links
//! on a deployment with no mail server.

use std::sync::Arc;

use ianua_domain::domains::authentication::methods::AuthMethod;
use ianua_domain::domains::authentication::sessions::sign_in_progress::FederatedMethod;
use ianua_domain::domains::federation::connection::{FederatedIdpConnection, FederationProtocol};
use ianua_domain::domains::federation::connection_status::ConnectionStatus;
use ianua_domain::domains::tenant::access::auth_config::TenantAuthConfig;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::ConnectionId;

use crate::error::{AppError, OrInternal};
use crate::listing::{Limit, PageRequest, Sort, SortOrder};
use crate::ports::federation::{ConnectionSortField, ConnectionStore};
use crate::ports::shared::MailSetup;
use crate::ports::tenant::TenantStore;
use crate::services::authentication::channels::mail_reaches;
use crate::services::lookup::existing_tenant;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;

/// The most identity providers a sign-in page offers.
const MOST_OFFERED: u32 = 50;

/// What a tenant's sign-in page offers.
pub struct SignInOptions {
    /// Whether "email me a sign-in link" is offered.
    pub magic_link: bool,
    /// Whether "continue with a passkey" is offered.
    pub passkey: bool,
    /// The identity providers offered as "Sign in with ..." buttons.
    pub connections: Vec<SignInConnection>,
}

/// One identity provider a sign-in page offers.
pub struct SignInConnection {
    /// The connection to begin single sign-on with.
    pub id: ConnectionId,
    /// The name shown on the button.
    pub name: String,
    /// The protocol it signs in with.
    pub protocol: FederationProtocol,
}

/// The ports [`SignInOptionsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct SignInOptionsPorts {
    /// The tenant's identity provider connections.
    pub connection_store: Arc<dyn ConnectionStore>,
    /// Tenants, for the ways in each accepts.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Whether anything can be mailed here, before magic links are offered.
    pub mail: Arc<dyn MailSetup>,
}

/// Lists what a tenant's sign-in page offers.
pub struct SignInOptionsUseCase {
    ports: SignInOptionsPorts,
}

impl SignInOptionsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: SignInOptionsPorts) -> Self {
        Self { ports }
    }

    /// The tenant's enabled connections, by provider name, up to as many as
    /// a sign-in page offers.
    async fn active_connections(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<FederatedIdpConnection<ResolvedTenant>>, AppError> {
        let connections = self
            .ports
            .connection_store
            .list_all(
                tenant_id,
                Some(ConnectionStatus::Active),
                &SortOrder::single(Sort::ascending(ConnectionSortField::ProviderName)),
                &PageRequest::first(Limit::internal(MOST_OFFERED)),
            )
            .await
            .or_internal()?
            .items;
        Ok(connections)
    }
}

impl Query for SignInOptionsUseCase {
    type Caller = ScopedTenant;
    type Input = ();
    type Output = Result<SignInOptions, AppError>;

    /// The ways in the tenant has switched on, and its active connections
    /// whose protocol it accepts, by name.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the tenant does not exist.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(&self, tenant_id: &ScopedTenant, (): ()) -> Result<SignInOptions, AppError> {
        let tenant = existing_tenant(self.ports.tenant_store.as_ref(), tenant_id).await?;
        let config = tenant.auth_config();
        let connections = self.active_connections(tenant_id).await?;
        Ok(SignInOptions {
            magic_link: config.is_method_enabled(AuthMethod::MagicLink)
                && mail_reaches(self.ports.mail.as_ref()),
            passkey: config.is_method_enabled(AuthMethod::Passkey),
            connections: connections
                .iter()
                .filter(|connection| accepted(config, connection))
                .map(offered)
                .collect(),
        })
    }
}

/// Whether the tenant accepts sign-in through `connection`'s protocol.
fn accepted(
    config: &TenantAuthConfig,
    connection: &FederatedIdpConnection<ResolvedTenant>,
) -> bool {
    let method = AuthMethod::from(FederatedMethod::from(connection.protocol()));
    config.is_method_enabled(method)
}

/// The button a sign-in page shows for `connection`.
fn offered(connection: &FederatedIdpConnection<ResolvedTenant>) -> SignInConnection {
    SignInConnection {
        id: *connection.id(),
        name: connection.provider_name().as_str().to_owned(),
        protocol: connection.protocol(),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::access::auth_config::TenantAuthSettings;

    use super::*;
    use crate::test_support::federation::{FakeConnectionStore, test_connection_named};
    use crate::test_support::tenant::tenant_store_signing_in_with;
    use crate::test_support::{Fake, FakeMailSetup, block_on, test_ctx};

    fn okta(name: &str, status: ConnectionStatus) -> FederatedIdpConnection<ResolvedTenant> {
        test_connection_named(ConnectionId::new(), name, status)
    }

    fn offered_with(
        methods: &[AuthMethod],
        connections: Vec<FederatedIdpConnection<ResolvedTenant>>,
    ) -> SignInOptions {
        offered_reaching(Fake::fake(), methods, connections)
    }

    fn offered_reaching(
        mail: Arc<dyn MailSetup>,
        methods: &[AuthMethod],
        connections: Vec<FederatedIdpConnection<ResolvedTenant>>,
    ) -> SignInOptions {
        let tenant = test_ctx().tenant();
        let uc = SignInOptionsUseCase::new(SignInOptionsPorts {
            connection_store: Arc::new(FakeConnectionStore::holding(&tenant, connections)),
            tenant_store: tenant_store_signing_in_with(TenantAuthSettings {
                enabled_methods: methods.to_vec(),
                ..TenantAuthSettings::default()
            }),
            mail,
        });
        block_on(uc.execute(&tenant, ())).unwrap()
    }

    fn names(options: &SignInOptions) -> Vec<&str> {
        options
            .connections
            .iter()
            .map(|connection| connection.name.as_str())
            .collect()
    }

    /// Acme signs in through Okta and Entra. Its sign-in page shows both,
    /// in the order of their names.
    #[test]
    fn active_connections_are_offered_by_name() {
        let options = offered_with(
            &[AuthMethod::Password, AuthMethod::Saml],
            vec![
                okta("Okta", ConnectionStatus::Active),
                okta("Entra", ConnectionStatus::Active),
            ],
        );

        assert_eq!(names(&options), ["Entra", "Okta"]);
    }

    /// Acme switched its Okta connection off. Its sign-in page no longer
    /// offers it.
    #[test]
    fn a_disabled_connection_is_not_offered() {
        let options = offered_with(
            &[AuthMethod::Password, AuthMethod::Saml],
            vec![okta("Okta", ConnectionStatus::Disabled)],
        );

        assert!(options.connections.is_empty());
    }

    /// Acme switched SAML sign-in off but kept its Okta connection. The
    /// page offers no button that would be refused.
    #[test]
    fn nothing_is_offered_for_a_protocol_the_tenant_has_off() {
        let options = offered_with(
            &[AuthMethod::Password],
            vec![okta("Okta", ConnectionStatus::Active)],
        );

        assert!(options.connections.is_empty());
    }

    /// Magic links and passkeys appear on the page only once Acme switches
    /// them on.
    #[test]
    fn magic_links_and_passkeys_are_offered_only_when_switched_on() {
        let off = offered_with(&[AuthMethod::Password], Vec::new());
        let on = offered_with(
            &[
                AuthMethod::Password,
                AuthMethod::MagicLink,
                AuthMethod::Passkey,
            ],
            Vec::new(),
        );

        assert!(!off.magic_link && !off.passkey);
        assert!(on.magic_link && on.passkey);
    }

    /// Missing mail setup hides enabled magic links while keeping passkeys offered.
    #[test]
    fn magic_links_are_not_offered_where_nothing_is_mailed() {
        let options = offered_reaching(
            FakeMailSetup::not_set_up(),
            &[
                AuthMethod::Password,
                AuthMethod::MagicLink,
                AuthMethod::Passkey,
            ],
            Vec::new(),
        );

        assert!(!options.magic_link);
        assert!(options.passkey);
    }

    /// An unknown tenant returns NotFound when its sign-in options are requested.
    #[test]
    fn an_unknown_tenant_is_not_found() {
        let uc = SignInOptionsUseCase::new(SignInOptionsPorts::fakes());

        let result = block_on(uc.execute(&test_ctx().tenant(), ()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
