//! Discover connection: home realm discovery. A person types their address
//! on the sign-in page, and is sent straight to their company's identity
//! provider when the tenant routes that address's domain to one.
//!
//! Only an active connection whose domain hint is the address's domain, and
//! which may vouch for it, is named. Nobody is signed in yet, so the answer
//! says nothing about the address beyond its domain: whether the person
//! has an account is never looked at.

use std::sync::Arc;

use ianua_domain::domains::federation::connection::{FederatedIdpConnection, FederationProtocol};
use ianua_domain::domains::federation::connection_status::ConnectionStatus;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{ConnectionId, Email, Label};

use crate::error::{AppError, OrInternal};
use crate::listing::{Limit, PageRequest, SortOrder};
use crate::ports::federation::ConnectionStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;

/// The most connections a tenant's routing is read from.
const MAX_ROUTED_CONNECTIONS: u32 = 500;

/// Where an address signs in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HomeRealm {
    /// Through this connection's identity provider.
    Provider {
        /// The provider configuration selected for this address.
        connection_id: ConnectionId,
        /// The provider's name, to show on the button.
        provider_name: Label,
        /// The protocol it speaks.
        protocol: FederationProtocol,
    },
    /// The tenant routes the address nowhere; the person signs in as the
    /// tenant otherwise allows.
    NotRouted,
}

/// The ports [`DiscoverUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DiscoverPorts {
    /// The tenant's connections.
    pub connection_store: Arc<dyn ConnectionStore>,
}

/// Finds the identity provider an address signs in through.
pub struct DiscoverUseCase {
    ports: DiscoverPorts,
}

impl DiscoverUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: DiscoverPorts) -> Self {
        Self { ports }
    }
}

impl Query for DiscoverUseCase {
    type Caller = ScopedTenant;
    type Input = Email;
    type Output = Result<HomeRealm, AppError>;

    /// The connection `email`'s domain is routed to in `tenant`, or that it
    /// is routed nowhere.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` on persistence failure.
    async fn execute(&self, tenant: &ScopedTenant, email: Email) -> Result<HomeRealm, AppError> {
        let active = self
            .ports
            .connection_store
            .list_all(
                tenant,
                Some(ConnectionStatus::Active),
                &SortOrder::default(),
                &PageRequest::first(Limit::internal(MAX_ROUTED_CONNECTIONS)),
            )
            .await
            .or_internal()?
            .items;
        Ok(active
            .iter()
            .find(|connection| routes(connection, &email))
            .map_or(HomeRealm::NotRouted, realm_of))
    }
}

/// Whether `connection` takes `email`: it is on, its hint is the address's
/// domain, and it may vouch for that domain.
fn routes(connection: &FederatedIdpConnection<ResolvedTenant>, email: &Email) -> bool {
    let hinted = connection
        .domain_hint()
        .is_some_and(|hint| hint.as_str() == email.domain());
    connection.is_active() && hinted && connection.vouches_for(email)
}

/// `connection` as the place an address signs in.
fn realm_of(connection: &FederatedIdpConnection<ResolvedTenant>) -> HomeRealm {
    HomeRealm::Provider {
        connection_id: *connection.id(),
        provider_name: connection.provider_name().clone(),
        protocol: connection.protocol(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ianua_domain::domains::federation::connection::{
        AssuranceTrust, ConnectionRow, EmailTrust, GroupMapping, JitProvisioning,
    };
    use ianua_domain::shared::clock;
    use ianua_domain::types::{DomainName, Setting};

    use super::*;
    use crate::test_support::federation::{FakeConnectionStore, test_saml_config};
    use crate::test_support::{block_on, test_ctx};

    /// Acme's Okta, in `status`, vouching for `acme.com`, with `hint`.
    fn okta(
        status: ConnectionStatus,
        hint: Setting<DomainName>,
    ) -> FederatedIdpConnection<ResolvedTenant> {
        let now = clock::now();
        FederatedIdpConnection::reconstitute(ConnectionRow {
            id: ConnectionId::new(),
            provider_name: Label::new("name", "Okta").unwrap(),
            status,
            config: test_saml_config(),
            jit_provisioning: JitProvisioning::Disabled,
            jit_default_role_id: Setting::Unset,
            email_trust: EmailTrust::Unverified,
            assurance_trust: AssuranceTrust::Untrusted,
            domain_hint: hint,
            allowed_domains: vec![DomainName::new("acme.com").unwrap()],
            attribute_mapping: HashMap::new(),
            group_mapping: GroupMapping::Off,
            created_at: now,
            keyed_at: now,
        })
        .unwrap()
    }

    fn acme_hint() -> Setting<DomainName> {
        Setting::Set(DomainName::new("acme.com").unwrap())
    }

    fn discover(connection: FederatedIdpConnection<ResolvedTenant>, email: &str) -> HomeRealm {
        let store = FakeConnectionStore::holding(&test_ctx().tenant(), [connection]);
        let use_case = DiscoverUseCase::new(DiscoverPorts {
            connection_store: Arc::new(store),
        });
        block_on(use_case.execute(&test_ctx().tenant(), Email::new(email).unwrap())).unwrap()
    }

    /// Ann types `ann@acme.com`. Acme routes `acme.com` to Okta, so she is
    /// sent there.
    #[test]
    fn an_address_at_a_routed_domain_goes_to_its_provider() {
        let realm = discover(okta(ConnectionStatus::Active, acme_hint()), "ann@acme.com");

        assert!(matches!(
            realm,
            HomeRealm::Provider { provider_name, .. } if provider_name.as_str() == "Okta"
        ));
    }

    /// Bob types `bob@globex.com`. Acme routes that domain nowhere.
    #[test]
    fn an_address_at_another_domain_is_not_routed() {
        let realm = discover(
            okta(ConnectionStatus::Active, acme_hint()),
            "bob@globex.com",
        );

        assert_eq!(realm, HomeRealm::NotRouted);
    }

    /// Acme's Okta vouches for `acme.com` but is hinted for nothing. Ann is
    /// not sent anywhere on her own.
    #[test]
    fn a_connection_with_no_hint_routes_nobody() {
        let realm = discover(
            okta(ConnectionStatus::Active, Setting::Unset),
            "ann@acme.com",
        );

        assert_eq!(realm, HomeRealm::NotRouted);
    }

    /// A disabled connection does not route an address that matches its domain hint.
    #[test]
    fn a_switched_off_connection_routes_nobody() {
        let realm = discover(
            okta(ConnectionStatus::Disabled, acme_hint()),
            "ann@acme.com",
        );

        assert_eq!(realm, HomeRealm::NotRouted);
    }
}
