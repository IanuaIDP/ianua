//! A self-registered client reading its own registration (RFC 7592 2.1).

use ianua_domain::domains::oauth::clients::client::OAuthClient;
use ianua_domain::isolation::scope::ResolvedTenant;

use crate::error::AppError;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::oauth::registration::managed::{
    ManagingClient, SelfManagementPorts, self_managed,
};

/// Reads a client's own registration.
pub struct ReadUseCase {
    ports: SelfManagementPorts,
}

impl ReadUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: SelfManagementPorts) -> Self {
        Self { ports }
    }
}

impl Query for ReadUseCase {
    type Caller = ScopedTenant;
    type Input = ManagingClient;
    type Output = Result<OAuthClient<ResolvedTenant>, AppError>;

    /// The registration of the client `managing` names in `tenant`, once
    /// its registration access token proves the request is its own.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the client is unknown, revoked,
    ///   did not register itself, or the token is not its own.
    /// - `AppError::Internal` when hashing or the lookup fails.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        managing: ManagingClient,
    ) -> Result<OAuthClient<ResolvedTenant>, AppError> {
        let (client, _) = self_managed(&self.ports, tenant, &managing).await?;
        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClientRow};
    use ianua_domain::domains::oauth::clients::registration::ClientManagement;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::InitialAccessTokenId;

    use super::*;
    use crate::test_support::oauth::{FakeOAuthClientStore, client_with, hash_of};
    use crate::test_support::{block_on, test_ctx};

    /// The registration access token the app was handed.
    const REGISTRATION: &str = "registration-token";

    /// An app that registered itself, managing itself with
    /// [`REGISTRATION`].
    fn self_registered(row: &mut OAuthClientRow) {
        row.management = ClientManagement::ByItself {
            registration_token: hash_of(REGISTRATION),
            admitted_with: InitialAccessTokenId::new(),
        };
    }

    /// What reading `client`'s registration with `token` answers.
    fn read(
        client: OAuthClient<ResolvedTenant>,
        token: &str,
    ) -> Result<OAuthClient<ResolvedTenant>, AppError> {
        let managing = ManagingClient {
            client_id: client.client_id_value().clone(),
            registration_token: Secret::new(token),
        };
        let use_case = ReadUseCase::new(SelfManagementPorts {
            client_store: Arc::new(FakeOAuthClientStore::holding(&test_ctx().tenant(), client)),
            ..SelfManagementPorts::fakes()
        });
        block_on(use_case.execute(&test_ctx().tenant(), managing))
    }

    /// The app reads its registration with its token. It gets it.
    #[test]
    fn an_app_reads_its_own_registration() {
        let app = client_with("Claude", &[GrantType::AuthorizationCode], self_registered);

        let read = read(app, REGISTRATION).unwrap();

        assert_eq!(read.name().as_str(), "Claude");
    }

    /// A guessed registration token cannot authenticate a registration read.
    #[test]
    fn a_wrong_token_is_refused() {
        let app = client_with("Claude", &[GrantType::AuthorizationCode], self_registered);

        assert!(matches!(read(app, "guess"), Err(AppError::Unauthenticated)));
    }

    /// An administrator-registered client cannot authenticate a self-management
    /// read with a registration token.
    #[test]
    fn an_admin_registered_client_cannot_be_read_this_way() {
        let portal = client_with("Portal", &[GrantType::AuthorizationCode], |_| {});

        assert!(matches!(
            read(portal, REGISTRATION),
            Err(AppError::Unauthenticated)
        ));
    }
}
