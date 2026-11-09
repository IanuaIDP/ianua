//! A self-registered client deleting its own registration (RFC 7592 2.3).
//! It is revoked like a client an admin revokes.

use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ActorRef;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::oauth::registration::managed::{
    ManagingClient, SelfManagementPorts, self_managed,
};

/// Deletes a client's own registration.
pub struct DeleteUseCase {
    ports: SelfManagementPorts,
}

impl DeleteUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SelfManagementPorts) -> Self {
        Self { ports }
    }
}

impl Command for DeleteUseCase {
    type Caller = ScopedTenant;
    type Input = ManagingClient;
    type Output = Result<(), AppError>;

    /// Revokes, for good, the client `managing` names in `tenant`, as its
    /// registration access token asks, and records `oauth.client_revoked`
    /// with the client as actor.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the client is unknown, revoked
    ///   already, did not register itself, or the token is not its own.
    /// - `AppError::Internal` when hashing, the lookup, the save or the
    ///   audit fails.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        managing: ManagingClient,
    ) -> Result<(), AppError> {
        let (mut client, proof) = self_managed(&self.ports, tenant, &managing).await?;
        client.deregister(&proof).map_err(AppError::from_domain)?;
        self.ports
            .client_store
            .save(tenant, &client)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(
                &ActorRef::OAuthClient(*client.id()),
                client.take_events(tenant),
            )
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClientRow};
    use ianua_domain::domains::oauth::clients::registration::ClientManagement;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{ClientId, InitialAccessTokenId};

    use super::*;
    use crate::ports::oauth::OAuthClientStore;
    use crate::test_support::oauth::{FakeOAuthClientStore, client_with, hash_of};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The registration access token the app was handed.
    const REGISTRATION: &str = "registration-token";

    /// An app that registered itself, managing itself with
    /// [`REGISTRATION`], and the tenant's records.
    struct Fixture {
        client_id: ClientId,
        store: Arc<FakeOAuthClientStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        /// The app, kept in the tenant.
        fn new() -> Self {
            let app = client_with("Claude", &[GrantType::AuthorizationCode], self_registered);
            Self {
                client_id: app.client_id_value().clone(),
                store: Arc::new(FakeOAuthClientStore::holding(&test_ctx().tenant(), app)),
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        /// What deleting with `token` answers.
        fn delete(&self, token: &str) -> Result<(), AppError> {
            let managing = ManagingClient {
                client_id: self.client_id.clone(),
                registration_token: Secret::new(token),
            };
            let use_case = DeleteUseCase::new(SelfManagementPorts {
                client_store: self.store.clone(),
                ..SelfManagementPorts::fakes()
            });
            let auditor = test_auditor(self.audit.clone());
            block_on(use_case.execute(&test_ctx().tenant(), &auditor, managing))
        }

        /// Whether the app is still active.
        fn is_active(&self) -> bool {
            block_on(
                self.store
                    .find_by_client_id_value(&test_ctx().tenant(), &self.client_id),
            )
            .unwrap()
            .unwrap()
            .is_active()
        }

        /// The audit records written, by event name.
        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// The row of an app that registered itself with [`REGISTRATION`].
    fn self_registered(row: &mut OAuthClientRow) {
        row.management = ClientManagement::ByItself {
            registration_token: hash_of(REGISTRATION),
            admitted_with: InitialAccessTokenId::new(),
        };
    }

    /// The app deletes its registration. It is revoked and recorded.
    #[test]
    fn an_app_deletes_its_registration() {
        let fixture = Fixture::new();

        fixture.delete(REGISTRATION).unwrap();

        assert!(!fixture.is_active());
        assert_eq!(fixture.recorded(), ["oauth.client_revoked"]);
    }

    /// A guessed registration token cannot authenticate deletion. The app
    /// stays active and no revocation is recorded.
    #[test]
    fn a_wrong_token_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.delete("guess");

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(fixture.is_active());
        assert!(fixture.recorded().is_empty());
    }

    /// Reusing a deleted app's registration token is unauthenticated and
    /// leaves only the original revocation event.
    #[test]
    fn a_deleted_registration_manages_nothing() {
        let fixture = Fixture::new();
        fixture.delete(REGISTRATION).unwrap();

        let again = fixture.delete(REGISTRATION);

        assert!(matches!(again, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.recorded().len(), 1);
    }
}
