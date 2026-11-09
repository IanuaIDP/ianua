//! A self-registered client changing its own registration (RFC 7592 2.2).
//! It may change its name, redirects, sign-out addresses, scopes and
//! settings, but never make itself first-party.

use ianua_domain::domains::oauth::clients::client::{OAuthClient, OAuthClientChange};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::ActorRef;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::oauth::registration::managed::{
    ManagingClient, SelfManagementPorts, self_managed,
};

/// What a client changes on its own registration.
pub struct UpdateRequest {
    /// The client, with its registration access token.
    pub managing: ManagingClient,
    /// The changes, made in order.
    pub changes: Vec<OAuthClientChange>,
}

/// Changes a client's own registration.
pub struct UpdateUseCase {
    ports: SelfManagementPorts,
}

impl UpdateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: SelfManagementPorts) -> Self {
        Self { ports }
    }
}

impl Command for UpdateUseCase {
    type Caller = ScopedTenant;
    type Input = UpdateRequest;
    type Output = Result<OAuthClient<ResolvedTenant>, AppError>;

    /// Makes the changes `req` asks on the client's own registration in
    /// `tenant`, and records `oauth.client_updated` with the client as
    /// actor. A request with no change records nothing. Answers the
    /// registration as it now stands.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the client is unknown, revoked,
    ///   did not register itself, or the token is not its own.
    /// - `AppError::Forbidden` when a change makes it first-party.
    /// - `AppError::Domain` when a change breaks a client rule.
    /// - `AppError::Internal` when hashing, the lookup, the save or the
    ///   audit fails.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        req: UpdateRequest,
    ) -> Result<OAuthClient<ResolvedTenant>, AppError> {
        let (mut client, proof) = self_managed(&self.ports, tenant, &req.managing).await?;
        client
            .update_registration(req.changes, &proof)
            .map_err(AppError::from_domain)?;
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
            .or_internal()?;
        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClientRow};
    use ianua_domain::domains::oauth::clients::registration::ClientManagement;
    use ianua_domain::domains::oauth::clients::settings::{ConsentPrompt, SettingsChange};
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{InitialAccessTokenId, Label};

    use super::*;
    use crate::test_support::oauth::{FakeOAuthClientStore, client_with, hash_of};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

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

    /// What `changes`, asked with `token`, answer, with the records.
    fn update(
        token: &str,
        changes: Vec<OAuthClientChange>,
    ) -> (Result<OAuthClient<ResolvedTenant>, AppError>, Vec<String>) {
        let app = client_with("Claude", &[GrantType::AuthorizationCode], self_registered);
        let managing = ManagingClient {
            client_id: app.client_id_value().clone(),
            registration_token: Secret::new(token),
        };
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = UpdateUseCase::new(SelfManagementPorts {
            client_store: Arc::new(FakeOAuthClientStore::holding(&test_ctx().tenant(), app)),
            ..SelfManagementPorts::fakes()
        });
        let req = UpdateRequest { managing, changes };
        let result =
            block_on(use_case.execute(&test_ctx().tenant(), &test_auditor(audit.clone()), req));
        let recorded = audit.records.lock().unwrap().clone();
        (result, recorded)
    }

    /// The app renames itself. The new name is kept and recorded.
    #[test]
    fn an_app_renames_itself() {
        let (result, recorded) = update(
            REGISTRATION,
            vec![OAuthClientChange::Rename(
                Label::new("name", "Claude Code").unwrap(),
            )],
        );

        assert_eq!(result.unwrap().name().as_str(), "Claude Code");
        assert_eq!(recorded, ["oauth.client_updated"]);
    }

    /// A self-registered app cannot choose first-party consent. The change
    /// is forbidden and no update is recorded.
    #[test]
    fn an_app_may_not_make_itself_first_party() {
        let (result, recorded) = update(
            REGISTRATION,
            vec![OAuthClientChange::from(SettingsChange::Consent(
                ConsentPrompt::FirstParty,
            ))],
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(recorded.is_empty());
    }

    /// A guessed registration token cannot authenticate a rename request.
    /// No update is recorded.
    #[test]
    fn a_wrong_token_is_refused() {
        let (result, recorded) = update(
            "guess",
            vec![OAuthClientChange::Rename(
                Label::new("name", "Mallory").unwrap(),
            )],
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(recorded.is_empty());
    }
}
