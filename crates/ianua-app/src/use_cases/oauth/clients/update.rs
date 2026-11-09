//! Changing an OAuth client's name, redirect URIs, sign-out addresses,
//! scopes or settings: its token lifetimes, the pages shown about it,
//! whether people are asked to consent, the form of its access tokens, how
//! it hears of sign-outs, and what its tokens are bound to.

use std::sync::Arc;

use ianua_domain::domains::oauth::clients::client::OAuthClientChange;
use ianua_domain::domains::oauth::clients::settings::SettingsChange;
use ianua_domain::domains::oauth::control::{OAuthControl, OAuthRight};
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{Label, OAuthClientId, RedirectUri, Scope};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::oauth::OAuthClientStore;
use crate::use_case::Command;
use crate::use_cases::oauth::lookup::existing_client;

/// What to change on a client. `None` leaves a field as it is.
pub struct UpdateRequest {
    /// The client to change.
    pub client_id: OAuthClientId,
    /// The new name.
    pub name: Option<Label>,
    /// The new redirect URIs, replacing the old ones.
    pub redirect_uris: Option<Vec<RedirectUri>>,
    /// The new addresses a person may be sent back to after signing out,
    /// replacing the old ones.
    pub post_logout_redirect_uris: Option<Vec<RedirectUri>>,
    /// The new scopes, replacing the old ones.
    pub scopes: Option<Vec<Scope>>,
    /// Changes to its settings, made in order.
    pub settings: Vec<SettingsChange>,
}

impl UpdateRequest {
    /// The changes the request names, in the order they are made.
    fn changes(self) -> Vec<OAuthClientChange> {
        let renamed = self.name.map(OAuthClientChange::Rename);
        let redirected = self.redirect_uris.map(OAuthClientChange::RedirectTo);
        let after_logout = self
            .post_logout_redirect_uris
            .map(OAuthClientChange::AfterLogoutTo);
        let scoped = self.scopes.map(OAuthClientChange::Scopes);
        let settings = self.settings.into_iter().map(OAuthClientChange::from);
        renamed
            .into_iter()
            .chain(redirected)
            .chain(after_logout)
            .chain(scoped)
            .chain(settings)
            .collect()
    }
}

/// The ports [`UpdateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UpdatePorts {
    /// Where clients are kept.
    pub client_store: Arc<dyn OAuthClientStore>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Changes an OAuth client's settings.
pub struct UpdateUseCase {
    ports: UpdatePorts,
}

impl UpdateUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: UpdatePorts) -> Self {
        Self { ports }
    }
}

impl Command for UpdateUseCase {
    type Caller = CallerContext;
    type Input = UpdateRequest;
    type Output = Result<(), AppError>;

    /// Changes the fields `req` names on the client. Records
    /// `OAuthClientUpdated` when anything changed; a request naming no field
    /// changes and records nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without client-update rights.
    /// - `AppError::NotFound` for a missing tenant client; `Conflict` for a revoked client.
    /// - `AppError::Domain` for a code flow without redirects or duplicate redirects/scopes; `Internal` on read, save or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        req: UpdateRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = OAuthControl::new(&authority);
        control
            .ensure_may(OAuthRight::Update)
            .map_err(AppError::from_domain)?;
        let store = self.ports.client_store.as_ref();
        let tenant = caller.tenant();
        let mut client = existing_client(store, &tenant, &req.client_id).await?;
        let changes = req.changes();
        if changes.is_empty() {
            return Ok(());
        }
        client
            .update(changes, &control)
            .map_err(AppError::from_domain)?;
        store.save(&tenant, &client).await.or_internal()?;
        auditor
            .dispatch_by(&caller.actor(), client.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClient};
    use ianua_domain::domains::oauth::clients::settings::{AccessTokenFormat, ConsentPrompt};
    use ianua_domain::domains::oauth::clients::status::OAuthClientStatus;
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::oauth::{FakeOAuthClientStore, client_row, stored_client};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        store: Arc<FakeOAuthClientStore>,
        client_id: OAuthClientId,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn holding(client: OAuthClient<ResolvedTenant>) -> Self {
            let client_id = *client.id();
            Self {
                store: Arc::new(FakeOAuthClientStore::holding(&test_ctx().tenant(), client)),
                client_id,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn portal() -> Self {
            Self::holding(stored_client("Portal", &[GrantType::AuthorizationCode]))
        }

        fn change(&self) -> UpdateRequest {
            UpdateRequest {
                client_id: self.client_id,
                name: None,
                redirect_uris: None,
                post_logout_redirect_uris: None,
                scopes: None,
                settings: Vec::new(),
            }
        }

        fn update(&self, req: UpdateRequest) -> Result<(), AppError> {
            self.update_as(FakeTenantAuthorities::holding_everything(), req)
        }

        fn update_as(
            &self,
            authorities: FakeTenantAuthorities,
            req: UpdateRequest,
        ) -> Result<(), AppError> {
            let use_case = UpdateUseCase::new(UpdatePorts {
                client_store: self.store.clone(),
                tenant_authorities: Arc::new(authorities),
            });
            block_on(use_case.execute(&test_ctx(), &test_auditor(self.audit.clone()), req))
        }

        fn saved(&self) -> OAuthClient<ResolvedTenant> {
            block_on(self.store.find_by_id(&test_ctx().tenant(), &self.client_id))
                .unwrap()
                .unwrap()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn renamed(fixture: &Fixture, name: &str) -> UpdateRequest {
        UpdateRequest {
            name: Some(Label::new("name", name).unwrap()),
            ..fixture.change()
        }
    }

    /// Ann renames the portal to "Production". The new name is kept and the
    /// change recorded.
    #[test]
    fn a_rename_is_kept_and_recorded() {
        let fixture = Fixture::portal();

        fixture.update(renamed(&fixture, "Production")).unwrap();

        assert_eq!(fixture.saved().name().as_str(), "Production");
        assert_eq!(fixture.recorded(), ["oauth.client_updated"]);
    }

    /// Ann narrows the portal's scopes, then repoints its redirect. Each is a
    /// change on its own: reading either as nothing to do would leave the old
    /// values in force.
    #[test]
    fn scopes_and_redirects_each_count_as_a_change() {
        let fixture = Fixture::portal();

        fixture
            .update(UpdateRequest {
                scopes: Some(vec![Scope::new("read").unwrap()]),
                ..fixture.change()
            })
            .unwrap();
        fixture
            .update(UpdateRequest {
                redirect_uris: Some(vec![RedirectUri::new("https://app.acme.com/cb").unwrap()]),
                ..fixture.change()
            })
            .unwrap();

        let saved = fixture.saved();
        assert_eq!(saved.scopes().len(), 1);
        assert_eq!(saved.redirect_uris()[0].as_str(), "https://app.acme.com/cb");
        assert_eq!(fixture.recorded().len(), 2);
    }

    /// Ann makes the tenant's dashboard first-party, gives it JWT access
    /// tokens and a sign-out address. All three are kept, recorded as one
    /// change.
    #[test]
    fn settings_and_sign_out_addresses_are_kept() {
        let fixture = Fixture::portal();

        fixture
            .update(UpdateRequest {
                post_logout_redirect_uris: Some(vec![
                    RedirectUri::new("https://app.acme.com/bye").unwrap(),
                ]),
                settings: vec![
                    SettingsChange::Consent(ConsentPrompt::FirstParty),
                    SettingsChange::TokenFormat(AccessTokenFormat::Jwt),
                ],
                ..fixture.change()
            })
            .unwrap();

        let saved = fixture.saved();
        assert_eq!(saved.settings().consent, ConsentPrompt::FirstParty);
        assert_eq!(saved.settings().token_format, AccessTokenFormat::Jwt);
        assert_eq!(
            saved.post_logout_redirect_uris()[0].as_str(),
            "https://app.acme.com/bye"
        );
        assert_eq!(fixture.recorded(), ["oauth.client_updated"]);
    }

    /// Ann sends a change naming nothing. Nothing is saved or recorded.
    #[test]
    fn a_change_naming_nothing_records_nothing() {
        let fixture = Fixture::portal();

        fixture.update(fixture.change()).unwrap();

        assert!(fixture.recorded().is_empty());
    }

    /// Renaming a revoked client returns conflict and records no update event.
    #[test]
    fn a_revoked_client_is_not_changed() {
        let mut row = client_row("Old", &[GrantType::ClientCredentials]);
        row.status = OAuthClientStatus::Revoked;
        let fixture = Fixture::holding(OAuthClient::reconstitute(row).unwrap());

        let result = fixture.update(renamed(&fixture, "Revived"));

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// Removing every redirect from a code-flow client is refused and
    /// preserves its stored redirect.
    #[test]
    fn a_code_client_keeps_a_redirect() {
        let fixture = Fixture::portal();

        let result = fixture.update(UpdateRequest {
            redirect_uris: Some(Vec::new()),
            ..fixture.change()
        });

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(fixture.saved().redirect_uris().len(), 1);
    }

    /// Renaming an unknown client returns not found and records no event.
    #[test]
    fn an_unknown_client_is_not_found() {
        let fixture = Fixture::portal();

        let result = fixture.update(UpdateRequest {
            client_id: OAuthClientId::new(),
            ..renamed(&fixture, "Ghost")
        });

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// A caller with no permissions cannot replace the portal's redirect
    /// with an attacker address, which is not stored.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let fixture = Fixture::portal();

        let result = fixture.update_as(
            FakeTenantAuthorities::holding(&[]),
            UpdateRequest {
                redirect_uris: Some(vec![RedirectUri::new("https://evil.example/cb").unwrap()]),
                ..fixture.change()
            },
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_ne!(
            fixture.saved().redirect_uris()[0].as_str(),
            "https://evil.example/cb"
        );
    }

    /// A signed-out caller receives unauthenticated when renaming the portal.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::portal();

        let result = fixture.update_as(
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
            renamed(&fixture, "Mallory's"),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
