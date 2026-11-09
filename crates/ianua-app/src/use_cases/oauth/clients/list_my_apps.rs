//! "My apps": the apps the person signed in has let act for them, with
//! what they let each do, so they can withdraw what they no longer want.

use std::collections::HashMap;
use std::sync::Arc;

use ianua_domain::domains::oauth::clients::client::OAuthClient;
use ianua_domain::domains::oauth::clients::consent::OAuthConsent;
use ianua_domain::domains::oauth::clients::settings::ClientLinks;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{ClientId, Label, OAuthClientId, Scope};
use time::OffsetDateTime;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::oauth::{OAuthClientStore, OAuthConsentStore};
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;

/// One app the person let act for them.
pub struct AuthorizedApp {
    /// The client's internal id, to withdraw consent with.
    pub client_id: OAuthClientId,
    /// Its public client id.
    pub client_id_value: ClientId,
    /// The application label shown when reviewing granted consent.
    pub name: Label,
    /// The pages shown about it: logo, policy, terms.
    pub links: ClientLinks,
    /// What the person let it do.
    pub scopes: Vec<Scope>,
    /// When they last agreed.
    pub granted_at: OffsetDateTime,
}

/// The ports [`ListMyAppsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListMyAppsPorts {
    /// Where the scopes people gave clients are kept.
    pub consent_store: Arc<dyn OAuthConsentStore>,
    /// Where clients are kept, to name them.
    pub client_store: Arc<dyn OAuthClientStore>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Lists the apps the person signed in authorized.
pub struct ListMyAppsUseCase {
    ports: ListMyAppsPorts,
}

impl ListMyAppsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListMyAppsPorts) -> Self {
        Self { ports }
    }

    /// The apps with remaining consent, in consent order, with all their
    /// client records read together. Missing and revoked clients are omitted.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the client lookup fails.
    async fn authorized_apps(
        &self,
        tenant: &ScopedTenant,
        consents: &[OAuthConsent<ResolvedTenant>],
    ) -> Result<Vec<AuthorizedApp>, AppError> {
        let ids: Vec<OAuthClientId> = consents
            .iter()
            .filter(|consent| !consent.scopes().is_empty())
            .map(|consent| *consent.client_id())
            .collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let clients: HashMap<_, _> = self
            .ports
            .client_store
            .find_by_ids(tenant, &ids)
            .await
            .or_internal()?
            .into_iter()
            .filter(OAuthClient::is_active)
            .map(|client| (*client.id(), client))
            .collect();
        Ok(consents
            .iter()
            .filter(|consent| !consent.scopes().is_empty())
            .filter_map(|consent| {
                clients
                    .get(consent.client_id())
                    .map(|client| authorized_app(client, consent))
            })
            .collect())
    }
}

impl Query for ListMyAppsUseCase {
    type Caller = CallerContext;
    type Input = ();
    type Output = Result<Vec<AuthorizedApp>, AppError>;

    /// Every active app the person signed in to `caller`'s session still
    /// lets act for them, newest consent first. Consent they withdrew, and
    /// apps since revoked, are left out.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller is not a person signed
    ///   in to a session of the tenant, or the session no longer counts.
    /// - `AppError::Internal` when a lookup fails.
    async fn execute(
        &self,
        caller: &CallerContext,
        (): (),
    ) -> Result<Vec<AuthorizedApp>, AppError> {
        let person = self.ports.tenant_authorities.signed_in(caller).await?;
        let tenant = caller.tenant();
        let consents = self
            .ports
            .consent_store
            .list_for_user(&tenant, person.account.id())
            .await
            .or_internal()?;
        self.authorized_apps(&tenant, &consents).await
    }
}

/// Presents an active client with the scopes and timestamp of this person's consent.
fn authorized_app(
    client: &OAuthClient<ResolvedTenant>,
    consent: &OAuthConsent<ResolvedTenant>,
) -> AuthorizedApp {
    AuthorizedApp {
        client_id: *client.id(),
        client_id_value: client.client_id_value().clone(),
        name: client.name().clone(),
        links: client.settings().links.clone(),
        scopes: consent.scopes().to_vec(),
        granted_at: consent.granted_at(),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClient};
    use ianua_domain::domains::oauth::clients::consent::{OAuthConsent, OAuthConsentRow};
    use ianua_domain::domains::oauth::clients::status::OAuthClientStatus;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::oauth::{
        FakeOAuthClientStore, FakeOAuthConsentStore, client_with, stored_client,
    };
    use crate::test_support::{block_on, test_ctx, test_ctx_with};

    /// Ann, signed in, and the stores her consents and their apps are in.
    struct Fixture {
        ann: UserId,
        caller: CallerContext,
        clients: Arc<FakeOAuthClientStore>,
        consents: Arc<FakeOAuthConsentStore>,
    }

    impl Fixture {
        /// Ann, with no consent yet.
        fn new() -> Self {
            let ann = UserId::new();
            Self {
                caller: test_ctx_with(test_ctx().organization_id(), test_ctx().tenant_id(), ann),
                ann,
                clients: Arc::new(FakeOAuthClientStore::empty()),
                consents: Arc::new(FakeOAuthConsentStore::empty()),
            }
        }

        /// `client` kept, with `user` having let it do `scopes`.
        fn consented(&self, client: &OAuthClient<ResolvedTenant>, user: UserId, scopes: &[&str]) {
            let tenant = self.caller.tenant();
            block_on(self.clients.save(&tenant, client)).unwrap();
            let consent = OAuthConsent::reconstitute(OAuthConsentRow {
                user_id: user,
                client_id: *client.id(),
                scopes: scopes
                    .iter()
                    .map(|scope| Scope::new(*scope).unwrap())
                    .collect(),
                granted_at: clock::now(),
            })
            .unwrap();
            block_on(self.consents.save(&tenant, &consent)).unwrap();
        }

        /// What listing answers for a caller `authorities` describe.
        fn list_as(
            &self,
            authorities: FakeTenantAuthorities,
        ) -> Result<Vec<AuthorizedApp>, AppError> {
            let use_case = ListMyAppsUseCase::new(ListMyAppsPorts {
                consent_store: self.consents.clone(),
                client_store: self.clients.clone(),
                tenant_authorities: Arc::new(authorities),
            });
            block_on(use_case.execute(&self.caller, ()))
        }

        /// What listing answers for Ann.
        fn list(&self) -> Vec<AuthorizedApp> {
            self.list_as(FakeTenantAuthorities::holding(&[])).unwrap()
        }
    }

    /// Ann let the portal read. She sees it, with what she let it do.
    #[test]
    fn the_apps_a_person_authorized_are_listed() {
        let fixture = Fixture::new();
        let portal = stored_client("Portal", &[GrantType::AuthorizationCode]);
        fixture.consented(&portal, fixture.ann, &["read"]);

        let apps = fixture.list();

        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].name.as_str(), "Portal");
        assert_eq!(apps[0].scopes, [Scope::new("read").unwrap()]);
    }

    /// Multiple consents retain newest-first order and their own scopes,
    /// while their clients are read together rather than once per consent.
    #[test]
    fn authorized_apps_share_one_client_read() {
        let fixture = Fixture::new();
        let first = stored_client("First", &[GrantType::AuthorizationCode]);
        let second = stored_client("Second", &[GrantType::AuthorizationCode]);
        fixture.consented(&first, fixture.ann, &["read"]);
        fixture.consented(&second, fixture.ann, &["write"]);

        let apps = fixture.list();

        assert_eq!(
            apps.iter().map(|app| app.name.as_str()).collect::<Vec<_>>(),
            ["Second", "First"]
        );
        assert_eq!(apps[0].scopes, [Scope::new("write").unwrap()]);
        assert_eq!(apps[1].scopes, [Scope::new("read").unwrap()]);
        assert_eq!(fixture.clients.id_reads().len(), 1);
    }

    /// Ann withdrew her consent to the portal. It is no longer listed.
    #[test]
    fn a_withdrawn_consent_is_left_out() {
        let fixture = Fixture::new();
        let portal = stored_client("Portal", &[GrantType::AuthorizationCode]);
        fixture.consented(&portal, fixture.ann, &[]);

        assert!(fixture.list().is_empty());
    }

    /// The portal was revoked. It is no longer listed.
    #[test]
    fn a_revoked_app_is_left_out() {
        let fixture = Fixture::new();
        let portal = client_with("Portal", &[GrantType::AuthorizationCode], |row| {
            row.status = OAuthClientStatus::Revoked;
        });
        fixture.consented(&portal, fixture.ann, &["read"]);

        assert!(fixture.list().is_empty());
    }

    /// When only another person consented to the portal, Ann's app list is empty.
    #[test]
    fn another_persons_apps_are_not_listed() {
        let fixture = Fixture::new();
        let portal = stored_client("Portal", &[GrantType::AuthorizationCode]);
        fixture.consented(&portal, UserId::new(), &["read"]);

        assert!(fixture.list().is_empty());
    }

    /// A signed-out caller receives unauthenticated when listing personal apps.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.list_as(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
