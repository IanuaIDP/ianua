//! A person withdrawing the consent they gave an OAuth client.

use std::sync::Arc;

use ianua_domain::domains::oauth::clients::consent::OAuthConsent;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{OAuthClientId, UserId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::oauth::{
    AccessTokenStore, OAuthClientStore, OAuthConsentStore, RefreshTokenStore,
};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::oauth::lookup::existing_client;

/// The ports [`RevokeConsentUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokeConsentPorts {
    /// Where clients are kept, to name the client in the record.
    pub client_store: Arc<dyn OAuthClientStore>,
    /// Where the scopes people gave clients are kept.
    pub consent_store: Arc<dyn OAuthConsentStore>,
    /// Where access tokens are kept; the client's for the person end.
    pub access_token_store: Arc<dyn AccessTokenStore>,
    /// Where refresh tokens are kept; the client's for the person end.
    pub refresh_token_store: Arc<dyn RefreshTokenStore>,
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Withdraws, for the person signed in, the consent they gave a client.
///
/// The tokens the client holds for them end at once; its next
/// authorization request asks the person again.
pub struct RevokeConsentUseCase {
    ports: RevokeConsentPorts,
}

impl RevokeConsentUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RevokeConsentPorts) -> Self {
        Self { ports }
    }

    /// Ends every access and refresh token `client` holds for `person`.
    async fn end_tokens(
        &self,
        tenant: &ScopedTenant,
        person: &UserId,
        client: &OAuthClientId,
    ) -> Result<(), AppError> {
        let now = clock::now();
        self.ports
            .access_token_store
            .revoke_grant(tenant, person, client, now)
            .await
            .or_internal()?;
        self.ports
            .refresh_token_store
            .revoke_grant(tenant, person, client, now)
            .await
            .or_internal()
    }

    /// The consent `person` gave `client`, refused when they gave none or
    /// it was already taken back.
    async fn given_consent(
        &self,
        tenant: &ScopedTenant,
        person: &UserId,
        client: &OAuthClientId,
    ) -> Result<OAuthConsent<ResolvedTenant>, AppError> {
        self.ports
            .consent_store
            .find(tenant, person, client)
            .await
            .or_internal()?
            .filter(|consent| !consent.scopes().is_empty())
            .or_not_found(message!(
                "oauth-no-consent-was-given-to-this",
                "no consent was given to this client"
            ))
    }
}

impl Command for RevokeConsentUseCase {
    type Caller = CallerContext;
    type Input = OAuthClientId;
    type Output = Result<(), AppError>;

    /// Withdraws every scope the person signed in to `caller`'s session
    /// gave the client `client_id`, and ends the access and refresh tokens
    /// it holds for them. Records `oauth.consent_revoked`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller is not a person signed
    ///   in to a session of the tenant, or the session no longer counts.
    /// - `AppError::NotFound` when the tenant has no such client, or the
    ///   person has no consent standing with it.
    /// - `AppError::Internal` when the consent cannot be read, saved or
    ///   audited, or the tokens cannot be ended.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        client_id: OAuthClientId,
    ) -> Result<(), AppError> {
        let person = self.ports.tenant_authorities.signed_in(caller).await?;
        let store = self.ports.client_store.as_ref();
        let tenant = caller.tenant();
        let client = existing_client(store, &tenant, &client_id).await?;
        let mut consent = self
            .given_consent(&tenant, person.account.id(), &client_id)
            .await?;
        consent
            .revoke(&client, &person.signed_in)
            .map_err(AppError::from_domain)?;
        self.ports
            .consent_store
            .save(&tenant, &consent)
            .await
            .or_internal()?;
        self.end_tokens(&tenant, person.account.id(), &client_id)
            .await?;
        auditor
            .dispatch_by(&caller.actor(), consent.take_events(&tenant))
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::client::GrantType;
    use ianua_domain::domains::oauth::clients::consent::{OAuthConsent, OAuthConsentRow};
    use ianua_domain::domains::oauth::grants::access_token::TokenSubject;
    use ianua_domain::types::Scope;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::oauth::{
        FakeAccessTokenStore, FakeOAuthClientStore, FakeOAuthConsentStore, access_token,
        stored_client,
    };
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_ctx_with,
    };

    struct Fixture {
        ann: UserId,
        caller: CallerContext,
        client_id: OAuthClientId,
        clients: Arc<FakeOAuthClientStore>,
        consents: Arc<FakeOAuthConsentStore>,
        tokens: Arc<FakeAccessTokenStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn new() -> Self {
            let ann = UserId::new();
            let caller = test_ctx_with(test_ctx().organization_id(), test_ctx().tenant_id(), ann);
            let client = stored_client("Portal", &[GrantType::AuthorizationCode]);
            Self {
                client_id: *client.id(),
                clients: Arc::new(FakeOAuthClientStore::holding(&caller.tenant(), client)),
                consents: Arc::new(FakeOAuthConsentStore::empty()),
                tokens: Arc::new(FakeAccessTokenStore::empty()),
                audit: Arc::new(FakeEventDispatcher::new()),
                ann,
                caller,
            }
        }

        fn given(self, user_id: UserId, scopes: &[&str]) -> Self {
            let consent = OAuthConsent::reconstitute(OAuthConsentRow {
                user_id,
                client_id: self.client_id,
                scopes: scopes.iter().map(|s| Scope::new(*s).unwrap()).collect(),
                granted_at: clock::now(),
            })
            .unwrap();
            block_on(self.consents.save(&self.caller.tenant(), &consent)).unwrap();
            self
        }

        fn given_by_ann(self, scopes: &[&str]) -> Self {
            let ann = self.ann;
            self.given(ann, scopes)
        }

        fn revoke(&self) -> Result<(), AppError> {
            self.revoke_as(FakeTenantAuthorities::holding(&[]))
        }

        fn revoke_as(&self, authorities: FakeTenantAuthorities) -> Result<(), AppError> {
            let use_case = RevokeConsentUseCase::new(RevokeConsentPorts {
                client_store: self.clients.clone(),
                consent_store: self.consents.clone(),
                access_token_store: self.tokens.clone(),
                tenant_authorities: Arc::new(authorities),
                ..RevokeConsentPorts::fakes()
            });
            let auditor = test_auditor(self.audit.clone());
            block_on(use_case.execute(&self.caller, &auditor, self.client_id))
        }

        fn scopes_of(&self, user_id: &UserId) -> usize {
            block_on(
                self.consents
                    .find(&self.caller.tenant(), user_id, &self.client_id),
            )
            .unwrap()
            .map_or(0, |consent| consent.scopes().len())
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann let the portal read and write for her and changes her mind. Her
    /// consent is withdrawn and the withdrawal recorded, so the portal must
    /// ask her again.
    #[test]
    fn the_person_signed_in_withdraws_their_consent() {
        let fixture = Fixture::new().given_by_ann(&["read", "write"]);

        fixture.revoke().unwrap();

        assert_eq!(fixture.scopes_of(&fixture.ann), 0);
        assert_eq!(fixture.recorded(), ["oauth.consent_revoked"]);
    }

    /// Ann withdraws her consent while the portal still holds a token for
    /// her. The token ends at once, not when it would have run out.
    #[test]
    fn withdrawing_ends_the_tokens_the_client_holds() {
        let fixture = Fixture::new().given_by_ann(&["read"]);
        let tenant = fixture.caller.tenant();
        let portal = block_on(fixture.clients.find_by_id(&tenant, &fixture.client_id))
            .unwrap()
            .unwrap();
        let held = access_token(&portal, TokenSubject::Person(fixture.ann));
        block_on(fixture.tokens.save(&fixture.caller.tenant(), &held)).unwrap();

        fixture.revoke().unwrap();

        assert!(fixture.tokens.all()[0].revoked_at().is_some());
    }

    /// Bob also let the portal read for him. Ann withdrawing hers leaves
    /// Bob's consent as he gave it.
    #[test]
    fn withdrawing_leaves_other_peoples_consent_alone() {
        let bob = UserId::new();
        let fixture = Fixture::new().given_by_ann(&["read"]).given(bob, &["read"]);

        fixture.revoke().unwrap();

        assert_eq!(fixture.scopes_of(&bob), 1);
    }

    /// Withdrawing consent that Ann never gave returns not found and
    /// records no event.
    #[test]
    fn consent_never_given_is_not_found() {
        let fixture = Fixture::new();

        let result = fixture.revoke();

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(fixture.recorded().is_empty());
    }

    /// Repeating a consent withdrawal returns not found and leaves the
    /// audit trail at one event.
    #[test]
    fn consent_already_withdrawn_is_not_found() {
        let fixture = Fixture::new().given_by_ann(&["read"]);
        fixture.revoke().unwrap();

        let again = fixture.revoke();

        assert!(matches!(again, Err(AppError::NotFound(_))));
        assert_eq!(fixture.recorded().len(), 1);
    }

    /// A signed-out caller cannot withdraw Ann's consent, which retains its
    /// granted scope.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::new().given_by_ann(&["read"]);

        let result = fixture.revoke_as(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.scopes_of(&fixture.ann), 1);
    }
}
