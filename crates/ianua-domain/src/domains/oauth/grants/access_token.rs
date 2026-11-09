//! Access tokens: the token a relying party sends to OAuth-protected
//! resources.
//!
//! Each issued token is recorded. So a presented token finds its own grant,
//! for one client, limited to the scopes the user gave, until it expires or
//! is revoked. This is what lets `userinfo` answer only for the token's
//! grant. Without the record, it would have to trust a browser session or a
//! tenant API key instead, which carry none of the scopes the user gave.
//!
//! A token may be bound to a key or certificate its holder proves with each
//! request, may be meant for another client than its holder after an
//! exchange, and may name who acts for its subject.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::oauth::clients::client::{GrantType, OAuthClient};
use crate::domains::oauth::events::grants::{AccessTokenIssued, TokenExchanged, TokenRevoked};
use crate::domains::oauth::grants::resource::ensure_tunnel_for;
use crate::domains::oauth::grants::token_binding::{PresentedProof, SenderBinding};
use crate::domains::oauth::grants::token_exchange::TokenExchange;
use crate::domains::routing::stream::StreamRoute;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::row_check::RowCheck;
use crate::types::{
    EventLabel, Lifetime, OAuthClientId, Revocation, Scope, StreamRouteId, TokenHash, UserId,
};

/// Whom an access token acts for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSubject {
    /// A person, who granted the client access.
    Person(UserId),
    /// The client itself, with client credentials: a machine acting for
    /// no person.
    Client,
}

impl TokenSubject {
    /// Reads the stored person back. No person means the client itself.
    #[must_use]
    pub fn from_stored(person: Option<UserId>) -> Self {
        person.map_or(Self::Client, Self::Person)
    }

    /// The person, when the token acts for one. Storage keeps it this way.
    #[must_use]
    pub fn person(&self) -> Option<&UserId> {
        match self {
            Self::Person(user) => Some(user),
            Self::Client => None,
        }
    }
}

/// Whom an access token is meant for (`aud`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessAudience {
    /// The client it was issued to, and the APIs that client calls.
    Holder,
    /// Another client of the tenant, which it was exchanged for.
    Client(OAuthClientId),
    /// One of the tenant's stream routes, whose signed-in tunnel it opens
    /// and nothing else, asked for by a resource indicator (RFC 8707).
    StreamRoute(StreamRouteId),
}

/// One party acting for a token's subject (RFC 8693 4.1, `act`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActingParty {
    /// A tenant user acting on behalf of the token's subject.
    Person(UserId),
    /// A client of the tenant.
    Client(OAuthClientId),
}

/// What an access token says about itself when a resource server asks
/// (RFC 7662).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Introspection {
    /// It works now.
    Active {
        /// The client it was issued to.
        client_id: OAuthClientId,
        /// Whom it acts for.
        subject: TokenSubject,
        /// The scopes it carries.
        scopes: Vec<Scope>,
        /// When it was issued.
        issued_at: OffsetDateTime,
        /// When it expires.
        expires_at: OffsetDateTime,
        /// What it must be presented with (`cnf`).
        binding: SenderBinding,
        /// Who acts for its subject, outermost first (`act`).
        delegation: Vec<ActingParty>,
    },
    /// It does not work: revoked, expired, or never issued. Which one is
    /// not said.
    Inactive,
}

/// An issued OAuth access token.
///
/// Only the hash is kept. The raw token goes to the client once, at the
/// token endpoint, and cannot be recovered from here.
#[derive(Debug, Clone)]
pub struct AccessToken<T: TenantScope> {
    token_hash: TokenHash,
    client_id: OAuthClientId,
    subject: TokenSubject,
    scopes: Vec<Scope>,
    audience: AccessAudience,
    delegation: Vec<ActingParty>,
    binding: SenderBinding,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    /// Whether it was revoked, and when.
    revocation: Revocation,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

/// What a new access token is issued with.
pub struct IssueAccessTokenParams {
    /// The token's hash.
    pub token_hash: TokenHash,
    /// The client the token goes to.
    pub client_id: OAuthClientId,
    /// The user who approved the grant.
    pub user_id: UserId,
    /// The scopes the user gave.
    pub scopes: Vec<Scope>,
    /// How long the token is good for.
    pub lifetime: Lifetime,
    /// What it must be presented with.
    pub binding: SenderBinding,
}

/// The parts of a new token the token endpoint picks: its hash, how long it
/// lasts and what it is bound to.
#[derive(Debug, Clone)]
pub struct TokenIssue {
    /// The token's hash.
    pub token_hash: TokenHash,
    /// How long the token is good for.
    pub lifetime: Lifetime,
    /// What it must be presented with.
    pub binding: SenderBinding,
}

/// An access token as storage keeps it, checked again by
/// [`AccessToken::reconstitute`].
pub struct AccessTokenRow {
    /// The token's hash.
    pub token_hash: TokenHash,
    /// The client the token was issued to.
    pub client_id: OAuthClientId,
    /// Whom it acts for.
    pub subject: TokenSubject,
    /// The scopes it carries.
    pub scopes: Vec<Scope>,
    /// Whom it is meant for.
    pub audience: AccessAudience,
    /// Who acts for its subject, outermost first.
    pub delegation: Vec<ActingParty>,
    /// What it must be presented with.
    pub binding: SenderBinding,
    /// When the token was issued.
    pub created_at: OffsetDateTime,
    /// When the token expires.
    pub expires_at: OffsetDateTime,
    /// Whether it was revoked, and when.
    pub revocation: Revocation,
}

/// What a token carries besides its issue terms.
struct Grant {
    client_id: OAuthClientId,
    subject: TokenSubject,
    scopes: Vec<Scope>,
    audience: AccessAudience,
    delegation: Vec<ActingParty>,
}

impl<T: TenantScope> AccessToken<T> {
    /// Issues a token over the given lifetime. Raises
    /// `oauth.access_token_issued`, naming the client and how many scopes
    /// the token carries, never the token.
    #[must_use]
    pub fn issue(params: IssueAccessTokenParams) -> Self {
        let issue = TokenIssue {
            token_hash: params.token_hash,
            lifetime: params.lifetime,
            binding: params.binding,
        };
        Self::issued(
            issue,
            Grant {
                client_id: params.client_id,
                subject: TokenSubject::Person(params.user_id),
                scopes: params.scopes,
                audience: AccessAudience::Holder,
                delegation: Vec::new(),
            },
        )
    }

    /// Issues a token, as [`Self::issue`] does, meant for the signed-in
    /// tunnel of `route` alone, which a resource indicator asked for (RFC
    /// 8707). Its `aud` is the route's tunnel audience, so no app, API or
    /// other tunnel takes it. Raises `oauth.access_token_issued`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `client` is not the one the token
    ///   goes to.
    /// - [`DomainError::Validation`] when `client` takes opaque tokens,
    ///   which the gateway cannot read at a tunnel, or `route` opens no
    ///   signed-in tunnel or is not active.
    pub fn issue_for_tunnel(
        params: IssueAccessTokenParams,
        client: &OAuthClient<T>,
        route: &StreamRoute<T>,
    ) -> Result<Self, DomainError> {
        if *client.id() != params.client_id {
            return Err(DomainError::forbidden(message!(
                "oauth-the-token-goes-to-another-client",
                "the token goes to another client"
            )));
        }
        ensure_tunnel_for(client, route)?;
        let mut token = Self::issue(params);
        token.audience = AccessAudience::StreamRoute(*route.id());
        Ok(token)
    }

    /// Issues a token to `client` for itself, with client credentials, for
    /// `scopes`. Raises `oauth.access_token_issued`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `client` is revoked, public, or
    ///   was not given client credentials.
    /// - [`DomainError::Forbidden`] when a scope is not one `client` may ask
    ///   for.
    pub fn for_client(
        issue: TokenIssue,
        client: &OAuthClient<T>,
        scopes: Vec<Scope>,
    ) -> Result<Self, DomainError> {
        let may = client.is_active()
            && !client.is_public()
            && client.supports_grant_type(GrantType::ClientCredentials);
        if !may {
            return Err(DomainError::forbidden(message!(
                "oauth-this-client-may-not-use-client",
                "this client may not use client credentials"
            )));
        }
        if let Some(scope) = client.first_unallowed_scope(&scopes) {
            return Err(DomainError::forbidden(message!(
                "oauth-this-client-was-not-given-the",
                format!("this client was not given the scope {}", scope.as_str())
            )));
        }
        let grant = Grant {
            client_id: *client.id(),
            subject: TokenSubject::Client,
            scopes,
            audience: AccessAudience::Holder,
            delegation: Vec::new(),
        };
        Ok(Self::issued(issue, grant))
    }

    /// Issues the token `exchange` allowed. Raises
    /// `oauth.access_token_issued` and `oauth.token_exchanged`.
    #[must_use]
    pub fn exchanged(issue: TokenIssue, exchange: &TokenExchange) -> Self {
        let grant = Grant {
            client_id: *exchange.client_id(),
            subject: exchange.subject(),
            scopes: exchange.scopes().to_vec(),
            audience: exchange.audience(),
            delegation: exchange.delegation().to_vec(),
        };
        let mut token = Self::issued(issue, grant);
        let (audience_id, audience_label) = exchange.audience_named();
        token.raised.raise(TokenExchanged {
            client_id: token.client_id,
            client_label: exchange.client_label().clone(),
            audience_id,
            audience_label: audience_label.clone(),
            occurred_at: token.created_at,
        });
        token
    }

    /// A token issued now, having raised its issue.
    fn issued(issue: TokenIssue, grant: Grant) -> Self {
        let now = crate::shared::clock::now();
        let mut token = Self {
            token_hash: issue.token_hash,
            client_id: grant.client_id,
            subject: grant.subject,
            scopes: grant.scopes,
            audience: grant.audience,
            delegation: grant.delegation,
            binding: issue.binding,
            created_at: now,
            expires_at: issue.lifetime.ends_after(now),
            revocation: Revocation::InForce,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        token.raised.raise(AccessTokenIssued {
            client_id: token.client_id,
            scope_count: token.scopes.len(),
            occurred_at: now,
        });
        token
    }

    /// Rebuilds an access token from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the token expires
    ///   before it was issued.
    /// - [`DomainError::Infrastructure`] when the row says the token was
    ///   revoked before it was issued.
    pub fn reconstitute(row: AccessTokenRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            token_hash: row.token_hash,
            client_id: row.client_id,
            subject: row.subject,
            scopes: row.scopes,
            audience: row.audience,
            delegation: row.delegation,
            binding: row.binding,
            created_at: row.created_at,
            expires_at: row.expires_at,
            revocation: row.revocation,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &AccessTokenRow) -> Result<(), DomainError> {
        RowCheck::of("access token")
            .holds(
                row.created_at < row.expires_at,
                "expires before it was issued",
            )
            .in_order_if(
                row.created_at,
                row.revocation.revoked_at(),
                "revoked before it was issued",
            )
            .holds(
                tunnel_holds_a_person(row),
                "meant for a tunnel but acting for no person",
            )
            .finish()
    }

    /// The token's hash.
    #[must_use]
    pub fn token_hash(&self) -> &TokenHash {
        &self.token_hash
    }

    /// The client the token was issued to.
    #[must_use]
    pub fn client_id(&self) -> &OAuthClientId {
        &self.client_id
    }

    /// Whom the token acts for.
    #[must_use]
    pub fn subject(&self) -> TokenSubject {
        self.subject
    }

    /// Whom the token is meant for.
    #[must_use]
    pub fn audience(&self) -> AccessAudience {
        self.audience
    }

    /// Who acts for its subject, outermost first. Empty when nobody does.
    #[must_use]
    pub fn delegation(&self) -> &[ActingParty] {
        &self.delegation
    }

    /// What the token must be presented with.
    #[must_use]
    pub fn binding(&self) -> &SenderBinding {
        &self.binding
    }

    /// Whether it was issued to the client `client_id` names.
    #[must_use]
    pub fn belongs_to(&self, client_id: &OAuthClientId) -> bool {
        self.client_id == *client_id
    }

    /// Whether the client `client_id` names was handed the token: as its
    /// holder, or as the audience it was exchanged for.
    #[must_use]
    pub fn reaches(&self, client_id: &OAuthClientId) -> bool {
        self.belongs_to(client_id) || self.audience == AccessAudience::Client(*client_id)
    }

    /// What the token says about itself at `now`. A token that does not
    /// work says only that.
    #[must_use]
    pub fn introspect(&self, now: OffsetDateTime) -> Introspection {
        if !self.is_usable_at(now) {
            return Introspection::Inactive;
        }
        Introspection::Active {
            client_id: self.client_id,
            subject: self.subject,
            scopes: self.scopes.clone(),
            issued_at: self.created_at,
            expires_at: self.expires_at,
            binding: self.binding.clone(),
            delegation: self.delegation.clone(),
        }
    }

    /// The scopes the user gave.
    #[must_use]
    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// When the token was issued.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When the token expires.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// When the token was revoked, if it was.
    #[must_use]
    pub fn revoked_at(&self) -> Option<OffsetDateTime> {
        self.revocation.revoked_at()
    }

    /// Whether the token may still sign in a request at `now`.
    ///
    /// A revoked token and an expired one both say no.
    #[must_use]
    pub fn is_usable_at(&self, now: OffsetDateTime) -> bool {
        !self.revocation.is_revoked() && now < self.expires_at
    }

    /// Refuses the token for a request at `now` that proved `proof`: one
    /// that does not work, or lacks the key or certificate the token is
    /// bound to.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Unauthorized`] when the token is revoked or
    ///   expired, or `proof` lacks what it is bound to.
    pub fn ensure_usable_with(
        &self,
        proof: &PresentedProof,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        if !self.is_usable_at(now) {
            return Err(DomainError::unauthorized(message!(
                "oauth-this-access-token-is-revoked-or",
                "this access token is revoked or expired"
            )));
        }
        self.binding.ensure_admits(proof)
    }

    /// Whether the grant covers `scope`.
    #[must_use]
    pub fn grants(&self, scope: &Scope) -> bool {
        self.scopes.contains(scope)
    }

    /// Revokes the token.
    ///
    /// Revoking it again keeps the first time, since the token has not
    /// worked since then.
    pub fn revoke(&mut self) {
        if self.revocation.is_revoked() {
            return;
        }
        self.revocation = Revocation::Revoked {
            at: crate::shared::clock::now(),
        };
    }

    /// Revokes the token at the request of `client`, the one holding it
    /// (RFC 7009), and raises `oauth.token_revoked`. A token revoked
    /// already keeps the first time and raises nothing again.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `client` does not hold the token:
    ///   a client ends only its own.
    pub fn revoke_by_holder(&mut self, client: &OAuthClient<T>) -> Result<(), DomainError> {
        if !self.belongs_to(client.id()) {
            return Err(DomainError::forbidden(message!(
                "oauth-only-the-client-holding-a-token",
                "only the client holding a token may revoke it"
            )));
        }
        if self.revocation.is_revoked() {
            return Ok(());
        }
        let now = crate::shared::clock::now();
        self.revocation = Revocation::Revoked { at: now };
        self.raised.raise(TokenRevoked {
            client_id: self.client_id,
            client_label: EventLabel::of(client.name().as_str()),
            occurred_at: now,
        });
        Ok(())
    }
}

impl<T: TenantScope> Raises for AccessToken<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

/// Whether `row`, when meant for a tunnel, acts for a person: only a
/// person's grant asks for a tunnel, and a tunnel admits people by policy.
fn tunnel_holds_a_person(row: &AccessTokenRow) -> bool {
    match row.audience {
        AccessAudience::StreamRoute(_) => matches!(row.subject, TokenSubject::Person(_)),
        AccessAudience::Holder | AccessAudience::Client(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::oauth::clients::client::NewOAuthClient;
    use crate::domains::oauth::clients::credential::ClientCredential;
    use crate::domains::oauth::clients::settings::{AccessTokenFormat, ClientSettings};
    use crate::domains::oauth::grants::token_binding::{
        JwkThumbprint, PresentedCertificate, ProvenKey,
    };
    use crate::domains::routing::fixtures::routing_admin;
    use crate::domains::routing::matching::host::RouteHosts;
    use crate::domains::routing::policy::RoutePolicy;
    use crate::domains::routing::stream::access::StreamAccess;
    use crate::domains::routing::stream::{
        CreateStreamRouteParams, ListenPort, StreamBackend, StreamPolicy, StreamProtocol,
        StreamTimeouts,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{ClientId, RedirectUri};

    fn scope(value: &str) -> Scope {
        Scope::new(value).unwrap()
    }

    fn token(seconds: i64) -> AccessToken<ResolvedTenant> {
        bound_token(seconds, SenderBinding::Bearer)
    }

    fn bound_token(seconds: i64, binding: SenderBinding) -> AccessToken<ResolvedTenant> {
        AccessToken::issue(IssueAccessTokenParams {
            token_hash: TokenHash::from_stored("hash".to_owned()),
            client_id: OAuthClientId::new(),
            user_id: UserId::new(),
            scopes: vec![scope("openid"), scope("email")],
            lifetime: Lifetime::seconds(seconds).unwrap(),
            binding,
        })
    }

    /// The row `token` is stored as.
    fn row_of(token: &AccessToken<ResolvedTenant>) -> AccessTokenRow {
        AccessTokenRow {
            token_hash: token.token_hash.clone(),
            client_id: token.client_id,
            subject: token.subject,
            scopes: token.scopes.clone(),
            audience: token.audience,
            delegation: token.delegation.clone(),
            binding: token.binding.clone(),
            created_at: token.created_at,
            expires_at: token.expires_at,
            revocation: token.revocation,
        }
    }

    /// A token issued for an hour is usable right away.
    #[test]
    fn a_fresh_token_is_usable() {
        let token = token(3600);
        assert!(token.is_usable_at(crate::shared::clock::now()));
    }

    /// At its exact expiry time a token is not usable.
    #[test]
    fn a_token_does_not_outlive_its_window() {
        let token = token(3600);
        assert!(!token.is_usable_at(token.expires_at()));
    }

    /// A token revoked with most of its hour left stops working at once.
    #[test]
    fn a_revoked_token_is_unusable_within_its_window() {
        let mut token = token(3600);
        token.revoke();
        assert!(!token.is_usable_at(crate::shared::clock::now()));
    }

    /// A token is revoked twice. It keeps the first revoke time, when it
    /// really stopped working.
    #[test]
    fn revoking_twice_keeps_the_first_revocation() {
        let mut token = token(3600);
        token.revoke();
        let first = token.revoked_at();
        token.revoke();
        assert_eq!(token.revoked_at(), first);
    }

    /// A token for `openid` and `email` covers `email` but not `profile`.
    #[test]
    fn a_grant_covers_only_its_consented_scopes() {
        let token = token(3600);
        assert!(token.grants(&scope("email")));
        assert!(!token.grants(&scope("profile")));
    }

    /// A token keeps the hash, client, user and scopes it was issued with. A
    /// presented token is found by its hash, so any of these read back wrong
    /// would let the wrong caller in.
    #[test]
    fn a_token_names_the_caller_the_user_and_the_scopes_it_was_issued_for() {
        let client = OAuthClientId::new();
        let user = UserId::new();

        let token = AccessToken::<ResolvedTenant>::issue(IssueAccessTokenParams {
            token_hash: TokenHash::from_stored("hash".to_owned()),
            client_id: client,
            user_id: user,
            scopes: vec![scope("openid"), scope("email")],
            lifetime: Lifetime::seconds(3600).unwrap(),
            binding: SenderBinding::Bearer,
        });

        assert_eq!(token.token_hash().as_str(), "hash");
        assert_eq!(*token.client_id(), client);
        assert_eq!(token.subject(), TokenSubject::Person(user));
        assert_eq!(token.scopes(), &[scope("openid"), scope("email")]);
        assert_eq!(token.audience(), AccessAudience::Holder);
    }

    /// A stolen token is revoked five minutes from now on a frozen clock. It
    /// reports exactly that time, so an audit can tell when it stopped.
    #[test]
    fn revoking_a_token_records_when_it_happened() {
        let mut token = token(3600);
        assert_eq!(token.revoked_at(), None);

        let revoked_at = crate::shared::clock::now() + time::Duration::minutes(5);
        let _frozen = crate::shared::clock::freeze(revoked_at);
        token.revoke();

        assert_eq!(token.revoked_at(), Some(revoked_at));
    }

    /// A stored token says it was revoked one second before it was issued.
    /// It is refused as corrupt.
    #[test]
    fn a_stored_token_revoked_before_it_was_issued_is_refused() {
        let token = token(3600);
        let row = AccessTokenRow {
            revocation: Revocation::Revoked {
                at: token.created_at - time::Duration::SECOND,
            },
            ..row_of(&token)
        };

        assert!(refused_as_corrupt(
            &AccessToken::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A client is issued a token for `openid` and `email`. The issue is
    /// raised with the count of two scopes.
    #[test]
    fn issuing_raises_oauth_access_token_issued() {
        let mut token = token(3600);

        let events = raised(&mut token);

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "oauth.access_token_issued"
        );
        assert_eq!(events[0].payload().get("scope_count"), Some("2"));
    }

    /// A token is read back from storage and then revoked. Neither raises
    /// anything: loading is no change, and a revoke is not recorded here.
    #[test]
    fn a_token_read_back_from_storage_has_raised_nothing() {
        let token = token(3600);

        let mut read_back = AccessToken::<ResolvedTenant>::reconstitute(row_of(&token)).unwrap();
        read_back.revoke();

        assert!(raised_names(&mut read_back).is_empty());
    }

    /// A resource server asks about a working token and gets its facts;
    /// about a revoked one, only that it does not work.
    #[test]
    fn introspection_tells_only_a_working_tokens_facts() {
        let mut token = token(3600);
        let now = crate::shared::clock::now();

        let active = token.introspect(now);
        token.revoke();

        assert!(matches!(active, Introspection::Active { .. }));
        assert_eq!(token.introspect(now), Introspection::Inactive);
    }

    /// A machine client with client credentials gets a token for itself.
    #[test]
    fn a_machine_client_gets_a_token_for_itself() {
        let client = machine(GrantType::ClientCredentials);

        let token =
            AccessToken::<ResolvedTenant>::for_client(issue_terms(), &client, vec![scope("read")])
                .unwrap();

        assert_eq!(token.subject(), TokenSubject::Client);
        assert!(token.belongs_to(client.id()));
    }

    /// A code-only client cannot obtain a client-credentials token. A client
    /// with that grant still cannot request an unregistered scope.
    #[test]
    fn client_credentials_need_the_grant_and_its_scopes() {
        let code_only = machine(GrantType::AuthorizationCode);
        let machine = machine(GrantType::ClientCredentials);

        let no_grant = AccessToken::<ResolvedTenant>::for_client(issue_terms(), &code_only, vec![]);
        let wider = AccessToken::<ResolvedTenant>::for_client(
            issue_terms(),
            &machine,
            vec![scope("admin")],
        );

        assert!(matches!(no_grant, Err(DomainError::Forbidden(_))));
        assert!(matches!(wider, Err(DomainError::Forbidden(_))));
    }

    /// A DPoP-bound access token rejects a request with no proof as
    /// unauthorized. Proving its bound key makes the token usable.
    #[test]
    fn a_bound_token_is_usable_only_with_its_proof() {
        let anns_key = JwkThumbprint::new("a".repeat(43)).unwrap();
        let token = bound_token(3600, SenderBinding::DpopKey(anns_key.clone()));
        let now = crate::shared::clock::now();
        let with_key = PresentedProof {
            dpop: ProvenKey::Proved(anns_key),
            certificate: PresentedCertificate::NotShown,
        };

        let stolen = token.ensure_usable_with(&PresentedProof::nothing(), now);

        assert!(matches!(stolen, Err(DomainError::Unauthorized(_))));
        assert!(token.ensure_usable_with(&with_key, now).is_ok());
    }

    /// A revoked token is refused whatever it is presented with.
    #[test]
    fn a_revoked_token_is_refused_with_any_proof() {
        let mut token = token(3600);
        token.revoke();

        let result =
            token.ensure_usable_with(&PresentedProof::nothing(), crate::shared::clock::now());

        assert!(matches!(result, Err(DomainError::Unauthorized(_))));
    }

    /// The robot revokes its own token. It stops working and the revoke is
    /// recorded once; revoking it again records nothing more.
    #[test]
    fn the_holder_revoking_raises_oauth_token_revoked() {
        let robot = machine(GrantType::ClientCredentials);
        let mut token =
            AccessToken::<ResolvedTenant>::for_client(issue_terms(), &robot, vec![scope("read")])
                .unwrap();
        let _ = raised(&mut token);

        token.revoke_by_holder(&robot).unwrap();
        token.revoke_by_holder(&robot).unwrap();

        assert!(token.revoked_at().is_some());
        assert_eq!(raised_names(&mut token), ["oauth.token_revoked"]);
    }

    /// Mallory's client cannot revoke the robot client's token. The forbidden
    /// attempt leaves its revocation time unset.
    #[test]
    fn another_client_cannot_revoke_a_token() {
        let robot = machine(GrantType::ClientCredentials);
        let mallory = machine(GrantType::ClientCredentials);
        let mut token =
            AccessToken::<ResolvedTenant>::for_client(issue_terms(), &robot, vec![scope("read")])
                .unwrap();

        let result = token.revoke_by_holder(&mallory);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(token.revoked_at(), None);
    }

    /// An hour's bearer token, as the token endpoint picks it.
    fn issue_terms() -> TokenIssue {
        TokenIssue {
            token_hash: TokenHash::from_stored("hash".to_owned()),
            lifetime: Lifetime::seconds(3600).unwrap(),
            binding: SenderBinding::Bearer,
        }
    }

    /// The Acme CLI, a client whose tokens are written as `format`.
    fn cli(format: AccessTokenFormat) -> OAuthClient<ResolvedTenant> {
        OAuthClient::create(
            NewOAuthClient {
                id: OAuthClientId::new(),
                client_id_value: ClientId::new("acme_cli").unwrap(),
                credential: ClientCredential::secret(TokenHash::from_stored("s".to_owned())),
                name: crate::test_support::builders::label("Acme CLI"),
                redirect_uris: vec![RedirectUri::new("https://cli.acme.example/cb").unwrap()],
                post_logout_redirect_uris: Vec::new(),
                grant_types: vec![GrantType::AuthorizationCode],
                scopes: Vec::new(),
                settings: ClientSettings {
                    token_format: format,
                    ..ClientSettings::platform_defaults()
                },
            },
            &crate::domains::oauth::control::tests::key_admin(),
        )
        .unwrap()
    }

    /// The SSH port, checking `policy` on the wire and letting in `access`.
    fn ssh(policy: StreamPolicy, access: StreamAccess) -> StreamRoute<ResolvedTenant> {
        StreamRoute::create(
            CreateStreamRouteParams {
                name: crate::test_support::builders::label("ssh"),
                protocol: StreamProtocol::Tcp,
                listen_port: ListenPort::new(2222).unwrap(),
                sni: RouteHosts::Any,
                policy,
                access,
                backends: vec![StreamBackend::new("ssh.internal", 22, 100).unwrap()],
                timeouts: StreamTimeouts::default(),
            },
            &routing_admin(),
        )
        .unwrap()
    }

    /// The SSH port's signed-in tunnel, for signed-in people.
    fn ssh_tunnel() -> StreamRoute<ResolvedTenant> {
        ssh(
            StreamPolicy::Tunnel,
            StreamAccess::People(RoutePolicy::Authenticated),
        )
    }

    /// Ann's grant to `client`.
    fn anns_grant(client: &OAuthClient<ResolvedTenant>) -> IssueAccessTokenParams {
        IssueAccessTokenParams {
            token_hash: TokenHash::from_stored("hash".to_owned()),
            client_id: *client.id(),
            user_id: UserId::new(),
            scopes: vec![scope("openid")],
            lifetime: Lifetime::seconds(300).unwrap(),
            binding: SenderBinding::Bearer,
        }
    }

    /// Ann's CLI asks for a token for the SSH tunnel. It is meant for that
    /// route alone.
    #[test]
    fn a_tunnel_token_is_meant_for_its_route() {
        let client = cli(AccessTokenFormat::Jwt);
        let route = ssh_tunnel();

        let token = AccessToken::issue_for_tunnel(anns_grant(&client), &client, &route).unwrap();

        assert_eq!(token.audience(), AccessAudience::StreamRoute(*route.id()));
    }

    /// Issuing a tunnel token for a public route or a disabled tunnel fails
    /// validation.
    #[test]
    fn a_route_without_an_open_tunnel_gets_no_token() {
        let client = cli(AccessTokenFormat::Jwt);
        let public = ssh(StreamPolicy::Public, StreamAccess::AnyHolder);
        let mut closed = ssh_tunnel();
        closed.disable(&routing_admin()).unwrap();

        for route in [public, closed] {
            let minted = AccessToken::issue_for_tunnel(anns_grant(&client), &client, &route);

            assert!(matches!(minted, Err(DomainError::Validation(_))));
        }
    }

    /// Issuing a tunnel token to a client configured for opaque access tokens
    /// fails validation.
    #[test]
    fn an_opaque_client_gets_no_tunnel_token() {
        let client = cli(AccessTokenFormat::Opaque);

        let minted = AccessToken::issue_for_tunnel(anns_grant(&client), &client, &ssh_tunnel());

        assert!(matches!(minted, Err(DomainError::Validation(_))));
    }

    /// Issuing a tunnel token with a grant naming a different client is
    /// forbidden.
    #[test]
    fn a_tunnel_token_goes_to_its_own_client_only() {
        let client = cli(AccessTokenFormat::Jwt);
        let other = cli(AccessTokenFormat::Jwt);

        let minted = AccessToken::issue_for_tunnel(anns_grant(&other), &client, &ssh_tunnel());

        assert!(matches!(minted, Err(DomainError::Forbidden(_))));
    }

    /// A stored tunnel token whose subject is a client instead of a person
    /// is refused as corrupt.
    #[test]
    fn a_stored_tunnel_token_acting_for_no_person_is_refused() {
        let client = cli(AccessTokenFormat::Jwt);
        let token =
            AccessToken::issue_for_tunnel(anns_grant(&client), &client, &ssh_tunnel()).unwrap();
        let row = AccessTokenRow {
            subject: TokenSubject::Client,
            ..row_of(&token)
        };

        assert!(refused_as_corrupt(
            &AccessToken::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// A confidential client using `grant`, which may ask for `read`.
    fn machine(grant: GrantType) -> OAuthClient<ResolvedTenant> {
        OAuthClient::create(
            NewOAuthClient {
                id: OAuthClientId::new(),
                client_id_value: ClientId::new("robot").unwrap(),
                credential: ClientCredential::secret(TokenHash::from_stored("s".to_owned())),
                name: crate::test_support::builders::label("Robot"),
                redirect_uris: vec![RedirectUri::new("https://robot.example/cb").unwrap()],
                post_logout_redirect_uris: Vec::new(),
                grant_types: vec![grant],
                scopes: vec![scope("read")],
                settings: ClientSettings::platform_defaults(),
            },
            &crate::domains::oauth::control::tests::key_admin(),
        )
        .unwrap()
    }
}
