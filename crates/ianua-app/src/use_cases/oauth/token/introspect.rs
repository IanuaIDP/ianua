//! Token introspection (RFC 7662): a resource server, proving itself as a
//! confidential client, asks whether an access token works and what it
//! carries.
//!
//! A token that does not work says only that: revoked, expired, never
//! issued, its client revoked or its person shut out all answer the same,
//! so a caller learns nothing about tokens it could not use anyway.

use std::sync::Arc;

use ianua_domain::domains::oauth::clients::client::OAuthClient;
use ianua_domain::domains::oauth::grants::access_token::{
    AccessAudience, AccessToken, Introspection, TokenSubject,
};
use ianua_domain::domains::routing::stream::tunnel_audience_of;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Audience, ClientId, Issuer, OAuthClientId};

use crate::error::{AppError, OrInternal};
use crate::ports::identity::UserStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::oauth::presented::{PresentedTokenPorts, presented_access_token};
use crate::use_cases::oauth::token::client_auth::{
    Asking, ClientAuthPorts, ClientProof, authenticated_client,
};
use crate::use_cases::oauth::token::refusal::TokenError;

/// What a resource server asks about a token.
pub struct IntrospectRequest {
    /// How the resource server proves itself.
    pub client: ClientProof,
    /// The tenant's issuer.
    pub issuer: Issuer,
    /// The raw token it asks about.
    pub token: Secret,
}

/// What a token says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntrospectionResult {
    /// It does not work. Why is not said.
    Inactive,
    /// It works, as `facts` says.
    Active {
        /// What the token carries, as the domain reads it.
        facts: Introspection,
        /// The client holding it, by its public id (`client_id`).
        holder: ClientId,
        /// Whom it is meant for (`aud`): a client by its public id, or a
        /// stream route's tunnel.
        audience: Audience,
    },
}

/// The ports [`IntrospectUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct IntrospectPorts {
    /// How the resource server proves itself.
    pub client_auth: ClientAuthPorts,
    /// Finds the token's record.
    pub presented: PresentedTokenPorts,
    /// Where accounts are kept, to see the token's person may still sign
    /// in.
    pub users: Arc<dyn UserStore>,
}

/// Answers what an access token says about itself.
pub struct IntrospectUseCase {
    ports: IntrospectPorts,
}

impl IntrospectUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: IntrospectPorts) -> Self {
        Self { ports }
    }

    /// The active client `id` names, if the tenant still has one.
    async fn active_client(
        &self,
        tenant: &ScopedTenant,
        id: &OAuthClientId,
    ) -> Result<Option<OAuthClient<ResolvedTenant>>, AppError> {
        let client = self
            .ports
            .client_auth
            .client_store
            .find_by_id(tenant, id)
            .await
            .or_internal()?;
        Ok(client.filter(OAuthClient::is_active))
    }

    /// Whether the person `token` acts for, if any, may still sign in.
    async fn person_stands(
        &self,
        tenant: &ScopedTenant,
        token: &AccessToken<ResolvedTenant>,
    ) -> Result<bool, AppError> {
        let TokenSubject::Person(person) = token.subject() else {
            return Ok(true);
        };
        let account = self
            .ports
            .users
            .find_by_id(tenant, &person)
            .await
            .or_internal()?;
        Ok(account.is_some_and(|account| account.can_authenticate()))
    }

    /// Whom `token`, held by `holder`, is meant for: a client while it is
    /// active, or the tunnel of the stream route it was asked for.
    async fn audience_of(
        &self,
        tenant: &ScopedTenant,
        token: &AccessToken<ResolvedTenant>,
        holder: &OAuthClient<ResolvedTenant>,
    ) -> Result<Option<Audience>, AppError> {
        match token.audience() {
            AccessAudience::Holder => client_audience(holder).map(Some),
            AccessAudience::Client(id) => self
                .active_client(tenant, &id)
                .await?
                .map(|client| client_audience(&client))
                .transpose(),
            AccessAudience::StreamRoute(route) => tunnel_audience_of(&route)
                .map(Some)
                .map_err(AppError::from_domain),
        }
    }

    /// What `token` says now, with its holder and audience named, while
    /// both are active clients and its person may sign in.
    async fn answer(
        &self,
        tenant: &ScopedTenant,
        token: &AccessToken<ResolvedTenant>,
    ) -> Result<IntrospectionResult, AppError> {
        let facts = token.introspect(clock::now());
        if facts == Introspection::Inactive || !self.person_stands(tenant, token).await? {
            return Ok(IntrospectionResult::Inactive);
        }
        let Some(holder) = self.active_client(tenant, token.client_id()).await? else {
            return Ok(IntrospectionResult::Inactive);
        };
        let Some(audience) = self.audience_of(tenant, token, &holder).await? else {
            return Ok(IntrospectionResult::Inactive);
        };
        Ok(IntrospectionResult::Active {
            facts,
            holder: holder.client_id_value().clone(),
            audience,
        })
    }
}

impl Query for IntrospectUseCase {
    type Caller = ScopedTenant;
    type Input = IntrospectRequest;
    type Output = Result<IntrospectionResult, TokenError>;

    /// What the token `req` asks about says in `tenant`, for a resource
    /// server that proved itself as a confidential client.
    ///
    /// # Errors
    ///
    /// - `invalid_client` when the caller does not prove itself, or is a
    ///   public client, which proves nothing.
    /// - `TokenError::Failed` when a lookup fails.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        req: IntrospectRequest,
    ) -> Result<IntrospectionResult, TokenError> {
        let asking = Asking {
            tenant,
            issuer: &req.issuer,
        };
        let caller = authenticated_client(&self.ports.client_auth, asking, &req.client).await?;
        if caller.is_public() {
            return Err(TokenError::invalid_client());
        }
        let found = presented_access_token(&self.ports.presented, asking, &req.token).await?;
        let Some(token) = found else {
            return Ok(IntrospectionResult::Inactive);
        };
        Ok(self.answer(tenant, &token).await?)
    }
}

/// `client`'s id, as the audience it is.
///
/// # Errors
///
/// - `AppError::Domain` if the id does not read as an audience, which a
///   client id never does.
fn client_audience(client: &OAuthClient<ResolvedTenant>) -> Result<Audience, AppError> {
    Audience::new(client.client_id_value().as_str())
        .map_err(|refused| AppError::from_domain(DomainError::from(refused)))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::oauth::clients::client::GrantType;
    use ianua_domain::types::Scope;

    use super::*;
    use crate::ports::oauth::OAuthClientStore as _;
    use crate::test_support::identity::{FakeUserStore, stored_user};
    use crate::test_support::oauth::{
        FakeAccessTokenStore, TEST_ACCESS_TOKEN, TokenEndpoint, access_token, basic_proof,
        public_client, stored_client, test_issuer,
    };
    use crate::test_support::{block_on, test_ctx};
    use crate::use_cases::oauth::token::refusal::OAuthErrorCode;

    /// The orders API, a confidential client, asking about a token the
    /// portal holds for Ann.
    struct Fixture {
        endpoint: TokenEndpoint,
        orders: OAuthClient<ResolvedTenant>,
    }

    impl Fixture {
        /// The portal's live token for Ann, and the orders API beside it.
        fn new() -> Self {
            let portal = stored_client("Portal", &[GrantType::AuthorizationCode]);
            let mut endpoint = TokenEndpoint::serving(portal);
            let held = access_token(&endpoint.client, TokenSubject::Person(endpoint.ann));
            endpoint.tokens = Arc::new(FakeAccessTokenStore::holding(&test_ctx().tenant(), held));
            let orders = stored_client("Orders API", &[GrantType::ClientCredentials]);
            block_on(endpoint.clients.save(&test_ctx().tenant(), &orders)).unwrap();
            Self { endpoint, orders }
        }

        /// What `client` is told about the token, with `users` as the
        /// accounts.
        fn ask_as(&self, client: ClientProof, users: Arc<FakeUserStore>) -> IntrospectionResult {
            self.try_as(client, users).unwrap()
        }

        /// What `client` asking about the token answers, with `users` as
        /// the accounts.
        fn try_as(
            &self,
            client: ClientProof,
            users: Arc<FakeUserStore>,
        ) -> Result<IntrospectionResult, TokenError> {
            let use_case = IntrospectUseCase::new(IntrospectPorts {
                client_auth: self.endpoint.client_auth(),
                presented: self.endpoint.presented(),
                users,
            });
            let req = IntrospectRequest {
                client,
                issuer: test_issuer(),
                token: Secret::new(TEST_ACCESS_TOKEN.to_owned()),
            };
            block_on(use_case.execute(&test_ctx().tenant(), req))
        }

        /// What the orders API is told about the token.
        fn ask(&self) -> IntrospectionResult {
            self.ask_as(basic_proof(&self.orders), self.endpoint.users.clone())
        }
    }

    /// The orders API asks about the portal's live token for Ann. It is
    /// active, held by the portal, meant for it, for Ann, with `read`.
    #[test]
    fn a_live_token_is_active_with_its_facts() {
        let fixture = Fixture::new();

        let IntrospectionResult::Active {
            facts,
            holder,
            audience,
        } = fixture.ask()
        else {
            panic!("the live token read as inactive");
        };

        let Introspection::Active {
            subject, scopes, ..
        } = facts
        else {
            panic!("an active answer carried inactive facts");
        };
        assert_eq!(subject, TokenSubject::Person(fixture.endpoint.ann));
        assert!(scopes.contains(&Scope::new("read").unwrap()));
        assert_eq!(&holder, fixture.endpoint.client.client_id_value());
        assert_eq!(audience.as_str(), holder.as_str());
    }

    /// Introspection of a revoked token returns only the inactive result.
    #[test]
    fn a_revoked_token_is_inactive() {
        let fixture = Fixture::new();
        fixture.endpoint.tokens.revoke_all();

        assert_eq!(fixture.ask(), IntrospectionResult::Inactive);
    }

    /// A token whose subject account is deactivated introspects as inactive.
    #[test]
    fn a_token_of_a_deactivated_person_is_inactive() {
        let fixture = Fixture::new();
        let users = Arc::new(FakeUserStore::empty());
        users.add(stored_user(
            fixture.endpoint.ann,
            "ann@acme.example",
            UserStatus::Deactivated,
        ));

        let answer = fixture.ask_as(basic_proof(&fixture.orders), users);

        assert_eq!(answer, IntrospectionResult::Inactive);
    }

    /// A token absent from storage introspects as inactive.
    #[test]
    fn an_unknown_token_is_inactive() {
        let mut fixture = Fixture::new();
        fixture.endpoint.tokens = Arc::new(FakeAccessTokenStore::empty());

        assert_eq!(fixture.ask(), IntrospectionResult::Inactive);
    }

    /// A registered public client receives invalid client when introspecting
    /// a token without credentials.
    #[test]
    fn a_public_client_may_not_introspect() {
        let fixture = Fixture::new();
        let spa = public_client("SPA", &[GrantType::AuthorizationCode]);
        block_on(fixture.endpoint.clients.save(&test_ctx().tenant(), &spa)).unwrap();

        let result = fixture.try_as(
            ClientProof::Nothing {
                client_id: spa.client_id_value().clone(),
            },
            fixture.endpoint.users.clone(),
        );

        assert_eq!(
            result.err().and_then(|refusal| refusal.code()),
            Some(OAuthErrorCode::InvalidClient)
        );
    }

    /// A guessed confidential-client secret receives invalid client when
    /// introspecting a token.
    #[test]
    fn an_unproved_caller_is_refused() {
        let fixture = Fixture::new();

        let result = fixture.try_as(
            ClientProof::BasicSecret {
                client_id: fixture.orders.client_id_value().clone(),
                secret: Secret::new("guess"),
            },
            fixture.endpoint.users.clone(),
        );

        assert_eq!(
            result.err().and_then(|refusal| refusal.code()),
            Some(OAuthErrorCode::InvalidClient)
        );
    }
}
