//! The client credentials grant at the token endpoint: a machine client
//! gets a token for itself, acting for no person (RFC 6749 4.4).
//!
//! Only a confidential client the admins registered may: a public client
//! proves nothing, and an app that registered itself was never checked.
//! No refresh token follows; the client proves itself again instead (RFC
//! 6749 4.4.3).

use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClient};
use ianua_domain::domains::oauth::clients::lifetimes::TokenTerms;
use ianua_domain::domains::oauth::grants::access_token::{AccessToken, TokenIssue};
use ianua_domain::domains::oauth::grants::jwt_access_token::SignInFacts;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, Issuer, Scope};

use crate::auditor::RequestAuditor;
use crate::error::OrInternal;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::oauth::sender::SenderEvidence;
use crate::use_cases::oauth::token::client_auth::{
    Asking, ClientAuthPorts, ClientProof, authenticated_client,
};
use crate::use_cases::oauth::token::issuing::{
    HandedToken, Issued, IssuedTokens, IssuingPorts, Minting, TokenType, ensure_may_use,
    fresh_access_value, kept_access, proven_binding, terms_for,
};
use crate::use_cases::oauth::token::refusal::{OAuthErrorCode, TokenError};

/// The scopes a machine client asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineScopes {
    /// None named: every scope it was registered with.
    Registered,
    /// The requested subset of the client's registered permissions.
    Named(Vec<Scope>),
}

/// What a machine client presents to get a token for itself.
pub struct ClientCredentialsGrant {
    /// How the client proves itself.
    pub client: ClientProof,
    /// The tenant's issuer.
    pub issuer: Issuer,
    /// What the request carried to prove its holder.
    pub sender: SenderEvidence,
    /// The scopes it asks for.
    pub scopes: MachineScopes,
}

/// The ports [`ClientCredentialsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ClientCredentialsPorts {
    /// How the client proves itself.
    pub client_auth: ClientAuthPorts,
    /// How the token is made and kept.
    pub issuing: IssuingPorts,
}

/// Issues a machine client a token for itself.
pub struct ClientCredentialsUseCase {
    platform: TokenTerms,
    ports: ClientCredentialsPorts,
}

impl ClientCredentialsUseCase {
    /// A use case issuing tokens on the platform's `platform` terms, unless
    /// a client has its own, working through `ports`.
    #[must_use]
    pub fn new(platform: TokenTerms, ports: ClientCredentialsPorts) -> Self {
        Self { platform, ports }
    }

    /// The token `client` gets for `scopes`, bound as `grant` proved.
    async fn issued(
        &self,
        minting: Minting<'_>,
        grant: &ClientCredentialsGrant,
        scopes: Vec<Scope>,
    ) -> Result<(AccessToken<ResolvedTenant>, IssuedTokens), TokenError> {
        let issuing = &self.ports.issuing;
        let (binding, _) =
            proven_binding(issuing, minting.tenant, minting.client, &grant.sender).await?;
        let lifetime = terms_for(minting.client, self.platform).access();
        let (value, token_hash) = fresh_access_value(issuing, minting.client).await?;
        let issue = TokenIssue {
            token_hash,
            lifetime,
            binding,
        };
        let token = machine_token(issue, minting.client, scopes)?;
        let handed = Issued {
            token: &token,
            value,
            audience: minting.client,
            sign_in: SignInFacts::NotStated,
        };
        let access_token = kept_access(issuing, minting, handed).await?;
        let tokens = IssuedTokens {
            token_type: TokenType::of(token.binding()),
            access_token,
            expires_in: lifetime,
            scopes: token.scopes().to_vec(),
            refresh_token: HandedToken::NotIssued,
            id_token: HandedToken::NotIssued,
        };
        Ok((token, tokens))
    }
}

impl Command for ClientCredentialsUseCase {
    type Caller = ScopedTenant;
    type Input = ClientCredentialsGrant;
    type Output = Result<IssuedTokens, TokenError>;

    /// Issues the client `grant` proves, in `tenant`, an access token for
    /// itself. Records `oauth.access_token_issued`, with the client as
    /// actor.
    ///
    /// # Errors
    ///
    /// - `invalid_client` when the client does not prove itself.
    /// - `unauthorized_client` when it is public or was not given client
    ///   credentials.
    /// - `invalid_scope` when it asks for a scope it was not given.
    /// - `invalid_dpop_proof` or `invalid_request` when the client binds
    ///   its tokens and the request proved nothing to bind them to.
    /// - `TokenError::Failed` when signing, saving or auditing fails.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        grant: ClientCredentialsGrant,
    ) -> Result<IssuedTokens, TokenError> {
        let asking = Asking {
            tenant,
            issuer: &grant.issuer,
        };
        let client = authenticated_client(&self.ports.client_auth, asking, &grant.client).await?;
        ensure_may_use(&client, GrantType::ClientCredentials)?;
        ensure_confidential(&client)?;
        let scopes = asked_scopes(&client, &grant.scopes);
        let minting = Minting {
            tenant,
            issuer: &grant.issuer,
            client: &client,
        };
        let (mut token, tokens) = self.issued(minting, &grant, scopes).await?;
        auditor
            .dispatch_by(
                &ActorRef::OAuthClient(*client.id()),
                token.take_events(tenant),
            )
            .await
            .or_internal()?;
        Ok(tokens)
    }
}

/// Refuses a public client: anyone who copied its id from an app would
/// get its tokens.
fn ensure_confidential(client: &OAuthClient<ResolvedTenant>) -> Result<(), TokenError> {
    if !client.is_public() {
        return Ok(());
    }
    Err(TokenError::refused(
        OAuthErrorCode::UnauthorizedClient,
        "a public client may not act as itself",
    ))
}

/// The scopes `asked` names, or every scope `client` was given when it
/// names none.
fn asked_scopes(client: &OAuthClient<ResolvedTenant>, asked: &MachineScopes) -> Vec<Scope> {
    match asked {
        MachineScopes::Registered => client.scopes().to_vec(),
        MachineScopes::Named(scopes) => scopes.clone(),
    }
}

/// The access token `client` gets for itself under `issue`, for `scopes`.
///
/// # Errors
///
/// `invalid_scope` when a scope is not one `client` was given.
fn machine_token(
    issue: TokenIssue,
    client: &OAuthClient<ResolvedTenant>,
    scopes: Vec<Scope>,
) -> Result<AccessToken<ResolvedTenant>, TokenError> {
    AccessToken::for_client(issue, client, scopes).map_err(|_| {
        TokenError::refused(
            OAuthErrorCode::InvalidScope,
            "a scope is not one this client was given",
        )
    })
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::oauth::clients::settings::AccessTokenFormat;
    use ianua_domain::domains::oauth::grants::access_token::TokenSubject;

    use super::*;
    use crate::test_support::oauth::{
        TokenEndpoint, basic_proof, client_with, no_proof, refused_with, stored_client,
        test_issuer, test_terms,
    };
    use crate::test_support::{block_on, test_auditor, test_ctx};

    /// The billing sync, a machine given client credentials.
    fn robot() -> OAuthClient<ResolvedTenant> {
        stored_client("Billing sync", &[GrantType::ClientCredentials])
    }

    /// The endpoint's client asking, with its secret, for `scopes`.
    fn grant(endpoint: &TokenEndpoint, scopes: MachineScopes) -> ClientCredentialsGrant {
        ClientCredentialsGrant {
            client: basic_proof(&endpoint.client),
            issuer: test_issuer(),
            sender: no_proof(),
            scopes,
        }
    }

    /// What `grant` answers at `endpoint`.
    fn issue(
        endpoint: &TokenEndpoint,
        grant: ClientCredentialsGrant,
    ) -> Result<IssuedTokens, TokenError> {
        let use_case = ClientCredentialsUseCase::new(
            test_terms(),
            ClientCredentialsPorts {
                client_auth: endpoint.client_auth(),
                issuing: endpoint.issuing(),
            },
        );
        let auditor = test_auditor(endpoint.audit.clone());
        block_on(use_case.execute(&test_ctx().tenant(), &auditor, grant))
    }

    /// The billing sync proves itself and asks for `read`. It gets a token
    /// acting for itself, with no refresh or ID token, and the token is
    /// recorded.
    #[test]
    fn a_machine_gets_a_token_for_itself() {
        let endpoint = TokenEndpoint::serving(robot());

        let tokens = issue(
            &endpoint,
            grant(
                &endpoint,
                MachineScopes::Named(vec![Scope::new("read").unwrap()]),
            ),
        )
        .unwrap();

        assert!(matches!(tokens.refresh_token, HandedToken::NotIssued));
        assert!(matches!(tokens.id_token, HandedToken::NotIssued));
        assert_eq!(endpoint.tokens.all()[0].subject(), TokenSubject::Client);
        assert_eq!(endpoint.recorded(), ["oauth.access_token_issued"]);
    }

    /// The billing sync names no scope. Its token carries every scope it
    /// was registered with.
    #[test]
    fn no_scope_named_means_every_registered_one() {
        let endpoint = TokenEndpoint::serving(robot());

        let tokens = issue(&endpoint, grant(&endpoint, MachineScopes::Registered)).unwrap();

        assert_eq!(tokens.scopes, endpoint.client.scopes());
    }

    /// The billing sync chose JWT access tokens. It gets one about itself,
    /// signed by the tenant.
    #[test]
    fn a_machine_choosing_jwts_gets_one_about_itself() {
        let client = client_with("Billing sync", &[GrantType::ClientCredentials], |row| {
            row.settings.token_format = AccessTokenFormat::Jwt;
        });
        let endpoint = TokenEndpoint::serving(client);

        issue(&endpoint, grant(&endpoint, MachineScopes::Registered)).unwrap();

        let claims = endpoint.signed_claims();
        assert!(claims[0].contains(endpoint.client.client_id_value().as_str()));
    }

    /// A machine client requesting an unregistered `admin` scope receives
    /// invalid scope, and no token is stored.
    #[test]
    fn a_scope_the_machine_was_not_given_is_refused() {
        let endpoint = TokenEndpoint::serving(robot());

        let result = issue(
            &endpoint,
            grant(
                &endpoint,
                MachineScopes::Named(vec![Scope::new("admin").unwrap()]),
            ),
        );

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidScope));
        assert_eq!(endpoint.tokens.count(), 0);
    }

    /// A client registered only for authorization codes is unauthorized to
    /// use the client-credentials grant.
    #[test]
    fn a_client_without_client_credentials_is_unauthorized() {
        let endpoint =
            TokenEndpoint::serving(stored_client("Portal", &[GrantType::AuthorizationCode]));

        let result = issue(&endpoint, grant(&endpoint, MachineScopes::Registered));

        assert_eq!(
            refused_with(&result),
            Some(OAuthErrorCode::UnauthorizedClient)
        );
    }

    /// A guessed machine-client secret receives invalid client, and no event
    /// is recorded.
    #[test]
    fn a_wrong_secret_is_refused() {
        let endpoint = TokenEndpoint::serving(robot());

        let result = issue(
            &endpoint,
            ClientCredentialsGrant {
                client: ClientProof::BasicSecret {
                    client_id: endpoint.client.client_id_value().clone(),
                    secret: ianua_domain::shared::security::secret::Secret::new("guess"),
                },
                ..grant(&endpoint, MachineScopes::Registered)
            },
        );

        assert_eq!(refused_with(&result), Some(OAuthErrorCode::InvalidClient));
        assert!(endpoint.recorded().is_empty());
    }
}
