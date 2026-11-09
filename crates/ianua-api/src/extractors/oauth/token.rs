//! A request at the token endpoint, read into the grant its `grant_type`
//! names (RFC 6749 4.1.3, 4.4.2, 6; RFC 8628 3.4; RFC 8693 2.1), with the
//! resource a person's token is asked for (RFC 8707 2.2).
//!
//! The `DPoP` header is handed on with the method and address the request
//! was sent to, for the app to check. No TLS client certificate reaches the
//! API, so a client whose tokens are bound to one is refused by the app.

use axum::extract::{FromRequest, Request};
use ianua_app::use_cases::oauth::sender::SenderEvidence;
use ianua_app::use_cases::oauth::token::refusal::OAuthErrorCode;
use ianua_app::use_cases::oauth::token::{
    ActorSent, ClientCredentialsGrant, CodeGrant, DeviceCodeGrant, ExchangeGrant, MachineScopes,
    RefreshGrant,
};
use ianua_assembly::oauth::TokenGrant;
use ianua_domain::domains::oauth::grants::refresh_terms::RefreshScopes;
use ianua_domain::domains::oauth::grants::resource::TokenResource;
use ianua_domain::domains::oauth::grants::token_exchange::ExchangeScopes;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ClientId, RedirectUri, Scope};

use crate::error::oauth::OAuthError;
use crate::extractors::oauth::client::client_proof;
use crate::extractors::oauth::dpop::{SentTo, UnusableDpop, dpop_header, evidence};
use crate::extractors::oauth::form::OAuthForm;
use crate::state::ApiState;

/// The token endpoint's path under a tenant's issuer.
const TOKEN_PATH: &str = "/oauth/token";

/// `grant_type` for an authorization code.
const AUTHORIZATION_CODE: &str = "authorization_code";
/// `grant_type` for a refresh token.
const REFRESH_TOKEN: &str = "refresh_token";
/// `grant_type` for client credentials.
const CLIENT_CREDENTIALS: &str = "client_credentials";
/// `grant_type` for a device code.
pub(crate) const DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// `grant_type` for a token exchange.
pub(crate) const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// The only token type exchanged and issued (RFC 8693 3).
pub(crate) const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// Every `grant_type` the token endpoint answers, for discovery to list.
pub(crate) const GRANT_TYPES: [&str; 5] = [
    AUTHORIZATION_CODE,
    REFRESH_TOKEN,
    CLIENT_CREDENTIALS,
    DEVICE_CODE,
    TOKEN_EXCHANGE,
];

/// A request at the token endpoint, read into its grant.
pub(crate) struct TokenRequest(pub TokenGrant);

impl FromRequest<ApiState> for TokenRequest {
    type Rejection = OAuthError;

    async fn from_request(req: Request, state: &ApiState) -> Result<Self, Self::Rejection> {
        let dpop = dpop_header(req.headers()).map_err(unusable_dpop)?;
        let method = req.method().clone();
        let mut form = OAuthForm::from_request(req, state).await?;
        let issuer = form.issuer();
        let to = SentTo {
            method: &method,
            issuer: &issuer,
            path: TOKEN_PATH,
        };
        let sender = evidence(dpop, &to);
        let grant_type = form.required("grant_type")?;
        let grant = match grant_type.as_str() {
            AUTHORIZATION_CODE => TokenGrant::AuthorizationCode(code_grant(&mut form, sender)?),
            REFRESH_TOKEN => TokenGrant::RefreshToken(refresh_grant(&mut form, sender)?),
            CLIENT_CREDENTIALS => TokenGrant::ClientCredentials(machine_grant(&mut form, sender)?),
            DEVICE_CODE => TokenGrant::DeviceCode(device_grant(&mut form, sender)?),
            TOKEN_EXCHANGE => TokenGrant::TokenExchange(exchange_grant(&mut form, sender)?),
            _ => {
                return Err(OAuthError::refused(
                    OAuthErrorCode::UnsupportedGrantType,
                    "this grant_type is not offered",
                ));
            }
        };
        Ok(Self(grant))
    }
}

/// A `DPoP` header that cannot be a proof, refused as one that does not
/// check out.
fn unusable_dpop(_: UnusableDpop) -> OAuthError {
    OAuthError::refused(
        OAuthErrorCode::InvalidDpopProof,
        "send exactly one DPoP proof",
    )
}

/// An authorization code swapped for tokens.
fn code_grant(form: &mut OAuthForm, sender: SenderEvidence) -> Result<CodeGrant, OAuthError> {
    let redirect = form.required("redirect_uri")?;
    Ok(CodeGrant {
        client: client_proof(form)?,
        issuer: form.issuer(),
        sender,
        code: Secret::new(form.required("code")?),
        redirect_uri: RedirectUri::new(redirect)
            .map_err(|_| OAuthError::invalid_request("the redirect_uri is malformed"))?,
        code_verifier: Secret::new(form.required("code_verifier")?),
        resource: resource(form)?,
    })
}

/// A refresh token swapped for new tokens, for the scopes it asks or all
/// of the grant's.
fn refresh_grant(form: &mut OAuthForm, sender: SenderEvidence) -> Result<RefreshGrant, OAuthError> {
    let scopes = match form.take("scope") {
        None => RefreshScopes::AsGranted,
        Some(raw) => RefreshScopes::Narrowed(scope_list(&raw)?),
    };
    Ok(RefreshGrant {
        client: client_proof(form)?,
        issuer: form.issuer(),
        sender,
        refresh_token: Secret::new(form.required("refresh_token")?),
        scopes,
        resource: resource(form)?,
    })
}

/// A machine asking for tokens for itself, for the scopes it asks or all
/// it registered.
fn machine_grant(
    form: &mut OAuthForm,
    sender: SenderEvidence,
) -> Result<ClientCredentialsGrant, OAuthError> {
    let scopes = match form.take("scope") {
        None => MachineScopes::Registered,
        Some(raw) => MachineScopes::Named(scope_list(&raw)?),
    };
    Ok(ClientCredentialsGrant {
        client: client_proof(form)?,
        issuer: form.issuer(),
        sender,
        scopes,
    })
}

/// A device collecting the tokens a person approved.
fn device_grant(
    form: &mut OAuthForm,
    sender: SenderEvidence,
) -> Result<DeviceCodeGrant, OAuthError> {
    Ok(DeviceCodeGrant {
        client: client_proof(form)?,
        issuer: form.issuer(),
        sender,
        device_code: Secret::new(form.required("device_code")?),
        resource: resource(form)?,
    })
}

/// A token exchanged for a narrower one for another client's audience.
fn exchange_grant(
    form: &mut OAuthForm,
    sender: SenderEvidence,
) -> Result<ExchangeGrant, OAuthError> {
    ensure_access_token_type(form, "subject_token_type", TypeAbsent::Refused)?;
    ensure_access_token_type(form, "requested_token_type", TypeAbsent::Allowed)?;
    let actor_token = match form.take("actor_token") {
        None => ActorSent::NotSent,
        Some(actor) => {
            ensure_access_token_type(form, "actor_token_type", TypeAbsent::Refused)?;
            ActorSent::Sent(Secret::new(actor))
        }
    };
    let scopes = match form.take("scope") {
        None => ExchangeScopes::AsSubject,
        Some(raw) => ExchangeScopes::Narrowed(scope_list(&raw)?),
    };
    Ok(ExchangeGrant {
        client: client_proof(form)?,
        issuer: form.issuer(),
        sender,
        subject_token: Secret::new(form.required("subject_token")?),
        actor_token,
        audience: audience(form)?,
        scopes,
    })
}

/// Whether a token type parameter may be left out.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TypeAbsent {
    /// It may: the access token type is meant.
    Allowed,
    /// It may not.
    Refused,
}

/// Refuses a token type parameter `name` naming anything but an access
/// token.
fn ensure_access_token_type(
    form: &mut OAuthForm,
    name: &str,
    absent: TypeAbsent,
) -> Result<(), OAuthError> {
    match (form.take(name), absent) {
        (Some(kind), _) if kind == ACCESS_TOKEN_TYPE => Ok(()),
        (None, TypeAbsent::Allowed) => Ok(()),
        (None, TypeAbsent::Refused) => {
            Err(OAuthError::invalid_request(format!("{name} is required")))
        }
        (Some(_), _) => Err(OAuthError::invalid_request(format!(
            "{name} must be {ACCESS_TOKEN_TYPE}"
        ))),
    }
}

/// The client an exchanged token is for, named by `audience`.
fn audience(form: &mut OAuthForm) -> Result<ClientId, OAuthError> {
    let raw = form.required("audience")?;
    ClientId::new(raw).map_err(|_| {
        OAuthError::refused(
            OAuthErrorCode::InvalidTarget,
            "the audience is not a client id",
        )
    })
}

/// What a person's access token is asked to be meant for, by `resource`
/// (RFC 8707): a stream route's signed-in tunnel, or, sent without one,
/// its client.
///
/// # Errors
///
/// - `invalid_target` when the indicator names no stream route.
fn resource(form: &mut OAuthForm) -> Result<TokenResource, OAuthError> {
    let Some(indicator) = form.take("resource") else {
        return Ok(TokenResource::Holder);
    };
    TokenResource::from_indicator(&indicator).map_err(|_| {
        OAuthError::refused(
            OAuthErrorCode::InvalidTarget,
            "the resource names no stream route",
        )
    })
}

/// The scopes `raw` names, separated by spaces.
///
/// # Errors
///
/// - `invalid_scope` when one is not a scope.
pub(crate) fn scope_list(raw: &str) -> Result<Vec<Scope>, OAuthError> {
    raw.split_whitespace()
        .map(|scope| {
            Scope::new(scope).map_err(|_| {
                OAuthError::refused(OAuthErrorCode::InvalidScope, "a scope is malformed")
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A space-separated scope reads as each scope it names.
    #[test]
    fn a_spaced_scope_reads_as_each_scope() {
        let Ok(scopes) = scope_list("openid  email") else {
            panic!("the scopes are read");
        };

        assert_eq!(scopes.len(), 2);
    }
}
