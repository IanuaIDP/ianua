//! What federation requests carry: the tenant's federation addresses, the
//! browser a logout comes through, and SAML messages as a peer sent them
//! through the browser, read by binding.
//!
//! Reading a message only takes it apart. Who sent it, whether its
//! signature holds and what it may do are the use case's questions.

use axum::extract::{FromRequest, FromRequestParts, Path, Request};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use ianua_app::auditor::RequestAuditor;
use ianua_app::ports::federation::{InboundSamlMessage, RedirectSignature, SamlBinding};
use ianua_app::services::authentication::logout_browser::LogoutBrowser;
use ianua_app::use_cases::federation::idp::{ReceiveSignInRequest, SamlSignInTrigger};
use ianua_domain::message;
use ianua_domain::types::SamlArrivalId;

use crate::dto::federation::messages::{SamlForm, SamlMessageBody, SsoAnswerBody};
use crate::dto::federation::site::FederationSite;
use crate::error::ApiError;
use crate::extractors::callers::{PathSlugs, TenantCaller};
use crate::extractors::form::{Form, FormRefusal};
use crate::extractors::json::{BodyRejection, Json};
use crate::extractors::paths::federation::ConnectionPath;
use crate::extractors::public_tenant::PublicTenant;
use crate::state::ApiState;

/// A connection's public federation addresses and the connection route.
pub(crate) struct ConnectionSite {
    /// The service-provider and identity-provider addresses for this tenant.
    pub site: FederationSite,
    /// The connection named after the tenant's route segments.
    pub path: ConnectionPath,
}

impl FromRequestParts<ApiState> for ConnectionSite {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let site = FederationSite::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;
        let Path(path) = Path::<ConnectionPath>::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;
        Ok(Self { site, path })
    }
}

impl FromRequestParts<ApiState> for FederationSite {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let slugs = PathSlugs::of(parts, state).await?;
        Ok(Self::new(
            &state.federation.app_base_url,
            slugs.organization()?.clone(),
            slugs.tenant()?.clone(),
        ))
    }
}

/// The browser a peer's logout request came through: signed in to the
/// tenant, so the logout may end its session, or not.
pub(crate) struct LogoutVisitor {
    /// The browser, and the session it holds if any.
    pub browser: LogoutBrowser,
    /// Records what the request changes.
    pub auditor: RequestAuditor,
}

impl FromRequestParts<ApiState> for LogoutVisitor {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        if let Ok(tenant) = TenantCaller::from_request_parts(parts, state).await {
            return Ok(Self {
                browser: LogoutBrowser::SignedIn(Box::new(tenant.caller)),
                auditor: tenant.auditor,
            });
        }
        let tenant = PublicTenant::from_request_parts(parts, state).await?;
        Ok(Self {
            browser: LogoutBrowser::SignedOut(tenant.tenant),
            auditor: tenant.auditor,
        })
    }
}

/// Whether a peer sent a request or an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SamlMessageKind {
    /// A `SAMLRequest`.
    Request,
    /// A `SAMLResponse`.
    Response,
}

/// A SAML message a peer sent, taken apart by its binding.
pub(crate) struct ArrivedSamlMessage {
    /// Whether it is a request or an answer.
    pub kind: SamlMessageKind,
    /// The message, as the use case reads it.
    pub message: InboundSamlMessage,
    /// What the peer wants back with the answer.
    pub relay_state: Option<String>,
}

impl TryFrom<&SamlMessageBody> for ArrivedSamlMessage {
    type Error = ApiError;

    fn try_from(body: &SamlMessageBody) -> Result<Self, ApiError> {
        match body {
            SamlMessageBody::Redirect { query } => from_query(query),
            SamlMessageBody::Post {
                message,
                relay_state,
            } => Ok(Self {
                kind: SamlMessageKind::Request,
                message: InboundSamlMessage {
                    binding: SamlBinding::Post,
                    message: message.clone(),
                },
                relay_state: relay_state.clone(),
            }),
        }
    }
}

/// The SAML parameters of a redirect query.
#[derive(Default)]
struct RedirectFields {
    request: Option<String>,
    response: Option<String>,
    relay_state: Option<String>,
    sig_alg: Option<String>,
    signature: Option<String>,
}

/// The SAML parameters `raw` carries, decoded. Anything else is left out.
fn redirect_fields(raw: &str) -> RedirectFields {
    let mut fields = RedirectFields::default();
    for (name, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        let slot = match name.as_ref() {
            "SAMLRequest" => &mut fields.request,
            "SAMLResponse" => &mut fields.response,
            "RelayState" => &mut fields.relay_state,
            "SigAlg" => &mut fields.sig_alg,
            "Signature" => &mut fields.signature,
            _ => continue,
        };
        *slot = Some(value.into_owned());
    }
    fields
}

/// The message the HTTP-Redirect query `raw` carries.
fn from_query(raw: &str) -> Result<ArrivedSamlMessage, ApiError> {
    let fields = redirect_fields(raw);
    let (kind, message) = request_or_response(fields.request, fields.response)?;
    let signature = redirect_signature(fields.sig_alg, fields.signature, raw)?;
    Ok(ArrivedSamlMessage {
        kind,
        message: InboundSamlMessage {
            binding: SamlBinding::Redirect(signature),
            message,
        },
        relay_state: fields.relay_state,
    })
}

/// Which of `request` and `response` was sent, exactly one.
fn request_or_response(
    request: Option<String>,
    response: Option<String>,
) -> Result<(SamlMessageKind, String), ApiError> {
    match (request, response) {
        (Some(message), None) => Ok((SamlMessageKind::Request, message)),
        (None, Some(message)) => Ok((SamlMessageKind::Response, message)),
        (Some(_), Some(_)) | (None, None) => Err(ApiError::validation(message!(
            "api-send-exactly-one-of-samlrequest-and",
            "send exactly one of SAMLRequest and SAMLResponse"
        ))),
    }
}

/// The signature a redirect query carries beside its message: both its
/// parameters, or none.
fn redirect_signature(
    sig_alg: Option<String>,
    signature: Option<String>,
    raw: &str,
) -> Result<RedirectSignature, ApiError> {
    match (sig_alg, signature) {
        (None, None) => Ok(RedirectSignature::Absent),
        (Some(algorithm), Some(signature)) => Ok(RedirectSignature::Present {
            algorithm,
            signature,
            signed_query: raw.to_owned(),
        }),
        (Some(_), None) | (None, Some(_)) => Err(ApiError::validation(message!(
            "api-a-signed-redirect-carries-both-sigalg",
            "a signed redirect carries both SigAlg and Signature"
        ))),
    }
}

/// A SAML message a browser brought in its query string, by the
/// HTTP-Redirect binding: as it arrived, to carry on, and taken apart.
pub(crate) struct RedirectedSamlMessage {
    /// The message as it arrived.
    pub body: SamlMessageBody,
    /// The message taken apart.
    pub arrived: ArrivedSamlMessage,
}

impl<S: Send + Sync> FromRequestParts<S> for RedirectedSamlMessage {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let query = parts.uri.query().unwrap_or_default().to_owned();
        let arrived = from_query(&query)?;
        Ok(Self {
            body: SamlMessageBody::Redirect { query },
            arrived,
        })
    }
}

/// A SAML message a browser posted in a form, by the HTTP-POST binding: as
/// it arrived, to carry on, and taken apart.
pub(crate) struct PostedSamlMessage {
    /// The message as it arrived.
    pub body: SamlMessageBody,
    /// The message taken apart.
    pub arrived: ArrivedSamlMessage,
}

impl<S: Send + Sync> FromRequest<S> for PostedSamlMessage {
    type Rejection = FormRefusal;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Form(form) = Form::<SamlForm>::from_request(req, state).await?;
        let (kind, message) = request_or_response(form.saml_request, form.saml_response)?;
        Ok(Self {
            body: SamlMessageBody::Post {
                message: message.clone(),
                relay_state: form.relay_state.clone(),
            },
            arrived: ArrivedSamlMessage {
                kind,
                message: InboundSamlMessage {
                    binding: SamlBinding::Post,
                    message,
                },
                relay_state: form.relay_state,
            },
        })
    }
}

/// A peer's request the dashboard hands back with its session, taken
/// apart.
pub(crate) struct ForwardedSamlRequest(pub ArrivedSamlMessage);

impl<S: Send + Sync> FromRequest<S> for ForwardedSamlRequest {
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(body) = Json::<SamlMessageBody>::from_request(req, state)
            .await
            .map_err(IntoResponse::into_response)?;
        ArrivedSamlMessage::try_from(&body)
            .and_then(only_requests)
            .map(Self)
            .map_err(IntoResponse::into_response)
    }
}

/// `arrived`, refused when it is an answer rather than a request.
fn only_requests(arrived: ArrivedSamlMessage) -> Result<ArrivedSamlMessage, ApiError> {
    if arrived.kind != SamlMessageKind::Request {
        return Err(ApiError::validation(message!(
            "api-only-a-samlrequest-is-answered-here",
            "only a SAMLRequest is answered here"
        )));
    }
    Ok(arrived)
}

impl TryFrom<ArrivedSamlMessage> for ReceiveSignInRequest {
    type Error = ApiError;

    fn try_from(arrived: ArrivedSamlMessage) -> Result<Self, ApiError> {
        let request = only_requests(arrived)?;
        Ok(Self {
            message: request.message,
            relay_state: request.relay_state,
        })
    }
}

/// The app's sign-in request the dashboard asks to have answered, named by
/// the id it is held by on the server. The message and when it arrived are
/// read from there, never from the browser.
pub(crate) struct SsoAnswer(pub SamlSignInTrigger);

impl<S: Send + Sync> FromRequest<S> for SsoAnswer {
    type Rejection = BodyRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(body) = Json::<SsoAnswerBody>::from_request(req, state).await?;
        Ok(Self(SamlSignInTrigger::Request(SamlArrivalId::from_uuid(
            body.request,
        ))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A redirect query carrying a request and its signature reads as a
    /// signed request whose signature covers the query as it arrived.
    #[test]
    fn a_signed_redirect_request_keeps_the_query_it_arrived_in() {
        let raw = "SAMLRequest=abc%2B&RelayState=xyz&SigAlg=rsa&Signature=sig";

        let Ok(arrived) = from_query(raw) else {
            panic!("a well-formed signed redirect reads");
        };

        assert_eq!(arrived.kind, SamlMessageKind::Request);
        assert_eq!(arrived.message.message, "abc+");
        assert_eq!(arrived.relay_state.as_deref(), Some("xyz"));
        assert_eq!(
            arrived.message.binding,
            SamlBinding::Redirect(RedirectSignature::Present {
                algorithm: "rsa".to_owned(),
                signature: "sig".to_owned(),
                signed_query: raw.to_owned(),
            })
        );
    }

    /// A query with half a signature is refused rather than read as
    /// unsigned.
    #[test]
    fn half_a_signature_is_refused() {
        assert!(from_query("SAMLRequest=abc&SigAlg=rsa").is_err());
    }

    /// A query carrying both a request and an answer is refused.
    #[test]
    fn a_request_and_an_answer_together_are_refused() {
        assert!(from_query("SAMLRequest=a&SAMLResponse=b").is_err());
    }
}
