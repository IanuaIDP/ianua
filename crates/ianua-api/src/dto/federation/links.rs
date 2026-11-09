//! Link bodies: an account's links to identity providers, and what its
//! holder types again to confirm one.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_app::services::authentication::fresh_proof::ReenteredProof;
use ianua_app::services::authentication::passkey_answer::PresentedAssertion;
use ianua_app::use_cases::federation::links::ReconfirmRequest;
use ianua_domain::domains::federation::link::FederatedLink;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CeremonyId, ConnectionId, PasskeyCredentialId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;

/// What a person gives to prove who they are again, the way they sign in.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(tag = "method", rename_all = "snake_case")]
pub(crate) enum ReenteredProofBody {
    /// Their password, with a code from their second factor when they have
    /// one.
    Password {
        /// The password as typed.
        password: String,
        /// The code their authenticator shows, if they have one.
        #[serde(default)]
        code: Option<String>,
    },
    /// A sign-in link mailed to them and followed just now, for an account
    /// that signs in by its mailbox.
    Mailbox {
        /// The link's token, as followed.
        link: String,
        /// The code their authenticator shows, if they have one.
        #[serde(default)]
        code: Option<String>,
    },
    /// Their passkey's answer to a sign-in challenge opened for them.
    Passkey {
        /// The ceremony the challenge came from.
        ceremony_id: Uuid,
        /// The passkey's id, base64url without padding.
        credential_id: String,
        /// The authenticator's signed answer, base64url without padding.
        response: String,
    },
}

impl TryFrom<ReenteredProofBody> for ReenteredProof {
    type Error = ApiError;

    fn try_from(body: ReenteredProofBody) -> Result<Self, ApiError> {
        match body {
            ReenteredProofBody::Password { password, code } => Ok(Self::Password {
                password: Secret::new(password),
                code,
            }),
            ReenteredProofBody::Mailbox { link, code } => Ok(Self::Mailbox {
                link: Secret::new(link),
                code,
            }),
            ReenteredProofBody::Passkey {
                ceremony_id,
                credential_id,
                response,
            } => Ok(Self::Passkey(PresentedAssertion {
                ceremony_id: CeremonyId::from_uuid(ceremony_id),
                credential_id: PasskeyCredentialId::new(decoded("credential_id", &credential_id)?)
                    .map_err(ApiError::validation)?,
                response: decoded("response", &response)?,
            })),
        }
    }
}

/// The bytes `value` encodes in base64url without padding.
fn decoded(field: &str, value: &str) -> Result<Vec<u8>, ApiError> {
    URL_SAFE_NO_PAD.decode(value).map_err(|_| {
        ApiError::validation(message!(
            "api-is-not-base64url",
            format!("{field} is not base64url")
        ))
    })
}

/// One account's link to a connection's provider.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct LinkResponse {
    /// The connection the provider is reached through.
    #[schema(value_type = String, format = Uuid)]
    pub connection_id: ConnectionId,
    /// The id the provider knows the person by.
    pub subject: String,
    /// When the link was made.
    #[serde(with = "time::serde::rfc3339")]
    pub linked_at: OffsetDateTime,
    /// When its holder last confirmed it.
    #[serde(with = "time::serde::rfc3339")]
    pub confirmed_at: OffsetDateTime,
}

impl From<&FederatedLink<ResolvedTenant>> for LinkResponse {
    fn from(link: &FederatedLink<ResolvedTenant>) -> Self {
        Self {
            connection_id: *link.connection_id(),
            subject: link.subject().as_str().to_owned(),
            linked_at: link.linked_at(),
            confirmed_at: link.confirmed_at(),
        }
    }
}

/// An account's links to identity providers, oldest first.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct LinkListResponse {
    /// Each link.
    pub links: Vec<LinkResponse>,
}

impl From<Vec<FederatedLink<ResolvedTenant>>> for LinkListResponse {
    fn from(links: Vec<FederatedLink<ResolvedTenant>>) -> Self {
        Self {
            links: links.iter().map(LinkResponse::from).collect(),
        }
    }
}

/// Request body for confirming a link again.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ReconfirmLinkBody {
    /// What the holder typed again just now.
    pub proof: ReenteredProofBody,
}

impl ReconfirmLinkBody {
    /// The reconfirmation of the caller's link through `connection_id`.
    ///
    /// # Errors
    ///
    /// - [`ApiError::validation`] when a passkey answer is not base64url or
    ///   names no credential.
    pub(crate) fn through(self, connection_id: ConnectionId) -> Result<ReconfirmRequest, ApiError> {
        Ok(ReconfirmRequest {
            connection_id,
            proof: self.proof.try_into()?,
        })
    }
}
