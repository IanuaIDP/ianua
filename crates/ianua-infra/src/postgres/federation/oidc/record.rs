//! An OIDC sign-in in flight as its row holds it: the port's own value,
//! each part rebuilt through its own constructor, the PKCE verifier kept
//! sealed.

use ianua_app::ports::federation::OidcLoginFlow;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ConnectionId, HttpsUrl, Nonce, SealedSecret, TokenHash};
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const FLOW: Stored = Stored("OIDC sign-in in flight");

/// A sign-in in flight as it is read. The store's checked queries fill it.
pub(super) struct FlowRecord {
    pub(super) connection_id: Uuid,
    pub(super) nonce: String,
    pub(super) sealed_pkce_verifier: String,
    pub(super) redirect_uri: String,
    pub(super) binding_hash: String,
    pub(super) dashboard_hash: String,
}

impl FlowRecord {
    /// The PKCE verifier as it is kept, sealed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the column holds nothing
    /// a sealer wrote.
    pub(super) fn sealed_verifier(&self) -> Result<SealedSecret, DomainError> {
        FLOW.value(
            "sealed PKCE verifier",
            SealedSecret::new(self.sealed_pkce_verifier.as_str()),
        )
    }

    /// The sign-in the record holds, with its verifier opened as
    /// `pkce_verifier`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules.
    pub(super) fn into_flow(self, pkce_verifier: Secret) -> Result<OidcLoginFlow, DomainError> {
        Ok(OidcLoginFlow {
            connection_id: ConnectionId::from_uuid(self.connection_id),
            nonce: FLOW.value("nonce", Nonce::new(self.nonce))?,
            pkce_verifier,
            redirect_uri: FLOW.value("redirect uri", HttpsUrl::new(self.redirect_uri))?,
            binding_hash: TokenHash::from_stored(self.binding_hash),
            dashboard_hash: TokenHash::from_stored(self.dashboard_hash),
        })
    }
}

/// A sign-in in flight's columns, as they are written beside its state,
/// its verifier sealed.
pub(super) struct FlowColumns<'a> {
    pub(super) connection_id: &'a Uuid,
    pub(super) nonce: &'a str,
    pub(super) sealed_pkce_verifier: SealedSecret,
    pub(super) redirect_uri: &'a str,
    pub(super) binding_hash: &'a str,
    pub(super) dashboard_hash: &'a str,
}

impl<'a> FlowColumns<'a> {
    /// The columns `flow` is written to, its verifier as `sealed`.
    pub(super) fn of(flow: &'a OidcLoginFlow, sealed: SealedSecret) -> Self {
        Self {
            connection_id: flow.connection_id.as_uuid(),
            nonce: flow.nonce.as_str(),
            sealed_pkce_verifier: sealed,
            redirect_uri: flow.redirect_uri.as_str(),
            binding_hash: flow.binding_hash.as_str(),
            dashboard_hash: flow.dashboard_hash.as_str(),
        }
    }
}
