//! A dashboard sign-in in flight as its row holds it: read back into the
//! port's request, its PKCE verifier opened by the store, and written out
//! from it, the verifier sealed.
//!
//! The request is the port's own value, not an aggregate, so each part is
//! rebuilt through its own constructor; there is no `reconstitute` to call.

use ianua_app::ports::organization::{OrgSsoAwaiting, OrgSsoRequest};
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    ConnectionId, HttpsUrl, Nonce, OrganizationId, SealedSecret, TenantSlug, TokenHash,
};
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const REQUEST: Stored = Stored("organization sign-in request");

/// A sign-in in flight as it is read, its PKCE verifier still sealed. The
/// store's checked queries fill it.
pub(super) struct RequestRecord {
    pub(super) organization_id: Uuid,
    pub(super) connection_id: Uuid,
    pub(super) binding_hash: String,
    pub(super) tenant_slug: Option<String>,
    pub(super) nonce: Option<String>,
    pub(super) pkce_verifier: Option<String>,
    pub(super) redirect_uri: Option<String>,
}

impl RequestRecord {
    /// The organization whose provider the sign-in waits on.
    pub(super) fn organization(&self) -> OrganizationId {
        OrganizationId::from_uuid(self.organization_id)
    }

    /// The PKCE verifier as the record keeps it, sealed, or none for a
    /// SAML sign-in.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the column holds nothing
    /// a sealer could have written.
    pub(super) fn sealed_verifier(&self) -> Result<Option<SealedSecret>, DomainError> {
        self.pkce_verifier
            .as_deref()
            .map(|sealed| REQUEST.value("pkce verifier", SealedSecret::new(sealed)))
            .transpose()
    }

    /// The request the record holds, with `verifier` opened from its sealed
    /// form, each value read through its own checks, the tenant's slug
    /// against `limits`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, or the row holds part of what an OIDC answer is checked
    /// with but not all of it.
    pub(super) fn into_request(
        self,
        verifier: Option<Secret>,
        limits: &DomainLimits,
    ) -> Result<OrgSsoRequest, DomainError> {
        let tenant_slug = self
            .tenant_slug
            .map(|slug| REQUEST.value("tenant slug", TenantSlug::new(slug, &limits.slug)))
            .transpose()?;
        Ok(OrgSsoRequest {
            organization_id: OrganizationId::from_uuid(self.organization_id),
            connection_id: ConnectionId::from_uuid(self.connection_id),
            binding_hash: TokenHash::from_stored(self.binding_hash),
            tenant_slug,
            awaiting: awaiting_from(self.nonce, verifier, self.redirect_uri)?,
        })
    }
}

fn awaiting_from(
    nonce: Option<String>,
    pkce_verifier: Option<Secret>,
    redirect_uri: Option<String>,
) -> Result<OrgSsoAwaiting, DomainError> {
    match (nonce, pkce_verifier, redirect_uri) {
        (None, None, None) => Ok(OrgSsoAwaiting::Saml),
        (Some(nonce), Some(pkce_verifier), Some(redirect_uri)) => Ok(OrgSsoAwaiting::Oidc {
            nonce: REQUEST.value("nonce", Nonce::new(nonce))?,
            pkce_verifier,
            redirect_uri: REQUEST.value("redirect uri", HttpsUrl::new(redirect_uri))?,
        }),
        _ => Err(DomainError::corrupt_row(
            REQUEST.0,
            "part of what an OIDC answer is checked with, but not all of it",
        )),
    }
}

/// A sign-in in flight's columns, as they are written, beside its key and
/// its sealed verifier.
pub(super) struct RequestColumns<'a> {
    pub(super) organization_id: &'a Uuid,
    pub(super) connection_id: &'a Uuid,
    pub(super) binding_hash: &'a str,
    pub(super) tenant_slug: Option<&'a str>,
    pub(super) nonce: Option<&'a str>,
    pub(super) redirect_uri: Option<&'a str>,
}

impl<'a> RequestColumns<'a> {
    /// The columns `request` is written to.
    pub(super) fn of(request: &'a OrgSsoRequest) -> Self {
        let (nonce, redirect_uri) = match &request.awaiting {
            OrgSsoAwaiting::Oidc {
                nonce,
                redirect_uri,
                ..
            } => (Some(nonce.as_str()), Some(redirect_uri.as_str())),
            OrgSsoAwaiting::Saml => (None, None),
        };
        Self {
            organization_id: request.organization_id.as_uuid(),
            connection_id: request.connection_id.as_uuid(),
            binding_hash: request.binding_hash.as_str(),
            tenant_slug: request.tenant_slug.as_ref().map(TenantSlug::as_str),
            nonce,
            redirect_uri,
        }
    }
}

/// The PKCE verifier `request` waits with, or none for a SAML sign-in.
pub(super) fn verifier_of(request: &OrgSsoRequest) -> Option<&Secret> {
    match &request.awaiting {
        OrgSsoAwaiting::Oidc { pkce_verifier, .. } => Some(pkce_verifier),
        OrgSsoAwaiting::Saml => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rebuilding a sign-in with a nonce but no verifier or redirect URI
    /// returns an infrastructure error.
    #[test]
    fn part_of_an_oidc_check_is_refused() {
        let read = awaiting_from(Some("n".repeat(16)), None, None);

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
