//! What the authentication paths name: the tenant a password sign-in is
//! for, one of the caller's passkeys, and the connection single sign-on
//! begins with.

use ianua_app::error::AppError;
use ianua_app::use_cases::authentication::password::LoginTenant;
use ianua_domain::message;
use ianua_domain::shared::config::SlugLimits;
use ianua_domain::types::{ConnectionId, PasskeyId, TenantSlug};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::ApiError;

/// `.../organizations/{org_slug}/tenants/{tenant_slug}/login`.
#[derive(Deserialize)]
pub(crate) struct TenantLoginPath {
    org_slug: String,
    tenant_slug: String,
}

impl TenantLoginPath {
    /// The tenant the sign-in names, by its slugs.
    ///
    /// # Errors
    ///
    /// Returns a not-found refusal when either slug is not a valid one,
    /// worded like the one an unknown tenant gets, so a sign-in cannot tell
    /// a malformed address from an unknown one.
    pub(crate) fn tenant(&self) -> Result<LoginTenant, ApiError> {
        let limits = SlugLimits::default();
        let slug = |value: &str| {
            TenantSlug::new(value, &limits)
                .map_err(|_| ApiError(AppError::NotFound(message!("api-not-found", "not found"))))
        };
        Ok(LoginTenant::Named {
            org_slug: slug(&self.org_slug)?,
            tenant_slug: slug(&self.tenant_slug)?,
        })
    }
}

/// `.../auth/passkeys/{passkey_id}`.
#[derive(Deserialize)]
pub(crate) struct PasskeyPath {
    passkey_id: Uuid,
}

impl PasskeyPath {
    /// The passkey named.
    #[must_use]
    pub(crate) fn passkey(&self) -> PasskeyId {
        PasskeyId::from_uuid(self.passkey_id)
    }
}

/// `.../federation/connections/{id}/login`.
#[derive(Deserialize)]
pub(crate) struct SsoConnectionPath {
    id: Uuid,
}

impl SsoConnectionPath {
    /// The connection single sign-on begins with.
    #[must_use]
    pub(crate) fn connection(&self) -> ConnectionId {
        ConnectionId::from_uuid(self.id)
    }
}
