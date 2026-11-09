//! The member, erasure request, key, passkey, session and cloud an
//! organization request names.

use ianua_app::context::OrgCaller;
use ianua_app::use_cases::organization::privacy::whose::OrgWhose;
use ianua_domain::domains::tenant::provisioning::infrastructure::CloudProvider;
use ianua_domain::message;
use ianua_domain::shared::config::SlugLimits;
use ianua_domain::types::{
    ErasureRequestId, OrgApiKeyId, OrgUserId, PasskeyId, SessionId, TenantSlug,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::ApiError;

/// `.../organizations/{org_slug}/users/{user_id}/...`.
#[derive(Deserialize)]
pub(crate) struct OrgUserPath {
    user_id: Uuid,
}

impl OrgUserPath {
    /// The member named.
    #[must_use]
    pub(crate) fn member(&self) -> OrgUserId {
        OrgUserId::from_uuid(self.user_id)
    }

    /// Whose account a privacy request is about: the caller's own when the
    /// path names the member they are signed in as, another member's
    /// otherwise.
    ///
    /// This says only who the request concerns. Whether the caller may act
    /// on it, for themselves or for another, is the app's question.
    #[must_use]
    pub(crate) fn whose(&self, caller: &OrgCaller) -> OrgWhose {
        let member = self.member();
        if member == *caller.member() {
            return OrgWhose::Own;
        }
        OrgWhose::Member(member)
    }
}

/// `.../organizations/{org_slug}/users/erasure/{id}/...`: one erasure
/// request.
#[derive(Deserialize)]
pub(crate) struct OrgErasurePath {
    id: Uuid,
}

impl OrgErasurePath {
    /// The erasure request named.
    #[must_use]
    pub(crate) fn request(&self) -> ErasureRequestId {
        ErasureRequestId::from_uuid(self.id)
    }
}

/// `.../organizations/{org_slug}/users/{user_id}/tenants/{tenant_slug}`.
#[derive(Deserialize)]
pub(crate) struct OrgUserTenantPath {
    user_id: Uuid,
    tenant_slug: String,
}

impl OrgUserTenantPath {
    /// The member named.
    #[must_use]
    pub(crate) fn member(&self) -> OrgUserId {
        OrgUserId::from_uuid(self.user_id)
    }

    /// The tenant named.
    ///
    /// # Errors
    ///
    /// `422` when the segment is not a valid slug.
    pub(crate) fn tenant(&self) -> Result<TenantSlug, ApiError> {
        TenantSlug::new(&self.tenant_slug, &SlugLimits::default()).map_err(ApiError::validation)
    }
}

/// `.../organizations/{org_slug}/tenants/{tenant_slug}/...`, for a read made
/// under the organization's authority.
#[derive(Deserialize)]
pub(crate) struct OrgTenantPath {
    tenant_slug: String,
}

impl OrgTenantPath {
    /// The tenant named.
    ///
    /// # Errors
    ///
    /// `422` when the segment is not a valid slug.
    pub(crate) fn tenant(&self) -> Result<TenantSlug, ApiError> {
        TenantSlug::new(&self.tenant_slug, &SlugLimits::default()).map_err(ApiError::validation)
    }
}

/// `.../organizations/{org_slug}/api-keys/{key_id}/...`.
#[derive(Deserialize)]
pub(crate) struct OrgApiKeyPath {
    key_id: Uuid,
}

impl OrgApiKeyPath {
    /// The key named.
    #[must_use]
    pub(crate) fn key(&self) -> OrgApiKeyId {
        OrgApiKeyId::from_uuid(self.key_id)
    }
}

/// `.../organizations/{org_slug}/passkeys/{passkey_id}`.
#[derive(Deserialize)]
pub(crate) struct OrgPasskeyPath {
    passkey_id: Uuid,
}

impl OrgPasskeyPath {
    /// The passkey named.
    #[must_use]
    pub(crate) fn passkey(&self) -> PasskeyId {
        PasskeyId::from_uuid(self.passkey_id)
    }
}

/// `.../organizations/{org_slug}/sessions/{session_id}/...`.
#[derive(Deserialize)]
pub(crate) struct OrgSessionPath {
    session_id: Uuid,
}

impl OrgSessionPath {
    /// The session named.
    #[must_use]
    pub(crate) fn session(&self) -> SessionId {
        SessionId::from_uuid(self.session_id)
    }
}

/// `.../organizations/{org_slug}/cloud-accounts/{provider}/...`, the cloud
/// spelled in lower case (`aws`, `gcp`, `azure`, `digitalocean`,
/// `kubernetes`).
#[derive(Deserialize)]
pub(crate) struct CloudProviderPath {
    provider: String,
}

impl CloudProviderPath {
    /// The cloud named.
    ///
    /// # Errors
    ///
    /// `422` naming the accepted spellings when the segment names no cloud
    /// ianua drives.
    pub(crate) fn provider(&self) -> Result<CloudProvider, ApiError> {
        match self.provider.to_ascii_lowercase().as_str() {
            "aws" => Ok(CloudProvider::Aws),
            "gcp" => Ok(CloudProvider::Gcp),
            "azure" => Ok(CloudProvider::Azure),
            "digitalocean" => Ok(CloudProvider::DigitalOcean),
            "kubernetes" => Ok(CloudProvider::Kubernetes),
            other => Err(ApiError::validation(message!(
                "api-unknown-cloud-expected-aws-gcp-azure",
                format!(
                    "unknown cloud '{other}': expected aws, gcp, azure, digitalocean or kubernetes"
                )
            ))),
        }
    }
}
