//! Domain handover bodies: the giving tenant's offer, and the receiving
//! tenant's acceptance.

use ianua_app::use_cases::domain::handover::{AcceptDomainRequest, OfferDomainRequest};
use ianua_domain::types::{DomainId, DomainName, TenantId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;

/// Which tenant a domain is offered to.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OfferHandoverBody {
    /// The tenant that may take the domain, in the same organization.
    pub target_tenant_id: Uuid,
}

impl OfferHandoverBody {
    /// Offering `domain_id` to the tenant this body names.
    #[must_use]
    pub(crate) fn request(&self, domain_id: DomainId) -> OfferDomainRequest {
        OfferDomainRequest {
            domain_id,
            target_tenant_id: TenantId::from_uuid(self.target_tenant_id),
        }
    }
}

/// When an offer runs out.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct HandoverOfferResponse {
    /// The offer must be accepted before this.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

/// The domain a tenant takes over, and the tenant giving it.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AcceptHandoverBody {
    /// The tenant that offered the domain.
    pub source_tenant_id: Uuid,
    /// The domain offered, such as `auth.acme.com`.
    pub domain: String,
}

impl TryFrom<AcceptHandoverBody> for AcceptDomainRequest {
    type Error = ApiError;

    fn try_from(body: AcceptHandoverBody) -> Result<Self, Self::Error> {
        Ok(Self {
            source_tenant_id: TenantId::from_uuid(body.source_tenant_id),
            domain: DomainName::new(body.domain).map_err(ApiError::validation)?,
        })
    }
}
