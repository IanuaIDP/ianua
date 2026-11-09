//! The region a cloud-account request names in `?region=`.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use ianua_domain::domains::tenant::provisioning::infrastructure::DeploymentRegion;
use ianua_domain::message;
use serde::Deserialize;

use crate::error::ApiError;
use crate::extractors::query::{Query, QueryRefusal};

/// The region named by a `?region=` query parameter, in the cloud-neutral
/// spelling (`eu-central-1`).
///
/// Required rather than defaulted: network discovery is region-specific, and
/// answering for a region the caller did not ask about would let someone pick
/// a network in the wrong country.
pub(crate) struct RegionQuery(pub DeploymentRegion);

#[derive(Deserialize)]
struct RegionRaw {
    region: Option<String>,
}

impl<S: Send + Sync> FromRequestParts<S> for RegionQuery {
    type Rejection = QueryRefusal;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Query(raw) = Query::<RegionRaw>::from_request_parts(parts, state).await?;
        let Some(region) = raw.region else {
            return Err(ApiError::validation(message!(
                "api-a-region-is-required-networks-differ",
                "a region is required: networks differ by region, and so does where your \
                 data would sit"
            ))
            .into());
        };
        Ok(Self(region_named(&region)?))
    }
}

/// The region `value` spells.
fn region_named(value: &str) -> Result<DeploymentRegion, ApiError> {
    match value.to_ascii_lowercase().as_str() {
        "us-east-1" => Ok(DeploymentRegion::UsEast1),
        "us-west-2" => Ok(DeploymentRegion::UsWest2),
        "ca-central-1" => Ok(DeploymentRegion::CaCentral1),
        "eu-west-1" => Ok(DeploymentRegion::EuWest1),
        "eu-west-2" => Ok(DeploymentRegion::EuWest2),
        "eu-west-3" => Ok(DeploymentRegion::EuWest3),
        "eu-central-1" => Ok(DeploymentRegion::EuCentral1),
        "eu-central-2" => Ok(DeploymentRegion::EuCentral2),
        "eu-north-1" => Ok(DeploymentRegion::EuNorth1),
        "eu-south-1" => Ok(DeploymentRegion::EuSouth1),
        "sa-east-1" => Ok(DeploymentRegion::SaEast1),
        "ap-south-1" => Ok(DeploymentRegion::ApSouth1),
        "ap-northeast-1" => Ok(DeploymentRegion::ApNortheast1),
        "ap-southeast-1" => Ok(DeploymentRegion::ApSoutheast1),
        "ap-southeast-2" => Ok(DeploymentRegion::ApSoutheast2),
        other => Err(ApiError::validation(message!(
            "api-unknown-region-2",
            format!("unknown region '{other}'")
        ))),
    }
}
