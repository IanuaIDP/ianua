//! Where a tenant's request records go, in what shape, and which of them.

use crate::domains::audit::streaming::DatadogSite;
use crate::domains::proxy::observation::RequestObservation;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_range;
use crate::shared::validation::{Charset, TextValue, Validator, text_value};
use crate::types::{PublicHttpsUrl, SealedSecret};

text_value! {
    /// The name of an S3-compatible bucket, such as `acme-gateway-logs`:
    /// 3 to 63 lowercase letters, digits, dots and hyphens.
    pub struct BucketName;
}

impl TextValue for BucketName {
    const FIELD: &'static str = "bucket";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .length(3..=63)
            .charset(Charset::LOWERCASE | Charset::DIGIT | Charset::HYPHEN | Charset::DOT)
    }
}

text_value! {
    /// The region an S3-compatible bucket is signed for, such as
    /// `eu-central-1`, or `auto` for Cloudflare R2 and Google Cloud
    /// Storage: 2 to 32 lowercase letters, digits and hyphens.
    ///
    /// It is given, never read from the endpoint's host: only AWS writes
    /// the region into its hosts, and a request signed for the wrong one is
    /// refused.
    pub struct BucketRegion;
}

impl TextValue for BucketRegion {
    const FIELD: &'static str = "region";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(
            2..=32,
            Charset::LOWERCASE | Charset::DIGIT | Charset::HYPHEN,
        )
    }
}

/// Where shipped records go.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum LogDestination {
    /// A collector on the public internet that takes batches by `POST`,
    /// such as a Splunk HTTP event collector or an Elastic intake.
    Https(PublicHttpsUrl),
    /// An S3-compatible bucket, written to in batches.
    Bucket {
        /// The storage service's endpoint, such as
        /// `https://s3.eu-central-1.amazonaws.com`.
        endpoint: PublicHttpsUrl,
        /// The region requests to the bucket are signed for.
        region: BucketRegion,
        /// The object-storage container receiving each batch of request records.
        bucket: BucketName,
    },
    /// Datadog's log intake.
    Datadog(DatadogSite),
}

impl LogDestination {
    /// The kind of destination, as an audit record names it. Never the
    /// address, whose path may carry a token.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Https(_) => "https",
            Self::Bucket { .. } => "bucket",
            Self::Datadog(_) => "datadog",
        }
    }

    /// Whether the destination takes records only with a credential.
    fn needs_credential(&self) -> bool {
        matches!(self, Self::Bucket { .. } | Self::Datadog(_))
    }

    /// Refuses `credential` when this destination needs one and it is none.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] for a bucket or Datadog with no
    ///   credential, which would refuse every batch.
    pub(super) fn ensure_reachable_with(
        &self,
        credential: &ShippingCredential,
    ) -> Result<(), DomainError> {
        if self.needs_credential() && matches!(credential, ShippingCredential::None) {
            return Err(DomainError::invalid(message!(
                "proxy-a-destination-needs-a-credential-to",
                format!(
                    "a {} destination needs a credential to accept records",
                    self.kind()
                )
            )));
        }
        Ok(())
    }
}

/// What the gateway signs in to the destination with.
///
/// It is held sealed, so the domain never reads it and it never prints.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ShippingCredential {
    /// The destination takes records without one.
    None,
    /// An API key, token or access key, sealed.
    Sealed(SealedSecret),
}

/// The shape each shipped record is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum LogFormat {
    /// One JSON object per line.
    JsonLines,
    /// OpenTelemetry log records.
    OpenTelemetry,
}

/// The share of allowed requests a sampled target ships, in percent: 1 to
/// 100.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "u8", into = "u8"))]
pub struct SamplePercent(u8);

impl SamplePercent {
    /// A checked share.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] outside `1..=100`. Zero would ship
    ///   nothing while looking set up.
    pub fn new(percent: u8) -> Result<Self, DomainError> {
        validate_range("sample_percent", percent, 1..=100)?;
        Ok(Self(percent))
    }

    /// The share, in percent.
    #[must_use]
    pub fn get(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for SamplePercent {
    type Error = DomainError;

    fn try_from(percent: u8) -> Result<Self, Self::Error> {
        Self::new(percent)
    }
}

impl From<SamplePercent> for u8 {
    fn from(percent: SamplePercent) -> Self {
        percent.0
    }
}

/// Which request records a target ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ShippedRecords {
    /// Every request.
    All,
    /// Only refused requests.
    DeniedOnly,
    /// Every refused request, and this share of the rest.
    ///
    /// Refusals are never sampled away. They are the records a security
    /// team looks for, and there are few of them.
    Sampled(SamplePercent),
}

impl ShippedRecords {
    /// The stable name an audit record keeps.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::DeniedOnly => "denied_only",
            Self::Sampled(_) => "sampled",
        }
    }

    /// Whether `observed` is one of the records this selection ships.
    ///
    /// Sampling is decided from the request's correlation id. Every gateway
    /// replica makes the same choice for one request.
    #[must_use]
    pub fn selects(self, observed: &RequestObservation) -> bool {
        match self {
            Self::All => true,
            Self::DeniedOnly => !observed.is_allowed(),
            Self::Sampled(percent) => !observed.is_allowed() || in_sample(observed, percent),
        }
    }
}

/// Whether the request falls in the sampled `percent`, by its correlation
/// id.
fn in_sample(observed: &RequestObservation, percent: SamplePercent) -> bool {
    let bucket = observed
        .correlation_id
        .as_uuid()
        .as_u128()
        .checked_rem(100)
        .unwrap_or_default();
    bucket < u128::from(percent.get())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bucket or Datadog with no credential is refused. A collector that
    /// needs none is accepted.
    #[test]
    fn a_destination_that_needs_a_credential_gets_one() {
        let bucket = LogDestination::Bucket {
            endpoint: PublicHttpsUrl::new("https://s3.eu-central-1.amazonaws.com").unwrap(),
            region: BucketRegion::new("eu-central-1").unwrap(),
            bucket: BucketName::new("acme-gateway-logs").unwrap(),
        };
        let collector =
            LogDestination::Https(PublicHttpsUrl::new("https://logs.example.com/ingest").unwrap());

        assert!(
            bucket
                .ensure_reachable_with(&ShippingCredential::None)
                .is_err()
        );
        assert!(
            LogDestination::Datadog(DatadogSite::Eu1)
                .ensure_reachable_with(&ShippingCredential::None)
                .is_err()
        );
        assert!(
            collector
                .ensure_reachable_with(&ShippingCredential::None)
                .is_ok()
        );
    }

    /// A bucket named `Acme_Logs` or `ab` is refused. `acme-gateway-logs` is
    /// accepted.
    #[test]
    fn bucket_names_follow_the_storage_rules() {
        assert!(BucketName::new("Acme_Logs").is_err());
        assert!(BucketName::new("ab").is_err());
        assert!(BucketName::new("acme-gateway-logs").is_ok());
    }

    /// A region such as `eu-central-1`, `us-west-004` or `auto` is
    /// accepted; one with capitals, a dot or a slash, which no store
    /// names, is refused.
    #[test]
    fn a_bucket_region_is_a_plain_name() {
        assert!(BucketRegion::new("eu-central-1").is_ok());
        assert!(BucketRegion::new("us-west-004").is_ok());
        assert!(BucketRegion::new("auto").is_ok());
        assert!(BucketRegion::new("EU-Central-1").is_err());
        assert!(BucketRegion::new("eu.central").is_err());
        assert!(BucketRegion::new("eu/central").is_err());
        assert!(BucketRegion::new("").is_err());
    }

    /// A share of 0 or 101 percent is refused. 1 and 100 are accepted.
    #[test]
    fn a_sample_share_is_one_to_a_hundred_percent() {
        assert!(SamplePercent::new(0).is_err());
        assert!(SamplePercent::new(101).is_err());
        assert!(SamplePercent::new(1).is_ok());
        assert!(SamplePercent::new(100).is_ok());
    }
}
