//! A log shipping target as its row holds it: read back into the
//! aggregate, and written out from it. Its credential is kept in the
//! sealed form the target was made with.

use ianua_domain::domains::proxy::log_shipping::{
    LogDestination, LogShippingTarget, LogShippingTargetRow, LogTargetSettings, SamplePercent,
    ShippedRecords, ShippingCredential,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Label, LogShippingTargetId, SealedSecret};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const TARGET: Stored = Stored("log shipping target");

const DESTINATION: Kept = Kept {
    entity: TARGET.0,
    column: "destination",
    shape: 1,
};

/// A target as it is read. The store's checked queries fill it.
pub(super) struct TargetRecord {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) destination: Value,
    pub(super) credential: Option<String>,
    pub(super) records: String,
    pub(super) sample_percent: Option<i16>,
    pub(super) format: String,
    pub(super) status: String,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl TargetRecord {
    /// The target the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the target
    /// keeps, such as a destination that needs a credential holding none.
    pub(super) fn into_target(self) -> Result<LogShippingTarget<ResolvedTenant>, DomainError> {
        let credential = match self.credential {
            Some(sealed) => {
                ShippingCredential::Sealed(TARGET.value("credential", SealedSecret::new(sealed))?)
            }
            None => ShippingCredential::None,
        };
        LogShippingTarget::reconstitute(LogShippingTargetRow {
            id: LogShippingTargetId::from_uuid(self.id),
            name: TARGET.value("name", Label::new("name", self.name))?,
            settings: LogTargetSettings {
                destination: DESTINATION.open::<LogDestination>(self.destination)?,
                credential,
                records: records_of(&self.records, self.sample_percent)?,
                format: TARGET.choice(&self.format)?,
            },
            status: TARGET.choice(&self.status)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// The records `word` and `percent` choose.
fn records_of(word: &str, percent: Option<i16>) -> Result<ShippedRecords, DomainError> {
    match (word, percent) {
        ("all", None) => Ok(ShippedRecords::All),
        ("denied_only", None) => Ok(ShippedRecords::DeniedOnly),
        ("sampled", Some(percent)) => {
            let percent = u8::try_from(percent)
                .map_err(|_| DomainError::corrupt_row(TARGET.0, "a share out of range"))?;
            SamplePercent::new(percent)
                .map(ShippedRecords::Sampled)
                .map_err(|_| DomainError::corrupt_row(TARGET.0, "a share out of range"))
        }
        _ => Err(DomainError::corrupt_row(
            TARGET.0,
            "an unknown choice of records",
        )),
    }
}

/// A target's columns, as they are written.
pub(super) struct TargetColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) destination: Value,
    pub(super) credential: Option<&'a str>,
    pub(super) records: &'static str,
    pub(super) sample_percent: Option<i16>,
    pub(super) format: &'static str,
    pub(super) status: &'static str,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> TargetColumns<'a> {
    /// The columns `target` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the destination cannot be
    /// written out.
    pub(super) fn of(target: &'a LogShippingTarget<ResolvedTenant>) -> Result<Self, DomainError> {
        let sample_percent = match target.records() {
            ShippedRecords::Sampled(percent) => Some(i16::from(percent.get())),
            ShippedRecords::All | ShippedRecords::DeniedOnly => None,
        };
        Ok(Self {
            id: target.id().as_uuid(),
            name: target.name().as_str(),
            destination: DESTINATION.seal(target.destination())?,
            credential: match target.credential() {
                ShippingCredential::None => None,
                ShippingCredential::Sealed(sealed) => Some(sealed.as_str()),
            },
            records: target.records().as_str(),
            sample_percent,
            format: target.format().word(),
            status: target.status().word(),
            created_at: target.created_at(),
            updated_at: target.updated_at(),
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::streaming::DatadogSite;
    use serde_json::json;

    use super::*;

    /// A destination of each kind, in the shape the column keeps.
    fn stored_destinations() -> [Value; 3] {
        [
            json!({"v": 1, "value": {"datadog": "eu1"}}),
            json!({"v": 1, "value": {"https": "https://logs.example.com/ingest"}}),
            json!({"v": 1, "value": {"bucket": {
                "endpoint": "https://s3.eu-central-1.amazonaws.com",
                "region": "eu-central-1",
                "bucket": "acme-gateway-logs"
            }}}),
        ]
    }

    /// Destinations stored in the shapes pinned here read back, and are
    /// written again in the same shapes.
    #[test]
    fn a_destination_is_stored_in_its_pinned_shape() {
        for stored in stored_destinations() {
            let read: LogDestination = DESTINATION.open(stored.clone()).unwrap();

            assert_eq!(DESTINATION.seal(&read).unwrap(), stored);
        }
        assert_eq!(
            DESTINATION
                .open::<LogDestination>(stored_destinations()[0].clone())
                .unwrap(),
            LogDestination::Datadog(DatadogSite::Eu1)
        );
    }

    /// Sampled records require a percentage: missing and 200-percent
    /// shares fail to decode, while a ten-percent share succeeds.
    #[test]
    fn a_share_out_of_range_is_refused() {
        assert!(records_of("sampled", None).is_err());
        assert!(records_of("sampled", Some(200)).is_err());
        assert_eq!(
            records_of("sampled", Some(10)).unwrap(),
            ShippedRecords::Sampled(SamplePercent::new(10).unwrap())
        );
    }
}
