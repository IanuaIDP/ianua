//! A service trigger as a jsonb column holds it: the integration, the
//! event, the account it registers through and its filters, written by the
//! store in a shape of its own and read back through the domain's checks.
//! A version's trigger and a registration's are kept the same way, each
//! column sealing and opening this shape itself.

use ianua_domain::domains::workflows::data::FieldName;
use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::domains::workflows::integration::events::ServiceEventKey;
use ianua_domain::domains::workflows::triggers::{EventFilter, FilterValue, ServiceTrigger};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::IntegrationAccountId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

/// A service trigger as it is stored.
#[derive(Serialize, Deserialize)]
pub(in crate::postgres::workflows) struct StoredTrigger {
    integration: String,
    event: String,
    account: Uuid,
    filters: Vec<StoredFilter>,
}

/// JSON name/value pair validated when a service trigger is reconstituted.
#[derive(Serialize, Deserialize)]
struct StoredFilter {
    name: String,
    value: String,
}

impl StoredTrigger {
    /// `trigger` as it is stored.
    pub(in crate::postgres::workflows) fn of(trigger: &ServiceTrigger) -> Self {
        Self {
            integration: trigger.integration().as_str().to_owned(),
            event: trigger.event().as_str().to_owned(),
            account: *trigger.account().as_uuid(),
            filters: trigger
                .filters()
                .iter()
                .map(|filter| StoredFilter {
                    name: filter.name().as_str().to_owned(),
                    value: filter.value().as_str().to_owned(),
                })
                .collect(),
        }
    }

    /// The trigger the stored one holds, read back through its rules, in a
    /// row of `row`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value in it no longer
    /// passes its rules, or it names one filter twice.
    pub(in crate::postgres::workflows) fn into_trigger(
        self,
        row: Stored,
    ) -> Result<ServiceTrigger, DomainError> {
        let filters = self
            .filters
            .into_iter()
            .map(|filter| {
                Ok(EventFilter::new(
                    row.value("filter name", FieldName::new(filter.name))?,
                    row.value("filter value", FilterValue::new(filter.value))?,
                ))
            })
            .collect::<Result<Vec<_>, DomainError>>()?;
        ServiceTrigger::from_stored(
            row.value("integration", IntegrationKey::new(self.integration))?,
            row.value("event", ServiceEventKey::new(self.event))?,
            IntegrationAccountId::from_uuid(self.account),
            filters,
        )
    }
}
