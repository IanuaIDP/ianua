//! A version in service that starts on a schedule, as its row and its
//! tenant's row hold it: read back into the port's value through its own
//! constructors.

use std::collections::HashMap;

use ianua_app::ports::workflows::ScheduledVersion;
use ianua_domain::domains::workflows::triggers::CronSchedule;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{TenantId, Timezone, WorkflowId};
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const SCHEDULED: Stored = Stored("scheduled workflow");

/// A scheduled version as it is read, with its tenant. The store's checked
/// queries fill it.
pub(super) struct ScheduleRecord {
    pub(super) tenant_id: Uuid,
    pub(super) workflow_id: Uuid,
    pub(super) trigger_schedule: String,
}

/// A tenant's timezone as it is read. The store's checked queries fill it.
pub(super) struct TimezoneRecord {
    pub(super) id: Uuid,
    pub(super) timezone: String,
}

impl ScheduleRecord {
    /// The scheduled version the record holds, read in its tenant's
    /// timezone from `timezones`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the schedule or the
    /// timezone no longer reads, or the platform keeps no such tenant.
    pub(super) fn into_scheduled(
        self,
        timezones: &HashMap<Uuid, String>,
    ) -> Result<ScheduledVersion, DomainError> {
        let Some(timezone) = timezones.get(&self.tenant_id) else {
            return Err(DomainError::corrupt_row(
                SCHEDULED.0,
                "a tenant the platform does not keep",
            ));
        };
        Ok(ScheduledVersion {
            tenant_id: TenantId::from_uuid(self.tenant_id),
            workflow_id: WorkflowId::from_uuid(self.workflow_id),
            schedule: CronSchedule::parse(&self.trigger_schedule).map_err(DomainError::infra)?,
            timezone: SCHEDULED.value("timezone", Timezone::new(timezone.as_str()))?,
        })
    }
}

/// The timezones `records` hold, by tenant.
pub(super) fn timezones_of(records: Vec<TimezoneRecord>) -> HashMap<Uuid, String> {
    records
        .into_iter()
        .map(|record| (record.id, record.timezone))
        .collect()
}
