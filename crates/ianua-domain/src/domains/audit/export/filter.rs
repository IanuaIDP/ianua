//! What an audit log export holds: which records, and in what format.
//!
//! The filter is the audit log list's, kept with the export so the worker
//! that writes the file reads the same records the reader asked for.

use time::OffsetDateTime;

use crate::domains::audit::access::LogReach;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::{Charset, TextValue, Validator, text_value};
use crate::types::{ActorRef, IpAddress, TenantId};

text_value! {
    /// The start of an event type, such as `organization.org_user`. Every
    /// event whose type starts with it matches.
    pub struct EventTypePrefix;
}

impl TextValue for EventTypePrefix {
    const FIELD: &'static str = "event_type";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(
            1..=128,
            Charset::LOWERCASE | Charset::DIGIT | Charset::UNDERSCORE | Charset::DOT,
        )
    }
}

text_value! {
    /// The id of the entity an audit record is about, such as a user's or a
    /// role's, as the record keeps it.
    pub struct AuditTargetId;
}

impl TextValue for AuditTargetId {
    const FIELD: &'static str = "target";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.length(1..=256).no_control_chars()
    }
}

/// The format an export's file is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditExportFormat {
    /// One row per record, the columns
    /// `id,event_type,actor,tenant,target_id,ip_address,occurred_at,acted_through,through_id`.
    Csv,
    /// A JSON array of records, each as the audit log list shows it.
    Json,
}

impl AuditExportFormat {
    /// The format's name, stable across releases.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Json => "json",
        }
    }
}

/// Which records an export asks for. Each part left `None` narrows nothing.
#[derive(Debug, Clone, Default)]
pub struct AuditExportFilterParts {
    /// Only records whose event type starts with this.
    pub event_type: Option<EventTypePrefix>,
    /// Only records after this time.
    pub after: Option<OffsetDateTime>,
    /// Only records before this time.
    pub before: Option<OffsetDateTime>,
    /// Only records this actor made.
    pub actor: Option<ActorRef>,
    /// Only records of this tenant. A tenant's own log is always its own,
    /// whatever this says.
    pub tenant_id: Option<TenantId>,
    /// Only records about this entity.
    pub target: Option<AuditTargetId>,
    /// Only records from this address.
    pub ip_address: Option<IpAddress>,
}

/// Which records an export holds, its time window in order, as far into
/// an organization's tenants as whoever asked for it is shown.
#[derive(Debug, Clone, Default)]
pub struct AuditExportFilter {
    parts: AuditExportFilterParts,
    reach: LogReach,
}

impl AuditExportFilter {
    /// The filter `parts` describe.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `after` is not before `before`.
    pub fn new(parts: AuditExportFilterParts) -> Result<Self, DomainError> {
        let in_order = match (parts.after, parts.before) {
            (Some(after), Some(before)) => after < before,
            _ => true,
        };
        if !in_order {
            return Err(DomainError::invalid(message!(
                "audit-an-export-s-after-must-come",
                "an export's `after` must come before its `before`"
            )));
        }
        Ok(Self {
            parts,
            reach: LogReach::Every,
        })
    }

    /// Reads a stored filter back, as far as `reach` was shown.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when its window is out of order.
    pub fn from_stored(
        parts: AuditExportFilterParts,
        reach: LogReach,
    ) -> Result<Self, DomainError> {
        let filter = Self::new(parts).map_err(|_| {
            DomainError::infra_msg("a stored audit export filter has its window out of order")
        })?;
        Ok(filter.within(reach))
    }

    /// This filter, holding only what `reach` shows.
    #[must_use]
    pub(crate) fn within(self, reach: LogReach) -> Self {
        Self { reach, ..self }
    }

    /// Which tenants' records it holds.
    #[must_use]
    pub fn reach(&self) -> &LogReach {
        &self.reach
    }

    /// The parts it narrows by.
    #[must_use]
    pub fn parts(&self) -> &AuditExportFilterParts {
        &self.parts
    }

    /// The upper end of the window the file covers: the filter's own
    /// `before`, but never past `requested_at`, so records written while
    /// the file is written stay out and the file is the log as it stood.
    #[must_use]
    pub fn until(&self, requested_at: OffsetDateTime) -> OffsetDateTime {
        self.parts
            .before
            .map_or(requested_at, |before| before.min(requested_at))
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;

    /// An export from noon to eleven the same morning is refused; noon to
    /// one is kept.
    #[test]
    fn a_window_must_run_forward() {
        let noon = crate::shared::clock::now();
        let backwards = AuditExportFilterParts {
            after: Some(noon),
            before: Some(noon - Duration::hours(1)),
            ..AuditExportFilterParts::default()
        };
        let forwards = AuditExportFilterParts {
            after: Some(noon),
            before: Some(noon + Duration::hours(1)),
            ..AuditExportFilterParts::default()
        };

        assert!(matches!(
            AuditExportFilter::new(backwards),
            Err(DomainError::Validation(_))
        ));
        assert!(AuditExportFilter::new(forwards).is_ok());
    }

    /// Ann asks for everything up to next week. The file stops at the
    /// moment she asked, so records written meanwhile stay out.
    #[test]
    fn a_file_never_reaches_past_its_request() {
        let asked = crate::shared::clock::now();
        let filter = AuditExportFilter::new(AuditExportFilterParts {
            before: Some(asked + Duration::days(7)),
            ..AuditExportFilterParts::default()
        })
        .unwrap();

        assert_eq!(filter.until(asked), asked);
    }

    /// A prefix in capitals, or with a space, is refused; a dotted
    /// lowercase one is kept.
    #[test]
    fn an_event_type_prefix_is_dotted_lowercase() {
        assert!(EventTypePrefix::new("organization.org_user").is_ok());
        assert!(EventTypePrefix::new("Tenant created").is_err());
    }
}
