//! Events about a tenant's break-glass policy: what its users may give
//! themselves in an emergency.

use time::OffsetDateTime;

use crate::domains::authorization::break_glass::SelfService;
use crate::shared::events::data::EventData;
use crate::shared::events::event::tenant_event;

/// What a tenant's users may give themselves in an emergency changed.
///
/// Letting users give themselves an access hands it to each of them, so the
/// record keeps what was let before and what is let now.
#[derive(Debug)]
pub struct BreakGlassPolicyChanged {
    /// What users could give themselves before.
    pub(crate) previous: SelfService,
    /// What they may give themselves now.
    pub(crate) current: SelfService,
    /// When the policy changed.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    BreakGlassPolicyChanged => crate::types::event_type::AuthorizationEvent::BreakGlassPolicyChanged,
    fn payload(&self) -> EventData {
        EventData::new().change(
            "self_service",
            self_service_text(&self.previous),
            self_service_text(&self.current),
        )
    }
}

/// A self-service setting as the audit trail shows it: `off`, or the
/// permissions it lets, each by its stable name.
fn self_service_text(self_service: &SelfService) -> String {
    let SelfService::UpTo(access) = self_service else {
        return "off".to_owned();
    };
    access
        .system()
        .iter()
        .map(ToString::to_string)
        .chain(access.custom().iter().map(ToString::to_string))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::break_glass::BreakGlassAccess;
    use crate::domains::authorization::permission::{SystemPermission, UserAction};
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;

    /// Ann lets everyone give themselves "view users" in an emergency, where
    /// before nobody could give themselves anything. The record shows both.
    #[test]
    fn a_policy_change_records_what_was_let_before_and_after() {
        let access =
            BreakGlassAccess::new(vec![SystemPermission::Users(UserAction::View)], Vec::new())
                .unwrap();
        let event = BreakGlassPolicyChanged {
            previous: SelfService::Off,
            current: SelfService::UpTo(access),
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();
        let Some(FieldValue::Change(change)) = payload.value("self_service") else {
            panic!("self_service is not a change");
        };
        assert_eq!(change.from(), Some("off"));
        assert_eq!(
            change.to(),
            Some(
                SystemPermission::Users(UserAction::View)
                    .to_string()
                    .as_str()
            )
        );
    }
}
