//! Sign-in pressure events: a tenant's password sign-in coming under high
//! pressure, and easing again.

use time::OffsetDateTime;

use crate::shared::events::data::EventData;
use crate::shared::events::event::tenant_event;

/// Failed password sign-ins across the tenant reached its threshold.
///
/// From now on, a sign-in from a device nobody trusted must pass a challenge
/// before its password is hashed. The tenant's administrators are told: it
/// usually means someone is trying stolen passwords against the tenant.
#[derive(Debug)]
pub struct SignInPressureRose {
    /// The failures counted in the window when pressure rose.
    pub(crate) failures: u64,
    /// The tenant's threshold.
    pub(crate) threshold: u32,
    /// When pressure rose.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SignInPressureRose => crate::types::event_type::AuthenticationEvent::SignInPressureRose,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("failures", self.failures.to_string())
            .field("threshold", self.threshold.to_string())
    }
}

/// Failed password sign-ins across the tenant fell back under its
/// threshold, so sign-in goes on without challenges.
#[derive(Debug)]
pub struct SignInPressureEased {
    /// The tenant's threshold.
    pub(crate) threshold: u32,
    /// When pressure eased.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    SignInPressureEased => crate::types::event_type::AuthenticationEvent::SignInPressureEased,
    fn payload(&self) -> EventData {
        EventData::new().field("threshold", self.threshold.to_string())
    }
}
