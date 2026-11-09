//! Events about who a tenant lets in: sign-in and mutual TLS settings.

use time::OffsetDateTime;

use crate::shared::events::data::EventData;
use crate::shared::events::event::tenant_event;

/// A tenant's authentication configuration was updated.
///
/// It covers the JWT issuer, MFA policy, password policy, session lifetimes
/// and every other sign-in setting.
#[derive(Debug)]
pub(crate) struct TenantAuthConfigUpdated {
    /// When the change occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantAuthConfigUpdated => crate::types::event_type::TenantEvent::AuthConfigUpdated,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

/// A tenant's mTLS trust anchor was changed.
#[derive(Debug)]
pub(crate) struct TenantMtlsConfigUpdated {
    /// When the change occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    TenantMtlsConfigUpdated => crate::types::event_type::TenantEvent::MtlsConfigUpdated,
    fn payload(&self) -> EventData {
        EventData::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::tenant::events::lifecycle::TenantDeleted;
    use crate::shared::events::raised::TenantEventBody;

    /// A tenant changes its sign-in settings, its mTLS settings and is then
    /// deleted. Each event has an empty payload, since the event type says
    /// what changed.
    #[test]
    fn the_settings_and_deletion_events_have_no_payload() {
        let now = crate::shared::clock::now();

        let events: Vec<Box<dyn TenantEventBody>> = vec![
            Box::new(TenantAuthConfigUpdated { occurred_at: now }),
            Box::new(TenantMtlsConfigUpdated { occurred_at: now }),
            Box::new(TenantDeleted { occurred_at: now }),
        ];

        for event in events {
            let kind = event.event_type();
            assert!(event.payload().is_empty(), "{kind}");
        }
    }
}
