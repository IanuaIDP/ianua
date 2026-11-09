//! Events for adding and removing devices on a user's trusted device list.

use time::OffsetDateTime;

use crate::domains::authentication::events::changed_account;
use crate::domains::authentication::keeper::ChangedBy;
use crate::shared::events::data::EventData;
use crate::shared::events::event::tenant_event;
use crate::types::{TrustedDeviceId, UserId};

/// A device was added to a user's trusted device list.
///
/// Later logins from this device may skip MFA. The event names the device by
/// its record id. The secret the device presents is a credential, so it stays
/// inside the sign-in that checks it.
#[derive(Debug)]
pub struct DeviceTrusted {
    /// The trusted device's record.
    pub(crate) device_id: TrustedDeviceId,
    /// When the device was trusted.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    DeviceTrusted => crate::types::event_type::AuthenticationEvent::DeviceTrusted,
    fn payload(&self) -> EventData {
        EventData::new().field("device_id", self.device_id.to_string())
    }
}

/// A device was removed from a user's trusted device list.
///
/// The next login from the device counts as unknown. MFA is asked for when
/// the tenant's policy requires it.
#[derive(Debug)]
pub struct DeviceRevoked {
    /// The revoked device's record.
    pub(crate) device_id: TrustedDeviceId,
    /// Whose doing it was. The record names the account only when someone
    /// other than its holder forgot the device.
    pub(crate) by: ChangedBy<UserId>,
    /// When the device was revoked.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    DeviceRevoked => crate::types::event_type::AuthenticationEvent::DeviceRevoked,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("device_id", self.device_id.to_string())
            .optional_reference("user", changed_account(self.by))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::event::DomainEventCore;

    /// The trusted-device payload includes its ID and omits fingerprint hash and user ID fields.
    #[test]
    fn device_trusted_payload_names_the_device_and_carries_no_secret() {
        let device_id = TrustedDeviceId::new();
        let event = DeviceTrusted {
            device_id,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();

        assert_eq!(
            payload.get("device_id"),
            Some(device_id.to_string().as_str())
        );
        assert!(payload.get("fingerprint_hash").is_none());
        assert!(
            payload.get("user_id").is_none(),
            "the trusting user is the record's actor, not payload data"
        );
    }

    /// Ann revokes her laptop. The event names the device by its id and
    /// carries neither its secret nor Ann's id.
    #[test]
    fn device_revoked_payload_names_the_device_and_carries_no_secret() {
        let device_id = TrustedDeviceId::new();
        let event = DeviceRevoked {
            device_id,
            by: ChangedBy::Holder,
            occurred_at: crate::shared::clock::now(),
        };

        let payload = event.payload();

        assert_eq!(
            payload.get("device_id"),
            Some(device_id.to_string().as_str())
        );
        assert!(payload.get("fingerprint_hash").is_none());
        assert!(payload.get("user_id").is_none());
    }
}
