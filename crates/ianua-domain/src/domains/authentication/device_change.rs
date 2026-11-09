//! A tenant user remembering a device, or forgetting one, as the audit
//! trail records it.
//!
//! A [`TrustedDevice`] is kept on both planes, a workspace's and an
//! organization's, and each plane records its devices in its own words. So
//! the device itself raises nothing. A tenant user's change goes through a
//! [`DeviceChange`], which makes the change on the device and raises the
//! workspace's record of it. The change is a short-lived value: it is
//! dropped once its record is taken.

use std::marker::PhantomData;

use crate::domains::authentication::device_trust::{
    DeviceTrustRefused, TrustDeviceParams, TrustedDevice,
};
use crate::domains::authentication::events::device::{DeviceRevoked, DeviceTrusted};
use crate::domains::authentication::keeper::{AccountKeeper, ChangedBy};
use crate::domains::authentication::sessions::sign_in_progress::SignedIn;
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::types::UserId;

/// A change to a tenant user's remembered devices, with the record it
/// raised.
#[derive(Debug)]
pub struct DeviceChange<T: TenantScope> {
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> DeviceChange<T> {
    /// Remembers a new device for whoever `signed_in` names, as
    /// [`TrustedDevice::trust`] allows. Raises
    /// `authentication.device_trusted`.
    ///
    /// # Errors
    ///
    /// As [`TrustedDevice::trust`].
    pub fn trust(
        params: TrustDeviceParams,
        signed_in: &SignedIn<T>,
    ) -> Result<(TrustedDevice<T>, Self), DeviceTrustRefused> {
        let device = TrustedDevice::trust(params, signed_in)?;
        let mut change = Self::new();
        change.raised.raise(DeviceTrusted {
            device_id: *device.id(),
            occurred_at: device.created_at(),
        });
        Ok((device, change))
    }

    /// Forgets `device`, as [`TrustedDevice::revoke`] allows `by` to.
    /// Raises `authentication.device_revoked`.
    ///
    /// # Errors
    ///
    /// As [`TrustedDevice::revoke`].
    pub fn revoke(
        device: &mut TrustedDevice<T>,
        by: &impl AccountKeeper<T>,
    ) -> Result<Self, DomainError> {
        device.revoke(by)?;
        let holder = UserId::from_uuid(*device.subject_id().as_uuid());
        let mut change = Self::new();
        change.raised.raise(DeviceRevoked {
            device_id: *device.id(),
            by: ChangedBy::of::<T>(by, holder),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(change)
    }

    fn new() -> Self {
        Self {
            raised: Raised::default(),
            _scope: PhantomData,
        }
    }
}

impl<T: TenantScope> Raises for DeviceChange<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::mfa::owed::SecondFactor;
    use crate::domains::authentication::risk_engine::step_up::StepUpPolicy;
    use crate::domains::authentication::sessions::mfa_factor::MfaFactor;
    use crate::domains::authentication::sessions::sign_in_progress::{LocalMethod, SignInProgress};
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{IpAddress, Label, PrincipalId, TokenHash, UserAgent, UserId};

    fn params() -> TrustDeviceParams {
        TrustDeviceParams {
            secret_hash: TokenHash::from_stored("laptop".to_owned()),
            device_name: Label::new("name", "Ann's laptop").unwrap(),
            user_agent: UserAgent::new("Mozilla/5.0").unwrap(),
            ip: IpAddress::new("10.0.0.1").unwrap(),
        }
    }

    fn password_and_code(subject: PrincipalId) -> SignedIn<ResolvedTenant> {
        let policy = StepUpPolicy::relaxed();
        let progress = SignInProgress::begin(LocalMethod::Password, SecondFactor::Verify, &policy)
            .unwrap()
            .answer(MfaFactor::Totp, &policy)
            .unwrap();
        SignedIn::of(subject, progress)
    }

    fn anns_sign_in() -> SignedIn<ResolvedTenant> {
        password_and_code(UserId::new().into())
    }

    /// Ann signs in with her password and code and remembers her laptop.
    /// The change raises `authentication.device_trusted` naming the device.
    #[test]
    fn remembering_a_device_raises_device_trusted() {
        let (device, mut change) =
            DeviceChange::<ResolvedTenant>::trust(params(), &anns_sign_in()).unwrap();

        let events = raised(&mut change);

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().as_str(),
            "authentication.device_trusted"
        );
        assert_eq!(
            events[0].payload().get("device_id"),
            Some(device.id().to_string().as_str())
        );
    }

    /// Ann forgets the laptop she remembered. The change raises
    /// `authentication.device_revoked`.
    #[test]
    fn forgetting_a_device_raises_device_revoked() {
        let ann = PrincipalId::from(UserId::new());
        let (mut device, _) =
            DeviceChange::<ResolvedTenant>::trust(params(), &password_and_code(ann)).unwrap();
        let holder = password_and_code(ann);

        let mut change = DeviceChange::revoke(&mut device, &holder).unwrap();

        assert_eq!(raised_names(&mut change), ["authentication.device_revoked"]);
    }

    /// A password-only sign-in cannot remember a device without proving a second factor.
    #[test]
    fn a_refused_device_raises_nothing() {
        let policy = StepUpPolicy::relaxed();
        let progress =
            SignInProgress::begin(LocalMethod::Password, SecondFactor::NotOwed, &policy).unwrap();
        let password_alone = SignedIn::of(UserId::new().into(), progress);

        let refused = DeviceChange::<ResolvedTenant>::trust(params(), &password_alone);

        assert!(matches!(
            refused,
            Err(DeviceTrustRefused::SecondFactorNotProven)
        ));
    }

    /// Another account cannot revoke Ann's device, which remains trusted.
    #[test]
    fn a_refused_revocation_raises_nothing() {
        let (mut device, _) =
            DeviceChange::<ResolvedTenant>::trust(params(), &anns_sign_in()).unwrap();
        let mallory = anns_sign_in();

        let refused = DeviceChange::revoke(&mut device, &mallory);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(device.status().is_trusted());
    }
}
