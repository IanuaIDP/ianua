//! What a password sign-in learns from outside the domain once the password
//! is proven: whether it appears in known breaches, where the request came
//! from, and whether the browser is one the person remembered.
//!
//! A service that cannot answer never stops the sign-in. Its question is
//! recorded as unavailable, which the domain turns into an audit record, and
//! the sign-in goes on as if the password were clean and the address
//! unplaced. A device that cannot be checked counts as new, so the person is
//! asked for their second factor rather than let past it.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::breach::{BreachPolicy, BreachStatus};
use ianua_domain::domains::authentication::device_trust::{
    DeviceTrustRules, PresentedSecret, TrustWindow, TrustedDevice,
};
use ianua_domain::domains::authentication::operations::password_login::Lookup;
use ianua_domain::domains::authentication::risk_engine::assessment::IpGeolocation;
use ianua_domain::domains::authentication::risk_engine::step_up::Familiarity;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Fact, IpAddress, PrincipalId, UserId};

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{
    CredentialBreachChecker, Geolocator, SignInHistoryStore, TrustedDeviceStore,
};
use crate::ports::identity::UserStore;
use crate::ports::oauth::CodeHasher;
use crate::services::authentication::sign_in_gate::ClientOrigin;
use crate::tenancy::ScopedTenant;

/// The services and records a password sign-in asks once the password is
/// proven.
#[derive(ianua_macros::Fakes)]
pub struct LoginSecurityPorts {
    /// Checks the password against known breaches.
    pub breach_checker: Arc<dyn CredentialBreachChecker>,
    /// Places the request's address.
    pub geolocator: Arc<dyn Geolocator>,
    /// The browsers people remembered.
    pub devices: Arc<dyn TrustedDeviceStore>,
    /// Hashes a browser's secret the way remembering it stored it.
    pub device_secret_hasher: Arc<dyn CodeHasher>,
    /// Where people signed in from before.
    pub sign_in_history: Arc<dyn SignInHistoryStore>,
    /// The accounts, for when each last changed how it signs in.
    pub users: Arc<dyn UserStore>,
}

/// What the deployment decides about the checks, beside the tenant.
#[derive(Debug, Clone, Copy)]
pub struct SecurityRules {
    /// Whether passwords are checked against breaches, and what a breach
    /// does.
    pub breach_policy: BreachPolicy,
    /// How long a remembered browser may go unused and still count.
    pub device_trust: TrustWindow,
}

/// A browser presenting its secret for one account.
pub(in crate::use_cases::authentication::password) struct PresentedDevice<'a> {
    /// The tenant signing in to.
    pub(in crate::use_cases::authentication::password) tenant: &'a ScopedTenant,
    /// The account whose password was proven.
    pub(in crate::use_cases::authentication::password) user_id: &'a UserId,
    /// The secret the browser sent, if it sent one, with where it sent it:
    /// a device remembered at one place counts there alone.
    pub(in crate::use_cases::authentication::password) secret: Option<&'a PresentedSecret>,
}

impl LoginSecurityPorts {
    /// Whether the password appears in known breaches, unless the
    /// deployment does not check.
    pub(in crate::use_cases::authentication::password) async fn breach_of(
        &self,
        password: &Secret,
        policy: BreachPolicy,
    ) -> Lookup<BreachStatus> {
        if !policy.checks_passwords() {
            return Lookup::Unknown;
        }
        match self.breach_checker.check(password).await {
            Ok(status) => Lookup::Known(status),
            Err(error) => {
                tracing::warn!(%error, "sign-in: the breach check could not be reached");
                Lookup::Unavailable
            }
        }
    }

    /// Where `ip` is, when the request had an address and it can be placed.
    pub(in crate::use_cases::authentication::password) async fn location_of(
        &self,
        ip: Fact<&IpAddress>,
    ) -> Lookup<IpGeolocation> {
        let Fact::Known(ip) = ip else {
            return Lookup::Unknown;
        };
        match self.geolocator.locate(ip).await {
            Ok(Some(place)) => Lookup::Known(place),
            Ok(None) => Lookup::Unknown,
            Err(error) => {
                tracing::warn!(%error, "sign-in: the address could not be placed");
                Lookup::Unavailable
            }
        }
    }

    /// Whether `presented` is a browser the account remembered and that
    /// still counts under `window`.
    ///
    /// No secret, no matching device, a revoked or stale one, one
    /// remembered before the account last changed how it signs in, and a
    /// store that cannot answer all count as new.
    pub(in crate::use_cases::authentication::password) async fn device_familiarity(
        &self,
        presented: PresentedDevice<'_>,
        window: TrustWindow,
    ) -> Familiarity {
        match self.remembered_device(presented, window).await {
            Some(_) => Familiarity::Known,
            None => Familiarity::New,
        }
    }

    /// Stamps `device`, the remembered browser a sign-in that just went
    /// through came from, as used from `origin`. Its idle window starts
    /// again.
    ///
    /// A request whose address or client could not be told leaves nothing
    /// to stamp.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` when the device cannot be saved.
    pub(in crate::use_cases::authentication::password) async fn record_device_sign_in(
        &self,
        tenant: &ScopedTenant,
        mut device: TrustedDevice<ResolvedTenant>,
        origin: &ClientOrigin,
    ) -> Result<(), AppError> {
        let (Fact::Known(ip), Some(user_agent)) = (&origin.ip_address, &origin.user_agent) else {
            return Ok(());
        };
        device.record_login(user_agent.clone(), ip.clone());
        self.devices.save(tenant, &device).await.or_internal()
    }

    /// The device `presented` is, when the account remembered it and it
    /// still counts under `window`.
    ///
    /// No secret, no matching device, a revoked or stale one, one
    /// remembered before the account last changed how it signs in, and a
    /// store or hasher that cannot answer all give none.
    pub(in crate::use_cases::authentication::password) async fn remembered_device(
        &self,
        presented: PresentedDevice<'_>,
        window: TrustWindow,
    ) -> Option<TrustedDevice<ResolvedTenant>> {
        let secret = presented.secret?;
        let rules = self.trust_rules(&presented, window).await?;
        let devices = self
            .devices
            .list_by_user(presented.tenant, presented.user_id)
            .await
            .ok()?;
        let digest = self
            .device_secret_hasher
            .hash_code(&secret.bound())
            .await
            .ok()?;
        devices
            .into_iter()
            .find(|device| device.matches(&digest, &rules))
    }

    /// What a remembered device is held to for the account, when the
    /// account can be read.
    async fn trust_rules(
        &self,
        presented: &PresentedDevice<'_>,
        window: TrustWindow,
    ) -> Option<DeviceTrustRules> {
        let account = self
            .users
            .find_by_id(presented.tenant, presented.user_id)
            .await
            .ok()
            .flatten()?;
        Some(DeviceTrustRules {
            signing_in: PrincipalId::from(*presented.user_id),
            idle_window: window,
            credentials_changed_at: account.credentials_changed_at(),
        })
    }
}
