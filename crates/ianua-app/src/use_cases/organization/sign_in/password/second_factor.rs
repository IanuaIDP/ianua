//! What a member's password sign-in still owes in the way of a second
//! factor.
//!
//! The organization's step-up policy says whether the sign-in is asked for
//! more, and why; the domain then decides what the member owes from that,
//! the organization's MFA policy, whether they hold a factor, whether a
//! mail can reach them, and whether the setup token or an accepted
//! invitation vouches for this, their first sign-in. The only
//! signal a password sign-in carries is the device: one the member
//! remembered counts as known, anything else as new. While the account is
//! under attack, a new device is a risk signal of its own. A remembered
//! device a sign-in went through on is stamped as used, so it keeps
//! counting.

use ianua_domain::domains::authentication::device_trust::{
    DeviceSecret, DeviceTrustRules, TrustWindow, TrustedDevice,
};
use ianua_domain::domains::authentication::mfa::owed::{FactorOwed, SecondFactor};
use ianua_domain::domains::authentication::risk_engine::assessment::RiskLevel;
use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
use ianua_domain::domains::authentication::risk_engine::attack::AccountAttack;
use ianua_domain::domains::authentication::risk_engine::step_up::{
    AuthenticationContext, Familiarity, Sensitivity, SignInSignals,
};
use ianua_domain::domains::identity::account::address::MailReach;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Fact, PrincipalId};

use crate::error::{AppError, OrInternal};
use crate::ports::oauth::CodeHasher;
use crate::ports::organization::OrgTrustedDeviceStore;
use crate::services::authentication::sign_in_gate::ClientOrigin;
use crate::services::authentication::sign_in_steps::no_factor_to_prove_with;
use crate::use_cases::organization::sign_in::password::held_factors::MemberFactorSources;

/// What a password sign-in's second factor is worked out from.
#[derive(Clone, Copy)]
pub(in crate::use_cases::organization::sign_in) struct OwedFactor<'a> {
    /// The member's second factors.
    pub(in crate::use_cases::organization::sign_in) factors: MemberFactorSources<'a>,
    /// The devices members remembered.
    pub(in crate::use_cases::organization::sign_in) devices: &'a dyn OrgTrustedDeviceStore,
    /// Hashes a device's secret the way remembering it stored it.
    pub(in crate::use_cases::organization::sign_in) secret_hasher: &'a dyn CodeHasher,
    /// How long a remembered device may go unused and still count.
    pub(in crate::use_cases::organization::sign_in) window: TrustWindow,
    /// Whether a confirmation link mailed now would reach the member.
    pub(in crate::use_cases::organization::sign_in) mail: MailReach,
}

/// What a member's password sign-in came with besides the password: the
/// device it came from, and whether the account is under attack.
#[derive(Clone, Copy)]
pub(in crate::use_cases::organization::sign_in) struct SignInCircumstances<'a> {
    /// The secret of a device the member remembered, if it sent one.
    pub(in crate::use_cases::organization::sign_in) secret: Option<&'a DeviceSecret>,
    /// Whether failures from many networks put the account under attack.
    pub(in crate::use_cases::organization::sign_in) attack: AccountAttack,
}

impl OwedFactor<'_> {
    /// What `member`'s password sign-in to `organization` owes, in the
    /// circumstances it `came` in. Under attack, a device the member did
    /// not remember asks for more than the password, as any risk signal
    /// does.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the sign-in looks risky, or comes from
    ///   a new device while the account is under attack, the member has no
    ///   second factor, no mail could confirm it, and neither the setup
    ///   token nor an accepted invitation vouches for this sign-in. The
    ///   answer tells them to ask for a new invitation.
    /// - `AppError::Internal` when the member's factors cannot be read.
    pub(in crate::use_cases::organization::sign_in) async fn owed_by_member(
        &self,
        member: &OrgUser,
        organization: &Organization,
        came: SignInCircumstances<'_>,
    ) -> Result<SecondFactor, AppError> {
        let enrolment = self.factors.held_by(member.id()).await?;
        let device = self.member_device(member, came.secret).await;
        let config = organization.auth_config();
        let asked = config
            .step_up_policy()
            .demand(&password_sign_in_from(device));
        let demand = came.attack.demand(asked, device);
        FactorOwed::under(
            config.mfa_policy(),
            demand,
            enrolment,
            self.mail,
            member.vouching(),
        )
        .owed()
        .map_err(|_| no_factor_to_prove_with())
    }

    /// Whether `secret` is a device `member` remembered and that still
    /// counts.
    pub(in crate::use_cases::organization::sign_in) async fn member_device(
        &self,
        member: &OrgUser,
        secret: Option<&DeviceSecret>,
    ) -> Familiarity {
        match self.remembered_device(member, secret).await {
            Some(_) => Familiarity::Known,
            None => Familiarity::New,
        }
    }

    /// Stamps the device `secret` names as used for `member`'s sign-in that
    /// just went through, from `origin`, when it is one they remembered and
    /// that still counts. Its idle window starts again.
    ///
    /// A device that is not remembered, or a request whose address or
    /// client could not be told, leaves nothing to stamp.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` when the device cannot be saved.
    pub(in crate::use_cases::organization::sign_in) async fn stamp_member_device(
        &self,
        member: &OrgUser,
        secret: Option<&DeviceSecret>,
        origin: &ClientOrigin,
    ) -> Result<(), AppError> {
        let (Fact::Known(ip), Some(user_agent)) = (&origin.ip_address, &origin.user_agent) else {
            return Ok(());
        };
        let Some(mut device) = self.remembered_device(member, secret).await else {
            return Ok(());
        };
        device.record_login(user_agent.clone(), ip.clone());
        self.devices.save(member.id(), &device).await.or_internal()
    }

    /// The device `secret` names, when `member` remembered it and it still
    /// counts.
    ///
    /// No secret, no matching device, a revoked or stale one, one
    /// remembered before the member last changed how they sign in, and a
    /// store or hasher that cannot answer all give none.
    async fn remembered_device(
        &self,
        member: &OrgUser,
        secret: Option<&DeviceSecret>,
    ) -> Option<TrustedDevice<ResolvedOrganization>> {
        let secret = secret?;
        let devices = self.devices.list_by_user(member.id()).await.ok()?;
        let digest = self
            .secret_hasher
            .hash_code(&Secret::new(secret.as_str()))
            .await
            .ok()?;
        let rules = DeviceTrustRules {
            signing_in: PrincipalId::from(*member.id()),
            idle_window: self.window,
            credentials_changed_at: member.credentials_changed_at(),
        };
        devices
            .into_iter()
            .find(|device| device.matches(&digest, &rules))
    }
}

/// A password sign-in from `device`, as the step-up policy reads it.
fn password_sign_in_from(device: Familiarity) -> AuthenticationContext {
    AuthenticationContext::new(
        AssuranceLevel::Aal1,
        RiskLevel::Low,
        SignInSignals {
            device,
            country: Familiarity::Known,
            operation: Sensitivity::Ordinary,
        },
    )
}
