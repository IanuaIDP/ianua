//! Holding a tenant's password sign-in to the count of failures across the
//! whole tenant, before any password is hashed.
//!
//! The count and its threshold are the tenant's, never the account's, so a
//! sign-in under high pressure is answered the same whether or not the
//! address has an account. Only the device can let it past without a
//! challenge, and an address with no account has no remembered device.

use ianua_domain::domains::authentication::device_trust::TrustWindow;
use ianua_domain::domains::authentication::operations::password_login::LoginCandidate;
use ianua_domain::domains::authentication::risk_engine::step_up::Familiarity;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::shared::events::event::DomainEvent;

use crate::error::AppError;
use crate::ports::authentication::FailureScope;
use crate::services::authentication::flood_gate::{AtTheGate, Budget, FloodGatePorts};
use crate::tenancy::ScopedTenant;
use crate::use_cases::authentication::password::sign_in::login::LoginRequest;
use crate::use_cases::authentication::password::sign_in::login_security::{
    LoginSecurityPorts, PresentedDevice,
};
use crate::use_cases::authentication::password::sign_in::settlement::{Settlement, Tally};

/// What a tenant's password sign-in is held to before its password is
/// hashed.
#[derive(Clone, Copy)]
pub(in crate::use_cases::authentication::password) struct TenantFlood<'a> {
    /// The counts of failures, and the challenge.
    pub(in crate::use_cases::authentication::password) gate: &'a FloodGatePorts,
    /// The browsers people remembered.
    pub(in crate::use_cases::authentication::password) security: &'a LoginSecurityPorts,
    /// How long a remembered browser may go unused and still count.
    pub(in crate::use_cases::authentication::password) device_trust: TrustWindow,
}

/// The count of failures across the tenant `record`, and its threshold.
pub(in crate::use_cases::authentication::password) fn tenant_budget(record: &Tenant) -> Budget {
    Budget {
        scope: FailureScope::Tenant(*record.id()),
        threshold: record.auth_config().challenge_threshold(),
    }
}

impl TenantFlood<'_> {
    /// Lets `request` on to its password, or refuses it while `budget` is
    /// under high pressure, and answers with the record of pressure easing
    /// when this reading saw it ease.
    ///
    /// # Errors
    ///
    /// - `AppError::ChallengeRequired` under high pressure, for a browser
    ///   `candidate` never remembered that brings no passed challenge.
    pub(in crate::use_cases::authentication::password) async fn admit(
        &self,
        tenant: &ScopedTenant,
        request: &LoginRequest,
        candidate: Option<&LoginCandidate>,
        budget: Budget,
    ) -> Result<Vec<DomainEvent>, AppError> {
        let at = AtTheGate {
            budget,
            proof: request.challenge.as_ref(),
            client_ip: request.origin.ip_address.as_ref(),
        };
        let device = self.device_of(tenant, request, candidate);
        self.gate.admit(at, device).await
    }

    /// The record of pressure rising, when `settlement` was a real failure
    /// that took the tenant's count over its threshold. Only a wrong
    /// password or an unknown address is counted.
    pub(in crate::use_cases::authentication::password) async fn counted(
        &self,
        settlement: &Settlement,
        budget: Budget,
    ) -> Vec<DomainEvent> {
        match settlement.tally {
            Tally::Failure => self.gate.count_failure(budget).await,
            Tally::NotAFailure => Vec::new(),
        }
    }

    /// Whether the browser `request` came from is one `candidate`
    /// remembered. An address with no account has no remembered browser.
    pub(in crate::use_cases::authentication::password) async fn device_of(
        &self,
        tenant: &ScopedTenant,
        request: &LoginRequest,
        candidate: Option<&LoginCandidate>,
    ) -> Familiarity {
        let Some(candidate) = candidate else {
            return Familiarity::New;
        };
        let device = PresentedDevice {
            tenant,
            user_id: &candidate.user_id,
            secret: request.device_secret.as_ref(),
        };
        self.security
            .device_familiarity(device, self.device_trust)
            .await
    }
}
