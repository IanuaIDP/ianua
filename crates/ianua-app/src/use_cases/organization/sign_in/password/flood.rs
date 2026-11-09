//! Holding a member's password sign-in to the count of failures across an
//! organization, before any password is hashed.
//!
//! The count a sign-in is held to comes from what it names, never from the
//! accounts on its address, so it answers the same whether or not the
//! address has an account. A sign-in naming an organization is held to
//! that organization's count and threshold. One naming none, as the sign-in
//! page does at first, is held to the count of every such sign-in across
//! the platform, under the deployment's threshold: which organization it is
//! for is only settled by the password itself.

use ianua_domain::domains::authentication::device_trust::DeviceSecret;
use ianua_domain::domains::authentication::risk_engine::pressure::FailureThreshold;
use ianua_domain::domains::authentication::risk_engine::step_up::Familiarity;
use ianua_domain::shared::events::event::DomainEvent;

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::FailureScope;
use crate::ports::organization::OrganizationStore;
use crate::services::authentication::flood_gate::{AtTheGate, Budget, FloodGatePorts};
use crate::use_cases::organization::sign_in::password::login::OrgPasswordLoginRequest;
use crate::use_cases::organization::sign_in::password::second_factor::OwedFactor;
use crate::use_cases::organization::sign_in::steps::choice::{
    Holder, OrgLoginOutcome, OrganizationChoice,
};

/// What a member's sign-in is held to before its password is hashed.
#[derive(Clone, Copy)]
pub(in crate::use_cases::organization::sign_in) struct MemberFlood<'a> {
    /// Finds the organization a sign-in names.
    pub(in crate::use_cases::organization::sign_in) organizations: &'a dyn OrganizationStore,
    /// The counts of failures, and the challenge.
    pub(in crate::use_cases::organization::sign_in) gate: &'a FloodGatePorts,
    /// The devices members remembered.
    pub(in crate::use_cases::organization::sign_in) owed: OwedFactor<'a>,
    /// The deployment's threshold for sign-ins that name no organization.
    pub(in crate::use_cases::organization::sign_in) unnamed: FailureThreshold,
}

impl MemberFlood<'_> {
    /// The count a sign-in under `choice` is held to: the named
    /// organization's, or the one for sign-ins naming none, which a name no
    /// organization has falls back to as well.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the organization cannot be read.
    pub(in crate::use_cases::organization::sign_in) async fn budget(
        &self,
        choice: &OrganizationChoice,
    ) -> Result<Budget, AppError> {
        let OrganizationChoice::Named(slug) = choice else {
            return Ok(self.unnamed_budget());
        };
        let named = self.organizations.find_by_slug(slug).await.or_internal()?;
        Ok(named.map_or_else(
            || self.unnamed_budget(),
            |organization| Budget {
                scope: FailureScope::Organization(*organization.id()),
                threshold: organization.auth_config().challenge_threshold(),
            },
        ))
    }

    /// Lets `request` on to its password, or refuses it while `budget` is
    /// under high pressure, and answers with what that reading recorded.
    ///
    /// The device counts as trusted when any account on the address
    /// remembered it.
    ///
    /// # Errors
    ///
    /// - `AppError::ChallengeRequired` under high pressure, for a device no
    ///   member remembered that brings no passed challenge, alike whether or
    ///   not the address has an account.
    pub(in crate::use_cases::organization::sign_in) async fn admit(
        &self,
        budget: Budget,
        holders: &[Holder],
        request: &OrgPasswordLoginRequest,
    ) -> Result<Vec<DomainEvent>, AppError> {
        let at = AtTheGate {
            budget,
            proof: request.challenge.as_ref(),
            client_ip: request.origin.ip_address.as_ref(),
        };
        let device = self.device_among(holders, request.device_secret.as_ref());
        self.gate.admit(at, device).await
    }

    /// Counts `outcome` against `budget`, and against each organization an
    /// account on the address belongs to, when it was answered as invalid
    /// credentials: a wrong password, an address with no account, or any
    /// refusal that reads like one. A refusal from the cap or the challenge
    /// never reaches here.
    pub(in crate::use_cases::organization::sign_in) async fn counted(
        &self,
        budget: Budget,
        holders: &[Holder],
        outcome: &Result<OrgLoginOutcome, AppError>,
    ) -> Vec<DomainEvent> {
        let Err(AppError::NotFound(_)) = outcome else {
            return Vec::new();
        };
        let mut recorded = self.gate.count_failure(budget).await;
        for holder in holders {
            let held = Budget {
                scope: FailureScope::Organization(*holder.organization.id()),
                threshold: holder.organization.auth_config().challenge_threshold(),
            };
            if held.scope == budget.scope {
                continue;
            }
            recorded.extend(self.gate.count_failure(held).await);
        }
        recorded
    }

    /// The count for sign-ins naming no organization.
    fn unnamed_budget(&self) -> Budget {
        Budget {
            scope: FailureScope::UnnamedOrganizations,
            threshold: self.unnamed,
        }
    }

    /// Whether `secret` is a device one of `holders` remembered.
    async fn device_among(&self, holders: &[Holder], secret: Option<&DeviceSecret>) -> Familiarity {
        for holder in holders {
            if self.owed.member_device(&holder.member, secret).await == Familiarity::Known {
                return Familiarity::Known;
            }
        }
        Familiarity::New
    }
}
