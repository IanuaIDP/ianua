//! The check a password sign-in passes before its password is hashed: is
//! sign-in under high pressure, and if so, may this device through.
//!
//! The cheapest checks come first. One read of the failure count answers
//! most sign-ins. Only under high pressure is the device looked up, and
//! only for a device nobody trusted is a challenge proof sent out to be
//! checked. Every path that cannot decide refuses: an unreadable count
//! reads as high pressure, a provider that cannot answer reads as a failed
//! proof, and with no provider at all a device nobody trusted is refused.

use std::future::Future;
use std::sync::Arc;

use ianua_domain::domains::authentication::risk_engine::challenge::{
    ChallengeProof, ChallengeSetup, ChallengeVerdict, GateSignals, GateStep, RequiredChallenge,
    under_high_pressure,
};
use ianua_domain::domains::authentication::risk_engine::pressure::{
    FailureCount, FailureThreshold, Pressure,
};
use ianua_domain::domains::authentication::risk_engine::step_up::Familiarity;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::types::{Fact, IpAddress};

use crate::error::AppError;
use crate::ports::authentication::{ChallengeVerifier, FailureScope, SignInFailureBudget};

/// What the gate reads and asks.
#[derive(ianua_macros::Fakes)]
pub struct FloodGatePorts {
    /// Failed password sign-ins per tenant and per organization.
    pub failures: Arc<dyn SignInFailureBudget>,
    /// The deployment's challenge provider, when one is set up.
    pub challenges: Option<Arc<dyn ChallengeVerifier>>,
}

/// The count a sign-in is held to, and where it reaches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Budget {
    /// Whose failures are counted together.
    pub(crate) scope: FailureScope,
    /// The count that puts sign-in under high pressure.
    pub(crate) threshold: FailureThreshold,
}

/// A sign-in at the gate.
pub(crate) struct AtTheGate<'a> {
    /// The count it is held to.
    pub(crate) budget: Budget,
    /// The proof of a passed challenge it sent, if it sent one.
    pub(crate) proof: Option<&'a ChallengeProof>,
    /// Where it came from, for the challenge provider.
    pub(crate) client_ip: Fact<&'a IpAddress>,
}

impl FloodGatePorts {
    /// Lets `at` on to its password, or refuses it, and answers with the
    /// record of pressure easing when this reading saw it ease.
    ///
    /// `device` says whether the device is one the person trusted. It is
    /// only awaited under high pressure, so a sign-in in quiet times costs
    /// one read of the count.
    ///
    /// # Errors
    ///
    /// - `AppError::ChallengeRequired` under high pressure, for a device
    ///   nobody trusted that sent no proof, a proof the provider did not
    ///   pass, or any proof while no provider is set up. The answer is the
    ///   same whether or not the address has an account.
    pub(crate) async fn admit(
        &self,
        at: AtTheGate<'_>,
        device: impl Future<Output = Familiarity> + Send,
    ) -> Result<Vec<DomainEvent>, AppError> {
        let (pressure, eased) = self.reading(at.budget).await;
        if pressure == Pressure::Normal {
            return Ok(eased);
        }
        let signals = GateSignals {
            device: device.await,
            setup: self.setup(),
            proof: at.proof,
        };
        let step = match under_high_pressure(signals) {
            GateStep::CheckProof(kind, proof) => self.verdict(proof, at.client_ip).await.step(kind),
            other => other,
        };
        ensure_proceed(step).map(|()| eased)
    }

    /// Counts a real failure, a wrong password or an unknown address,
    /// against `budget`, and answers with the record of pressure rising
    /// when this failure took it over the threshold.
    ///
    /// A count that cannot be kept is logged and left: the attempt already
    /// failed, and the gate reads an unreadable count as high anyway.
    pub(crate) async fn count_failure(&self, budget: Budget) -> Vec<DomainEvent> {
        let counted = self.failures.record_failure(&budget.scope).await;
        let Some(failures) = known(counted, "a failed sign-in could not be counted") else {
            return Vec::new();
        };
        match budget.threshold.pressure_at(failures) {
            Pressure::Normal => Vec::new(),
            Pressure::High => self.shifted(budget, Pressure::High, failures).await,
        }
    }

    /// The pressure `budget` is under now, with the record of its easing
    /// when this reading saw it ease. A count that cannot be read is high
    /// pressure: the gate never opens because its count is missing.
    async fn reading(&self, budget: Budget) -> (Pressure, Vec<DomainEvent>) {
        let read = self.failures.failures(&budget.scope).await;
        let Some(failures) = known(read, "the failure count could not be read") else {
            return (Pressure::High, Vec::new());
        };
        let now = budget.threshold.pressure_at(failures);
        let eased = match now {
            Pressure::High => Vec::new(),
            Pressure::Normal => self.shifted(budget, now, failures).await,
        };
        (now, eased)
    }

    /// Keeps `now` as `budget`'s pressure and answers with the record of
    /// the move from the pressure kept before, for a tenant's budget.
    async fn shifted(
        &self,
        budget: Budget,
        now: Pressure,
        failures: FailureCount,
    ) -> Vec<DomainEvent> {
        let before = match self.failures.swap_pressure(&budget.scope, now).await {
            Ok(before) => before,
            Err(error) => {
                tracing::warn!(%error, "sign-in: the pressure could not be kept");
                return Vec::new();
            }
        };
        let FailureScope::Tenant(tenant_id) = budget.scope else {
            return Vec::new();
        };
        now.shift_from(before)
            .recorded(tenant_id, budget.threshold, failures)
            .into_iter()
            .collect()
    }

    /// Whether challenges can be set, and which kind.
    fn setup(&self) -> ChallengeSetup {
        self.challenges
            .as_ref()
            .map_or(ChallengeSetup::Unconfigured, |verifier| {
                ChallengeSetup::Configured(verifier.kind())
            })
    }

    /// What the provider says about `proof`. No provider, and a provider
    /// that cannot answer, both fail it.
    async fn verdict(
        &self,
        proof: &ChallengeProof,
        client_ip: Fact<&IpAddress>,
    ) -> ChallengeVerdict {
        let Some(verifier) = &self.challenges else {
            return ChallengeVerdict::Failed;
        };
        match verifier.verify(proof, client_ip).await {
            Ok(verdict) => verdict,
            Err(error) => {
                tracing::warn!(%error, "sign-in: the challenge provider could not be reached");
                ChallengeVerdict::Failed
            }
        }
    }
}

/// The count `read` gave, or none when the store failed, which is logged
/// as `failed`.
fn known(read: Result<FailureCount, DomainError>, failed: &str) -> Option<FailureCount> {
    read.inspect_err(|error| tracing::warn!(%error, "sign-in: {failed}"))
        .ok()
}

/// The answer a settled step gives. A step still waiting on a proof is
/// refused: nothing passed it.
fn ensure_proceed(step: GateStep<'_>) -> Result<(), AppError> {
    match step {
        GateStep::Proceed => Ok(()),
        GateStep::Refuse(required) => Err(AppError::ChallengeRequired(required)),
        GateStep::CheckProof(..) => {
            Err(AppError::ChallengeRequired(RequiredChallenge::Unavailable))
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::risk_engine::challenge::ChallengeKind;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::authentication::{
        FakeChallengeVerifier, FakeSignInFailureBudget, UnreachableSignInFailureBudget,
    };
    use crate::test_support::block_on;

    const SOLVED: &str = "solved-puzzle-0042";

    fn budget(scope: FailureScope) -> Budget {
        Budget {
            scope,
            threshold: FailureThreshold::new(10).unwrap(),
        }
    }

    fn acme() -> FailureScope {
        FailureScope::Tenant(TenantId::new())
    }

    fn gate(failures: Arc<dyn SignInFailureBudget>) -> FloodGatePorts {
        FloodGatePorts {
            failures,
            challenges: Some(Arc::new(FakeChallengeVerifier::accepting(SOLVED))),
        }
    }

    fn sign_in(
        gate: &FloodGatePorts,
        scope: FailureScope,
        proof: Option<&ChallengeProof>,
        device: Familiarity,
    ) -> Result<Vec<DomainEvent>, AppError> {
        let at = AtTheGate {
            budget: budget(scope),
            proof,
            client_ip: Fact::Unknown,
        };
        block_on(gate.admit(at, async move { device }))
    }

    /// Ten wrong passwords at Acme reach its threshold. The tenth records
    /// that pressure rose, once; the eleventh records nothing more.
    #[test]
    fn pressure_rises_past_the_threshold_once() {
        let scope = acme();
        let gate = gate(Arc::new(FakeSignInFailureBudget::default()));
        let mut recorded = Vec::new();

        for _ in 0..11 {
            recorded.extend(block_on(gate.count_failure(budget(scope))));
        }

        let names: Vec<String> = recorded
            .iter()
            .map(|event| event.event_type().as_str().to_owned())
            .collect();
        assert_eq!(names, ["authentication.sign_in_pressure_rose"]);
    }

    /// At the failure threshold, a new device without proof receives a
    /// proof-of-work challenge requirement.
    #[test]
    fn an_untrusted_device_without_a_proof_is_challenged() {
        let scope = acme();
        let gate = gate(Arc::new(FakeSignInFailureBudget::over(scope, 10)));

        let result = sign_in(&gate, scope, None, Familiarity::New);

        assert!(matches!(
            result,
            Err(AppError::ChallengeRequired(RequiredChallenge::Solve(
                ChallengeKind::ProofOfWork
            )))
        ));
    }

    /// Ann signs in on her trusted laptop while Acme is under pressure.
    /// She goes through without a challenge.
    #[test]
    fn a_trusted_device_goes_through_under_pressure() {
        let scope = acme();
        let gate = gate(Arc::new(FakeSignInFailureBudget::over(scope, 10)));

        assert!(sign_in(&gate, scope, None, Familiarity::Known).is_ok());
    }

    /// Ann, on a new phone, solves the challenge. Her proof passes once;
    /// Mallory replaying it is refused, and so is a forged one.
    #[test]
    fn a_proof_passes_once_and_a_forged_one_never() {
        let scope = acme();
        let gate = gate(Arc::new(FakeSignInFailureBudget::over(scope, 10)));
        let solved = ChallengeProof::new(SOLVED).unwrap();
        let forged = ChallengeProof::new("made-up").unwrap();

        let first = sign_in(&gate, scope, Some(&solved), Familiarity::New);
        let replayed = sign_in(&gate, scope, Some(&solved), Familiarity::New);
        let made_up = sign_in(&gate, scope, Some(&forged), Familiarity::New);

        assert!(first.is_ok());
        assert!(matches!(replayed, Err(AppError::ChallengeRequired(_))));
        assert!(matches!(made_up, Err(AppError::ChallengeRequired(_))));
    }

    /// Under pressure without a challenge provider, new devices are
    /// refused with challenge unavailable whether or not they submit proof.
    /// A trusted device still passes.
    #[test]
    fn with_no_provider_an_untrusted_device_is_refused() {
        let scope = acme();
        let gate = FloodGatePorts {
            failures: Arc::new(FakeSignInFailureBudget::over(scope, 10)),
            challenges: None,
        };
        let proof = ChallengeProof::new(SOLVED).unwrap();

        let bare = sign_in(&gate, scope, None, Familiarity::New);
        let proved = sign_in(&gate, scope, Some(&proof), Familiarity::New);
        let trusted = sign_in(&gate, scope, None, Familiarity::Known);

        for refused in [bare, proved] {
            assert!(matches!(
                refused,
                Err(AppError::ChallengeRequired(RequiredChallenge::Unavailable))
            ));
        }
        assert!(trusted.is_ok());
    }

    /// An unreadable failure count requires a challenge from a new device
    /// instead of admitting it unchecked.
    #[test]
    fn an_unreadable_count_reads_as_high_pressure() {
        let scope = acme();
        let gate = gate(Arc::new(UnreachableSignInFailureBudget));

        let result = sign_in(&gate, scope, None, Familiarity::New);

        assert!(matches!(result, Err(AppError::ChallengeRequired(_))));
    }

    /// Acme was under pressure and its failures have aged out of the
    /// window. The next sign-in goes through and records that pressure
    /// eased.
    #[test]
    fn pressure_easing_is_recorded_by_the_next_sign_in() {
        let scope = acme();
        let failures = Arc::new(FakeSignInFailureBudget::under_pressure_kept(scope));
        let gate = gate(failures);

        let recorded = sign_in(&gate, scope, None, Familiarity::New).unwrap();

        assert_eq!(
            recorded[0].event_type().as_str(),
            "authentication.sign_in_pressure_eased"
        );
    }

    /// An organization's sign-in comes under pressure. It is counted and
    /// challenged like a tenant's, but records no tenant event.
    #[test]
    fn an_organizations_pressure_records_no_tenant_event() {
        let scope = FailureScope::UnnamedOrganizations;
        let gate = gate(Arc::new(FakeSignInFailureBudget::default()));
        let mut recorded = Vec::new();

        for _ in 0..10 {
            recorded.extend(block_on(gate.count_failure(budget(scope))));
        }
        let result = sign_in(&gate, scope, None, Familiarity::New);

        assert!(recorded.is_empty());
        assert!(matches!(result, Err(AppError::ChallengeRequired(_))));
    }
}
