//! A security signal a person reports by hand, or a workflow step reports
//! for them, about a person of the tenant.
//!
//! Most signals follow from what happened: a session revoked, an account
//! locked. Some have no change of their own to follow. Pat's workflow sees
//! Lee sign in from a country Lee never visits and reports Lee's risk as
//! high; it finds Lee's password in a breach list and reports it
//! compromised. The report is recorded, and every stream that takes the
//! signal hears of it, as of any other.

use crate::domains::signals::events::SignalReported;
use crate::domains::signals::signal::{CredentialKind, SignalEvent, SignalRiskLevel};
use crate::isolation::scope::TenantScope;
use crate::shared::events::data::EventData;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::types::{EventLabel, UserId};

/// What a report says of a person.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportedSignal {
    /// Their risk level is now this.
    RiskLevel(SignalRiskLevel),
    /// A credential of theirs is in other hands.
    CredentialCompromised(CredentialKind),
    /// A device they sign in from is no longer to be trusted.
    DeviceCompromised,
}

impl ReportedSignal {
    /// The signal it goes out as.
    #[must_use]
    pub fn event(self) -> SignalEvent {
        match self {
            Self::RiskLevel(current) => SignalEvent::RiskLevelChanged { current },
            Self::CredentialCompromised(credential) => {
                SignalEvent::CredentialCompromised { credential }
            }
            Self::DeviceCompromised => SignalEvent::DeviceCompromised,
        }
    }

    /// The report a `signals.signal_reported` record's `payload` carries,
    /// or `None` when it carries none this reads.
    #[must_use]
    pub fn read(payload: &EventData) -> Option<Self> {
        match payload.get("signal")? {
            "risk_level" => {
                let level = payload.get("level")?;
                RISK_LEVELS
                    .into_iter()
                    .find(|known| known.as_str() == level)
                    .map(Self::RiskLevel)
            }
            "credential_compromise" => {
                let credential = payload.get("credential")?;
                CREDENTIALS
                    .into_iter()
                    .find(|known| known.as_str() == credential)
                    .map(Self::CredentialCompromised)
            }
            "device_compromise" => Some(Self::DeviceCompromised),
            _ => None,
        }
    }
}

/// Every risk level a report may give.
const RISK_LEVELS: [SignalRiskLevel; 3] = [
    SignalRiskLevel::Low,
    SignalRiskLevel::Medium,
    SignalRiskLevel::High,
];

/// Every credential a report may say is compromised.
const CREDENTIALS: [CredentialKind; 5] = [
    CredentialKind::Password,
    CredentialKind::Fido2Platform,
    CredentialKind::Fido2Roaming,
    CredentialKind::X509,
    CredentialKind::App,
];

/// A report about one person, on its way to the streams that take it.
#[derive(Debug)]
pub struct SignalReport<T: TenantScope> {
    raised: Raised<T>,
}

impl<T: TenantScope> SignalReport<T> {
    /// Reports `signal` about `person`, named `label` on the audit trail.
    ///
    /// Raises `signals.signal_reported`.
    #[must_use]
    pub fn of(person: UserId, label: EventLabel, signal: ReportedSignal) -> Self {
        let mut raised = Raised::default();
        raised.raise(SignalReported {
            person,
            label,
            signal,
            occurred_at: crate::shared::clock::now(),
        });
        Self { raised }
    }
}

impl<T: TenantScope> Raises for SignalReport<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::signals::signal::SecuritySignalType;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::events::raised_names;

    /// Pat's workflow reports Lee's risk as high. The report is raised,
    /// and goes out as a change of risk level.
    #[test]
    fn a_report_is_raised_and_goes_out_as_its_signal() {
        let high = ReportedSignal::RiskLevel(SignalRiskLevel::High);
        let mut report =
            SignalReport::<ResolvedTenant>::of(UserId::new(), EventLabel::of("lee@acme.com"), high);

        assert_eq!(raised_names(&mut report), ["signals.signal_reported"]);
        assert_eq!(
            high.event().signal_type(),
            SecuritySignalType::RiskLevelChanged
        );
    }

    /// Each report is read back from the record it raised as itself.
    #[test]
    fn a_report_reads_back_from_its_record() {
        for signal in [
            ReportedSignal::RiskLevel(SignalRiskLevel::Medium),
            ReportedSignal::CredentialCompromised(CredentialKind::Fido2Roaming),
            ReportedSignal::DeviceCompromised,
        ] {
            let mut report = SignalReport::<ResolvedTenant>::of(
                UserId::new(),
                EventLabel::of("lee@acme.com"),
                signal,
            );
            let events = crate::test_support::events::raised(&mut report);

            assert_eq!(ReportedSignal::read(&events[0].payload()), Some(signal));
        }
    }
}
