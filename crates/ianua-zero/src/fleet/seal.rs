//! The seal on every verdict an instance broadcasts.

use ianua_infra::crypto::FleetVerdictSeal;

/// Seals the verdicts the gateway's instances share, under a key derived
/// from the platform's root for this use alone, so a seal made for anything
/// else never holds here.
pub(crate) trait VerdictSeal: Send + Sync {
    /// The seal on `verdict` broadcast on `subject`. It never holds a `.`.
    fn seal(&self, subject: &str, verdict: &[u8]) -> String;

    /// Whether `seal` is the seal on `verdict` broadcast on `subject`,
    /// compared in constant time.
    fn holds(&self, subject: &str, verdict: &[u8], seal: &str) -> bool;
}

impl VerdictSeal for FleetVerdictSeal {
    fn seal(&self, subject: &str, verdict: &[u8]) -> String {
        Self::seal(self, subject, verdict)
    }

    fn holds(&self, subject: &str, verdict: &[u8], seal: &str) -> bool {
        Self::holds(self, subject, verdict, seal)
    }
}
