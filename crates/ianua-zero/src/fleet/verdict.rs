//! What one instance tells the others about a client.

use std::net::IpAddr;
use std::time::Duration;

use ianua_domain::types::TenantId;

/// How long a verdict lasts from when it is applied: a day at most,
/// whatever it asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerdictLifetime(Duration);

impl VerdictLifetime {
    /// The longest a verdict lasts. An honest verdict that needs longer is
    /// raised again by the instance still seeing the traffic.
    pub(crate) const LONGEST: Duration = Duration::from_secs(24 * 60 * 60);

    /// A lifetime of `asked`, cut to [`LONGEST`](Self::LONGEST).
    #[must_use]
    pub(crate) fn capped(asked: Duration) -> Self {
        Self(asked.min(Self::LONGEST))
    }

    /// How long the verdict lasts.
    #[must_use]
    pub(crate) fn get(self) -> Duration {
        self.0
    }
}

/// A verdict about a client that every instance should hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThreatVerdict {
    /// The client tripped the tenant's honeypot and is blocked for that
    /// tenant.
    ClientBlocked {
        /// The tenant whose decoy was hit.
        tenant: TenantId,
        /// The client's address.
        client: IpAddr,
        /// How long the block lasts.
        lasts: VerdictLifetime,
    },
    /// The client was flagged by some tenant's defences, for the tenants
    /// that take the cross-tenant signal.
    ClientFlagged {
        /// The client's address.
        client: IpAddr,
        /// How long the flag lasts.
        lasts: VerdictLifetime,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Even the largest representable duration is capped at the one-day verdict limit.
    #[test]
    fn a_lifetime_is_capped_at_one_day() {
        let lifetime = VerdictLifetime::capped(Duration::from_secs(u64::MAX));

        assert_eq!(lifetime.get(), VerdictLifetime::LONGEST);
    }

    #[test]
    fn a_shorter_lifetime_is_kept() {
        let lifetime = VerdictLifetime::capped(Duration::from_secs(600));

        assert_eq!(lifetime.get(), Duration::from_secs(600));
    }
}
