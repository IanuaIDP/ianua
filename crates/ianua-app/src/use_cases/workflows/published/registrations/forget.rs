//! The background sweep that forgets which deliveries already started a
//! run once no service would send them again.
//!
//! A service resends a delivery it is not sure arrived for a few hours to a
//! few days; one noted a week ago will not come again, so the record which
//! kept it from starting twice has done its work.

use std::sync::Arc;

use ianua_domain::shared::clock;
use time::Duration;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::workflows::DeliveryRetention;
use crate::use_case::Command;

/// How long a delivery is remembered after it started a run.
const REMEMBERED_FOR: Duration = Duration::days(7);

/// The most deliveries one round forgets; the next round forgets the rest.
const MOST_PER_ROUND: u32 = 5_000;

/// The ports [`ForgetUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ForgetPorts {
    /// Forgets old deliveries, across every tenant.
    pub retention: Arc<dyn DeliveryRetention>,
}

/// Forgets the deliveries no service would send again.
///
/// It runs as a periodic job of the platform, with nobody asking.
pub struct ForgetUseCase {
    ports: ForgetPorts,
}

impl ForgetUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ForgetPorts) -> Self {
        Self { ports }
    }
}

impl Command for ForgetUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<u64, AppError>;

    /// Forgets up to a round's worth of deliveries noted over a week ago,
    /// and how many.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when they cannot be removed; the next round
    /// tries again.
    async fn execute(
        &self,
        _caller: &(),
        _auditor: &RequestAuditor,
        _input: (),
    ) -> Result<u64, AppError> {
        self.ports
            .retention
            .forget_before(clock::now() - REMEMBERED_FOR, MOST_PER_ROUND)
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{ServiceSubscriptionId, TenantId};

    use super::*;
    use crate::ports::workflows::{DeliveryId, DeliveryLedger as _};
    use crate::tenancy::ScopedTenant;
    use crate::test_support::workflows::FakeDeliveryLedger;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    /// A delivery GitHub sent this morning is still remembered, so a resend
    /// starts nothing; the sweep leaves it.
    #[test]
    fn a_recent_delivery_is_still_remembered() {
        let ledger = Arc::new(FakeDeliveryLedger::default());
        let tenant = ScopedTenant::for_background(TenantId::new());
        block_on(ledger.first_time(
            &tenant,
            &ServiceSubscriptionId::new(),
            &DeliveryId::new("delivery-1".to_owned()),
        ))
        .unwrap();
        let use_case = ForgetUseCase::new(ForgetPorts {
            retention: ledger.clone(),
        });

        let forgotten = block_on(use_case.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            (),
        ))
        .unwrap();

        assert_eq!(forgotten, 0);
        assert_eq!(ledger.remembered(), 1);
    }
}
