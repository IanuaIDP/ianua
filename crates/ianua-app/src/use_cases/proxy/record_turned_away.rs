//! Record a signed-in person the gateway turned away from an app, for
//! workflows to start from.
//!
//! The gateway records at most one refusal for a person on one app in a
//! while, so a page that keeps retrying does not fill the trail. The person
//! is refused whether or not it is recorded.

use ianua_domain::domains::proxy::events::{PersonTurnedAway, Refused};
use ianua_domain::types::ActorRef;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// Records a person turned away at the gateway.
pub struct RecordTurnedAwayUseCase;

impl Command for RecordTurnedAwayUseCase {
    type Caller = ScopedTenant;
    type Input = Refused;
    type Output = Result<(), AppError>;

    /// Records `proxy.person_turned_away` in the tenant whose app refused,
    /// by the system: the gateway refused, not the person. It is one of the
    /// few events the gateway's inbox takes.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the record cannot be written. The person
    ///   stays refused.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        refused: Refused,
    ) -> Result<(), AppError> {
        let event = PersonTurnedAway::observed(**tenant, refused);
        auditor
            .dispatch_by(&ActorRef::System, vec![event])
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::types::{CorrelationId, EventLabel, RouteId, UserId};

    use super::*;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Pat is refused the payroll app. The refusal is recorded in his
    /// tenant, naming the app.
    #[test]
    fn a_refusal_is_recorded_naming_the_app() {
        let sink = Arc::new(FakeEventDispatcher::new());
        let refused = Refused {
            user_id: UserId::new(),
            route_id: RouteId::new(),
            route_label: EventLabel::of("payroll"),
            reason: "policy_denied",
            correlation_id: CorrelationId::new(),
        };

        block_on(RecordTurnedAwayUseCase.execute(
            &test_ctx().tenant(),
            &test_auditor(sink.clone()),
            refused,
        ))
        .unwrap();

        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["proxy.person_turned_away"]
        );
    }
}
