//! Record a way out the egress gateway refused a service while it handled
//! an agent's request.
//!
//! The agent's request caused the call, so the refusal is held against the
//! agent as drift once a worker hears it.

use ianua_domain::domains::agents::events::enforcement::{AgentAtWork, AgentEgressDenied};
use ianua_domain::domains::routing::egress::{EgressDenial, ServiceIdentity};
use ianua_domain::types::{ActingFor, ActorRef, AgentId, DelegationId, UntrustedText};
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// One way out the egress gateway refused.
pub(crate) struct RecordEgressDenialRequest {
    /// The agent whose request caused the call.
    pub agent_id: AgentId,
    /// The delegation it acted under.
    pub delegation_id: DelegationId,
    /// The service that tried to go out.
    pub service: ServiceIdentity,
    /// Where it tried to go, as `host:port`.
    pub destination: UntrustedText,
    /// Why it was refused: the gateway's own reason, so a service cannot
    /// write its own text into the record.
    pub reason: EgressDenial,
    /// When it was refused. The monitor rebuilds the record at this
    /// instant.
    pub decided_at: OffsetDateTime,
}

/// Records a refused way out against the agent behind it.
pub(crate) struct RecordEgressDenialUseCase;

impl Command for RecordEgressDenialUseCase {
    type Caller = ScopedTenant;
    type Input = RecordEgressDenialRequest;
    type Output = Result<(), AppError>;

    /// Records `agents.egress_denied`, by the agent acting for itself, in
    /// the tenant whose policy refused it. It is one of the few events the
    /// gateway's inbox takes.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the record cannot be written. The way
    ///   out stays refused either way.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        req: RecordEgressDenialRequest,
    ) -> Result<(), AppError> {
        let by_agent = ActorRef::Agent {
            id: req.agent_id,
            on_behalf_of: ActingFor::Itself,
        };
        let by = AgentAtWork::new(**tenant, req.agent_id, req.delegation_id);
        let refused = AgentEgressDenied::observed(
            by,
            req.service,
            req.destination,
            req.reason,
            req.decided_at,
        );
        auditor
            .dispatch_by(&by_agent, vec![refused])
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::shared::clock;
    use ianua_domain::shared::events::data::FieldValue;

    use super::*;
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, block_on, test_auditor, test_ctx,
    };

    fn request() -> RecordEgressDenialRequest {
        RecordEgressDenialRequest {
            agent_id: AgentId::new(),
            delegation_id: DelegationId::new(),
            service: ServiceIdentity::new("spiffe://ianua.test/ns/svc/sa/orders").unwrap(),
            destination: UntrustedText::record("evil.example:443"),
            reason: EgressDenial::DestinationNotListed,
            decided_at: clock::now(),
        }
    }

    /// The orders service, handling an agent's request, tries to reach a
    /// host not on its list. The refusal is recorded against the agent,
    /// with the gateway's reason and the tenant whose policy refused it.
    #[test]
    fn a_refused_way_out_is_recorded_against_the_agent() {
        let sink = Arc::new(FakeEventDispatcher::new());
        let req = request();
        let agent = req.agent_id;

        block_on(RecordEgressDenialUseCase.execute(
            &test_ctx().tenant(),
            &test_auditor(sink.clone()),
            req,
        ))
        .unwrap();

        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["agents.egress_denied"]
        );
        let payload = sink.payload_of("agents.egress_denied");
        assert_eq!(
            payload.value("agent_id"),
            Some(&FieldValue::Text(agent.to_string()))
        );
        assert_eq!(
            payload.value("reason"),
            Some(&FieldValue::Text(
                EgressDenial::DestinationNotListed.as_str().to_owned()
            ))
        );
        assert_eq!(
            sink.tenant_of("agents.egress_denied"),
            Some(test_ctx().tenant_id())
        );
    }

    /// Failure to persist an egress-denial record returns an internal error.
    #[test]
    fn an_unwritten_record_is_an_error() {
        let recorded = block_on(RecordEgressDenialUseCase.execute(
            &test_ctx().tenant(),
            &test_auditor(Arc::new(FailingEventDispatcher)),
            request(),
        ));

        assert!(matches!(recorded, Err(AppError::Internal(_))));
    }
}
