//! Record one of a tenant's canary tokens caught leaking from its upstream.
//!
//! The gateway withholds a response that renders a canary token. That is
//! no sign the caller is malicious: the tenant's own service exposes a
//! secret it should never show, in a debug dump or an error page, and an
//! administrator must find it on record to fix it. The response stays
//! withheld whether or not it is recorded.

use ianua_domain::domains::proxy::events::CanaryTokenLeaked;
use ianua_domain::types::{ActorRef, CorrelationId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// One response withheld for a leaking canary token.
pub struct RecordCanaryLeakRequest {
    /// The request whose response was withheld.
    pub correlation_id: CorrelationId,
}

/// Records a canary token leaking from a tenant's upstream.
pub struct RecordCanaryLeakUseCase;

impl Command for RecordCanaryLeakUseCase {
    type Caller = ScopedTenant;
    type Input = RecordCanaryLeakRequest;
    type Output = Result<(), AppError>;

    /// Records `proxy.canary_token_leaked` in the tenant whose upstream
    /// leaked, by the system. It is one of the few events the gateway's
    /// inbox takes. Neither the token nor the response is recorded.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the record cannot be written. The
    ///   response stays withheld.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        req: RecordCanaryLeakRequest,
    ) -> Result<(), AppError> {
        let leaked = CanaryTokenLeaked::observed(**tenant, req.correlation_id);
        auditor
            .dispatch_by(&ActorRef::System, vec![leaked])
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::shared::events::data::FieldValue;

    use super::*;
    use crate::test_support::{
        FailingEventDispatcher, FakeEventDispatcher, block_on, test_auditor, test_ctx,
    };

    const LEAKED: &str = "proxy.canary_token_leaked";

    /// The shop's upstream renders its canary key in a debug page. The leak
    /// is recorded in the shop's tenant against the withheld request.
    #[test]
    fn a_leak_is_recorded_against_its_request() {
        let sink = Arc::new(FakeEventDispatcher::new());
        let correlation_id = CorrelationId::new();

        block_on(RecordCanaryLeakUseCase.execute(
            &test_ctx().tenant(),
            &test_auditor(sink.clone()),
            RecordCanaryLeakRequest { correlation_id },
        ))
        .unwrap();

        assert_eq!(sink.records.lock().unwrap().as_slice(), [LEAKED]);
        assert_eq!(
            sink.payload_of(LEAKED).value("correlation_id"),
            Some(&FieldValue::Text(correlation_id.to_string()))
        );
        assert_eq!(sink.tenant_of(LEAKED), Some(test_ctx().tenant_id()));
    }

    /// Failing to audit a canary leak returns an internal error to the gateway.
    #[test]
    fn an_unwritten_record_is_an_error() {
        let recorded = block_on(RecordCanaryLeakUseCase.execute(
            &test_ctx().tenant(),
            &test_auditor(Arc::new(FailingEventDispatcher)),
            RecordCanaryLeakRequest {
                correlation_id: CorrelationId::new(),
            },
        ));

        assert!(matches!(recorded, Err(AppError::Internal(_))));
    }
}
