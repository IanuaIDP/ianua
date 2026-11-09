//! Record a client presenting one of a tenant's canary tokens.
//!
//! A canary token is planted where only a thief would find it and is never
//! issued to anyone, so whoever presents it is replaying a stolen copy. The
//! record shows the tenant's threat dashboard where it came from, and is
//! what an administrator is alerted on. The client is refused whether or
//! not it is recorded.

use ianua_domain::domains::proxy::events::CanaryTokenTriggered;
use ianua_domain::types::{ActorRef, CorrelationId, IpAddress};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// One request that presented a canary token.
pub struct RecordCanaryTriggeredRequest {
    /// The address the request came from, as the gateway established it.
    pub ip_address: IpAddress,
    /// The request that carried the token.
    pub correlation_id: CorrelationId,
}

/// Records a canary token presented to a tenant's host.
pub struct RecordCanaryTriggeredUseCase;

impl Command for RecordCanaryTriggeredUseCase {
    type Caller = ScopedTenant;
    type Input = RecordCanaryTriggeredRequest;
    type Output = Result<(), AppError>;

    /// Records `proxy.canary_token_triggered` in the tenant whose host was
    /// asked, by the system: the client is nobody the platform knows. It is
    /// one of the few events the gateway's inbox takes. The token itself is
    /// never recorded.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the record cannot be written. The client
    ///   stays refused.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        req: RecordCanaryTriggeredRequest,
    ) -> Result<(), AppError> {
        let presented =
            CanaryTokenTriggered::observed(**tenant, req.ip_address, req.correlation_id);
        auditor
            .dispatch_by(&ActorRef::System, vec![presented])
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

    const TRIGGERED: &str = "proxy.canary_token_triggered";

    fn request() -> RecordCanaryTriggeredRequest {
        RecordCanaryTriggeredRequest {
            ip_address: IpAddress::new("203.0.113.7").unwrap(),
            correlation_id: CorrelationId::new(),
        }
    }

    /// Mallory replays the shop's canary API key she found in a leaked
    /// backup. It is recorded in the shop's tenant with her address.
    #[test]
    fn a_presented_canary_is_recorded_with_its_address() {
        let sink = Arc::new(FakeEventDispatcher::new());

        block_on(RecordCanaryTriggeredUseCase.execute(
            &test_ctx().tenant(),
            &test_auditor(sink.clone()),
            request(),
        ))
        .unwrap();

        assert_eq!(sink.records.lock().unwrap().as_slice(), [TRIGGERED]);
        assert_eq!(
            sink.payload_of(TRIGGERED).value("ip_address"),
            Some(&FieldValue::Text("203.0.113.7".to_owned()))
        );
        assert_eq!(sink.tenant_of(TRIGGERED), Some(test_ctx().tenant_id()));
    }

    /// Failing to audit a presented canary returns an internal error to the
    /// gateway.
    #[test]
    fn an_unwritten_record_is_an_error() {
        let recorded = block_on(RecordCanaryTriggeredUseCase.execute(
            &test_ctx().tenant(),
            &test_auditor(Arc::new(FailingEventDispatcher)),
            request(),
        ));

        assert!(matches!(recorded, Err(AppError::Internal(_))));
    }
}
