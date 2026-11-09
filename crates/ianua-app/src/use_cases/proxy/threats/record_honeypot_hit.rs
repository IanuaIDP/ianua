//! Record a client asking for one of a tenant's decoy paths.
//!
//! No real client asks for a decoy, so whoever does is almost certainly
//! malicious automation. The record shows the tenant's threat dashboard
//! what was hit and from where. The client is refused whether or not it is
//! recorded.

use ianua_domain::domains::proxy::events::HoneypotHit;
use ianua_domain::types::{ActorRef, CorrelationId, IpAddress, UntrustedText};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// One request for a decoy path.
pub struct RecordHoneypotHitRequest {
    /// The address the request came from, as the gateway established it.
    pub ip_address: IpAddress,
    /// The decoy path asked for, as the client sent it.
    pub path: UntrustedText,
    /// The request that hit the decoy.
    pub correlation_id: CorrelationId,
}

/// Records a hit on a tenant's decoy path.
pub struct RecordHoneypotHitUseCase;

impl Command for RecordHoneypotHitUseCase {
    type Caller = ScopedTenant;
    type Input = RecordHoneypotHitRequest;
    type Output = Result<(), AppError>;

    /// Records `proxy.honeypot_hit` in the tenant whose host was asked, by
    /// the system: the client is nobody the platform knows. It is one of the
    /// few events the gateway's inbox takes.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the record cannot be written. The client
    ///   stays refused.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        req: RecordHoneypotHitRequest,
    ) -> Result<(), AppError> {
        let hit = HoneypotHit::observed(**tenant, req.ip_address, req.path, req.correlation_id);
        auditor
            .dispatch_by(&ActorRef::System, vec![hit])
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

    fn request() -> RecordHoneypotHitRequest {
        RecordHoneypotHitRequest {
            ip_address: IpAddress::new("203.0.113.7").unwrap(),
            path: UntrustedText::record("/.env"),
            correlation_id: CorrelationId::new(),
        }
    }

    /// Mallory's scanner asks the shop for `/.env`. The hit is recorded in
    /// the shop's tenant with the path and the address it came from.
    #[test]
    fn a_hit_is_recorded_with_its_path_and_address() {
        let sink = Arc::new(FakeEventDispatcher::new());

        block_on(RecordHoneypotHitUseCase.execute(
            &test_ctx().tenant(),
            &test_auditor(sink.clone()),
            request(),
        ))
        .unwrap();

        assert_eq!(
            sink.records.lock().unwrap().as_slice(),
            ["proxy.honeypot_hit"]
        );
        let payload = sink.payload_of("proxy.honeypot_hit");
        assert_eq!(
            payload.value("path"),
            Some(&FieldValue::Text("/.env".to_owned()))
        );
        assert_eq!(
            payload.value("ip_address"),
            Some(&FieldValue::Text("203.0.113.7".to_owned()))
        );
        assert_eq!(
            sink.tenant_of("proxy.honeypot_hit"),
            Some(test_ctx().tenant_id())
        );
    }

    /// Failing to audit a honeypot hit returns an internal error to the gateway.
    #[test]
    fn an_unwritten_record_is_an_error() {
        let recorded = block_on(RecordHoneypotHitUseCase.execute(
            &test_ctx().tenant(),
            &test_auditor(Arc::new(FailingEventDispatcher)),
            request(),
        ));

        assert!(matches!(recorded, Err(AppError::Internal(_))));
    }
}
