//! Receive sign-in: an app's sign-in request reaches the tenant's single
//! sign-on service and is held on the server until the person is signed in.
//!
//! The browser goes on to the dashboard with only the id it is held by.
//! When the request arrived is written here, so the answer later reads it
//! from the server and never from the browser: a person holding a session
//! cannot backdate a request to slip past an app's demand for a fresh
//! sign-in.

use std::sync::Arc;

use ianua_domain::shared::clock;
use ianua_domain::types::SamlArrivalId;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::federation::{HeldSamlSignIn, HeldSamlSignInStore, InboundSamlMessage};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// An app's sign-in request as it reached this platform.
pub struct ReceiveSignInRequest {
    /// The request, as it arrived.
    pub message: InboundSamlMessage,
    /// What the app wants back with the answer, if it sent anything.
    pub relay_state: Option<String>,
}

/// The ports [`ReceiveSignInUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ReceiveSignInPorts {
    /// Holds the request until it is answered.
    pub held: Arc<dyn HeldSamlSignInStore>,
}

/// Holds an app's sign-in request, with when it arrived, until it is
/// answered.
pub struct ReceiveSignInUseCase {
    ports: ReceiveSignInPorts,
}

impl ReceiveSignInUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ReceiveSignInPorts) -> Self {
        Self { ports }
    }
}

impl Command for ReceiveSignInUseCase {
    type Caller = ScopedTenant;
    type Input = ReceiveSignInRequest;
    type Output = Result<SamlArrivalId, AppError>;

    /// Holds `request` in `tenant`, arrived now, and gives the id it is
    /// held by. Nothing is read from the request yet: who sent it and
    /// whether it may be answered are checked when it is answered. Records
    /// nothing.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        _auditor: &RequestAuditor,
        request: ReceiveSignInRequest,
    ) -> Result<SamlArrivalId, AppError> {
        let held = HeldSamlSignIn {
            id: SamlArrivalId::new(),
            message: request.message,
            relay_state: request.relay_state,
            arrived_at: clock::now(),
        };
        self.ports.held.hold(tenant, &held).await.or_internal()?;
        Ok(held.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::federation::{FakeHeldSamlSignIns, posted_message};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Salesforce sends Ann's browser with a sign-in request. It is held in
    /// Acme, arrived now, under the id the browser goes on with.
    #[test]
    fn a_request_is_held_under_the_id_given_back() {
        let held = Arc::new(FakeHeldSamlSignIns::empty());
        let use_case = ReceiveSignInUseCase::new(ReceiveSignInPorts { held: held.clone() });
        let auditor = test_auditor(Arc::new(FakeEventDispatcher::new()));
        let before = clock::now();

        let id = block_on(use_case.execute(
            &test_ctx().tenant(),
            &auditor,
            ReceiveSignInRequest {
                message: posted_message(),
                relay_state: Some("back".to_owned()),
            },
        ))
        .unwrap();

        let kept = held.all();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].id, id);
        assert_eq!(kept[0].message, posted_message());
        assert_eq!(kept[0].relay_state.as_deref(), Some("back"));
        assert!(kept[0].arrived_at >= before);
    }
}
