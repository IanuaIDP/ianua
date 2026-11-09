//! Beginning a passkey sign-in before anyone typed an address: the browser
//! offers a passkey from the empty sign-in field, so the ceremony opens for
//! nobody, and the passkey that answers names its owner.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::passkey_ceremony::PasskeyCeremony;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::Lifetime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{PasskeyCeremonyStore, PasskeyVerifier};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::passkeys::LoginStarted;

/// The ports [`DiscoverableBeginUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DiscoverableBeginPorts {
    /// Makes the `WebAuthn` challenge.
    pub verifier: Arc<dyn PasskeyVerifier>,
    /// Keeps the ceremony's state the client must not see.
    pub ceremony_store: Arc<dyn PasskeyCeremonyStore>,
}

/// Opens a passkey sign-in that names nobody yet.
pub struct DiscoverableBeginUseCase {
    ttl: Lifetime,
    ports: DiscoverableBeginPorts,
}

impl DiscoverableBeginUseCase {
    /// A use case opening ceremonies that last `ttl`, through `ports`.
    #[must_use]
    pub fn new(ttl: Lifetime, ports: DiscoverableBeginPorts) -> Self {
        Self { ttl, ports }
    }
}

impl Command for DiscoverableBeginUseCase {
    type Caller = ScopedTenant;
    type Input = ();
    type Output = Result<LoginStarted, AppError>;

    /// Opens a ceremony for whichever passkey the browser offers and hands
    /// back its challenge. Records `authentication.passkey_challenge_issued`.
    ///
    /// Nothing is looked up, so nothing can be learned: every caller gets a
    /// real ceremony, and one answered by a passkey the tenant never saw
    /// fails at confirm.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the challenge cannot be made or the
    ///   ceremony cannot be stored or recorded.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<LoginStarted, AppError> {
        let started = self
            .ports
            .verifier
            .start_discoverable_authentication()
            .await
            .or_internal()?;
        let mut ceremony =
            PasskeyCeremony::open_discoverable(**tenant, started.server_state, self.ttl);
        self.ports
            .ceremony_store
            .save(&ceremony)
            .await
            .or_internal()?;
        auditor
            .dispatch(&ceremony.take_events())
            .await
            .or_internal()?;
        Ok(LoginStarted {
            ceremony_id: *ceremony.id(),
            challenge: started.client_payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::authentication::{FakePasskeyCeremonyStore, ceremony_lifetime};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// Ann's browser offers her passkey from the empty sign-in field. A
    /// ceremony naming nobody is kept on the server and its challenge
    /// recorded.
    #[test]
    fn a_ceremony_naming_nobody_is_opened_and_recorded() {
        let ceremonies = Arc::new(FakePasskeyCeremonyStore::new());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = DiscoverableBeginUseCase::new(
            ceremony_lifetime(),
            DiscoverableBeginPorts {
                ceremony_store: ceremonies.clone(),
                ..DiscoverableBeginPorts::fakes()
            },
        );

        let started =
            block_on(use_case.execute(&test_ctx().tenant(), &test_auditor(audit.clone()), ()))
                .unwrap();

        assert_eq!(started.challenge, vec![0xDD; 32]);
        assert_eq!(ceremonies.len(), 1);
        assert_eq!(
            *audit.records.lock().unwrap(),
            vec!["authentication.passkey_challenge_issued"]
        );
    }
}
