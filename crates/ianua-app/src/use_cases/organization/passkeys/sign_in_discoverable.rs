//! Beginning a member's passkey sign-in before anyone typed an address: the
//! browser offers a passkey from the empty sign-in field, so the ceremony
//! opens for nobody, and the passkey that answers names its member.

use std::sync::Arc;

use ianua_domain::domains::organization::events::access::OrgPasskeyChallengeIssued;
use ianua_domain::types::{ActorRef, Lifetime};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::PasskeyVerifier;
use crate::ports::organization::OrgPasskeyCeremonyStore;
use crate::use_case::Command;
use crate::use_cases::organization::passkeys::challenge::{OrgPasskeyStarted, opened_for_nobody};

/// The ports [`OrgDiscoverBeginUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OrgDiscoverBeginPorts {
    /// Makes the `WebAuthn` challenge.
    pub verifier: Arc<dyn PasskeyVerifier>,
    /// Keeps the ceremony's state the client must not see.
    pub ceremony_store: Arc<dyn OrgPasskeyCeremonyStore>,
}

/// Opens a member's passkey sign-in that names nobody yet.
pub struct OrgDiscoverBeginUseCase {
    ttl: Lifetime,
    ports: OrgDiscoverBeginPorts,
}

impl OrgDiscoverBeginUseCase {
    /// A use case opening ceremonies that last `ttl`, through `ports`.
    #[must_use]
    pub fn new(ttl: Lifetime, ports: OrgDiscoverBeginPorts) -> Self {
        Self { ttl, ports }
    }
}

impl Command for OrgDiscoverBeginUseCase {
    type Caller = ();
    type Input = ();
    type Output = Result<OrgPasskeyStarted, AppError>;

    /// Opens a ceremony for whichever passkey the browser offers and hands
    /// back its challenge. Records
    /// `organization.org_passkey_challenge_issued`, on the platform, since
    /// nobody is known yet.
    ///
    /// Nothing is looked up, so nothing can be learned: every caller gets a
    /// real ceremony, and one answered by a passkey no member holds fails
    /// at confirm.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the challenge cannot be made or the
    ///   ceremony cannot be stored or recorded.
    async fn execute(
        &self,
        (): &(),
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<OrgPasskeyStarted, AppError> {
        let started = opened_for_nobody(
            self.ports.verifier.as_ref(),
            self.ports.ceremony_store.as_ref(),
            self.ttl,
        )
        .await?;
        auditor
            .dispatch_by(
                &ActorRef::System,
                vec![OrgPasskeyChallengeIssued::observed()],
            )
            .await
            .or_internal()?;
        Ok(started)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::authentication::ceremony_lifetime;
    use crate::test_support::organization::FakeOrgPasskeyCeremonyStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};

    /// A browser offers a passkey from the empty sign-in field. A ceremony
    /// for nobody is kept, and the challenge is recorded.
    #[test]
    fn every_caller_gets_a_ceremony_for_nobody() {
        let ceremonies = Arc::new(FakeOrgPasskeyCeremonyStore::new());
        let audit = Arc::new(FakeEventDispatcher::new());
        let use_case = OrgDiscoverBeginUseCase::new(
            ceremony_lifetime(),
            OrgDiscoverBeginPorts {
                ceremony_store: ceremonies.clone(),
                ..OrgDiscoverBeginPorts::fakes()
            },
        );

        let started = block_on(use_case.execute(&(), &test_auditor(audit.clone()), ())).unwrap();

        let kept = block_on(ceremonies.find_by_id(&started.ceremony_id))
            .unwrap()
            .unwrap();
        assert!(kept.org_user_id().is_none());
        assert_eq!(
            *audit.records.lock().unwrap(),
            vec!["organization.org_passkey_challenge_issued"]
        );
    }
}
