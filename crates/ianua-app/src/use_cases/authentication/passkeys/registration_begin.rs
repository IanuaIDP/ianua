//! Beginning to add a passkey: a registration ceremony is opened for the
//! person adding it and kept on the server, and the browser gets only its
//! challenge.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::passkey_ceremony::{
    OpenCeremonyParams, PasskeyCeremony, TargetedPurpose,
};
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, CeremonyId, Lifetime};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{PasskeyCeremonyStore, PasskeyVerifier};
use crate::use_case::Command;
use crate::use_cases::authentication::passkeys::registrant::{Registrant, RegistrantPorts};

/// The challenge adding a passkey begins with.
pub struct RegistrationChallenge {
    /// Names the ceremony the server keeps for this challenge.
    pub ceremony_id: CeremonyId,
    /// The `WebAuthn` options to pass to `navigator.credentials.create()`.
    pub challenge: Vec<u8>,
}

/// The ports [`RegistrationBeginUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RegistrationBeginPorts {
    /// Finds out who is adding the passkey.
    pub registrant: RegistrantPorts,
    /// Makes the `WebAuthn` challenge.
    pub verifier: Arc<dyn PasskeyVerifier>,
    /// Keeps the ceremony's state the client must not see.
    pub ceremony_store: Arc<dyn PasskeyCeremonyStore>,
}

/// Opens a ceremony to add a passkey to the registrant's own account.
pub struct RegistrationBeginUseCase {
    ttl: Lifetime,
    ports: RegistrationBeginPorts,
}

impl RegistrationBeginUseCase {
    /// A use case opening ceremonies that last `ttl`, through `ports`.
    #[must_use]
    pub fn new(ttl: Lifetime, ports: RegistrationBeginPorts) -> Self {
        Self { ttl, ports }
    }
}

impl Command for RegistrationBeginUseCase {
    type Caller = Registrant;
    type Input = ();
    type Output = Result<RegistrationChallenge, AppError>;

    /// Opens a registration ceremony for the registrant's own account and
    /// hands back the browser's challenge. Records
    /// `authentication.passkey_registration_started`.
    ///
    /// The ceremony is bound to the account, so only its holder can add a
    /// passkey with it. The name the authenticator shows comes from the
    /// account, never from the request: the browser shows it as given, on
    /// the one screen the person is meant to trust.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the registrant's session no
    ///   longer counts, or their sign-in does not wait for a factor.
    /// - `AppError::Internal` when the challenge cannot be made or the
    ///   ceremony cannot be stored or recorded.
    async fn execute(
        &self,
        registrant: &Registrant,
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<RegistrationChallenge, AppError> {
        let tenant = registrant.tenant();
        let account = self.ports.registrant.registering(registrant).await?.account;
        let started = self
            .ports
            .verifier
            .start_registration(account.id(), account.email())
            .await
            .or_internal()?;
        let mut ceremony = PasskeyCeremony::open(OpenCeremonyParams {
            tenant_id: *tenant,
            user_id: *account.id(),
            purpose: TargetedPurpose::Registration,
            state: started.server_state,
            ttl: self.ttl,
        });
        self.ports
            .ceremony_store
            .save(&ceremony)
            .await
            .or_internal()?;
        auditor
            .dispatch_by(&ActorRef::User(*account.id()), ceremony.take_events())
            .await
            .or_internal()?;
        Ok(RegistrationChallenge {
            ceremony_id: *ceremony.id(),
            challenge: started.client_payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::UserId;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{
        FakePasskeyCeremonyStore, FakeSessionStore, PASSKEY_CEREMONY_STATE, WAITING_REFRESH_TOKEN,
        ceremony_lifetime, sign_in_waiting_for_a_factor,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};
    use crate::use_cases::authentication::passkeys::registrant::PendingSignIn;

    struct Fixture {
        use_case: RegistrationBeginUseCase,
        ceremonies: Arc<FakePasskeyCeremonyStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn finding(registrant: RegistrantPorts) -> Self {
            let ceremonies = Arc::new(FakePasskeyCeremonyStore::new());
            let use_case = RegistrationBeginUseCase::new(
                ceremony_lifetime(),
                RegistrationBeginPorts {
                    registrant,
                    ceremony_store: ceremonies.clone(),
                    ..RegistrationBeginPorts::fakes()
                },
            );
            Self {
                use_case,
                ceremonies,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn new() -> Self {
            Self::finding(RegistrantPorts::fakes())
        }

        fn begin(&self, registrant: &Registrant) -> Result<RegistrationChallenge, AppError> {
            block_on(
                self.use_case
                    .execute(registrant, &test_auditor(self.audit.clone()), ()),
            )
        }
    }

    fn waiting_sign_in() -> Registrant {
        Registrant::SettingUpFactor(PendingSignIn {
            tenant: test_ctx().tenant(),
            refresh_token: Secret::new(WAITING_REFRESH_TOKEN),
        })
    }

    /// Ann, signed in, starts adding a passkey. She gets a challenge, the
    /// ceremony is kept on the server, and the start is recorded.
    #[test]
    fn a_signed_in_person_gets_a_challenge() {
        let fixture = Fixture::new();

        let started = fixture.begin(&Registrant::SignedIn(Box::new(test_ctx())));

        assert_eq!(started.unwrap().challenge.len(), 32);
        assert_eq!(fixture.ceremonies.len(), 1);
        assert_eq!(
            *fixture.audit.records.lock().unwrap(),
            vec!["authentication.passkey_registration_started"]
        );
    }

    /// The returned registration challenge excludes the server's ceremony-state bytes.
    #[test]
    fn the_ceremony_state_never_reaches_the_client() {
        let started = Fixture::new().begin(&Registrant::SignedIn(Box::new(test_ctx())));

        let challenge = started.unwrap().challenge;
        assert!(
            !challenge
                .windows(PASSKEY_CEREMONY_STATE.len())
                .any(|window| window == PASSKEY_CEREMONY_STATE)
        );
    }

    /// A signed-out registrant is unauthenticated and stores no ceremony.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture::finding(RegistrantPorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..RegistrantPorts::fakes()
        });

        let started = fixture.begin(&Registrant::SignedIn(Box::new(test_ctx())));

        assert!(matches!(started, Err(AppError::Unauthenticated)));
        assert!(fixture.ceremonies.is_empty());
    }

    /// Ann's workspace requires a second factor she has not set up, so her
    /// sign-in waits for one. With that sign-in she starts adding a
    /// passkey, and gets a challenge.
    #[test]
    fn a_sign_in_waiting_for_a_factor_gets_a_challenge() {
        let ann = UserId::new();
        let fixture = Fixture::finding(RegistrantPorts {
            sessions: Arc::new(FakeSessionStore::with_session(
                sign_in_waiting_for_a_factor(ann),
            )),
            users: Arc::new(FakeUserStore::with_user(ann, "ann@acme.test")),
            ..RegistrantPorts::fakes()
        });

        let started = fixture.begin(&waiting_sign_in());

        assert!(started.is_ok());
        assert_eq!(fixture.ceremonies.len(), 1);
    }

    /// An unknown waiting-sign-in token cannot begin registration and is unauthenticated.
    #[test]
    fn an_unknown_sign_in_is_refused() {
        let fixture = Fixture::new();

        let started = fixture.begin(&waiting_sign_in());

        assert!(matches!(started, Err(AppError::Unauthenticated)));
    }
}
