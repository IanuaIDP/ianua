//! Beginning a passkey sign-in for someone who typed their address: a
//! ceremony is opened over their passkeys and kept on the server, and the
//! browser gets only its challenge.
//!
//! The ceremony's state never crosses the wire. When it did, a caller could
//! present a ceremony they made themselves with a signature over it, and be
//! signed in to any account whose address they knew.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::passkey::PasskeyCredential;
use ianua_domain::domains::authentication::credentials::passkey_ceremony::{
    OpenCeremonyParams, PasskeyCeremony, TargetedPurpose,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{CeremonyId, Email, Lifetime, UserId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{
    PasskeyCeremonyStore, PasskeyStore, PasskeyVerifier, UserLookup,
};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// The challenge a passkey sign-in begins with.
pub struct LoginStarted {
    /// Names the ceremony the server keeps for this challenge. The client
    /// returns it on confirm; it is the only handle they get.
    pub ceremony_id: CeremonyId,
    /// The `WebAuthn` options to pass to `navigator.credentials.get()`.
    pub challenge: Vec<u8>,
}

/// The ports [`LoginBeginUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct LoginBeginPorts {
    /// Finds the account an address names.
    pub user_lookup: Arc<dyn UserLookup>,
    /// The account's passkeys.
    pub passkey_store: Arc<dyn PasskeyStore>,
    /// Makes the `WebAuthn` challenge.
    pub verifier: Arc<dyn PasskeyVerifier>,
    /// Keeps the ceremony's state the client must not see.
    pub ceremony_store: Arc<dyn PasskeyCeremonyStore>,
}

/// Opens a passkey sign-in for the account an address names.
pub struct LoginBeginUseCase {
    ttl: Lifetime,
    ports: LoginBeginPorts,
}

impl LoginBeginUseCase {
    /// A use case opening ceremonies that last `ttl`, through `ports`.
    #[must_use]
    pub fn new(ttl: Lifetime, ports: LoginBeginPorts) -> Self {
        Self { ttl, ports }
    }

    /// Opens and stores a ceremony over `passkeys`, records its start and
    /// hands back the browser's challenge for it.
    async fn challenge_for(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        user_id: UserId,
        passkeys: &[PasskeyCredential<ResolvedTenant>],
    ) -> Result<LoginStarted, AppError> {
        let keys: Vec<Vec<u8>> = passkeys.iter().map(|p| p.public_key().to_vec()).collect();
        let started = self
            .ports
            .verifier
            .start_authentication(&keys)
            .await
            .or_internal()?;
        let mut ceremony = PasskeyCeremony::open(OpenCeremonyParams {
            tenant_id: **tenant,
            user_id,
            purpose: TargetedPurpose::Authentication,
            state: started.server_state,
            ttl: self.ttl,
        });
        self.keep(auditor, &mut ceremony).await?;
        Ok(LoginStarted {
            ceremony_id: *ceremony.id(),
            challenge: started.client_payload,
        })
    }

    /// Stores `ceremony` and records what opening it raised.
    async fn keep(
        &self,
        auditor: &RequestAuditor,
        ceremony: &mut PasskeyCeremony,
    ) -> Result<(), AppError> {
        self.ports
            .ceremony_store
            .save(ceremony)
            .await
            .or_internal()?;
        auditor
            .dispatch(&ceremony.take_events())
            .await
            .or_internal()
    }

    /// A challenge for `email`, whose account cannot answer one.
    ///
    /// It is a real, fresh challenge naming a ceremony that was never
    /// stored, so confirming it reports an unknown challenge, as a real one
    /// does once it expires. It lists a credential as a real account's
    /// does, the same one for the same address each time. A fixed
    /// placeholder, or a challenge listing nothing, would tell an unknown
    /// address from a known one at a glance.
    async fn decoy(&self, email: &Email) -> Result<LoginStarted, AppError> {
        let started = self
            .ports
            .verifier
            .start_decoy_authentication(email)
            .await
            .or_internal()?;
        Ok(LoginStarted {
            ceremony_id: CeremonyId::new(),
            challenge: started.client_payload,
        })
    }

    /// The account `email` names and its passkeys, when it has any.
    async fn holder_of(
        &self,
        tenant: &ScopedTenant,
        email: &Email,
    ) -> Result<Option<(UserId, Vec<PasskeyCredential<ResolvedTenant>>)>, AppError> {
        let lookup = self.ports.user_lookup.as_ref();
        let Some(candidate) = lookup.find_by_email(tenant, email).await.or_internal()? else {
            return Ok(None);
        };
        let passkeys = self
            .ports
            .passkey_store
            .list_by_user(tenant, &candidate.user_id)
            .await
            .or_internal()?;
        Ok((!passkeys.is_empty()).then_some((candidate.user_id, passkeys)))
    }
}

impl Command for LoginBeginUseCase {
    type Caller = ScopedTenant;
    type Input = Email;
    type Output = Result<LoginStarted, AppError>;

    /// Opens a ceremony over the passkeys of the account `email` names and
    /// hands back the browser's challenge. Records
    /// `authentication.passkey_sign_in_started`.
    ///
    /// An unknown address, or an account without passkeys, gets a decoy of
    /// the same shape, no stored ceremony and no record, so neither the
    /// answer nor the audit log tells which accounts exist.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when the challenge cannot be made or the
    ///   ceremony cannot be stored or recorded.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        email: Email,
    ) -> Result<LoginStarted, AppError> {
        let Some((user_id, passkeys)) = self.holder_of(tenant, &email).await? else {
            return self.decoy(&email).await;
        };
        self.challenge_for(tenant, auditor, user_id, &passkeys)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::authentication::{
        FakePasskeyCeremonyStore, FakePasskeyStore, FakeUserLookup, PASSKEY_CEREMONY_STATE,
        ceremony_lifetime, passkey_owner,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    struct Fixture {
        use_case: LoginBeginUseCase,
        ceremonies: Arc<FakePasskeyCeremonyStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    impl Fixture {
        fn ann_holding(passkeys: impl FnOnce(UserId) -> FakePasskeyStore) -> Self {
            let ann = UserId::new();
            let ceremonies = Arc::new(FakePasskeyCeremonyStore::new());
            let use_case = LoginBeginUseCase::new(
                ceremony_lifetime(),
                LoginBeginPorts {
                    user_lookup: Arc::new(FakeUserLookup::holding([passkey_owner(
                        ann,
                        "ann@acme.test",
                    )])),
                    passkey_store: Arc::new(passkeys(ann)),
                    ceremony_store: ceremonies.clone(),
                    ..LoginBeginPorts::fakes()
                },
            );
            Self {
                use_case,
                ceremonies,
                audit: Arc::new(FakeEventDispatcher::new()),
            }
        }

        fn ann_with_a_passkey() -> Self {
            Self::ann_holding(FakePasskeyStore::with_passkey)
        }

        fn begin(self, email: &str) -> (Result<LoginStarted, AppError>, Self) {
            let started = block_on(self.use_case.execute(
                &test_ctx().tenant(),
                &test_auditor(self.audit.clone()),
                Email::new(email).unwrap(),
            ));
            (started, self)
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Ann types her address. She gets a challenge, the ceremony is kept
    /// on the server, and the start of her sign-in is recorded.
    #[test]
    fn a_challenge_is_returned_and_its_state_kept() {
        let (started, fixture) = Fixture::ann_with_a_passkey().begin("ann@acme.test");

        assert_eq!(started.unwrap().challenge, vec![0xBB; 32]);
        assert_eq!(fixture.ceremonies.len(), 1);
        assert_eq!(
            fixture.recorded(),
            vec!["authentication.passkey_sign_in_started"]
        );
    }

    /// The returned authentication challenge does not contain the server's
    /// ceremony-state bytes.
    #[test]
    fn the_ceremony_state_never_reaches_the_client() {
        let (started, _) = Fixture::ann_with_a_passkey().begin("ann@acme.test");

        let challenge = started.unwrap().challenge;
        assert!(
            !challenge
                .windows(PASSKEY_CEREMONY_STATE.len())
                .any(|window| window == PASSKEY_CEREMONY_STATE)
        );
    }

    /// An unknown address receives a nonzero decoy challenge without a
    /// stored ceremony or audit event.
    #[test]
    fn an_unknown_address_gets_a_decoy() {
        let (started, fixture) = Fixture::ann_with_a_passkey().begin("nobody@acme.test");

        assert_ne!(started.unwrap().challenge, vec![0x00; 32]);
        assert!(fixture.ceremonies.is_empty());
        assert!(fixture.recorded().is_empty());
    }

    /// An account without passkeys can begin sign-in without storing a ceremony.
    #[test]
    fn an_account_without_passkeys_gets_a_decoy() {
        let fixture = Fixture::ann_holding(|_| FakePasskeyStore::empty());

        let (started, fixture) = fixture.begin("ann@acme.test");

        assert!(started.is_ok());
        assert!(fixture.ceremonies.is_empty());
    }

    /// Known and unknown addresses receive challenges of equal length.
    #[test]
    fn a_decoy_has_the_shape_of_a_real_challenge() {
        let (real, _) = Fixture::ann_with_a_passkey().begin("ann@acme.test");
        let (decoy, _) = Fixture::ann_with_a_passkey().begin("nobody@acme.test");

        assert_eq!(
            real.unwrap().challenge.len(),
            decoy.unwrap().challenge.len()
        );
    }

    /// The fake verifier's decoy and real authentication challenges have
    /// identical payloads.
    #[test]
    fn a_decoy_lists_credentials_as_a_real_challenge_does() {
        let (real, _) = Fixture::ann_with_a_passkey().begin("ann@acme.test");
        let (decoy, _) = Fixture::ann_with_a_passkey().begin("nobody@acme.test");

        assert_eq!(decoy.unwrap().challenge, real.unwrap().challenge);
    }
}
