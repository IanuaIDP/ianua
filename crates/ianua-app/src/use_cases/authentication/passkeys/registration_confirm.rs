//! Finishing adding a passkey: the authenticator's attestation is checked
//! against the ceremony kept on the server, and the passkey is stored for
//! the person who proved who they are.
//!
//! A passkey signs in on its own, so adding one is a change of how the
//! account signs in. Mallory with a stolen session must not add her own,
//! so the person proves who they are again, or adds it from the sign-in
//! that waits for exactly this factor. The new passkey ends every session
//! opened before it, except the one the person added it from.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::passkey::{
    PasskeyCredential, RegisterPasskeyParams,
};
use ianua_domain::domains::authentication::credentials::passkey_ceremony::{
    CeremonyPurpose, PasskeyCeremony,
};
use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
use ianua_domain::domains::authentication::sessions::fresh_sign_in::{
    EnrolmentProof, FreshSignIn, SpentPasskey,
};
use ianua_domain::domains::authentication::sessions::proved_factor::ProvedFactor;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, CeremonyId, Label, PasskeyCredentialId, UserId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::{PasskeyCeremonyStore, PasskeyStore, PasskeyVerifier};
use crate::ports::tenant::TenantStore;
use crate::services::authentication::fresh_proof::{FreshProofs, ReenteredProof};
use crate::services::lookup::existing_tenant;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::authentication::passkeys::lookup::owned_ceremony;
use crate::use_cases::authentication::passkeys::registrant::{
    Registering, Registrant, RegistrantPorts,
};

/// How the person shows they may add a passkey now.
pub enum SetupProof {
    /// What they gave to prove who they are again.
    Reentered(ReenteredProof),
    /// Nothing more: the sign-in they hold waits for this factor, and lets
    /// them set it up for a few minutes.
    WaitingSignIn,
}

/// The authenticator's answer to a registration ceremony, and the person's
/// leave to add the passkey.
pub struct RegistrationConfirmRequest {
    /// The ceremony the answer belongs to.
    pub ceremony_id: CeremonyId,
    /// The authenticator's attestation response, as sent.
    pub response: Vec<u8>,
    /// The name the person gave the passkey.
    pub passkey_name: Label,
    /// How they show they may add it now.
    pub proof: SetupProof,
}

/// How many passkeys one person may hold.
pub struct RegistrationPolicy {
    /// The most passkeys one account may hold.
    pub max_passkeys_per_user: usize,
}

/// The ports [`RegistrationConfirmUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RegistrationConfirmPorts {
    /// Finds out who is adding the passkey, and keeps their account and
    /// session.
    pub registrant: RegistrantPorts,
    /// Turns what the person typed again into a fresh proof of them.
    pub fresh_proofs: Arc<dyn FreshProofs>,
    /// The tenant's passkeys.
    pub passkey_store: Arc<dyn PasskeyStore>,
    /// Checks the attestation.
    pub verifier: Arc<dyn PasskeyVerifier>,
    /// The ceremonies in flight, spent here.
    pub ceremony_store: Arc<dyn PasskeyCeremonyStore>,
    /// The tenant, whose rules a sign-in finished by the new passkey meets.
    pub tenant_store: Arc<dyn TenantStore>,
}

/// Adds a passkey to the registrant's own account.
pub struct RegistrationConfirmUseCase {
    policy: RegistrationPolicy,
    ports: RegistrationConfirmPorts,
}

/// What lets the person add a passkey now.
enum Leave {
    /// They proved who they are again just now.
    Fresh(FreshSignIn),
    /// Their sign-in waits for this factor.
    Enrolment(EnrolmentProof),
}

impl Leave {
    /// The passkey `params` describe, added under this leave.
    fn register(
        &self,
        params: RegisterPasskeyParams,
    ) -> Result<PasskeyCredential<ResolvedTenant>, AppError> {
        let registered = match self {
            Self::Fresh(fresh) => PasskeyCredential::register(params, fresh),
            Self::Enrolment(enrolment) => PasskeyCredential::register(params, enrolment),
        };
        registered.map_err(AppError::from_domain)
    }

    /// Keeps the finished session the passkey was added from through the
    /// change it makes. Only a fresh proof keeps one.
    fn keep(&self, who: &mut Registering) -> Result<(), AppError> {
        match self {
            Self::Fresh(fresh) => who
                .session
                .keep_through_own_password_change(&who.account, fresh)
                .map_err(AppError::from_domain),
            Self::Enrolment(_) => Ok(()),
        }
    }
}

/// The authenticator's answer, for the account adding the passkey.
struct Answer<'a> {
    ceremony_id: CeremonyId,
    response: &'a [u8],
    name: Label,
    user_id: UserId,
}

/// The spent ceremony and the passkey that answered it.
struct Added<'a> {
    ceremony: &'a PasskeyCeremony,
    passkey: &'a PasskeyCredential<ResolvedTenant>,
}

impl RegistrationConfirmUseCase {
    /// A use case keeping to `policy`, working through `ports`.
    #[must_use]
    pub fn new(policy: RegistrationPolicy, ports: RegistrationConfirmPorts) -> Self {
        Self { policy, ports }
    }

    /// What lets `who` add a passkey now, from the proof they gave.
    async fn leave(
        &self,
        tenant: &ScopedTenant,
        who: &Registering,
        proof: SetupProof,
    ) -> Result<Leave, AppError> {
        match proof {
            SetupProof::Reentered(reentered) => {
                let fresh =
                    self.ports
                        .fresh_proofs
                        .prove(tenant, &who.account, reentered, who.origin);
                Ok(Leave::Fresh(fresh.await?))
            }
            SetupProof::WaitingSignIn => who
                .session
                .enrolment_proof(clock::now())
                .map(Leave::Enrolment)
                .ok_or_else(|| {
                    AppError::Forbidden(message!(
                        "authentication-adding-a-passkey-needs-you-to",
                        "adding a passkey needs you to prove who you are again"
                    ))
                }),
        }
    }

    /// Refuses another passkey once the account holds the most it may.
    async fn ensure_room_for_another(
        &self,
        tenant: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<(), AppError> {
        let held = self
            .ports
            .passkey_store
            .list_by_user(tenant, user_id)
            .await
            .or_internal()?;
        if held.len() >= self.policy.max_passkeys_per_user {
            return Err(AppError::Conflict(message!(
                "authentication-maximum-passkeys-reached",
                "maximum passkeys reached"
            )));
        }
        Ok(())
    }

    /// Refuses a credential some passkey of the tenant already carries.
    async fn ensure_new_credential(
        &self,
        tenant: &ScopedTenant,
        credential_id: &PasskeyCredentialId,
    ) -> Result<(), AppError> {
        let held = self
            .ports
            .passkey_store
            .find_by_credential_id(tenant, credential_id)
            .await
            .or_internal()?;
        match held {
            Some(_) => Err(AppError::Conflict(message!(
                "authentication-credential-id-already-registered",
                "credential ID already registered"
            ))),
            None => Ok(()),
        }
    }

    /// The account's own registration ceremony `answer` names, spent while
    /// the account has room for another passkey, with the state it held.
    async fn spent_ceremony(
        &self,
        tenant: &ScopedTenant,
        answer: &Answer<'_>,
    ) -> Result<(PasskeyCeremony, Vec<u8>), AppError> {
        let store = self.ports.ceremony_store.as_ref();
        let mut ceremony =
            owned_ceremony(store, tenant, &answer.ceremony_id, &answer.user_id).await?;
        self.ensure_room_for_another(tenant, &answer.user_id)
            .await?;
        let state = ceremony
            .consume(CeremonyPurpose::Registration)
            .map_err(AppError::from_domain)?
            .to_vec();
        store
            .mark_consumed(&ceremony)
            .await
            .map_err(AppError::from_domain)?;
        Ok((ceremony, state))
    }

    /// What the attestation vouches for, as the passkey to add.
    async fn attested(
        &self,
        tenant: &ScopedTenant,
        state: &[u8],
        answer: Answer<'_>,
    ) -> Result<RegisterPasskeyParams, AppError> {
        let verified = self
            .ports
            .verifier
            .verify_registration(state, answer.response)
            .await
            .map_err(|_| {
                AppError::Forbidden(message!(
                    "authentication-the-attestation-does-not-verify",
                    "the attestation does not verify"
                ))
            })?;
        self.ensure_new_credential(tenant, &verified.credential_id)
            .await?;
        Ok(RegisterPasskeyParams {
            user_id: answer.user_id,
            credential_id: verified.credential_id,
            public_key: verified.public_key,
            authenticator_type: verified.authenticator_type,
            attestation: verified.attestation,
            name: answer.name,
        })
    }

    /// Carries the session the passkey was added from through the change.
    /// A sign-in waiting for this factor is finished by it; a finished
    /// session is kept under the fresh proof.
    async fn carry_session(
        &self,
        tenant: &ScopedTenant,
        who: &mut Registering,
        leave: &Leave,
        added: Added<'_>,
    ) -> Result<(), AppError> {
        if who.session.owed() != SecondFactor::Enrol {
            return leave.keep(who);
        }
        let spent =
            SpentPasskey::answered(added.ceremony, added.passkey).map_err(AppError::from_domain)?;
        let factor = ProvedFactor::by_passkey(&spent).map_err(AppError::from_domain)?;
        let record = existing_tenant(self.ports.tenant_store.as_ref(), tenant).await?;
        who.session
            .answer(&who.account, factor, record.auth_config().step_up_policy())
            .map_err(|_| {
                AppError::Forbidden(message!(
                    "authentication-the-new-passkey-does-not-finish",
                    "the new passkey does not finish the sign-in"
                ))
            })
    }

    /// Keeps the passkey, the account's change and the session.
    async fn save(
        &self,
        tenant: &ScopedTenant,
        who: &Registering,
        passkey: &PasskeyCredential<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let registrant = &self.ports.registrant;
        self.ports
            .passkey_store
            .save(tenant, passkey)
            .await
            .or_internal()?;
        registrant
            .users
            .save(tenant, &who.account)
            .await
            .or_internal()?;
        registrant
            .sessions
            .save(tenant, &who.session)
            .await
            .or_internal()
    }
}

impl Command for RegistrationConfirmUseCase {
    type Caller = Registrant;
    type Input = RegistrationConfirmRequest;
    type Output = Result<(), AppError>;

    /// Checks the attestation against the registrant's own ceremony, adds
    /// the passkey, records the change of how the account signs in, and
    /// records `authentication.passkey_registered`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid session or sign-in not waiting for a factor; `StepUpRequired` for a missing factor code.
    /// - `AppError::Forbidden` for inadequate/missing fresh proof, another person's ceremony or invalid attestation; `AccountLocked` after too many wrong codes.
    /// - `AppError::NotFound` for an unknown ceremony; `Domain` for an expired, spent or sign-in ceremony.
    /// - `AppError::Conflict` for a full passkey allowance or an already registered key; `Internal` on storage failure.
    async fn execute(
        &self,
        registrant: &Registrant,
        auditor: &RequestAuditor,
        request: RegistrationConfirmRequest,
    ) -> Result<(), AppError> {
        let RegistrationConfirmRequest {
            ceremony_id,
            response,
            passkey_name,
            proof,
        } = request;
        let tenant = registrant.tenant();
        let mut who = self.ports.registrant.registering(registrant).await?;
        let leave = self.leave(&tenant, &who, proof).await?;
        let answer = Answer {
            ceremony_id,
            response: &response,
            name: passkey_name,
            user_id: *who.account.id(),
        };
        let (ceremony, state) = self.spent_ceremony(&tenant, &answer).await?;
        let mut passkey = leave.register(self.attested(&tenant, &state, answer).await?)?;
        who.account.record_credential_change();
        let added = Added {
            ceremony: &ceremony,
            passkey: &passkey,
        };
        self.carry_session(&tenant, &mut who, &leave, added).await?;
        self.save(&tenant, &who, &passkey).await?;
        record_passkey(auditor, &tenant, &mut passkey).await
    }
}

/// Records the passkey just kept through `auditor`, by its holder.
async fn record_passkey(
    auditor: &RequestAuditor,
    tenant: &ScopedTenant,
    passkey: &mut PasskeyCredential<ResolvedTenant>,
) -> Result<(), AppError> {
    let holder = ActorRef::User(*passkey.user_id());
    auditor
        .dispatch_by(&holder, passkey.take_events(tenant))
        .await
        .or_internal()
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::passkey_ceremony::TargetedPurpose;
    use ianua_domain::domains::authentication::sessions::mfa_factor::{FactorProved, MfaFactor};
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{CredentialChange, TenantId};

    use super::*;
    use crate::context::CallerContext;
    use crate::ports::identity::UserStore;
    use crate::ports::shared::SessionStore;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::authentication::{
        FakePasskeyCeremonyStore, FakePasskeyStore, FakePasskeyVerifier, FakeSessionStore,
        WAITING_REFRESH_TOKEN, kept_ceremony, right_password, sign_in_waiting_for_a_factor,
        targeted_ceremony, waiting_refresh_hash, wrong_password,
    };
    use crate::test_support::identity::FakeUserStore;
    use crate::test_support::tenant::tenant_store_signing_in_with;
    use crate::test_support::{
        FakeEventDispatcher, ReadBeforeWrite, block_on, test_auditor, test_ctx, test_ctx_with,
        test_session_id,
    };
    use crate::use_cases::authentication::passkeys::registrant::PendingSignIn;

    struct Fixture {
        ann: UserId,
        authorities: FakeTenantAuthorities,
        passkeys: Arc<FakePasskeyStore>,
        ceremonies: Arc<FakePasskeyCeremonyStore>,
        ceremony_store: Arc<dyn PasskeyCeremonyStore>,
        verifier: Arc<FakePasskeyVerifier>,
        sessions: Arc<FakeSessionStore>,
        users: Arc<FakeUserStore>,
        audit: Arc<FakeEventDispatcher>,
        most: usize,
    }

    impl Fixture {
        fn new() -> Self {
            let ann = UserId::new();
            let ceremonies = Arc::new(FakePasskeyCeremonyStore::new());
            Self {
                ann,
                authorities: FakeTenantAuthorities::holding(&[]),
                passkeys: Arc::new(FakePasskeyStore::empty()),
                ceremony_store: ceremonies.clone(),
                ceremonies,
                verifier: Arc::new(FakePasskeyVerifier::succeeding()),
                sessions: Arc::new(FakeSessionStore::empty()),
                users: Arc::new(FakeUserStore::with_user(ann, "ann@acme.test")),
                audit: Arc::new(FakeEventDispatcher::new()),
                most: 10,
            }
        }

        fn waiting_for_a_factor() -> Self {
            let fixture = Self::new();
            Self {
                sessions: Arc::new(FakeSessionStore::with_session(
                    sign_in_waiting_for_a_factor(fixture.ann),
                )),
                ..fixture
            }
        }

        fn ann(&self) -> CallerContext {
            test_ctx_with(
                test_ctx().organization_id(),
                test_ctx().tenant_id(),
                self.ann,
            )
        }

        fn open_for(&self, user_id: UserId) -> CeremonyId {
            kept_ceremony(
                &self.ceremonies,
                &targeted_ceremony(user_id, TargetedPurpose::Registration),
            )
        }

        fn confirm_as(
            self,
            registrant: &Registrant,
            ceremony_id: CeremonyId,
            proof: SetupProof,
        ) -> (Result<(), AppError>, Self) {
            let use_case = RegistrationConfirmUseCase::new(
                RegistrationPolicy {
                    max_passkeys_per_user: self.most,
                },
                RegistrationConfirmPorts {
                    registrant: RegistrantPorts {
                        tenant_authorities: Arc::new(self.authorities),
                        sessions: self.sessions.clone(),
                        users: self.users.clone(),
                        ..RegistrantPorts::fakes()
                    },
                    passkey_store: self.passkeys.clone(),
                    verifier: self.verifier.clone(),
                    ceremony_store: self.ceremony_store.clone(),
                    tenant_store: tenant_store_signing_in_with(Default::default()),
                    ..RegistrationConfirmPorts::fakes()
                },
            );
            let request = registration_answer(ceremony_id, proof);
            let result =
                block_on(use_case.execute(registrant, &test_auditor(self.audit.clone()), request));
            let fixture = Self {
                authorities: FakeTenantAuthorities::holding(&[]),
                ..self
            };
            (result, fixture)
        }

        fn confirm(
            self,
            ceremony_id: CeremonyId,
            proof: ReenteredProof,
        ) -> (Result<(), AppError>, Self) {
            let ann = Registrant::SignedIn(Box::new(self.ann()));
            self.confirm_as(&ann, ceremony_id, SetupProof::Reentered(proof))
        }

        fn credentials_changed(&self) -> CredentialChange {
            block_on(self.users.find_by_id(&test_ctx().tenant(), &self.ann))
                .unwrap()
                .unwrap()
                .credentials_changed_at()
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    /// Supplies the fixture's attestation and key name for this ceremony and setup proof.
    fn registration_answer(
        ceremony_id: CeremonyId,
        proof: SetupProof,
    ) -> RegistrationConfirmRequest {
        RegistrationConfirmRequest {
            ceremony_id,
            response: vec![0x01],
            passkey_name: Label::new("name", "YubiKey 5").unwrap(),
            proof,
        }
    }

    fn waiting_sign_in() -> Registrant {
        Registrant::SettingUpFactor(PendingSignIn {
            tenant: test_ctx().tenant(),
            refresh_token: Secret::new(WAITING_REFRESH_TOKEN),
        })
    }

    /// Ann, signed in, types her password again and adds her YubiKey. It is
    /// stored, the change of how her account signs in is recorded, and so
    /// is the new passkey.
    #[test]
    fn a_proven_person_adds_a_passkey() {
        let fixture = Fixture::new();
        let ceremony = fixture.open_for(fixture.ann);

        let (result, fixture) = fixture.confirm(ceremony, right_password());

        assert!(result.is_ok());
        assert_eq!(fixture.passkeys.count(), 1);
        assert!(matches!(
            fixture.credentials_changed(),
            CredentialChange::At { .. }
        ));
        assert_eq!(
            fixture.recorded(),
            vec!["authentication.passkey_registered"]
        );
    }

    /// Ann adds a passkey from her session. The change ends sessions opened
    /// before it, but the one she proved herself in is kept.
    #[test]
    fn the_session_the_passkey_was_added_from_is_kept() {
        let fixture = Fixture::new();
        let ceremony = fixture.open_for(fixture.ann);

        let (_, fixture) = fixture.confirm(ceremony, right_password());

        let session = fixture.sessions.get_session(&test_session_id()).unwrap();
        assert_eq!(session.kept_through(), fixture.credentials_changed());
    }

    /// An incorrect password forbids registration, stores no passkey and
    /// records no event.
    #[test]
    fn a_wrong_password_is_refused() {
        let fixture = Fixture::new();
        let ceremony = fixture.open_for(fixture.ann);

        let (result, fixture) = fixture.confirm(ceremony, wrong_password());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.passkeys.count(), 0);
        assert!(fixture.recorded().is_empty());
    }

    /// A finished session cannot use waiting-sign-in proof to register a
    /// passkey; the request is forbidden and stores no key.
    #[test]
    fn a_finished_session_gives_no_leave_on_its_own() {
        let fixture = Fixture::new();
        let ceremony = fixture.open_for(fixture.ann);
        let ann = Registrant::SignedIn(Box::new(fixture.ann()));

        let (result, fixture) = fixture.confirm_as(&ann, ceremony, SetupProof::WaitingSignIn);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.passkeys.count(), 0);
    }

    /// A signed-out registrant is unauthenticated and stores no passkey.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let fixture = Fixture {
            authorities: FakeTenantAuthorities::refusing(Refusal::SignedOut),
            ..Fixture::new()
        };
        let ceremony = fixture.open_for(fixture.ann);

        let (result, fixture) = fixture.confirm(ceremony, right_password());

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.passkeys.count(), 0);
    }

    /// Ann's workspace requires a second factor she has not set up, so her
    /// sign-in waits for one. She adds a passkey from it, and the passkey
    /// finishes her sign-in.
    #[test]
    fn a_passkey_added_while_signing_in_finishes_the_sign_in() {
        let fixture = Fixture::waiting_for_a_factor();
        let ceremony = fixture.open_for(fixture.ann);

        let (result, fixture) =
            fixture.confirm_as(&waiting_sign_in(), ceremony, SetupProof::WaitingSignIn);

        assert!(result.is_ok());
        let session = block_on(
            fixture
                .sessions
                .find_by_refresh_token_hash(&test_ctx().tenant(), &waiting_refresh_hash()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(session.owed(), SecondFactor::NotOwed);
        assert_eq!(
            session.mfa_method(),
            FactorProved::Proved(MfaFactor::Passkey)
        );
    }

    /// Another account's ceremony is forbidden and adds no passkey.
    #[test]
    fn a_ceremony_of_another_account_is_refused() {
        let fixture = Fixture::new();
        let ceremony = fixture.open_for(UserId::new());

        let (result, fixture) = fixture.confirm(ceremony, right_password());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.passkeys.count(), 0);
    }

    /// An unknown registration ceremony returns NotFound and stores no key.
    #[test]
    fn an_unknown_ceremony_is_not_found() {
        let (result, fixture) = Fixture::new().confirm(CeremonyId::new(), right_password());

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert_eq!(fixture.passkeys.count(), 0);
    }

    /// Reusing a registration ceremony returns a domain error and leaves
    /// only one passkey stored.
    #[test]
    fn a_ceremony_adds_one_passkey() {
        let fixture = Fixture::new();
        let ceremony = fixture.open_for(fixture.ann);
        let (_, fixture) = fixture.confirm(ceremony, right_password());

        let (replay, fixture) = fixture.confirm(ceremony, right_password());

        assert!(matches!(replay, Err(AppError::Domain(_))));
        assert_eq!(fixture.passkeys.count(), 1);
    }

    /// Two confirmations reading the same open ceremony store one passkey;
    /// the second receives a domain error.
    #[test]
    fn two_confirmations_of_one_ceremony_at_once_add_one_passkey() {
        let fixture = Fixture::new();
        let ceremony = targeted_ceremony(fixture.ann, TargetedPurpose::Registration);
        let id = *ceremony.id();
        let racing = ReadBeforeWrite::new(
            FakePasskeyCeremonyStore::new(),
            Arc::new(FakePasskeyCeremonyStore::new()),
        );
        block_on(racing.seen.save(&ceremony)).unwrap();
        block_on(racing.live.save(&ceremony)).unwrap();
        let fixture = Fixture {
            ceremony_store: Arc::new(racing),
            ..fixture
        };
        let (_, fixture) = fixture.confirm(id, right_password());

        let (replay, fixture) = fixture.confirm(id, right_password());

        assert!(matches!(replay, Err(AppError::Domain(_))));
        assert_eq!(fixture.passkeys.count(), 1);
    }

    /// A registration ceremony presented through another tenant returns NotFound.
    #[test]
    fn a_ceremony_does_not_cross_tenants() {
        let fixture = Fixture::new();
        let ceremony = fixture.open_for(fixture.ann);
        let elsewhere = Registrant::SignedIn(Box::new(test_ctx_with(
            test_ctx().organization_id(),
            TenantId::new(),
            fixture.ann,
        )));

        let (result, _) = fixture.confirm_as(
            &elsewhere,
            ceremony,
            SetupProof::Reentered(right_password()),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Registration at the account's passkey limit returns a conflict.
    #[test]
    fn a_passkey_beyond_the_most_allowed_is_refused() {
        let fixture = Fixture::new();
        let fixture = Fixture {
            passkeys: Arc::new(FakePasskeyStore::with_passkeys(fixture.ann, 3)),
            most: 3,
            ..fixture
        };
        let ceremony = fixture.open_for(fixture.ann);

        let (result, _) = fixture.confirm(ceremony, right_password());

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// An already registered credential conflicts and leaves the single
    /// existing passkey stored.
    #[test]
    fn a_passkey_already_registered_is_refused() {
        let fixture = Fixture::new();
        let fixture = Fixture {
            passkeys: Arc::new(FakePasskeyStore::with_passkey(UserId::new())),
            ..fixture
        };
        let ceremony = fixture.open_for(fixture.ann);

        let (result, fixture) = fixture.confirm(ceremony, right_password());

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(fixture.passkeys.count(), 1);
    }

    /// Failed attestation verification is forbidden, stores no passkey and
    /// records no registration event.
    #[test]
    fn an_attestation_that_does_not_verify_is_refused() {
        let fixture = Fixture {
            verifier: Arc::new(FakePasskeyVerifier::failing()),
            ..Fixture::new()
        };
        let ceremony = fixture.open_for(fixture.ann);

        let (result, fixture) = fixture.confirm(ceremony, right_password());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.passkeys.count(), 0);
        assert!(fixture.recorded().is_empty());
    }
}
