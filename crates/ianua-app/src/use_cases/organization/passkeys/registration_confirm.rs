//! A member finishing adding a passkey: the authenticator's attestation is
//! checked against the ceremony kept on the server, and the passkey is
//! stored for the member who proved who they are.
//!
//! A passkey signs in on its own, so adding one changes how the member
//! signs in. Mallory with a stolen session must not add her own, so the
//! member proves who they are again, or adds it from the sign-in that
//! waits for exactly this factor. The change is recorded on the member, so
//! every session and device from before it stops counting, except the
//! session the passkey was added from.

use std::sync::Arc;

use ianua_domain::domains::authentication::credentials::passkey::{
    PasskeyCredential, RegisterPasskeyParams,
};
use ianua_domain::domains::authentication::credentials::passkey_ceremony::CeremonyPurpose;
use ianua_domain::domains::authentication::sessions::fresh_sign_in::{
    EnrolmentProof, FreshSignIn, SpentPasskey,
};
use ianua_domain::domains::authentication::sessions::proved_factor::ProvedFactor;
use ianua_domain::domains::organization::access::passkey::OrgPasskeyCeremony;
use ianua_domain::domains::organization::access::session::OrgSession;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, CeremonyId, Label, OrgUserId, PasskeyCredentialId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::authentication::PasskeyVerifier;
use crate::ports::organization::{OrgPasskeyCeremonyStore, OrgPasskeyStore};
use crate::services::authentication::fresh_proof::{FreshProofs, ReenteredProof};
use crate::use_case::Command;
use crate::use_cases::organization::lookup::existing_ceremony;
use crate::use_cases::organization::passkeys::registrant::{
    MemberRegistering, MemberRegistrant, MemberRegistrantPorts, RegisteringFrom,
};

/// How the member shows they may add a passkey now.
pub enum MemberSetupProof {
    /// What they gave to prove who they are again.
    Reentered(ReenteredProof),
    /// Nothing more: the sign-in they hold waits for this factor, and lets
    /// them set it up for a few minutes.
    WaitingSignIn,
}

/// The authenticator's answer to a registration ceremony, the name for the
/// new passkey, and the member's leave to add it.
pub struct OrgRegisterConfirmRequest {
    /// The ceremony the answer belongs to.
    pub ceremony_id: CeremonyId,
    /// The authenticator's attestation response, as sent.
    pub response: Vec<u8>,
    /// The name the passkey is listed under.
    pub name: Label,
    /// How the member shows they may add it now.
    pub proof: MemberSetupProof,
}

/// How many passkeys one member may hold.
pub struct OrgPolicy {
    /// The most passkeys one member may hold.
    pub max_passkeys_per_user: usize,
}

/// The ports [`OrgRegisterConfirmUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OrgRegisterConfirmPorts {
    /// Finds out who is adding the passkey, and keeps the member and the
    /// waiting sign-in.
    pub registrant: MemberRegistrantPorts,
    /// Turns what the member typed again into a fresh proof of them.
    pub fresh_proofs: Arc<dyn FreshProofs>,
    /// Members' passkeys.
    pub passkey_store: Arc<dyn OrgPasskeyStore>,
    /// Checks the attestation.
    pub verifier: Arc<dyn PasskeyVerifier>,
    /// The ceremonies in flight, spent here.
    pub ceremony_store: Arc<dyn OrgPasskeyCeremonyStore>,
}

/// Adds a passkey to the registrant's own membership.
pub struct OrgRegisterConfirmUseCase {
    policy: OrgPolicy,
    ports: OrgRegisterConfirmPorts,
}

/// What lets the member add a passkey now.
enum MemberLeave {
    /// They proved who they are again just now.
    Reproved(FreshSignIn),
    /// The sign-in they add it from waits for this factor.
    FinishingSignIn(EnrolmentProof),
}

/// The authenticator's answer, for the member adding the passkey.
struct Attestation<'a> {
    response: &'a [u8],
    name: Label,
    member: OrgUserId,
}

impl OrgRegisterConfirmUseCase {
    /// A use case keeping to `policy`, working through `ports`.
    #[must_use]
    pub fn new(policy: OrgPolicy, ports: OrgRegisterConfirmPorts) -> Self {
        Self { policy, ports }
    }

    /// What lets `who` add a passkey now, from the proof they gave and the
    /// sign-in they hold.
    async fn leave(
        &self,
        who: &MemberRegistering,
        proof: MemberSetupProof,
    ) -> Result<MemberLeave, AppError> {
        match (proof, &who.from) {
            (MemberSetupProof::Reentered(reentered), _) => self
                .ports
                .fresh_proofs
                .prove_member(&who.member, &who.organization, reentered, who.origin)
                .await
                .map(MemberLeave::Reproved),
            (MemberSetupProof::WaitingSignIn, RegisteringFrom::WaitingSignIn(session)) => session
                .enrolment_proof(clock::now())
                .map(MemberLeave::FinishingSignIn)
                .ok_or(AppError::Unauthenticated),
            (MemberSetupProof::WaitingSignIn, RegisteringFrom::SignedIn) => {
                Err(AppError::Forbidden(message!(
                    "authentication-adding-a-passkey-needs-you-to",
                    "adding a passkey needs you to prove who you are again"
                )))
            }
        }
    }

    /// Refuses another passkey once the member holds the most they may.
    async fn ensure_room_for_another(&self, member: &OrgUserId) -> Result<(), AppError> {
        let held = self
            .ports
            .passkey_store
            .list_by_user(member)
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

    /// Refuses a credential some member's passkey already carries.
    async fn ensure_unseen_credential(
        &self,
        credential_id: &PasskeyCredentialId,
    ) -> Result<(), AppError> {
        let held = self
            .ports
            .passkey_store
            .find_by_credential_id(credential_id)
            .await
            .or_internal()?;
        match held {
            None => Ok(()),
            Some(_) => Err(AppError::Conflict(message!(
                "authentication-credential-id-already-registered",
                "credential ID already registered"
            ))),
        }
    }

    /// The member's own registration ceremony `ceremony_id` names, spent
    /// while they have room for another passkey, with the state it held.
    async fn spent_registration(
        &self,
        member: &OrgUserId,
        ceremony_id: &CeremonyId,
    ) -> Result<(OrgPasskeyCeremony, Vec<u8>), AppError> {
        let store = self.ports.ceremony_store.as_ref();
        let mut ceremony = existing_ceremony(store, ceremony_id).await?;
        ensure_opened_for(&ceremony, member)?;
        self.ensure_room_for_another(member).await?;
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
        state: &[u8],
        given: Attestation<'_>,
    ) -> Result<RegisterPasskeyParams<OrgUserId>, AppError> {
        let verified = self
            .ports
            .verifier
            .verify_registration(state, given.response)
            .await
            .map_err(|_| {
                AppError::Forbidden(message!(
                    "authentication-the-attestation-does-not-verify",
                    "the attestation does not verify"
                ))
            })?;
        self.ensure_unseen_credential(&verified.credential_id)
            .await?;
        Ok(RegisterPasskeyParams {
            user_id: given.member,
            credential_id: verified.credential_id,
            public_key: verified.public_key,
            authenticator_type: verified.authenticator_type,
            attestation: verified.attestation,
            name: given.name,
        })
    }

    /// Keeps the passkey, the member's change and a sign-in it finished.
    async fn save(
        &self,
        who: &MemberRegistering,
        passkey: &PasskeyCredential<ResolvedOrganization>,
    ) -> Result<(), AppError> {
        let member = &who.member;
        self.ports
            .passkey_store
            .save(member.organization_id(), member.id(), passkey)
            .await
            .or_internal()?;
        self.ports
            .registrant
            .members
            .save(member)
            .await
            .or_internal()?;
        let RegisteringFrom::WaitingSignIn(session) = &who.from else {
            return Ok(());
        };
        self.ports
            .registrant
            .sessions
            .save(session)
            .await
            .or_internal()
    }

    /// The finished session a signed-in member adds the passkey from, once
    /// they proved who they are again, loaded before the change ends it.
    /// A sign-in the passkey finishes is kept through the change by the
    /// answer itself.
    async fn session_to_keep(
        &self,
        registrant: &MemberRegistrant,
        leave: &MemberLeave,
    ) -> Result<Option<OrgSession>, AppError> {
        let (MemberRegistrant::SignedIn(caller), MemberLeave::Reproved(_)) = (registrant, leave)
        else {
            return Ok(None);
        };
        self.ports.registrant.own_session(caller).await.map(Some)
    }

    /// Keeps `session` through the change `member` just made from it, and
    /// saves it.
    async fn keep_own_session(
        &self,
        session: Option<OrgSession>,
        leave: &MemberLeave,
        member: &OrgUser,
    ) -> Result<(), AppError> {
        let (Some(mut session), MemberLeave::Reproved(fresh)) = (session, leave) else {
            return Ok(());
        };
        session
            .keep_through_own_change(member, fresh)
            .map_err(AppError::from_domain)?;
        self.ports
            .registrant
            .sessions
            .save(&session)
            .await
            .or_internal()
    }
}

impl Command for OrgRegisterConfirmUseCase {
    type Caller = MemberRegistrant;
    type Input = OrgRegisterConfirmRequest;
    type Output = Result<(), AppError>;

    /// Checks the attestation against the registrant's own ceremony, adds
    /// the passkey, records the change of how the member signs in, and
    /// records `organization.org_passkey_registered`. A sign-in waiting for
    /// this factor is finished by the new passkey, and a finished session
    /// it was added from is kept through the change.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid session, key-based caller or sign-in not waiting for a factor; `StepUpRequired` for a missing factor code.
    /// - `AppError::Forbidden` for inadequate/missing fresh proof, another member's ceremony, invalid attestation or a passkey unable to finish sign-in; `AccountLocked` after wrong codes.
    /// - `AppError::NotFound` for an unknown ceremony/member/originating session; `Domain` for an expired, spent or sign-in ceremony.
    /// - `AppError::Conflict` for a full passkey allowance or an already registered key; `Internal` on storage failure.
    async fn execute(
        &self,
        registrant: &MemberRegistrant,
        auditor: &RequestAuditor,
        request: OrgRegisterConfirmRequest,
    ) -> Result<(), AppError> {
        let mut who = self.ports.registrant.registering(registrant).await?;
        let leave = self.leave(&who, request.proof).await?;
        let own_session = self.session_to_keep(registrant, &leave).await?;
        let member = *who.member.id();
        let (ceremony, state) = self
            .spent_registration(&member, &request.ceremony_id)
            .await?;
        let given = Attestation {
            response: &request.response,
            name: request.name,
            member,
        };
        let passkey = registered_under(self.attested(&state, given).await?, &leave)?;
        who.member.record_passkey_registered(&passkey);
        finish_waiting_sign_in(&mut who, &ceremony, &passkey)?;
        self.save(&who, &passkey).await?;
        self.keep_own_session(own_session, &leave, &who.member)
            .await?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(member), who.member.take_events())
            .await
            .or_internal()
    }
}

/// Refuses a ceremony opened for someone else than `member`.
fn ensure_opened_for(ceremony: &OrgPasskeyCeremony, member: &OrgUserId) -> Result<(), AppError> {
    if ceremony.org_user_id() == Some(member) {
        return Ok(());
    }
    Err(AppError::Forbidden(message!(
        "organization-this-challenge-belongs-to-another-member",
        "this challenge belongs to another member"
    )))
}

/// The passkey `params` describe, added under `leave`.
fn registered_under(
    params: RegisterPasskeyParams<OrgUserId>,
    leave: &MemberLeave,
) -> Result<PasskeyCredential<ResolvedOrganization>, AppError> {
    let added = match leave {
        MemberLeave::FinishingSignIn(enrolment) => PasskeyCredential::register(params, enrolment),
        MemberLeave::Reproved(fresh) => PasskeyCredential::register(params, fresh),
    };
    added.map_err(AppError::from_domain)
}

/// Finishes the sign-in the passkey was added from, when it waited for
/// this factor, keeping it through the change the passkey made. A finished
/// session is left as it is.
fn finish_waiting_sign_in(
    who: &mut MemberRegistering,
    ceremony: &OrgPasskeyCeremony,
    passkey: &PasskeyCredential<ResolvedOrganization>,
) -> Result<(), AppError> {
    let RegisteringFrom::WaitingSignIn(session) = &mut who.from else {
        return Ok(());
    };
    let spent = SpentPasskey::answered(ceremony, passkey).map_err(AppError::from_domain)?;
    let factor = ProvedFactor::by_passkey(&spent).map_err(AppError::from_domain)?;
    session
        .answer(
            &who.member,
            factor,
            who.organization.auth_config().step_up_policy(),
        )
        .map_err(|_| {
            AppError::Forbidden(message!(
                "authentication-the-new-passkey-does-not-finish",
                "the new passkey does not finish the sign-in"
            ))
        })
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::authentication::credentials::passkey_ceremony::TargetedPurpose;
    use ianua_domain::domains::authentication::mfa::owed::SecondFactor;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{CredentialChange, OrganizationId, TenantId};

    use super::*;
    use crate::ports::organization::{OrgSessionStore, OrgUserStore};
    use crate::test_support::acting::{FakeOrgActors, Refusal, caller_session};
    use crate::test_support::authentication::{
        FakePasskeyVerifier, WAITING_REFRESH_TOKEN, right_password, wrong_password,
    };
    use crate::test_support::organization::{
        FakeOrgPasskeyCeremonyStore, FakeOrgPasskeyStore, FakeOrgUserStore,
        RecordingOrgSessionStore, kept_member_ceremony, member_ceremony,
        member_sign_in_waiting_for_a_factor, org_store_with, stored_caller, test_org,
    };
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_org_caller, test_session_id,
    };
    use crate::use_cases::organization::passkeys::registrant::PendingMemberToken;

    struct Fixture {
        olivia: OrgUserId,
        organization: OrganizationId,
        actors: Arc<FakeOrgActors>,
        passkeys: Arc<FakeOrgPasskeyStore>,
        ceremonies: Arc<FakeOrgPasskeyCeremonyStore>,
        verifier: Arc<FakePasskeyVerifier>,
        members: Arc<FakeOrgUserStore>,
        sessions: Arc<RecordingOrgSessionStore>,
        audit: Arc<FakeEventDispatcher>,
        most: usize,
    }

    impl Fixture {
        fn new() -> Self {
            let olivia = stored_caller(OrgRole::Member, "irrelevant");
            let members = FakeOrgUserStore::empty();
            block_on(members.save(&olivia)).unwrap();
            Self {
                olivia: *olivia.id(),
                organization: *olivia.organization_id(),
                actors: Arc::new(FakeOrgActors::in_role(OrgRole::Member)),
                passkeys: Arc::new(FakeOrgPasskeyStore::empty()),
                ceremonies: Arc::new(FakeOrgPasskeyCeremonyStore::new()),
                verifier: Arc::new(FakePasskeyVerifier::succeeding()),
                members: Arc::new(members),
                sessions: Arc::new(RecordingOrgSessionStore::holding([caller_session(&olivia)])),
                audit: Arc::new(FakeEventDispatcher::new()),
                most: 10,
            }
        }

        fn waiting_for_a_factor() -> Self {
            let fixture = Self {
                sessions: Arc::new(RecordingOrgSessionStore::new()),
                ..Self::new()
            };
            let olivia = block_on(fixture.members.find_by_id(&fixture.olivia))
                .unwrap()
                .unwrap();
            block_on(fixture.sessions.save(&member_sign_in_waiting_for_a_factor(
                &olivia,
                TenantId::new(),
            )))
            .unwrap();
            fixture
        }

        fn open_for(&self, member: OrgUserId) -> CeremonyId {
            kept_member_ceremony(
                &self.ceremonies,
                &member_ceremony(member, TargetedPurpose::Registration),
            )
        }

        fn confirm(
            self,
            registrant: &MemberRegistrant,
            request: OrgRegisterConfirmRequest,
        ) -> (Self, Result<(), AppError>) {
            let use_case = OrgRegisterConfirmUseCase::new(
                OrgPolicy {
                    max_passkeys_per_user: self.most,
                },
                OrgRegisterConfirmPorts {
                    registrant: MemberRegistrantPorts {
                        org_actors: self.actors.clone(),
                        sessions: self.sessions.clone(),
                        members: self.members.clone(),
                        organizations: org_store_with([test_org(self.organization, "acme")]),
                        ..MemberRegistrantPorts::fakes()
                    },
                    passkey_store: self.passkeys.clone(),
                    verifier: self.verifier.clone(),
                    ceremony_store: self.ceremonies.clone(),
                    ..OrgRegisterConfirmPorts::fakes()
                },
            );
            let result =
                block_on(use_case.execute(registrant, &test_auditor(self.audit.clone()), request));
            (self, result)
        }

        fn recorded(&self) -> Vec<String> {
            self.audit.records.lock().unwrap().clone()
        }
    }

    fn answer(ceremony_id: CeremonyId, proof: MemberSetupProof) -> OrgRegisterConfirmRequest {
        OrgRegisterConfirmRequest {
            ceremony_id,
            response: b"attestation".to_vec(),
            name: Label::new("name", "YubiKey 5").unwrap(),
            proof,
        }
    }

    fn signed_in() -> MemberRegistrant {
        MemberRegistrant::SignedIn(test_org_caller())
    }

    fn waiting() -> MemberRegistrant {
        MemberRegistrant::SettingUpFactor(PendingMemberToken {
            refresh_token: Secret::new(WAITING_REFRESH_TOKEN),
        })
    }

    /// Olivia proves who she is again and adds a passkey. It is stored,
    /// the change of how she signs in is recorded, and so is the passkey.
    #[test]
    fn a_proven_member_adds_a_passkey() {
        let fixture = Fixture::new();
        let ceremony = fixture.open_for(fixture.olivia);

        let (fixture, result) = fixture.confirm(
            &signed_in(),
            answer(ceremony, MemberSetupProof::Reentered(right_password())),
        );

        result.unwrap();
        assert_eq!(fixture.passkeys.count(), 1);
        let olivia = block_on(fixture.members.find_by_id(&fixture.olivia))
            .unwrap()
            .unwrap();
        assert_ne!(olivia.credentials_changed_at(), CredentialChange::Never);
        assert_eq!(
            fixture.recorded(),
            vec!["organization.org_passkey_registered"]
        );
    }

    /// Olivia adds a passkey from her laptop's session, having proved who
    /// she is again. The change ends her sessions from before it, but the
    /// laptop's is kept through it.
    #[test]
    fn the_session_a_passkey_was_added_from_is_kept_through_the_change() {
        let fixture = Fixture::new();
        let ceremony = fixture.open_for(fixture.olivia);

        let (fixture, result) = fixture.confirm(
            &signed_in(),
            answer(ceremony, MemberSetupProof::Reentered(right_password())),
        );

        result.unwrap();
        let olivia = block_on(fixture.members.find_by_id(&fixture.olivia))
            .unwrap()
            .unwrap();
        let laptop = block_on(fixture.sessions.find_by_id(&test_session_id()))
            .unwrap()
            .unwrap();
        assert_eq!(laptop.kept_through(), olivia.credentials_changed_at());
        assert!(laptop.counts_for(&olivia));
    }

    /// Olivia's sign-in waits for her to set up a factor, and the passkey
    /// she adds from it finishes it. The passkey changes how she signs in,
    /// and the sign-in it finished is kept through that change.
    #[test]
    fn the_sign_in_a_passkey_finished_counts_after_the_change() {
        let fixture = Fixture::waiting_for_a_factor();
        let ceremony = fixture.open_for(fixture.olivia);

        let (fixture, result) = fixture.confirm(
            &waiting(),
            answer(ceremony, MemberSetupProof::WaitingSignIn),
        );

        result.unwrap();
        let olivia = block_on(fixture.members.find_by_id(&fixture.olivia))
            .unwrap()
            .unwrap();
        let finished = &fixture.sessions.saved()[0];
        assert_eq!(finished.kept_through(), olivia.credentials_changed_at());
        assert!(finished.counts_for(&olivia));
    }

    /// A signed-in member's wrong password fails fresh proof, so no passkey
    /// is registered.
    #[test]
    fn a_wrong_password_is_refused() {
        let fixture = Fixture::new();
        let ceremony = fixture.open_for(fixture.olivia);

        let (fixture, result) = fixture.confirm(
            &signed_in(),
            answer(ceremony, MemberSetupProof::Reentered(wrong_password())),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.passkeys.count(), 0);
    }

    /// A completed session cannot authorize registration by claiming to
    /// wait for factor setup, and no passkey is added.
    #[test]
    fn a_finished_session_gives_no_leave_on_its_own() {
        let fixture = Fixture::new();
        let ceremony = fixture.open_for(fixture.olivia);

        let (fixture, result) = fixture.confirm(
            &signed_in(),
            answer(ceremony, MemberSetupProof::WaitingSignIn),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.passkeys.count(), 0);
    }

    /// Olivia's sign-in waits for her to set up the factor her organization
    /// requires. She adds a passkey from it, and it finishes the sign-in.
    #[test]
    fn a_passkey_added_while_signing_in_finishes_the_sign_in() {
        let fixture = Fixture::waiting_for_a_factor();
        let ceremony = fixture.open_for(fixture.olivia);

        let (fixture, result) = fixture.confirm(
            &waiting(),
            answer(ceremony, MemberSetupProof::WaitingSignIn),
        );

        result.unwrap();
        assert_eq!(fixture.passkeys.count(), 1);
        assert_eq!(fixture.sessions.saved()[0].owed(), SecondFactor::NotOwed);
    }

    /// A member cannot complete another member's registration ceremony,
    /// and no passkey is added.
    #[test]
    fn a_ceremony_of_another_member_is_refused() {
        let fixture = Fixture::new();
        let ceremony = fixture.open_for(OrgUserId::new());

        let (fixture, result) = fixture.confirm(
            &signed_in(),
            answer(ceremony, MemberSetupProof::Reentered(right_password())),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.passkeys.count(), 0);
    }

    /// An answer naming a ceremony nobody opened is not found.
    #[test]
    fn an_unknown_ceremony_is_not_found() {
        let fixture = Fixture::new();

        let (_, result) = fixture.confirm(
            &signed_in(),
            answer(
                CeremonyId::new(),
                MemberSetupProof::Reentered(right_password()),
            ),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Replaying a completed registration ceremony is rejected, leaving
    /// only the passkey registered by its first use.
    #[test]
    fn a_ceremony_adds_one_passkey() {
        let fixture = Fixture::new();
        let ceremony = fixture.open_for(fixture.olivia);
        let (fixture, first) = fixture.confirm(
            &signed_in(),
            answer(ceremony, MemberSetupProof::Reentered(right_password())),
        );
        first.unwrap();

        let (fixture, replayed) = fixture.confirm(
            &signed_in(),
            answer(ceremony, MemberSetupProof::Reentered(right_password())),
        );

        assert!(matches!(replayed, Err(AppError::Domain(_))));
        assert_eq!(fixture.passkeys.count(), 1);
    }

    /// A zero passkey allowance prevents registration with a conflict and
    /// leaves the member without passkeys.
    #[test]
    fn a_passkey_beyond_the_most_allowed_is_refused() {
        let fixture = Fixture {
            most: 0,
            ..Fixture::new()
        };
        let ceremony = fixture.open_for(fixture.olivia);

        let (fixture, result) = fixture.confirm(
            &signed_in(),
            answer(ceremony, MemberSetupProof::Reentered(right_password())),
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(fixture.passkeys.count(), 0);
    }

    /// A credential registered to another member conflicts with a new
    /// registration, leaving only the existing passkey.
    #[test]
    fn a_passkey_already_registered_is_refused() {
        let organization = OrganizationId::new();
        let fixture = Fixture {
            passkeys: Arc::new(FakeOrgPasskeyStore::with_passkey(
                organization,
                OrgUserId::new(),
            )),
            ..Fixture::new()
        };
        let ceremony = fixture.open_for(fixture.olivia);

        let (fixture, result) = fixture.confirm(
            &signed_in(),
            answer(ceremony, MemberSetupProof::Reentered(right_password())),
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
        assert_eq!(fixture.passkeys.count(), 1);
    }

    /// A failed attestation is forbidden and creates no passkey.
    #[test]
    fn an_attestation_that_does_not_verify_is_refused() {
        let fixture = Fixture {
            verifier: Arc::new(FakePasskeyVerifier::failing()),
            ..Fixture::new()
        };
        let ceremony = fixture.open_for(fixture.olivia);

        let (fixture, result) = fixture.confirm(
            &signed_in(),
            answer(ceremony, MemberSetupProof::Reentered(right_password())),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(fixture.passkeys.count(), 0);
    }

    /// A signed-out session cannot complete registration, and no passkey is added.
    #[test]
    fn a_signed_out_member_is_refused() {
        let fixture = Fixture {
            actors: Arc::new(FakeOrgActors::refusing(Refusal::SignedOut)),
            ..Fixture::new()
        };
        let ceremony = fixture.open_for(fixture.olivia);

        let (fixture, result) = fixture.confirm(
            &signed_in(),
            answer(ceremony, MemberSetupProof::Reentered(right_password())),
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert_eq!(fixture.passkeys.count(), 0);
    }
}
