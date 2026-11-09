//! A passkey's answer to a sign-in challenge, checked: the challenge spent
//! once, the assertion verified against the key it names, and the key's use
//! counted. Signing in with a passkey and proving who you are again before
//! a change both take it, on a tenant and on the organization plane alike.

use ianua_domain::domains::authentication::credentials::passkey::{
    PasskeyCredential, PasskeyPlane,
};
use ianua_domain::domains::authentication::credentials::passkey_ceremony::{
    CeremonyPurpose, PasskeyCeremony, PasskeyChallenge,
};
use ianua_domain::domains::authentication::sessions::fresh_sign_in::SpentPasskey;
use ianua_domain::domains::organization::access::passkey::OrgPasskeyCeremony;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{CeremonyId, PasskeyCredentialId};

use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::authentication::{
    PasskeyAuthenticationResult, PasskeyCeremonyStore, PasskeyStore, PasskeyVerifier,
};
use crate::ports::organization::{OrgPasskeyCeremonyStore, OrgPasskeyStore, OrgUserStore};
use crate::tenancy::ScopedTenant;

/// What the browser sends back for a passkey challenge. The response is
/// the authenticator's signed answer; it proves nothing until verified.
pub struct PresentedAssertion {
    /// The ceremony the challenge came from.
    pub ceremony_id: CeremonyId,
    /// The passkey that signed the answer, as the authenticator names it.
    pub credential_id: PasskeyCredentialId,
    /// The authenticator's signed answer.
    pub response: Vec<u8>,
}

/// Where passkeys and their ceremonies are kept, and what checks an
/// assertion.
#[derive(Clone, Copy)]
pub(crate) struct PasskeyAnswering<'a> {
    /// The tenant's passkeys.
    pub(crate) passkeys: &'a dyn PasskeyStore,
    /// The ceremonies in flight.
    pub(crate) ceremonies: &'a dyn PasskeyCeremonyStore,
    /// Checks an assertion against a passkey's public key.
    pub(crate) verifier: &'a dyn PasskeyVerifier,
}

/// A passkey that answered a sign-in challenge, with the domain's record
/// of the answer.
pub(crate) struct AnsweredPasskey {
    /// The passkey, its use counted and saved.
    pub(crate) passkey: PasskeyCredential<ResolvedTenant>,
    /// The challenge it answered, spent.
    pub(crate) spent: SpentPasskey,
}

/// Where organization members' passkeys and their ceremonies are kept, and
/// what checks an assertion.
#[derive(Clone, Copy)]
pub(crate) struct MemberPasskeyAnswering<'a> {
    /// Members' passkeys.
    pub(crate) passkeys: &'a dyn OrgPasskeyStore,
    /// The ceremonies in flight on the organization plane.
    pub(crate) ceremonies: &'a dyn OrgPasskeyCeremonyStore,
    /// The members, to find who owns a passkey.
    pub(crate) members: &'a dyn OrgUserStore,
    /// Checks an assertion against a passkey's public key.
    pub(crate) verifier: &'a dyn PasskeyVerifier,
}

/// A member's passkey that answered a sign-in challenge, with the member
/// and the domain's record of the answer.
pub(crate) struct AnsweredMemberPasskey {
    /// The member who owns the passkey, as they stand now.
    pub(crate) member: OrgUser,
    /// The challenge it answered, spent.
    pub(crate) spent: SpentPasskey,
}

impl PasskeyAnswering<'_> {
    /// The passkey whose assertion answers the sign-in challenge
    /// `presented` names, with its use counted.
    ///
    /// The challenge is spent before the assertion is checked, so a failed
    /// answer burns it rather than leaving it open for another forgery.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the ceremony or the passkey is unknown.
    /// - `AppError::Domain` when the ceremony expired, was used, or was
    ///   opened for a registration.
    /// - `AppError::Forbidden` when the assertion does not verify, the
    ///   passkey is not the one the challenge was opened for, or the
    ///   passkey's counter went backwards.
    /// - `AppError::Internal` on storage failure.
    pub(crate) async fn answered(
        &self,
        tenant: &ScopedTenant,
        presented: &PresentedAssertion,
    ) -> Result<AnsweredPasskey, AppError> {
        let mut ceremony = self.ceremony(tenant, &presented.ceremony_id).await?;
        let state = self.spent_state(&mut ceremony).await?;
        let mut passkey = self.passkey(tenant, &presented.credential_id).await?;
        let signed = Signed {
            purpose: ceremony.purpose(),
            state: &state,
            response: &presented.response,
        };
        let spent = answered_by(self.verifier, &ceremony, &mut passkey, signed).await?;
        self.passkeys.save(tenant, &passkey).await.or_internal()?;
        Ok(AnsweredPasskey { passkey, spent })
    }

    async fn ceremony(
        &self,
        tenant: &ScopedTenant,
        id: &CeremonyId,
    ) -> Result<PasskeyCeremony, AppError> {
        self.ceremonies
            .find_by_id(tenant, id)
            .await
            .or_internal()?
            .or_not_found(message!(
                "authentication-passkey-challenge-not-found",
                "passkey challenge not found"
            ))
    }

    /// Spends a sign-in ceremony and hands back the state it held.
    async fn spent_state(&self, ceremony: &mut PasskeyCeremony) -> Result<Vec<u8>, AppError> {
        let purpose = sign_in_purpose(ceremony.purpose())?;
        let state = ceremony
            .consume(purpose)
            .map_err(AppError::from_domain)?
            .to_vec();
        self.ceremonies
            .mark_consumed(ceremony)
            .await
            .map_err(AppError::from_domain)?;
        Ok(state)
    }

    async fn passkey(
        &self,
        tenant: &ScopedTenant,
        credential_id: &PasskeyCredentialId,
    ) -> Result<PasskeyCredential<ResolvedTenant>, AppError> {
        self.passkeys
            .find_by_credential_id(tenant, credential_id)
            .await
            .or_internal()?
            .or_not_found(message!(
                "authentication-passkey-not-found",
                "passkey not found"
            ))
    }
}

impl MemberPasskeyAnswering<'_> {
    /// The member's passkey whose assertion answers the sign-in challenge
    /// `presented` names, with its use counted, and the member it belongs
    /// to.
    ///
    /// The challenge is spent before the assertion is checked, so a failed
    /// answer burns it rather than leaving it open for another forgery.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the ceremony, the passkey or its member
    ///   is unknown.
    /// - `AppError::Domain` when the ceremony expired, was used, or was
    ///   opened for a registration.
    /// - `AppError::Forbidden` when the assertion does not verify, the
    ///   passkey is not the one the challenge was opened for, or the
    ///   passkey's counter went backwards.
    /// - `AppError::Internal` on storage failure.
    pub(crate) async fn answered(
        &self,
        presented: &PresentedAssertion,
    ) -> Result<AnsweredMemberPasskey, AppError> {
        let mut ceremony = self
            .ceremonies
            .find_by_id(&presented.ceremony_id)
            .await
            .or_internal()?
            .or_not_found(message!(
                "authentication-passkey-challenge-not-found",
                "passkey challenge not found"
            ))?;
        let state = self.spent_state(&mut ceremony).await?;
        let (member, mut passkey) = self.owned_passkey(&presented.credential_id).await?;
        let signed = Signed {
            purpose: ceremony.purpose(),
            state: &state,
            response: &presented.response,
        };
        let spent = answered_by(self.verifier, &ceremony, &mut passkey, signed).await?;
        self.passkeys
            .save(member.organization_id(), member.id(), &passkey)
            .await
            .or_internal()?;
        Ok(AnsweredMemberPasskey { member, spent })
    }

    /// Spends a sign-in ceremony and hands back the state it held.
    async fn spent_state(&self, ceremony: &mut OrgPasskeyCeremony) -> Result<Vec<u8>, AppError> {
        let purpose = sign_in_purpose(ceremony.purpose())?;
        let state = ceremony
            .consume(purpose)
            .map_err(AppError::from_domain)?
            .to_vec();
        self.ceremonies
            .mark_consumed(ceremony)
            .await
            .map_err(AppError::from_domain)?;
        Ok(state)
    }

    /// The passkey `credential_id` names, with the member who owns it.
    async fn owned_passkey(
        &self,
        credential_id: &PasskeyCredentialId,
    ) -> Result<(OrgUser, PasskeyCredential<ResolvedOrganization>), AppError> {
        let passkey = self
            .passkeys
            .find_by_credential_id(credential_id)
            .await
            .or_internal()?
            .or_not_found(message!(
                "authentication-passkey-not-found",
                "passkey not found"
            ))?;
        let member = self
            .members
            .find_by_id(passkey.user_id())
            .await
            .or_internal()?
            .or_not_found(message!(
                "authentication-passkey-not-found",
                "passkey not found"
            ))?;
        Ok((member, passkey))
    }
}

/// What `passkey`'s assertion in `signed` proves about the spent
/// `ceremony`: the assertion checked against the passkey's public key and
/// counter the way the ceremony asks, and the new count recorded on it.
/// The caller saves the passkey.
///
/// # Errors
///
/// - `AppError::Forbidden` when the assertion does not verify, the
///   passkey's counter went backwards, or the passkey is not the one the
///   challenge was opened for.
async fn answered_by<S: PasskeyPlane>(
    verifier: &dyn PasskeyVerifier,
    ceremony: &impl PasskeyChallenge<S>,
    passkey: &mut PasskeyCredential<S>,
    signed: Signed<'_>,
) -> Result<SpentPasskey, AppError> {
    let verified = verified_assertion(verifier, passkey, signed).await?;
    passkey
        .update_sign_count(verified.new_sign_count)
        .map_err(AppError::from_domain)?;
    SpentPasskey::answered(ceremony, passkey).map_err(AppError::from_domain)
}

/// The verifier's answer to the assertion, checked against the passkey's
/// public key and counter the way the ceremony asks.
async fn verified_assertion<S: PasskeyPlane>(
    verifier: &dyn PasskeyVerifier,
    passkey: &PasskeyCredential<S>,
    signed: Signed<'_>,
) -> Result<PasskeyAuthenticationResult, AppError> {
    let (key, count) = (passkey.public_key(), passkey.sign_count());
    let verified = match signed.purpose {
        CeremonyPurpose::DiscoverableAuthentication => {
            verifier
                .verify_discoverable_authentication(signed.state, signed.response, key, count)
                .await
        }
        CeremonyPurpose::Authentication | CeremonyPurpose::Registration => {
            verifier
                .verify_authentication(signed.state, signed.response, key, count)
                .await
        }
    };
    verified.map_err(|_| {
        AppError::Forbidden(message!(
            "authentication-the-passkey-s-answer-does-not",
            "the passkey's answer does not verify"
        ))
    })
}

/// Refuses a ceremony opened to register a passkey: it never signs anyone
/// in.
fn sign_in_purpose(purpose: CeremonyPurpose) -> Result<CeremonyPurpose, AppError> {
    match purpose {
        CeremonyPurpose::Authentication | CeremonyPurpose::DiscoverableAuthentication => {
            Ok(purpose)
        }
        CeremonyPurpose::Registration => Err(AppError::Forbidden(message!(
            "authentication-this-challenge-was-opened-to-register",
            "this challenge was opened to register a passkey"
        ))),
    }
}

/// An authenticator's signed answer to a spent ceremony.
struct Signed<'a> {
    purpose: CeremonyPurpose,
    state: &'a [u8],
    response: &'a [u8],
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::domains::authentication::credentials::passkey_ceremony::{
        OpenCeremonyParams, TargetedPurpose,
    };
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::types::{Lifetime, OrgUserId, OrganizationId, UserId};

    use super::*;
    use crate::test_support::authentication::{
        FakePasskeyCeremonyStore, FakePasskeyStore, FakePasskeyVerifier, PASSKEY_CEREMONY_STATE,
        passkey_credential_id,
    };
    use crate::test_support::organization::{
        FakeOrgPasskeyCeremonyStore, FakeOrgPasskeyStore, FakeOrgUserStore, test_org_user,
    };
    use crate::test_support::{ReadBeforeWrite, block_on, test_ctx};

    struct Fixture {
        ann: UserId,
        passkeys: FakePasskeyStore,
        ceremonies: FakePasskeyCeremonyStore,
        verifier: FakePasskeyVerifier,
    }

    impl Fixture {
        fn with_passkey() -> Self {
            let ann = UserId::new();
            Self {
                ann,
                passkeys: FakePasskeyStore::with_passkey(ann),
                ceremonies: FakePasskeyCeremonyStore::new(),
                verifier: FakePasskeyVerifier::succeeding(),
            }
        }

        fn open(&self, user_id: UserId, purpose: TargetedPurpose) -> CeremonyId {
            let ceremony = ceremony_for(user_id, purpose);
            let id = *ceremony.id();
            block_on(self.ceremonies.save(&ceremony)).unwrap();
            id
        }

        fn answer(&self, ceremony_id: CeremonyId) -> Result<AnsweredPasskey, AppError> {
            self.answer_through(&self.ceremonies, ceremony_id)
        }

        fn answer_through(
            &self,
            ceremonies: &dyn PasskeyCeremonyStore,
            ceremony_id: CeremonyId,
        ) -> Result<AnsweredPasskey, AppError> {
            let answering = PasskeyAnswering {
                passkeys: &self.passkeys,
                ceremonies,
                verifier: &self.verifier,
            };
            let presented = PresentedAssertion {
                ceremony_id,
                credential_id: passkey_credential_id(),
                response: b"signed".to_vec(),
            };
            block_on(answering.answered(&test_ctx().tenant(), &presented))
        }
    }

    fn ceremony_for(user_id: UserId, purpose: TargetedPurpose) -> PasskeyCeremony {
        PasskeyCeremony::open(OpenCeremonyParams {
            tenant_id: test_ctx().tenant_id(),
            user_id,
            purpose,
            state: PASSKEY_CEREMONY_STATE.to_vec(),
            ttl: Lifetime::seconds(300).unwrap(),
        })
    }

    /// Ann answers the challenge opened for her with her passkey. The answer
    /// is hers, and her passkey's use is counted.
    #[test]
    fn a_verified_answer_names_its_passkey() {
        let fixture = Fixture::with_passkey();
        let ceremony = fixture.open(fixture.ann, TargetedPurpose::Authentication);

        let answered = fixture.answer(ceremony).unwrap();

        assert_eq!(answered.passkey.user_id(), &fixture.ann);
        assert!(answered.passkey.last_used_at().is_some());
    }

    /// After Ann's first answer succeeds, answering the same tenant
    /// challenge again returns a domain refusal.
    #[test]
    fn a_spent_challenge_is_refused() {
        let fixture = Fixture::with_passkey();
        let ceremony = fixture.open(fixture.ann, TargetedPurpose::Authentication);
        fixture.answer(ceremony).unwrap();

        let replayed = fixture.answer(ceremony);

        assert!(matches!(replayed, Err(AppError::Domain(_))));
    }

    /// Two readers see the same open challenge, but its live store accepts
    /// only the first answer. The stale reader receives a domain refusal.
    #[test]
    fn two_answers_to_one_challenge_at_once_settle_it_once() {
        let fixture = Fixture::with_passkey();
        let ceremony = ceremony_for(fixture.ann, TargetedPurpose::Authentication);
        let racing = ReadBeforeWrite::new(
            FakePasskeyCeremonyStore::new(),
            Arc::new(FakePasskeyCeremonyStore::new()),
        );
        block_on(racing.seen.save(&ceremony)).unwrap();
        block_on(racing.live.save(&ceremony)).unwrap();
        fixture.answer_through(&racing, *ceremony.id()).unwrap();

        let replayed = fixture.answer_through(&racing, *ceremony.id());

        assert!(matches!(replayed, Err(AppError::Domain(_))));
    }

    /// Ann has already used the passkey. A later assertion whose counter
    /// does not advance is forbidden, even with a fresh challenge.
    #[test]
    fn a_passkey_whose_counter_did_not_go_up_is_forbidden() {
        let fixture = Fixture::with_passkey();
        let first = fixture.open(fixture.ann, TargetedPurpose::Authentication);
        fixture.answer(first).unwrap();
        let copied = Fixture {
            verifier: FakePasskeyVerifier::copied_authenticator(),
            ..fixture
        };
        let ceremony = copied.open(copied.ann, TargetedPurpose::Authentication);

        let answered = copied.answer(ceremony);

        assert!(matches!(answered, Err(AppError::Forbidden(_))));
    }

    /// A failed assertion is forbidden and consumes its challenge. Even
    /// a verifier that would accept the next assertion cannot reuse it.
    #[test]
    fn an_answer_that_does_not_verify_is_refused_and_burns_the_challenge() {
        let fixture = Fixture {
            verifier: FakePasskeyVerifier::failing(),
            ..Fixture::with_passkey()
        };
        let ceremony = fixture.open(fixture.ann, TargetedPurpose::Authentication);

        let forged = fixture.answer(ceremony);

        assert!(matches!(forged, Err(AppError::Forbidden(_))));
        let retried = Fixture {
            verifier: FakePasskeyVerifier::succeeding(),
            ..fixture
        }
        .answer(ceremony);
        assert!(matches!(retried, Err(AppError::Domain(_))));
    }

    /// Ann's passkey cannot answer a tenant challenge opened for another
    /// account; the result is forbidden.
    #[test]
    fn a_challenge_opened_for_another_account_is_refused() {
        let fixture = Fixture::with_passkey();
        let ceremony = fixture.open(UserId::new(), TargetedPurpose::Authentication);

        let answered = fixture.answer(ceremony);

        assert!(matches!(answered, Err(AppError::Forbidden(_))));
    }

    /// A registration ceremony is forbidden on the passkey sign-in path,
    /// even when the passkey belongs to the ceremony's user.
    #[test]
    fn a_registration_challenge_is_refused() {
        let fixture = Fixture::with_passkey();
        let ceremony = fixture.open(fixture.ann, TargetedPurpose::Registration);

        let answered = fixture.answer(ceremony);

        assert!(matches!(answered, Err(AppError::Forbidden(_))));
    }

    /// An assertion naming an unknown ceremony returns not found.
    #[test]
    fn an_unknown_challenge_is_not_found() {
        let fixture = Fixture::with_passkey();

        let answered = fixture.answer(CeremonyId::new());

        assert!(matches!(answered, Err(AppError::NotFound(_))));
    }

    /// Ann, a member of Acme, and her passkey, kept on the organization
    /// plane.
    struct MemberFixture {
        ann: OrgUser,
        passkeys: FakeOrgPasskeyStore,
        ceremonies: FakeOrgPasskeyCeremonyStore,
        members: FakeOrgUserStore,
        verifier: FakePasskeyVerifier,
    }

    impl MemberFixture {
        fn with_passkey() -> Self {
            let organization = OrganizationId::new();
            let ann = test_org_user(organization, "ann@acme.test", OrgRole::Member);
            let members = FakeOrgUserStore::empty();
            block_on(members.save(&ann)).unwrap();
            Self {
                passkeys: FakeOrgPasskeyStore::with_passkey(organization, *ann.id()),
                ceremonies: FakeOrgPasskeyCeremonyStore::new(),
                members,
                verifier: FakePasskeyVerifier::succeeding(),
                ann,
            }
        }

        fn open_for(&self, member: OrgUserId) -> CeremonyId {
            let ceremony = OrgPasskeyCeremony::open(
                member,
                TargetedPurpose::Authentication,
                PASSKEY_CEREMONY_STATE.to_vec(),
                Lifetime::seconds(300).unwrap(),
            );
            let id = *ceremony.id();
            block_on(self.ceremonies.save(&ceremony)).unwrap();
            id
        }

        fn answer(&self, ceremony_id: CeremonyId) -> Result<AnsweredMemberPasskey, AppError> {
            let answering = MemberPasskeyAnswering {
                passkeys: &self.passkeys,
                ceremonies: &self.ceremonies,
                members: &self.members,
                verifier: &self.verifier,
            };
            block_on(answering.answered(&PresentedAssertion {
                ceremony_id,
                credential_id: passkey_credential_id(),
                response: b"signed".to_vec(),
            }))
        }
    }

    /// Ann, a member, answers the challenge opened for her with her
    /// passkey. The answer names her, and her passkey's use is counted.
    #[test]
    fn a_member_answer_names_the_member() {
        let fixture = MemberFixture::with_passkey();
        let ceremony = fixture.open_for(*fixture.ann.id());

        let answered = fixture.answer(ceremony).unwrap();

        assert_eq!(answered.member.id(), fixture.ann.id());
        let kept = block_on(fixture.passkeys.list_by_user(fixture.ann.id())).unwrap();
        assert!(kept[0].last_used_at().is_some());
    }

    /// An organization challenge opened for another member cannot be
    /// answered with Ann's passkey; the result is forbidden.
    #[test]
    fn a_member_challenge_opened_for_another_member_is_refused() {
        let fixture = MemberFixture::with_passkey();
        let ceremony = fixture.open_for(OrgUserId::new());

        let answered = fixture.answer(ceremony);

        assert!(matches!(answered, Err(AppError::Forbidden(_))));
    }

    /// Ann's successful answer spends the organization challenge. A
    /// second answer to that ceremony returns a domain refusal.
    #[test]
    fn a_spent_member_challenge_is_refused() {
        let fixture = MemberFixture::with_passkey();
        let ceremony = fixture.open_for(*fixture.ann.id());
        fixture.answer(ceremony).unwrap();

        let replayed = fixture.answer(ceremony);

        assert!(matches!(replayed, Err(AppError::Domain(_))));
    }
}
