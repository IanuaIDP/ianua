//! Which member sets up a second factor, and what lets them.
//!
//! Setting up a factor changes how the member signs in. Whoever steals a
//! session must not add their own authenticator with it, so a member
//! signed in proves who they are again first. A sign-in that waits for the
//! factor the organization requires carries its own short leave to set it
//! up, and nothing else.

use std::sync::Arc;

use ianua_domain::domains::authentication::mfa::enrollment::{
    EnrolledFactor, MfaEnrollment, MfaEnrollmentError,
};
use ianua_domain::domains::authentication::mfa::offer::FactorOffer;
use ianua_domain::domains::authentication::risk_engine::origin::AttemptOrigin;
use ianua_domain::domains::authentication::sessions::fresh_sign_in::{EnrolmentProof, FreshSignIn};
use ianua_domain::domains::organization::access::session::OrgSession;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::isolation::organization::scope::ResolvedOrganization;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::types::{OrgUserId, PrincipalId, SessionId};

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::organization::{OrgSessionStore, OrgUserStore, OrganizationStore};
use crate::services::authentication::fresh_proof::FreshProofs;
use crate::use_cases::authentication::mfa::SetupProof;
use crate::use_cases::organization::lookup::{
    existing_member, existing_organization, owned_org_session,
};

/// A member's sign-in waiting for a second factor, named by its session.
#[derive(Debug, Clone, Copy)]
pub struct PendingMemberSession {
    /// The session of the sign-in.
    pub session_id: SessionId,
    /// The member signing in.
    pub member: OrgUserId,
}

/// Who sets up, confirms or gives up a member's second factor.
pub enum MemberFactorSetter {
    /// A member signed in to a session of the organization.
    SignedIn(OrgCaller),
    /// A sign-in that waits for its member to set up the factor the
    /// organization requires.
    SigningIn(PendingMemberSession),
}

/// Where a setter is worked out from, and their leave to set up a factor.
/// The member use cases that set up, confirm or give up a factor share it.
#[derive(Clone, ianua_macros::Fakes)]
pub struct MemberSetterPorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// Loads the account whose factor setup is changing.
    pub members: Arc<dyn OrgUserStore>,
    /// The organizations, for a waiting sign-in's.
    pub organizations: Arc<dyn OrganizationStore>,
    /// The members' sessions, for a waiting sign-in.
    pub sessions: Arc<dyn OrgSessionStore>,
    /// Turns what a signed-in member typed again into a fresh proof.
    pub fresh_proofs: Arc<dyn FreshProofs>,
}

/// The member setting up a factor, as they stand now, with their
/// organization and the sign-in waiting for the factor, if any.
pub(in crate::use_cases::organization::mfa) struct Setter {
    /// The account whose current standing permits factor setup.
    pub(in crate::use_cases::organization::mfa) member: OrgUser,
    /// The owning account whose authentication policy applies.
    pub(in crate::use_cases::organization::mfa) organization: Organization,
    /// Where they set it up from.
    pub(in crate::use_cases::organization::mfa) from: SettingFrom,
}

/// Where a member sets up a factor from.
pub(in crate::use_cases::organization::mfa) enum SettingFrom {
    /// Their own finished session, the request coming from this origin.
    SignedIn(AttemptOrigin),
    /// The sign-in waiting for the factor.
    WaitingSignIn(Box<OrgSession>),
}

/// The domain's leave to set up a member's factor, in whichever form it
/// came.
pub(in crate::use_cases::organization::mfa) enum MemberLeave {
    /// A fresh proof of the member.
    Fresh(FreshSignIn),
    /// A sign-in waiting for the factor it owes.
    Enrolment(EnrolmentProof),
}

impl MemberSetterPorts {
    /// The member `setter` names, as they stand now.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when a signed-in member's session no
    ///   longer counts, or they act through a key.
    /// - `AppError::Forbidden` when the session is someone else's.
    /// - `AppError::NotFound` when a waiting sign-in's session, member or
    ///   organization is gone.
    /// - `AppError::Internal` on storage failure.
    pub(in crate::use_cases::organization::mfa) async fn setter(
        &self,
        setter: &MemberFactorSetter,
    ) -> Result<Setter, AppError> {
        match setter {
            MemberFactorSetter::SignedIn(caller) => self.signed_in(caller).await,
            MemberFactorSetter::SigningIn(pending) => self.signing_in(pending).await,
        }
    }

    /// The leave `proof` gives `setter` to set up a factor.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` when the proof does not prove the member,
    ///   the waiting sign-in owes no factor to set up or began too long
    ///   ago, or the proof does not fit how the member is signed in.
    /// - `AppError::StepUpRequired` when the member has a second factor and
    ///   gave no code from it.
    /// - `AppError::Internal` on storage failure.
    pub(in crate::use_cases::organization::mfa) async fn leave(
        &self,
        setter: &Setter,
        proof: SetupProof,
    ) -> Result<MemberLeave, AppError> {
        match (&setter.from, proof) {
            (SettingFrom::SignedIn(from), SetupProof::Reentered(proof)) => self
                .fresh_proofs
                .prove_member(&setter.member, &setter.organization, proof, *from)
                .await
                .map(MemberLeave::Fresh),
            (SettingFrom::WaitingSignIn(session), SetupProof::OwedBySignIn) => session
                .enrolment_proof(clock::now())
                .map(MemberLeave::Enrolment)
                .ok_or_else(|| {
                    AppError::Forbidden(message!(
                        "authentication-this-sign-in-does-not-wait",
                        "this sign-in does not wait for a second factor to be set up"
                    ))
                }),
            (SettingFrom::SignedIn(_), SetupProof::OwedBySignIn)
            | (SettingFrom::WaitingSignIn(_), SetupProof::Reentered(_)) => {
                Err(AppError::Forbidden(message!(
                    "organization-this-proof-does-not-fit-how",
                    "this proof does not fit how the member signs in"
                )))
            }
        }
    }

    /// The session a signed-in member acts through, as stored, for the
    /// change setting up a factor makes to keep it.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the session no longer counts, or
    ///   the member acts through a key.
    /// - `AppError::NotFound` when the session is gone.
    /// - `AppError::Internal` on storage failure.
    pub(in crate::use_cases::organization::mfa) async fn own_session(
        &self,
        caller: &OrgCaller,
    ) -> Result<OrgSession, AppError> {
        let (organization, actor) = self.org_actors.actor(caller).await?;
        owned_org_session(self.sessions.as_ref(), &organization, &actor).await
    }

    async fn signed_in(&self, caller: &OrgCaller) -> Result<Setter, AppError> {
        let (organization, actor) = self.org_actors.actor(caller).await?;
        actor.signed_in()?;
        let members = self.members.as_ref();
        let member = existing_member(members, organization.id(), actor.member().id()).await?;
        Ok(Setter {
            member,
            organization,
            from: SettingFrom::SignedIn(caller.origin()),
        })
    }

    async fn signing_in(&self, pending: &PendingMemberSession) -> Result<Setter, AppError> {
        let session = waiting_session(self.sessions.as_ref(), pending).await?;
        let organization_id = *session.organization_id();
        let members = self.members.as_ref();
        let member = existing_member(members, &organization_id, &pending.member).await?;
        let organization =
            existing_organization(self.organizations.as_ref(), &organization_id).await?;
        Ok(Setter {
            member,
            organization,
            from: SettingFrom::WaitingSignIn(Box::new(session)),
        })
    }
}

/// The session of `pending`, provided it is the member's.
///
/// # Errors
///
/// - `AppError::NotFound` when there is no such session, or it is another
///   member's.
/// - `AppError::Internal` on storage failure.
pub(in crate::use_cases::organization::mfa) async fn waiting_session(
    sessions: &dyn OrgSessionStore,
    pending: &PendingMemberSession,
) -> Result<OrgSession, AppError> {
    sessions
        .find_by_id(&pending.session_id)
        .await
        .or_internal()?
        .filter(|session| *session.org_user_id() == pending.member)
        .or_not_found(message!("app-session-not-found", "session not found"))
}

/// A pending enrollment of `member` over `factor`, begun on `leave` under
/// the organization's `offer`.
///
/// # Errors
///
/// Returns `AppError::Forbidden` when `leave` does not let the member set
/// up a factor now, or `offer` is for another kind of factor.
pub(in crate::use_cases::organization::mfa) fn begun_member_enrollment(
    member: &OrgUserId,
    factor: EnrolledFactor,
    offer: &FactorOffer,
    leave: &MemberLeave,
) -> Result<MfaEnrollment<ResolvedOrganization>, AppError> {
    let subject = PrincipalId::from(*member);
    let begun = match leave {
        MemberLeave::Fresh(proof) => MfaEnrollment::begin(subject, factor, offer, proof),
        MemberLeave::Enrolment(proof) => MfaEnrollment::begin(subject, factor, offer, proof),
    };
    begun.map_err(|refused| refused_member_setup(&refused))
}

/// Gives up `enrollment`, a member's setup never confirmed, on `leave`.
///
/// # Errors
///
/// - `AppError::Forbidden` when `leave` does not let the member set up a
///   factor now.
/// - `AppError::NotFound` when the enrollment no longer waits to be
///   confirmed.
pub(in crate::use_cases::organization::mfa) fn give_up_member_enrollment(
    enrollment: &mut MfaEnrollment<ResolvedOrganization>,
    leave: &MemberLeave,
) -> Result<(), AppError> {
    let given_up = match leave {
        MemberLeave::Fresh(proof) => enrollment.abandon(proof),
        MemberLeave::Enrolment(proof) => enrollment.abandon(proof),
    };
    given_up.map_err(|refused| refused_member_setup(&refused))
}

/// The error a member's enrollment that would not change answers with.
pub(in crate::use_cases::organization::mfa) fn refused_member_setup(
    refused: &MfaEnrollmentError,
) -> AppError {
    match refused {
        MfaEnrollmentError::NotPending => AppError::NotFound(message!(
            "organization-no-second-factor-is-waiting-to",
            "no second factor is waiting to be confirmed"
        )),
        MfaEnrollmentError::NotActive => AppError::NotFound(message!(
            "organization-no-second-factor-is-in-force",
            "no second factor is in force"
        )),
        MfaEnrollmentError::NotItsCode
        | MfaEnrollmentError::AccountHoldsMore
        | MfaEnrollmentError::NotProvedNow
        | MfaEnrollmentError::NotThisAccount
        | MfaEnrollmentError::NotOffered => AppError::Forbidden(refused.to_string().into()),
    }
}
