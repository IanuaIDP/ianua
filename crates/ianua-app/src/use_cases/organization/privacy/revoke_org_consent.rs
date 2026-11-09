//! A member withdraws consent they gave, themselves or through someone who
//! may update members and records it for them.

use std::sync::Arc;

use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::domains::identity::privacy::consent::{ConsentDecision, ConsentTerms};
use ianua_domain::domains::organization::members::account_control::{
    OrgAccountControl, ensure_may_act_on_others,
};
use ianua_domain::domains::organization::members::control::OrgControl;
use ianua_domain::domains::organization::members::privacy::consent::OrgConsentRecord;
use ianua_domain::message;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActorRef, Fact, IpAddress, OrgUserId, OrganizationId};

use crate::acting::OrgActors;
use crate::acting::organization::OrgActor;
use crate::auditor::RequestAuditor;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgConsentStore, OrgUserStore};
use crate::use_case::Command;
use crate::use_cases::organization::lookup::existing_member;
use crate::use_cases::organization::privacy::whose::OrgWhose;

/// Whose consent to withdraw, and on which terms.
pub struct RevokeOrgConsentRequest {
    /// Whose consent it is.
    pub whose: OrgWhose,
    /// The kind and version of consent withdrawn.
    pub terms: ConsentTerms,
}

/// What is withdrawn, and from where the request came.
struct Withdrawal {
    /// The kind and version of consent withdrawn.
    terms: ConsentTerms,
    /// The address the request came from, when known.
    ip_address: Fact<IpAddress>,
}

/// The ports [`RevokeOrgConsentUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RevokeOrgConsentPorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// The organization's members, to name the member on the record.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Members' consent records.
    pub consents: Arc<dyn OrgConsentStore>,
}

/// Records a withdrawal of a member's consent.
pub struct RevokeOrgConsentUseCase {
    ports: RevokeOrgConsentPorts,
}

impl RevokeOrgConsentUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: RevokeOrgConsentPorts) -> Self {
        Self { ports }
    }

    /// The record of `withdrawal` for the member `whose` names, made by the
    /// member themselves or for them.
    async fn record_of(
        &self,
        actor: &OrgActor,
        organization_id: &OrganizationId,
        whose: OrgWhose,
        withdrawal: Withdrawal,
    ) -> Result<OrgConsentRecord, AppError> {
        let control = actor.control()?;
        let member_id = whose.member(actor.member().id());
        if control.is_member(&member_id) {
            return OrgConsentRecord::record(
                actor.member(),
                withdrawal.terms,
                ConsentDecision::Withdrawn,
                withdrawal.ip_address,
                &control,
            )
            .map_err(AppError::from_domain);
        }
        self.recorded_for(control, organization_id, &member_id, withdrawal)
            .await
    }

    /// The record of `withdrawal` that someone who may update members makes
    /// for `member_id`.
    async fn recorded_for(
        &self,
        control: OrgControl<'_>,
        organization_id: &OrganizationId,
        member_id: &OrgUserId,
        withdrawal: Withdrawal,
    ) -> Result<OrgConsentRecord, AppError> {
        ensure_may_act_on_others(&control, organization_id, AccountAction::RecordForThem)
            .map_err(AppError::from_domain)?;
        let users = self.ports.org_users.as_ref();
        let member = existing_member(users, organization_id, member_id).await?;
        let on_them = OrgAccountControl::new(control, &member);
        let Withdrawal { terms, ip_address } = withdrawal;
        OrgConsentRecord::withdraw_for(&member, terms, ip_address, &on_them)
            .map_err(AppError::from_domain)
    }
}

impl Command for RevokeOrgConsentUseCase {
    type Caller = OrgCaller;
    type Input = RevokeOrgConsentRequest;
    type Output = Result<(), AppError>;

    /// Records that consent on `request.terms` is withdrawn, as a new
    /// record, and records `organization.org_user_consent_revoked`.
    /// Withdrawing is as easy as giving: the member does it from their own
    /// session, or someone who may update members records it for them,
    /// since withdrawing only lowers what is done with their data.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the member withdraws through a key, or
    ///   the caller may not update that member.
    /// - `AppError::NotFound` when the organization has no such member, or
    ///   no consent was given before.
    /// - `AppError::Conflict` if it is already withdrawn.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        auditor: &RequestAuditor,
        request: RevokeOrgConsentRequest,
    ) -> Result<(), AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let withdrawal = Withdrawal {
            terms: request.terms,
            ip_address: caller.audit_context().ip_address().clone(),
        };
        let mut record = self
            .record_of(&actor, organization.id(), request.whose, withdrawal)
            .await?;
        let consents = self.ports.consents.as_ref();
        ensure_latest_granted(consents, &record).await?;
        consents.save(&record).await.or_internal()?;
        auditor
            .dispatch_by(&ActorRef::OrgUser(*caller.member()), record.take_events())
            .await
            .or_internal()
    }
}

/// Refuses unless the member `withdrawal` is for last gave consent of its
/// kind.
///
/// # Errors
///
/// - `AppError::NotFound` if no consent was given before.
/// - `AppError::Conflict` if it is already withdrawn.
/// - `AppError::Internal` on storage failure.
async fn ensure_latest_granted(
    store: &dyn OrgConsentStore,
    withdrawal: &OrgConsentRecord,
) -> Result<(), AppError> {
    let latest = store
        .find_latest(
            withdrawal.organization_id(),
            withdrawal.org_user_id(),
            withdrawal.consent_type(),
        )
        .await
        .or_internal()?;
    let Some(latest) = latest else {
        return Err(AppError::NotFound(message!(
            "identity-no-consent-record-found",
            "no consent record found"
        )));
    };
    if latest.decision() == ConsentDecision::Withdrawn {
        return Err(AppError::Conflict(message!(
            "organization-consent-already-withdrawn",
            "consent already withdrawn"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::privacy::consent::ConsentType;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::org_user::OrgUser;
    use ianua_domain::types::Label;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        FakeOrgConsentStore, org_user_store_with, stored_caller, stored_org_consent, test_org_user,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_org_caller};

    struct Setup {
        uc: RevokeOrgConsentUseCase,
        consents: Arc<FakeOrgConsentStore>,
        audit: Arc<FakeEventDispatcher>,
    }

    /// `members` as stored, `consents` given before, and the caller acting
    /// as `actors` says.
    fn seeded(
        actors: FakeOrgActors,
        members: Vec<OrgUser>,
        consents: FakeOrgConsentStore,
    ) -> Setup {
        let consents = Arc::new(consents);
        Setup {
            uc: RevokeOrgConsentUseCase::new(RevokeOrgConsentPorts {
                org_actors: Arc::new(actors),
                org_users: Arc::new(org_user_store_with(members)),
                consents: consents.clone(),
            }),
            consents,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn withdraw(setup: &Setup, whose: OrgWhose) -> Result<(), AppError> {
        let terms = ConsentTerms {
            consent_type: ConsentType::Marketing,
            version: Label::new("version", "v1").unwrap(),
        };
        block_on(setup.uc.execute(
            &test_org_caller(),
            &test_auditor(setup.audit.clone()),
            RevokeOrgConsentRequest { whose, terms },
        ))
    }

    fn sam_in_acme() -> OrgUser {
        test_org_user(
            test_org_caller().organization_id(),
            "sam@acme.test",
            OrgRole::Member,
        )
    }

    fn agreed(member: &OrgUser) -> FakeOrgConsentStore {
        FakeOrgConsentStore::holding([stored_org_consent(
            member,
            ConsentType::Marketing,
            ConsentDecision::Granted,
        )])
    }

    /// Sam withdraws the marketing consent he gave. A withdrawal is kept
    /// beside it and recorded.
    #[test]
    fn a_member_withdraws_their_own_consent() {
        let sam = stored_caller(OrgRole::Member, "pw");
        let consents = agreed(&sam);
        let setup = seeded(FakeOrgActors::in_role(OrgRole::Member), vec![sam], consents);

        withdraw(&setup, OrgWhose::Own).unwrap();

        assert_eq!(setup.consents.count(), 2);
        assert_eq!(
            *setup.audit.records.lock().unwrap(),
            ["organization.org_user_consent_revoked"]
        );
    }

    /// Sam phones in, and Ada, an admin, withdraws his consent for him. The
    /// withdrawal is kept.
    #[test]
    fn an_admin_withdraws_for_a_member() {
        let sam = sam_in_acme();
        let (sam_id, consents) = (*sam.id(), agreed(&sam));
        let setup = seeded(FakeOrgActors::in_role(OrgRole::Admin), vec![sam], consents);

        withdraw(&setup, OrgWhose::Member(sam_id)).unwrap();

        assert_eq!(setup.consents.count(), 2);
    }

    /// Sam never agreed to marketing. There is nothing to withdraw.
    #[test]
    fn consent_never_given_is_not_found() {
        let sam = stored_caller(OrgRole::Member, "pw");
        let setup = seeded(
            FakeOrgActors::in_role(OrgRole::Member),
            vec![sam],
            FakeOrgConsentStore::empty(),
        );

        let result = withdraw(&setup, OrgWhose::Own);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(setup.audit.records.lock().unwrap().is_empty());
    }

    /// A viewer cannot withdraw another member's consent; the existing
    /// consent remains the only record.
    #[test]
    fn a_viewer_withdrawing_for_another_is_refused() {
        let sam = sam_in_acme();
        let (sam_id, consents) = (*sam.id(), agreed(&sam));
        let setup = seeded(FakeOrgActors::in_role(OrgRole::Viewer), vec![sam], consents);

        let result = withdraw(&setup, OrgWhose::Member(sam_id));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(setup.consents.count(), 1);
    }

    /// A viewer receives the same forbidden response for an unknown member
    /// as for an existing member.
    #[test]
    fn a_viewer_naming_an_unknown_member_is_refused_the_same() {
        let setup = seeded(
            FakeOrgActors::in_role(OrgRole::Viewer),
            Vec::new(),
            FakeOrgConsentStore::empty(),
        );

        let result = withdraw(&setup, OrgWhose::Member(OrgUserId::new()));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot withdraw consent.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let setup = seeded(
            FakeOrgActors::refusing(Refusal::SignedOut),
            Vec::new(),
            FakeOrgConsentStore::empty(),
        );

        let result = withdraw(&setup, OrgWhose::Own);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
