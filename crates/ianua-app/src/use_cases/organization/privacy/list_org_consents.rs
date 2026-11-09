//! Reading a member's consent history: every consent they gave and
//! withdrew, newest first. A member reads their own; reading another's
//! needs the right to view members, and only an owner reads an owner's.

use std::sync::Arc;

use ianua_domain::domains::identity::account::control::AccountAction;
use ianua_domain::domains::organization::members::account_control::OrgAccountControl;
use ianua_domain::domains::organization::members::control::OrgControl;
use ianua_domain::domains::organization::members::permission::{MemberAction, OrgPermission};
use ianua_domain::domains::organization::members::privacy::consent::OrgConsentRecord;
use ianua_domain::types::{OrgUserId, OrganizationId};

use crate::acting::OrgActors;
use crate::context::OrgCaller;
use crate::error::{AppError, OrInternal};
use crate::ports::organization::{OrgConsentStore, OrgUserStore};
use crate::use_case::Query;
use crate::use_cases::organization::lookup::existing_member;
use crate::use_cases::organization::privacy::whose::OrgWhose;

/// The ports [`ListOrgConsentsUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ListOrgConsentsPorts {
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// The organization's members.
    pub org_users: Arc<dyn OrgUserStore>,
    /// Members' consent records.
    pub consents: Arc<dyn OrgConsentStore>,
}

/// Lists a member's consent records.
pub struct ListOrgConsentsUseCase {
    ports: ListOrgConsentsPorts,
}

impl ListOrgConsentsUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: ListOrgConsentsPorts) -> Self {
        Self { ports }
    }

    /// Refuses reading another member's history unless the caller may read
    /// what is kept about that member, and an unknown member as not found.
    ///
    /// The right to view members is checked before anyone is looked up, so
    /// a caller without it learns nothing of who exists. Then the member's
    /// own standing decides: only an owner reads an owner's history.
    async fn ensure_may_read(
        &self,
        control: &OrgControl<'_>,
        organization_id: &OrganizationId,
        member_id: &OrgUserId,
    ) -> Result<(), AppError> {
        if control.is_member(member_id) {
            return Ok(());
        }
        control
            .ensure_may(organization_id, OrgPermission::Members(MemberAction::View))
            .map_err(AppError::from_domain)?;
        let member =
            existing_member(self.ports.org_users.as_ref(), organization_id, member_id).await?;
        OrgAccountControl::new(*control, &member)
            .ensure_on(member.id(), AccountAction::Export)
            .map_err(AppError::from_domain)
    }
}

impl Query for ListOrgConsentsUseCase {
    type Caller = OrgCaller;
    type Input = OrgWhose;
    type Output = Result<Vec<OrgConsentRecord>, AppError>;

    /// Every consent decision of the member `whose` names, newest first.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller reads another member's
    ///   history without the right to view members.
    /// - `AppError::NotFound` when the organization has no such member.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        caller: &OrgCaller,
        whose: OrgWhose,
    ) -> Result<Vec<OrgConsentRecord>, AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let member_id = whose.member(caller.member());
        self.ensure_may_read(&control, organization.id(), &member_id)
            .await?;
        self.ports
            .consents
            .list_by_member(organization.id(), &member_id)
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::identity::privacy::consent::{ConsentDecision, ConsentType};
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::org_user::OrgUser;

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, Refusal};
    use crate::test_support::organization::{
        FakeOrgConsentStore, org_user_store_with, stored_caller, stored_org_consent, test_org_user,
    };
    use crate::test_support::{block_on, test_org_caller};

    /// Sam, his marketing consent given and then withdrawn, and the caller
    /// acting as `actors` says, reading whose history `whose` names.
    fn read(
        actors: FakeOrgActors,
        sam: OrgUser,
        whose: OrgWhose,
    ) -> Result<Vec<OrgConsentRecord>, AppError> {
        let consents = FakeOrgConsentStore::holding([
            stored_org_consent(&sam, ConsentType::Marketing, ConsentDecision::Granted),
            stored_org_consent(&sam, ConsentType::Marketing, ConsentDecision::Withdrawn),
        ]);
        let use_case = ListOrgConsentsUseCase::new(ListOrgConsentsPorts {
            org_actors: Arc::new(actors),
            org_users: Arc::new(org_user_store_with([sam])),
            consents: Arc::new(consents),
        });
        block_on(use_case.execute(&test_org_caller(), whose))
    }

    fn sam_in_acme() -> OrgUser {
        test_org_user(
            test_org_caller().organization_id(),
            "sam@acme.test",
            OrgRole::Member,
        )
    }

    /// Sam reads his own history. He sees the withdrawal first, then the
    /// consent it withdrew.
    #[test]
    fn a_member_reads_their_own_history_newest_first() {
        let records = read(
            FakeOrgActors::in_role(OrgRole::Member),
            stored_caller(OrgRole::Member, "pw"),
            OrgWhose::Own,
        )
        .unwrap();

        let decisions: Vec<_> = records.iter().map(OrgConsentRecord::decision).collect();
        assert_eq!(
            decisions,
            [ConsentDecision::Withdrawn, ConsentDecision::Granted]
        );
    }

    /// Olivia, an owner, reads Sam's history to answer his data request.
    #[test]
    fn an_owner_reads_a_members_history() {
        let sam = sam_in_acme();
        let sam_id = *sam.id();

        let records = read(
            FakeOrgActors::in_role(OrgRole::Owner),
            sam,
            OrgWhose::Member(sam_id),
        )
        .unwrap();

        assert_eq!(records.len(), 2);
    }

    /// A billing contact cannot read another member's consent history.
    #[test]
    fn a_billing_contact_reading_another_is_refused() {
        let sam = sam_in_acme();
        let sam_id = *sam.id();

        let result = read(
            FakeOrgActors::in_role(OrgRole::Billing),
            sam,
            OrgWhose::Member(sam_id),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An admin's permission to view members does not allow reading an
    /// owner's consent history.
    #[test]
    fn an_admin_reading_an_owners_history_is_refused() {
        let owen = test_org_user(
            test_org_caller().organization_id(),
            "owen@acme.test",
            OrgRole::Owner,
        );
        let owen_id = *owen.id();

        let result = read(
            FakeOrgActors::in_role(OrgRole::Admin),
            owen,
            OrgWhose::Member(owen_id),
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// Olivia names a member Acme does not have. It is not found.
    #[test]
    fn an_unknown_member_is_not_found() {
        let result = read(
            FakeOrgActors::in_role(OrgRole::Owner),
            sam_in_acme(),
            OrgWhose::Member(OrgUserId::new()),
        );

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A signed-out session cannot read consent history.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let result = read(
            FakeOrgActors::refusing(Refusal::SignedOut),
            sam_in_acme(),
            OrgWhose::Own,
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
