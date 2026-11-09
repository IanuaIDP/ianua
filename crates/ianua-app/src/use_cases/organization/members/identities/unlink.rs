//! Taking one account out of a group of linked accounts: by the person,
//! signed in to an account of the group, or by a member who may update
//! members. A group left with no account goes.

use std::sync::Arc;

use ianua_domain::domains::organization::members::linked_identity::{
    LinkRemoval, LinkedIdentity, ProvenAccount,
};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::{ActedBy, ActorRef, Email, OrganizationId, TenantId};

use crate::acting::{OrgActors, TenantAuthorities};
use crate::auditor::RequestAuditor;
use crate::context::{CallerContext, OrgCaller};
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::organization::LinkedIdentityStore;
use crate::ports::tenant::TenantStore;
use crate::use_case::Command;
use crate::use_cases::organization::lookup::tenant_label;

/// Who takes an account out of a group.
pub enum Unlinker {
    /// The person, signed in to one of the group's accounts.
    Holder(CallerContext),
    /// A member of the organization who may update members.
    Member(OrgCaller),
}

/// Which group loses which tenant's account.
pub struct UnlinkIdentityRequest {
    /// The address the group shares.
    pub email: Email,
    /// The tenant whose account leaves the group.
    pub tenant_id: TenantId,
}

/// The ports [`UnlinkIdentityUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct UnlinkIdentityPorts {
    /// Who is signed in to a tenant session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Who acts on an organization.
    pub org_actors: Arc<dyn OrgActors>,
    /// The linked identities.
    pub identities: Arc<dyn LinkedIdentityStore>,
    /// Tenants, for the name the audit record gives.
    pub tenants: Arc<dyn TenantStore>,
}

/// Takes an account out of a group of linked accounts.
pub struct UnlinkIdentityUseCase {
    ports: UnlinkIdentityPorts,
}

impl UnlinkIdentityUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: UnlinkIdentityPorts) -> Self {
        Self { ports }
    }

    /// The group under `email` in `organization_id`.
    async fn group(
        &self,
        organization_id: &OrganizationId,
        email: &Email,
    ) -> Result<LinkedIdentity, AppError> {
        self.ports
            .identities
            .find_by_email(organization_id, email)
            .await
            .or_internal()?
            .or_not_found(message!(
                "organization-no-linked-identity-found",
                "no linked identity found"
            ))
    }

    /// The group with the link taken out by the person signed in to
    /// `session`, and who they are for the audit record.
    async fn unlinked_by_holder(
        &self,
        session: &CallerContext,
        request: &UnlinkIdentityRequest,
    ) -> Result<(LinkedIdentity, ActorRef), AppError> {
        let person = self.ports.tenant_authorities.signed_in(session).await?;
        let account = ProvenAccount::of(session.tenant_id(), &person.account, &person.signed_in)
            .map_err(AppError::from_domain)?;
        let mut group = self
            .group(&session.organization_id(), &request.email)
            .await?;
        let label = tenant_label(self.ports.tenants.as_ref(), &request.tenant_id).await;
        ensure_removed(group.remove_link(
            &request.tenant_id,
            LinkRemoval::Holder(&account),
            label,
        ))?;
        Ok((group, ActorRef::User(*person.account.id())))
    }

    /// The group with the link taken out by the member `caller`, and who
    /// they are for the audit record.
    async fn unlinked_by_member(
        &self,
        caller: &OrgCaller,
        request: &UnlinkIdentityRequest,
    ) -> Result<(LinkedIdentity, ActorRef), AppError> {
        let (organization, actor) = self.ports.org_actors.actor(caller).await?;
        let control = actor.control()?;
        let mut group = self.group(organization.id(), &request.email).await?;
        let by = LinkRemoval::Organization(ActedBy::By(control));
        let label = tenant_label(self.ports.tenants.as_ref(), &request.tenant_id).await;
        ensure_removed(group.remove_link(&request.tenant_id, by, label))?;
        Ok((group, ActorRef::OrgUser(*caller.member())))
    }

    /// Saves `group`, or deletes it once it holds no account.
    async fn keep_or_delete(&self, group: &LinkedIdentity) -> Result<(), AppError> {
        let identities = self.ports.identities.as_ref();
        if group.tenant_count() == 0 {
            return identities
                .delete(group.organization_id(), group.email())
                .await
                .or_internal();
        }
        identities.save(group).await.or_internal()
    }
}

impl Command for UnlinkIdentityUseCase {
    type Caller = Unlinker;
    type Input = UnlinkIdentityRequest;
    type Output = Result<(), AppError>;

    /// Takes the account in `request.tenant_id` out of the group under
    /// `request.email`, deletes the group once it is empty, and records
    /// `organization.identity_unlinked`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when a person is signed in to no account of
    ///   the group, or a member may not update members.
    /// - `AppError::Domain` when the person's address is not verified.
    /// - `AppError::NotFound` when there is no such group, or the tenant is
    ///   not linked in it.
    /// - `AppError::Internal` on persistence or audit failure.
    async fn execute(
        &self,
        unlinker: &Unlinker,
        auditor: &RequestAuditor,
        request: UnlinkIdentityRequest,
    ) -> Result<(), AppError> {
        let (mut group, actor) = match unlinker {
            Unlinker::Holder(session) => self.unlinked_by_holder(session, &request).await?,
            Unlinker::Member(caller) => self.unlinked_by_member(caller, &request).await?,
        };
        self.keep_or_delete(&group).await?;
        auditor
            .dispatch_by(&actor, group.take_events())
            .await
            .or_internal()
    }
}

/// Refuses a removal that found no link to take out.
///
/// # Errors
///
/// - `AppError::NotFound` when the tenant was not linked in the group.
/// - The error the domain refused the removal with.
fn ensure_removed(removed: Result<bool, DomainError>) -> Result<(), AppError> {
    match removed.map_err(AppError::from_domain)? {
        true => Ok(()),
        false => Err(AppError::NotFound(message!(
            "organization-email-not-linked-to-this-tenant",
            "email not linked to this tenant"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::tenant::lifecycle::Tenant;
    use ianua_domain::types::{EventLabel, UserId};

    use super::*;
    use crate::test_support::acting::{FakeOrgActors, FakeTenantAuthorities, Refusal};
    use crate::test_support::organization::{FakeLinkedIdentityStore, test_org_on};
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_in};
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx_with, test_org_caller,
    };

    const ADDRESS: &str = "caller@example.test";

    struct Setup {
        uc: UnlinkIdentityUseCase,
        identities: Arc<FakeLinkedIdentityStore>,
        audit: Arc<FakeEventDispatcher>,
        staging: CallerContext,
        production: TenantId,
    }

    /// Acme on Business with staging and production, and Ann's group
    /// linking her accounts in both. `org_actors` answers for members.
    fn setup_with(org_actors: FakeOrgActors) -> Setup {
        let org_id = test_org_caller().organization_id();
        let staging = test_tenant_in(org_id, "staging", "staging.test");
        let production = test_tenant_in(org_id, "production", "production.test");
        let staging_ctx = test_ctx_with(org_id, *staging.id(), UserId::new());
        let production_ctx = test_ctx_with(org_id, *production.id(), UserId::new());
        let acme = acme_with(org_id, [&staging, &production]);
        let group = group_of(&acme, &staging_ctx, &production_ctx);
        let production_id = *production.id();
        let identities = Arc::new(FakeLinkedIdentityStore::holding([group]));
        Setup {
            uc: UnlinkIdentityUseCase::new(UnlinkIdentityPorts {
                tenant_authorities: Arc::new(FakeTenantAuthorities::holding_everything()),
                org_actors: Arc::new(org_actors),
                identities: identities.clone(),
                tenants: Arc::new(FakeTenantStore::holding_all([staging, production])),
            }),
            identities,
            audit: Arc::new(FakeEventDispatcher::new()),
            staging: staging_ctx,
            production: production_id,
        }
    }

    fn acme_with<'a>(
        org_id: OrganizationId,
        tenants: impl IntoIterator<Item = &'a Tenant>,
    ) -> Organization {
        let mut acme = test_org_on(org_id, "acme", OrganizationPlan::Business);
        for tenant in tenants {
            acme.add_tenant(tenant, ActedBy::Platform).unwrap();
        }
        acme
    }

    /// Ann's group, with both accounts proven by her sign-ins.
    fn group_of(
        acme: &Organization,
        first: &CallerContext,
        second: &CallerContext,
    ) -> LinkedIdentity {
        let authorities = FakeTenantAuthorities::holding_everything();
        let proven = |session: &CallerContext| {
            let person = block_on(authorities.signed_in(session)).unwrap();
            ProvenAccount::of(session.tenant_id(), &person.account, &person.signed_in).unwrap()
        };
        let staging = proven(first);
        let mut group =
            LinkedIdentity::create(acme, staging.clone(), EventLabel::of("Staging")).unwrap();
        group
            .add_link(acme, &staging, proven(second), EventLabel::of("Production"))
            .unwrap();
        group
    }

    fn unlink(s: &Setup, unlinker: &Unlinker, tenant_id: TenantId) -> Result<(), AppError> {
        block_on(s.uc.execute(
            unlinker,
            &test_auditor(s.audit.clone()),
            UnlinkIdentityRequest {
                email: Email::new(ADDRESS).unwrap(),
                tenant_id,
            },
        ))
    }

    fn stored(s: &Setup) -> Option<LinkedIdentity> {
        block_on(s.identities.find_by_email(
            &test_org_caller().organization_id(),
            &Email::new(ADDRESS).unwrap(),
        ))
        .unwrap()
    }

    /// Ann, signed in to staging, takes her production account out of her
    /// group. Staging stays linked and the change is recorded.
    #[test]
    fn the_holder_takes_an_account_out_of_their_group() {
        let s = setup_with(FakeOrgActors::in_role(OrgRole::Owner));

        unlink(&s, &Unlinker::Holder(s.staging.clone()), s.production).unwrap();

        let group = stored(&s).unwrap();
        assert!(!group.is_linked_to(&s.production));
        assert_eq!(group.tenant_count(), 1);
        assert_eq!(
            *s.audit.records.lock().unwrap(),
            ["organization.identity_unlinked"]
        );
    }

    /// Olivia, an owner, takes both of Ann's accounts out. The group,
    /// left empty, goes.
    #[test]
    fn an_owner_empties_a_group_and_it_goes() {
        let s = setup_with(FakeOrgActors::in_role(OrgRole::Owner));
        let owner = || Unlinker::Member(test_org_caller());

        unlink(&s, &owner(), s.production).unwrap();
        unlink(&s, &owner(), s.staging.tenant_id()).unwrap();

        assert!(stored(&s).is_none());
    }

    /// A tenant the group does not link is not found.
    #[test]
    fn a_tenant_not_in_the_group_is_not_found() {
        let s = setup_with(FakeOrgActors::in_role(OrgRole::Owner));

        let result = unlink(&s, &Unlinker::Member(test_org_caller()), TenantId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// A different account in the same tenant cannot unlink Ann's production
    /// account; both original links remain.
    #[test]
    fn a_person_outside_the_group_is_refused() {
        let s = setup_with(FakeOrgActors::in_role(OrgRole::Owner));
        let mallory = test_ctx_with(
            test_org_caller().organization_id(),
            s.staging.tenant_id(),
            UserId::new(),
        );

        let result = unlink(&s, &Unlinker::Holder(mallory), s.production);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(stored(&s).unwrap().tenant_count(), 2);
    }

    /// A plain member cannot unlink Ann's account, leaving both links in place.
    #[test]
    fn a_member_without_the_update_right_is_refused() {
        let s = setup_with(FakeOrgActors::in_role(OrgRole::Member));

        let result = unlink(&s, &Unlinker::Member(test_org_caller()), s.production);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(stored(&s).unwrap().tenant_count(), 2);
    }

    /// A signed-out organization member must authenticate before unlinking an account.
    #[test]
    fn a_signed_out_member_is_refused() {
        let s = setup_with(FakeOrgActors::refusing(Refusal::SignedOut));

        let result = unlink(&s, &Unlinker::Member(test_org_caller()), s.production);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }

    /// Refused organization authority prevents unlinking Ann's account.
    #[test]
    fn a_member_the_organization_turns_away_is_refused() {
        let s = setup_with(FakeOrgActors::refusing(Refusal::Forbidden));

        let result = unlink(&s, &Unlinker::Member(test_org_caller()), s.production);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
