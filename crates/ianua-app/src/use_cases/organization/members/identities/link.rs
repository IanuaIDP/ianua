//! A person linking their own accounts across the tenants of one
//! organization, so they can switch between them without signing in again.
//!
//! A link lets someone signed in to one account become another. So the
//! person proves both ends with their own sign-in: the account joining the
//! group, and, when the group exists already, one of its accounts. Nobody
//! links accounts on someone else's behalf.

use std::sync::Arc;

use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::linked_identity::{
    LinkedIdentity, ProvenAccount,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::RaisesComplete as _;
use ianua_domain::types::ActorRef;

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal, OrNotFound};
use crate::ports::organization::{LinkedIdentityStore, OrganizationStore};
use crate::ports::tenant::TenantStore;
use crate::use_case::Command;
use crate::use_cases::organization::lookup::{existing_organization, tenant_label};

/// The person linking, signed in to each end.
pub struct LinkingPerson {
    /// Their session in the account joining a group.
    pub joining: CallerContext,
    /// Their session in an account already in the group, or none to start
    /// a new group with the joining account.
    pub already_linked: Option<CallerContext>,
}

/// The ports [`LinkIdentityUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct LinkIdentityPorts {
    /// Who is signed in to a tenant session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// Organizations, whose tenants a group may span.
    pub organizations: Arc<dyn OrganizationStore>,
    /// The linked identities.
    pub identities: Arc<dyn LinkedIdentityStore>,
    /// Tenants, for the name the audit record gives.
    pub tenants: Arc<dyn TenantStore>,
}

/// Links the caller's account into a group of their accounts.
pub struct LinkIdentityUseCase {
    ports: LinkIdentityPorts,
}

/// An account the person proved with their own sign-in, and the account as
/// it stands.
struct Proven {
    account: ProvenAccount,
    user: User<ResolvedTenant>,
}

impl LinkIdentityUseCase {
    /// A use case writing through `ports`.
    #[must_use]
    pub fn new(ports: LinkIdentityPorts) -> Self {
        Self { ports }
    }

    /// The account `session` is signed in to, proven by that sign-in.
    async fn proven(&self, session: &CallerContext) -> Result<Proven, AppError> {
        let person = self.ports.tenant_authorities.signed_in(session).await?;
        let account = ProvenAccount::of(session.tenant_id(), &person.account, &person.signed_in)
            .map_err(AppError::from_domain)?;
        Ok(Proven {
            account,
            user: person.account,
        })
    }

    /// The group `joining` joins: a new one, or the one the person's other
    /// sign-in shows they are in.
    async fn group_joined(
        &self,
        organization: &Organization,
        joining: ProvenAccount,
        already_linked: Option<&CallerContext>,
    ) -> Result<LinkedIdentity, AppError> {
        let tenants = self.ports.tenants.as_ref();
        let tenant_label = tenant_label(tenants, joining.tenant_id()).await;
        let Some(session) = already_linked else {
            return LinkedIdentity::create(organization, joining, tenant_label)
                .map_err(AppError::from_domain);
        };
        let by = self.proven(session).await?;
        let mut group = self
            .ports
            .identities
            .find_by_email(organization.id(), by.user.email())
            .await
            .or_internal()?
            .or_not_found(message!(
                "organization-the-account-signed-in-to-is-2",
                "the account signed in to is in no group"
            ))?;
        group
            .add_link(organization, &by.account, joining, tenant_label)
            .map_err(AppError::from_domain)?;
        Ok(group)
    }
}

impl Command for LinkIdentityUseCase {
    type Caller = LinkingPerson;
    type Input = ();
    type Output = Result<(), AppError>;

    /// Links the account `person.joining` is signed in to into the group of
    /// the account `person.already_linked` is signed in to, or starts a new
    /// group with it, and records `organization.identity_linked`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid/nontenant session; `Forbidden` for a foreign tenant, account outside the existing group or joining address mismatch.
    /// - `AppError::Domain` for an unverified joining address; `Conflict` for duplicate tenant/account membership or another group's address.
    /// - `AppError::NotFound` for a missing organization or an already linked account without a group; `Internal` on persistence or audit failure.
    async fn execute(
        &self,
        person: &LinkingPerson,
        auditor: &RequestAuditor,
        (): (),
    ) -> Result<(), AppError> {
        let joining = self.proven(&person.joining).await?;
        let organization = existing_organization(
            self.ports.organizations.as_ref(),
            &person.joining.organization_id(),
        )
        .await?;
        let mut group = self
            .group_joined(
                &organization,
                joining.account,
                person.already_linked.as_ref(),
            )
            .await?;
        self.ports
            .identities
            .save(&group)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&ActorRef::User(*joining.user.id()), group.take_events())
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::billing::plan::OrganizationPlan;
    use ianua_domain::types::{ActedBy, OrganizationId, TenantId, UserId};

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::organization::{FakeLinkedIdentityStore, org_store_with, test_org_on};
    use crate::test_support::tenant::{FakeTenantStore, test_tenant_in};
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx_with};

    struct Setup {
        uc: LinkIdentityUseCase,
        identities: Arc<FakeLinkedIdentityStore>,
        audit: Arc<FakeEventDispatcher>,
        org_id: OrganizationId,
        staging: TenantId,
        production: TenantId,
    }

    /// Acme on Business, owning staging and production, and a tenant of
    /// another organization.
    fn setup_with(authorities: FakeTenantAuthorities) -> Setup {
        let org_id = OrganizationId::new();
        let staging = test_tenant_in(org_id, "staging", "staging.test");
        let production = test_tenant_in(org_id, "production", "production.test");
        let (staging_id, production_id) = (*staging.id(), *production.id());
        let mut acme = test_org_on(org_id, "acme", OrganizationPlan::Business);
        acme.add_tenant(&staging, ActedBy::Platform).unwrap();
        acme.add_tenant(&production, ActedBy::Platform).unwrap();
        let identities = Arc::new(FakeLinkedIdentityStore::empty());
        Setup {
            uc: LinkIdentityUseCase::new(LinkIdentityPorts {
                tenant_authorities: Arc::new(authorities),
                organizations: org_store_with([acme]),
                identities: identities.clone(),
                tenants: Arc::new(FakeTenantStore::holding_all([staging, production])),
            }),
            identities,
            audit: Arc::new(FakeEventDispatcher::new()),
            org_id,
            staging: staging_id,
            production: production_id,
        }
    }

    fn setup() -> Setup {
        setup_with(FakeTenantAuthorities::holding_everything())
    }

    fn signed_in_to(s: &Setup, tenant: TenantId) -> CallerContext {
        test_ctx_with(s.org_id, tenant, UserId::new())
    }

    fn link(s: &Setup, person: &LinkingPerson) -> Result<(), AppError> {
        block_on(s.uc.execute(person, &test_auditor(s.audit.clone()), ()))
    }

    fn start_group(s: &Setup) -> CallerContext {
        let staging = signed_in_to(s, s.staging);
        link(
            s,
            &LinkingPerson {
                joining: staging.clone(),
                already_linked: None,
            },
        )
        .unwrap();
        staging
    }

    fn group(s: &Setup, email: &str) -> Option<LinkedIdentity> {
        block_on(
            s.identities
                .find_by_email(&s.org_id, &ianua_domain::types::Email::new(email).unwrap()),
        )
        .unwrap()
    }

    /// Ann, signed in to her staging account, starts a group with it. The
    /// group holds that one account and the link is recorded.
    #[test]
    fn a_person_starts_a_group_with_the_account_they_are_signed_in_to() {
        let s = setup();

        start_group(&s);

        let group = group(&s, "caller@example.test").unwrap();
        assert_eq!(group.tenant_count(), 1);
        assert!(group.is_linked_to(&s.staging));
        assert_eq!(
            *s.audit.records.lock().unwrap(),
            ["organization.identity_linked"]
        );
    }

    /// Ann, signed in to both her staging and her production accounts,
    /// links production into the group staging is in.
    #[test]
    fn a_person_signed_in_to_both_ends_links_a_second_account() {
        let s = setup();
        let staging = start_group(&s);

        link(
            &s,
            &LinkingPerson {
                joining: signed_in_to(&s, s.production),
                already_linked: Some(staging),
            },
        )
        .unwrap();

        let group = group(&s, "caller@example.test").unwrap();
        assert!(group.is_linked_to(&s.production));
        assert_eq!(group.tenant_count(), 2);
    }

    /// A staging account outside the existing group cannot authorize a
    /// production link; the group keeps only its original account.
    #[test]
    fn an_account_outside_the_group_is_refused_as_the_other_end() {
        let s = setup();
        start_group(&s);

        let result = link(
            &s,
            &LinkingPerson {
                joining: signed_in_to(&s, s.production),
                already_linked: Some(signed_in_to(&s, s.staging)),
            },
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(group(&s, "caller@example.test").unwrap().tenant_count(), 1);
    }

    /// Adding a second account from an already linked tenant conflicts.
    #[test]
    fn linking_a_tenant_twice_is_a_conflict() {
        let s = setup();
        let staging = start_group(&s);

        let result = link(
            &s,
            &LinkingPerson {
                joining: signed_in_to(&s, s.staging),
                already_linked: Some(staging),
            },
        );

        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    /// An account from a tenant Acme does not own cannot start a linked
    /// group in Acme; no group is stored.
    #[test]
    fn a_tenant_outside_the_organization_is_refused() {
        let s = setup();

        let result = link(
            &s,
            &LinkingPerson {
                joining: signed_in_to(&s, TenantId::new()),
                already_linked: None,
            },
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(group(&s, "caller@example.test").is_none());
    }

    /// A signed-out caller cannot start a linked group, leaving none stored.
    #[test]
    fn a_signed_out_person_is_refused() {
        let s = setup_with(FakeTenantAuthorities::refusing(Refusal::SignedOut));

        let result = link(
            &s,
            &LinkingPerson {
                joining: signed_in_to(&s, s.staging),
                already_linked: None,
            },
        );

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(group(&s, "caller@example.test").is_none());
    }
}
