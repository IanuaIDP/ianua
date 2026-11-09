//! Linked identities, which link one person's accounts across the tenants of
//! an organization.
//!
//! When a user has accounts in several tenants of the same organization, a
//! `LinkedIdentity` connects them. The user can then switch tenants without
//! signing in again.
//!
//! Each linked identity belongs to one organization, has its own id and
//! shares one verified email. The user records stay fully apart in their own tenants. Linking
//! only lets a session in one tenant open a session in another.

mod checks;

use time::OffsetDateTime;

use crate::domains::authentication::mfa::owed::SecondFactor;
use crate::domains::authentication::risk_engine::step_up::StepUpPolicy;
use crate::domains::authentication::sessions::account_check::MaySignIn;
use crate::domains::authentication::sessions::sign_in_progress::SignedIn;
use crate::domains::identity::account::control::{SignedInPerson, ensure_holder};
use crate::domains::identity::account::user::User;
use crate::domains::organization::events::members::{IdentityLinked, IdentityUnlinked};
use crate::domains::organization::lifecycle::Organization;
use crate::domains::organization::members::control::{OrgControl, ensure_platform_or_may};
use crate::domains::organization::members::linked_identity::checks::{
    ensure_signed_in_to_source, ensure_target_admits, ensure_tenant_of,
};
use crate::domains::organization::members::permission::{MemberAction, OrgPermission};
use crate::domains::tenant::lifecycle::Tenant;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete};
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::distinct::first_repeat;
use crate::types::{
    ActedBy, Email, EventLabel, Fact, IpAddress, LinkedIdentityId, OrganizationId, TenantId, UserId,
};

/// One person's account in one tenant, shown to be theirs by their own
/// finished sign-in to it.
///
/// A link lets someone signed in to one account become another without
/// signing in again. So both ends must be the same person, not just the
/// same address. Mallory admins tenant A and runs its sign-in provider. She
/// makes an account there with Ann's verified address. Without this proof
/// she links it to Ann's account in tenant B and switches into it.
#[derive(Debug, Clone)]
pub struct ProvenAccount {
    tenant_id: TenantId,
    user_id: UserId,
    email: Email,
}

impl ProvenAccount {
    /// `user`'s account in `tenant_id`, proven by `signed_in`, the person's
    /// finished sign-in to that very account.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when someone else is signed in.
    /// - [`DomainError::Validation`] when the user's address is not
    ///   verified. An unproven address says nothing about who holds the
    ///   account.
    pub fn of<T: TenantScope>(
        tenant_id: TenantId,
        user: &User<T>,
        signed_in: &impl SignedInPerson<T>,
    ) -> Result<Self, DomainError> {
        ensure_holder(signed_in, user.id())?;
        if !user.email_verified() {
            return Err(DomainError::invalid(message!(
                "organization-only-an-account-with-a-verified",
                "only an account with a verified address can be linked"
            )));
        }
        Ok(Self {
            tenant_id,
            user_id: *user.id(),
            email: user.email().clone(),
        })
    }

    /// The tenant the account is in.
    #[must_use]
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

/// Who takes a link out of a group.
#[derive(Debug, Clone, Copy)]
pub enum LinkRemoval<'a> {
    /// The person, signed in to one of the group's accounts.
    Holder(&'a ProvenAccount),
    /// A member who may update members, or the platform, as when a tenant
    /// or an account is deleted.
    Organization(ActedBy<OrgControl<'a>>),
}

/// A tenant link as stored, for rebuilding it with
/// [`TenantLink::reconstitute`].
pub struct TenantLinkRow {
    /// The tenant this link points to.
    pub tenant_id: TenantId,
    /// The user's ID within that tenant.
    pub user_id: UserId,
    /// The user's verified address, which every link in a group shares.
    pub email: Email,
    /// When this link was created.
    pub linked_at: OffsetDateTime,
}

/// A link between a user and a specific tenant within the identity group.
#[derive(Debug, Clone)]
pub struct TenantLink {
    /// The tenant this link points to.
    tenant_id: TenantId,
    /// The user's ID within that tenant.
    user_id: UserId,
    /// The user's verified address.
    email: Email,
    /// When this link was created.
    linked_at: OffsetDateTime,
}

impl From<ProvenAccount> for TenantLink {
    /// A link to the proven account, made now. Built from the account and
    /// the person's sign-in to it, never from an id and an address typed in
    /// separately.
    fn from(account: ProvenAccount) -> Self {
        Self {
            tenant_id: account.tenant_id,
            user_id: account.user_id,
            email: account.email,
            linked_at: crate::shared::clock::now(),
        }
    }
}

impl TenantLink {
    /// Rebuilds a tenant link from storage.
    ///
    /// # Errors
    ///
    /// - Never fails. No part of the row can contradict another, and each part
    ///   was read through its own checked type.
    pub fn reconstitute(row: TenantLinkRow) -> Result<Self, DomainError> {
        Ok(Self {
            tenant_id: row.tenant_id,
            user_id: row.user_id,
            email: row.email,
            linked_at: row.linked_at,
        })
    }

    /// The linked account's verified address.
    #[must_use]
    pub fn email(&self) -> &Email {
        &self.email
    }

    /// The tenant this link points to.
    #[must_use]
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The user's ID within that tenant.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// When this link was created.
    #[must_use]
    pub fn linked_at(&self) -> OffsetDateTime {
        self.linked_at
    }
}

/// One end of a switch between linked accounts. It is the account as it
/// stands now in its tenant.
#[derive(Debug, Clone, Copy)]
pub struct LinkedMemberAccount<'a, T: TenantScope> {
    /// The tenant the account is in.
    pub tenant_id: TenantId,
    /// The account, freshly loaded.
    pub user: &'a User<T>,
}

/// A switch from the caller's account in one tenant to their linked account
/// in another.
#[derive(Debug, Clone, Copy)]
pub struct TenantSwitch<'a, S: TenantScope, T: TenantScope> {
    /// The organization the group belongs to, as it stands now.
    pub organization: &'a Organization,
    /// The account the caller is signed in to.
    pub from: LinkedMemberAccount<'a, S>,
    /// The account they would switch to.
    pub to: LinkedMemberAccount<'a, T>,
    /// The tenant the switch lands in, as it stands now. It decides, like
    /// for any sign-in, whether it lets anyone in at all.
    pub target_tenant: &'a Tenant,
    /// The target tenant's sign-in policy, whose baseline the carried
    /// sign-in must meet.
    pub target_policy: &'a StepUpPolicy,
    /// The caller's finished sign-in to the session they switch from. The
    /// target must accept its way in too, and the new session carries it.
    pub signed_in: &'a SignedIn<S>,
    /// What a sign-in to the target account would owe, from its own factors
    /// and the target's policy, as for any sign-in there.
    pub target_owes: SecondFactor,
    /// Where the caller is, for the target's address list.
    pub client_ip: Fact<&'a IpAddress>,
}

/// A group of linked user accounts across tenants within an organization.
///
/// Found by its own id, never by its address, so whoever starts a group
/// with an address first blocks nobody else's. Holds one link per tenant
/// where the user has an account.
///
/// Rules it keeps:
/// - At most one link per tenant. [`add_link`](Self::add_link) refuses a
///   second.
/// - Every link shares the group's email, taken from a verified account by
///   [`ProvenAccount::of`]. [`add_link`](Self::add_link) refuses another
///   address.
/// - Every link was made by the person signed in to that account, and a
///   new one also needs their sign-in to an account already in the group.
/// - Every tenant belongs to the same organization, as the organization's
///   own tenant list says.
#[derive(Debug)]
pub struct LinkedIdentity {
    /// The group's own id. A group is found by it, never by its address, so
    /// whoever starts a group with an address first blocks nobody else's.
    id: LinkedIdentityId,
    /// The organization these links belong to.
    organization_id: OrganizationId,
    /// The shared email across tenants.
    email: Email,
    /// Links to user accounts in individual tenants.
    links: Vec<TenantLink>,
    /// When this linked identity was first created.
    created_at: OffsetDateTime,
    raised: RaisedEvents,
}

/// A linked identity as stored, for rebuilding it with
/// [`LinkedIdentity::reconstitute`].
pub struct LinkedIdentityRow {
    /// The group's id.
    pub id: LinkedIdentityId,
    /// The ownership boundary within which the linked tenant accounts may be switched.
    pub organization_id: OrganizationId,
    /// The shared email.
    pub email: Email,
    /// The tenant links.
    pub links: Vec<TenantLink>,
    /// When created.
    pub created_at: OffsetDateTime,
}

impl LinkedIdentity {
    /// Creates a new linked identity in `organization` from its first
    /// account, whose address becomes the group's. Raises
    /// `organization.identity_linked`, naming the account's tenant as
    /// `tenant_label`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the account's tenant is not one of
    ///   the organization's.
    pub fn create(
        organization: &Organization,
        first: ProvenAccount,
        tenant_label: EventLabel,
    ) -> Result<Self, DomainError> {
        ensure_tenant_of(organization, first.tenant_id())?;
        let mut identity = Self {
            id: LinkedIdentityId::new(),
            organization_id: *organization.id(),
            email: first.email.clone(),
            links: Vec::new(),
            created_at: crate::shared::clock::now(),
            raised: RaisedEvents::default(),
        };
        identity.link(first, tenant_label);
        Ok(identity)
    }

    /// Links `account`, whose tenant `tenant_label` names, and raises it.
    fn link(&mut self, account: ProvenAccount, tenant_label: EventLabel) {
        self.raised.raise_organization(IdentityLinked {
            organization_id: self.organization_id,
            email: self.email.clone(),
            tenant_id: account.tenant_id,
            tenant_label,
            user_id: account.user_id,
            occurred_at: crate::shared::clock::now(),
        });
        self.links.push(TenantLink::from(account));
    }

    /// Rebuilds a linked identity from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row has no link, a link
    ///   under another address, or two links to one tenant or one account.
    pub fn reconstitute(row: LinkedIdentityRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            organization_id: row.organization_id,
            email: row.email,
            links: row.links,
            created_at: row.created_at,
            raised: RaisedEvents::default(),
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &LinkedIdentityRow) -> Result<(), DomainError> {
        RowCheck::of("linked identity")
            .holds(
                links_fit_the_group(row),
                "no link, a link under another address, or two links to one tenant or account",
            )
            .finish()
    }

    /// The organization these links belong to.
    #[must_use]
    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// The shared email.
    #[must_use]
    pub fn email(&self) -> &Email {
        &self.email
    }

    /// All tenant links.
    #[must_use]
    pub fn links(&self) -> &[TenantLink] {
        &self.links
    }

    /// Number of tenants this identity is linked to.
    #[must_use]
    pub fn tenant_count(&self) -> usize {
        self.links.len()
    }

    /// When this linked identity was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// The group's own id.
    #[must_use]
    pub fn id(&self) -> &LinkedIdentityId {
        &self.id
    }

    pub(crate) fn link_for_tenant(&self, tenant_id: &TenantId) -> Option<&TenantLink> {
        self.links.iter().find(|l| l.tenant_id() == tenant_id)
    }

    /// The sign-in a switch from `request.from` opens on the linked account
    /// in `request.to`'s tenant, carrying the caller's finished sign-in,
    /// checked against both accounts as they are now.
    ///
    /// The switch rests on the caller's own sign-in to the source account,
    /// never on an account id. Mallory holds no session of Ann's. Without
    /// the proof, she names Ann's source account and lands in Ann's linked
    /// one.
    ///
    /// A link records an account's address when it was made. Since then the
    /// account may have been given to someone else or lost its verified
    /// address. So both ends are read fresh.
    ///
    /// A switch is a sign-in. So the target tenant is asked, as any sign-in
    /// asks it, whether it is open, takes this way in and admits the
    /// caller's address, and the carried sign-in must meet its baseline.
    ///
    /// Without a carried second factor, the new session owes `request.target_owes`.
    /// For example, switching from password-only staging to production can require
    /// the production account's authenticator code.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Forbidden`] for incomplete or wrong-source sign-in,
    /// a different organization, a tenant outside it, accounts not matching their links
    /// or verified group address, or a target account that cannot sign in.
    /// The target admission must belong to the destination, allow sign-in, and
    /// accept the carried assurance or require further proof.
    pub fn switch_target<S: TenantScope, T: TenantScope>(
        &self,
        request: &TenantSwitch<'_, S, T>,
    ) -> Result<MaySignIn<T>, DomainError> {
        ensure_signed_in_to_source(request)?;
        self.ensure_both_ends(request)?;
        if !request.to.user.can_authenticate() {
            return Err(DomainError::forbidden(message!(
                "organization-the-linked-account-cannot-be-signed",
                "the linked account cannot be signed in to"
            )));
        }
        ensure_target_admits(request)?;
        let progress = request
            .signed_in
            .progress()
            .carried_owing(request.target_owes, request.target_policy)
            .map_err(|_| {
                DomainError::forbidden(message!(
                    "organization-the-sign-in-falls-short-of",
                    "the sign-in falls short of the target's baseline"
                ))
            })?;
        Ok(MaySignIn::active(*request.to.user.id(), progress))
    }

    /// Refuses a switch unless both tenants are the group organization's,
    /// and both accounts are the ones their links name, under the group's
    /// verified address.
    fn ensure_both_ends<S: TenantScope, T: TenantScope>(
        &self,
        request: &TenantSwitch<'_, S, T>,
    ) -> Result<(), DomainError> {
        self.ensure_organization(request.organization)?;
        ensure_tenant_of(request.organization, &request.from.tenant_id)?;
        ensure_tenant_of(request.organization, &request.to.tenant_id)?;
        self.ensure_holds(request.from.tenant_id, request.from.user)?;
        self.ensure_holds(request.to.tenant_id, request.to.user)
    }

    fn ensure_organization(&self, organization: &Organization) -> Result<(), DomainError> {
        if *organization.id() != self.organization_id {
            return Err(DomainError::forbidden(message!(
                "organization-the-linked-identity-belongs-to-another",
                "the linked identity belongs to another organization"
            )));
        }
        Ok(())
    }

    fn ensure_holds<T: TenantScope>(
        &self,
        tenant_id: TenantId,
        user: &User<T>,
    ) -> Result<(), DomainError> {
        let named = self
            .link_for_tenant(&tenant_id)
            .is_some_and(|link| link.user_id() == user.id());
        if !named || user.email() != &self.email || !user.email_verified() {
            return Err(DomainError::forbidden(message!(
                "organization-the-account-is-not-linked-under",
                "the account is not linked under its verified address"
            )));
        }
        Ok(())
    }

    /// Whether this identity has a link in the given tenant.
    #[must_use]
    pub fn is_linked_to(&self, tenant_id: &TenantId) -> bool {
        self.links.iter().any(|l| l.tenant_id() == tenant_id)
    }

    /// Every tenant ID this identity is linked to.
    #[must_use]
    pub fn tenant_ids(&self) -> Vec<&TenantId> {
        self.links.iter().map(TenantLink::tenant_id).collect()
    }

    /// Adds `account`, in a new tenant of the group's organization, for the
    /// person who proved `by`, an account already in the group. Raises
    /// `organization.identity_linked`, naming the account's tenant as
    /// `tenant_label`.
    ///
    /// The person proves both ends with their own sign-in. So nobody links
    /// an account into a group whose other accounts they cannot sign in to.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `organization` is not the group's,
    ///   or either tenant is not one of its.
    /// - [`DomainError::Forbidden`] when `by` is not an account of the group.
    /// - [`DomainError::Forbidden`] when the account's address is not the
    ///   group's. Linking it would let whoever holds this group's address
    ///   switch into someone else's account.
    /// - [`DomainError::Conflict`] when the tenant is already linked, or the
    ///   account is already in the group under another tenant.
    pub fn add_link(
        &mut self,
        organization: &Organization,
        by: &ProvenAccount,
        account: ProvenAccount,
        tenant_label: EventLabel,
    ) -> Result<(), DomainError> {
        self.ensure_organization(organization)?;
        ensure_tenant_of(organization, by.tenant_id())?;
        ensure_tenant_of(organization, account.tenant_id())?;
        self.ensure_member_account(by)?;
        if account.email != self.email {
            return Err(DomainError::forbidden(message!(
                "organization-an-account-can-only-be-linked",
                "an account can only be linked under its own verified address"
            )));
        }
        self.ensure_not_linked(&account)?;
        self.link(account, tenant_label);
        Ok(())
    }

    /// Refuses `account` when its tenant, or the account itself, is in the
    /// group already. One account linked under two tenants would take a
    /// tenant's one place with an account that does not live there.
    fn ensure_not_linked(&self, account: &ProvenAccount) -> Result<(), DomainError> {
        if self.is_linked_to(account.tenant_id()) {
            return Err(DomainError::conflict(message!(
                "organization-this-identity-is-already-linked-in",
                "this identity is already linked in that tenant"
            )));
        }
        if self
            .links
            .iter()
            .any(|link| link.user_id == account.user_id)
        {
            return Err(DomainError::conflict(message!(
                "organization-this-account-is-already-linked-in",
                "this account is already linked in the group"
            )));
        }
        Ok(())
    }

    /// Removes the link to `tenant_id`, whose tenant `tenant_label` names,
    /// as `by` decides. `false` when there was none. Raises
    /// `organization.identity_unlinked` when a link was removed.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is a holder whose account is
    ///   not in the group, or a member without the right to update members.
    pub fn remove_link(
        &mut self,
        tenant_id: &TenantId,
        by: LinkRemoval<'_>,
        tenant_label: EventLabel,
    ) -> Result<bool, DomainError> {
        match by {
            LinkRemoval::Holder(account) => self.ensure_member_account(account)?,
            LinkRemoval::Organization(acted) => ensure_platform_or_may(
                acted,
                &self.organization_id,
                OrgPermission::Members(MemberAction::Update),
            )?,
        }
        let before = self.links.len();
        self.links.retain(|l| l.tenant_id() != tenant_id);
        if self.links.len() == before {
            return Ok(false);
        }
        self.raised.raise_organization(IdentityUnlinked {
            organization_id: self.organization_id,
            email: self.email.clone(),
            tenant_id: *tenant_id,
            tenant_label,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(true)
    }

    /// Refuses `account` unless it is the account the group links in its
    /// tenant, under the group's address.
    fn ensure_member_account(&self, account: &ProvenAccount) -> Result<(), DomainError> {
        let linked = self
            .link_for_tenant(account.tenant_id())
            .is_some_and(|link| *link.user_id() == account.user_id);
        if !linked || account.email != self.email {
            return Err(DomainError::forbidden(message!(
                "organization-the-account-signed-in-to-is",
                "the account signed in to is not one of this group's"
            )));
        }
        Ok(())
    }
}

impl RaisesComplete for LinkedIdentity {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

/// Whether a stored group's links all carry the group's address, one per
/// tenant and one per account, and there is at least one.
fn links_fit_the_group(row: &LinkedIdentityRow) -> bool {
    !row.links.is_empty()
        && row.links.iter().all(|link| link.email == row.email)
        && first_repeat(row.links.iter().map(TenantLink::tenant_id)).is_none()
        && first_repeat(row.links.iter().map(TenantLink::user_id)).is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::methods::AuthMethod;
    use crate::domains::authentication::mfa::owed::SecondFactor;
    use crate::domains::authentication::sessions::sign_in_progress::{LocalMethod, SignInProgress};
    use crate::domains::identity::account::user::tests::signed_in_as;
    use crate::domains::identity::account::verified_email::proof_of;
    use crate::domains::organization::billing::plan::OrganizationPlan;
    use crate::domains::organization::lifecycle::CreateOrganizationParams;
    use crate::domains::organization::lifecycle::tests::{founding_of, tenant_with};
    use crate::domains::organization::members::control::tests::{acting, session_of};
    use crate::domains::organization::members::membership::OrgRole;
    use crate::domains::organization::members::org_user::{
        AddedBy, CreateOrgUserParams, OrgPassword, OrgUser,
    };
    use crate::domains::tenant::hosts::PlatformLabel;
    use crate::domains::tenant::lifecycle::ProvisionTenantParams;
    use crate::domains::tenant::provisioning::infrastructure::{DeploymentRegion, TenantResidency};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::config::{DisplayNameLimits, SlugLimits};
    use crate::shared::events::data::FieldValue;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::types::{DisplayName, Label, Locale, OrgUserId, TenantSlug, Timezone};

    fn account(address: &str, verified: bool) -> User<ResolvedTenant> {
        let mut user = User::register(
            UserId::new(),
            Email::new(address).unwrap(),
            DisplayName::new(
                "Alice",
                &crate::shared::config::DomainLimits::default().display_name,
            )
            .unwrap(),
            &crate::test_support::authority::user_adder(),
        )
        .unwrap();
        if verified {
            user.verify_email(&proof_of(user.email())).unwrap();
        }
        user
    }

    fn organization() -> Organization {
        Organization::create(CreateOrganizationParams {
            id: OrganizationId::new(),
            slug: TenantSlug::new("acme", &SlugLimits::default()).unwrap(),
            name: Label::new("org_name", "Acme").unwrap(),
            contact_email: Email::new("admin@acme.com").unwrap(),
            display_name: DisplayName::new("Acme", &DisplayNameLimits::default()).unwrap(),
            plan: OrganizationPlan::Business,
        })
        .unwrap()
        .0
    }

    /// How the records name a tenant linked or unlinked in a test.
    fn staging() -> EventLabel {
        EventLabel::of("Staging")
    }

    /// Alice starts a group and links a second account. Each link is
    /// raised, naming the tenant as the caller called it; unlinking the
    /// second is raised too.
    #[test]
    fn linking_and_unlinking_raise_their_records() {
        let mut group = group();
        let next = group.link("alice@acme.com");
        let tenant = *next.tenant_id();
        group.add(next).unwrap();

        group
            .identity
            .remove_link(
                &tenant,
                LinkRemoval::Organization(ActedBy::Platform),
                staging(),
            )
            .unwrap();

        let events = group.identity.take_events();
        let names: Vec<String> = events.iter().map(|e| e.event_type().to_string()).collect();
        assert_eq!(
            names,
            [
                "organization.identity_linked",
                "organization.identity_linked",
                "organization.identity_unlinked",
            ]
        );
        let payload = events[2].payload();
        let Some(FieldValue::Reference(named)) = payload.value("tenant") else {
            panic!("the tenant is not referenced");
        };
        assert_eq!(named.label(), "Staging");
    }

    /// Unlinking a tenant absent from Alice's group returns false without
    /// raising an event.
    #[test]
    fn unlinking_a_tenant_never_linked_raises_nothing() {
        let mut group = group();
        let _ = group.identity.take_events();

        let removed = group
            .identity
            .remove_link(
                &TenantId::new(),
                LinkRemoval::Organization(ActedBy::Platform),
                staging(),
            )
            .unwrap();

        assert!(!removed);
        assert!(group.identity.take_events().is_empty());
    }

    /// `user`'s account in `tenant`, proven by their own sign-in.
    fn proven(tenant: TenantId, user: &User<ResolvedTenant>) -> ProvenAccount {
        ProvenAccount::of(tenant, user, &signed_in_as::<ResolvedTenant>(*user.id())).unwrap()
    }

    /// A new tenant of `organization`, holding `address`'s verified account,
    /// proven by its holder's sign-in.
    fn proven_in(organization: &mut Organization, address: &str) -> ProvenAccount {
        let tenant = TenantId::new();
        organization
            .add_tenant(&tenant_with(tenant), ActedBy::Platform)
            .unwrap();
        proven(tenant, &account(address, true))
    }

    struct Group {
        organization: Organization,
        identity: LinkedIdentity,
        first: ProvenAccount,
    }

    impl Group {
        fn link(&mut self, address: &str) -> ProvenAccount {
            proven_in(&mut self.organization, address)
        }

        fn add(&mut self, account: ProvenAccount) -> Result<(), DomainError> {
            self.identity
                .add_link(&self.organization, &self.first, account, staging())
        }
    }

    fn group() -> Group {
        let mut organization = organization();
        let first = proven_in(&mut organization, "alice@acme.com");
        let identity = LinkedIdentity::create(&organization, first.clone(), staging()).unwrap();
        Group {
            organization,
            identity,
            first,
        }
    }

    /// Signing in to a new account with Alice's address cannot authorize
    /// adding it to her group; the group retains its single link.
    #[test]
    fn linking_needs_a_sign_in_to_an_account_already_in_the_group() {
        let mut group = group();
        let mallorys = group.link("alice@acme.com");

        let result =
            group
                .identity
                .add_link(&group.organization, &mallorys.clone(), mallorys, staging());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(group.identity.tenant_count(), 1);
    }

    /// Mallory's sign-in cannot prove ownership of Alice's account.
    #[test]
    fn an_account_is_proven_only_by_its_own_sign_in() {
        let alice = account("alice@acme.com", true);
        let mallory = account("mallory@acme.com", true);

        let result = ProvenAccount::of(
            TenantId::new(),
            &alice,
            &signed_in_as::<ResolvedTenant>(*mallory.id()),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Sam's member role cannot unlink Alice's second account, while the
    /// platform can remove that same link.
    #[test]
    fn only_the_holder_a_manager_or_the_platform_unlinks() {
        let mut group = group();
        let next = group.link("alice@acme.com");
        let tenant = *next.tenant_id();
        group.add(next).unwrap();
        let sam = plain_member(&group.organization);
        let session = session_of(&sam);

        let by_sam = group.identity.remove_link(
            &tenant,
            LinkRemoval::Organization(ActedBy::By(acting(&sam, &session))),
            staging(),
        );
        let by_platform = group.identity.remove_link(
            &tenant,
            LinkRemoval::Organization(ActedBy::Platform),
            staging(),
        );

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(by_platform.unwrap());
    }

    /// A plain member of `organization`, added by its founder.
    fn plain_member(organization: &Organization) -> OrgUser {
        let params = |role, email: &str| CreateOrgUserParams {
            id: OrgUserId::new(),
            organization_id: *organization.id(),
            email: Email::new(email).unwrap(),
            display_name: DisplayName::new("Sam", &DisplayNameLimits::default()).unwrap(),
            password_hash: OrgPassword::NotSet,
            role,
        };
        let founder = OrgUser::create(
            params(OrgRole::Owner, "founder@acme.com"),
            AddedBy::Founding(founding_of(*organization.id())),
        )
        .unwrap();
        let session = session_of(&founder);
        OrgUser::create(
            params(OrgRole::Member, "sam@acme.com"),
            AddedBy::Member(acting(&founder, &session)),
        )
        .unwrap()
    }

    /// Alice's first account is linked. The group holds that one link and
    /// takes `alice@acme.com` as its address.
    #[test]
    fn create_has_one_link_and_takes_its_address() {
        let id = group().identity;
        assert_eq!(id.tenant_count(), 1);
        assert_eq!(id.email().as_str(), "alice@acme.com");
    }

    /// Alice's account in a second tenant of Acme is linked. The group then
    /// holds two links, one of them to that tenant.
    #[test]
    fn add_link_to_new_tenant() {
        let mut group = group();
        let next = group.link("alice@acme.com");
        let tenant = *next.tenant_id();

        group.add(next).unwrap();

        assert_eq!(group.identity.tenant_count(), 2);
        assert!(group.identity.is_linked_to(&tenant));
    }

    /// A second account of Alice's in a tenant already linked is added. It is
    /// refused, so a switch into that tenant has one account to land on.
    #[test]
    fn add_link_to_existing_tenant_fails() {
        let mut group = group();
        let tenant = *group.identity.links()[0].tenant_id();
        let again = proven(tenant, &account("alice@acme.com", true));

        assert!(matches!(group.add(again), Err(DomainError::Conflict(_))));
        assert_eq!(group.identity.tenant_count(), 1);
    }

    /// Linking Alice's existing account under a second tenant is refused;
    /// her group retains its one original link.
    #[test]
    fn an_account_already_in_the_group_is_not_linked_again() {
        let mut organization = organization();
        let (here, there) = (TenantId::new(), TenantId::new());
        organization
            .add_tenant(&tenant_with(here), ActedBy::Platform)
            .unwrap();
        organization
            .add_tenant(&tenant_with(there), ActedBy::Platform)
            .unwrap();
        let alice = account("alice@acme.com", true);
        let first = proven(here, &alice);
        let mut identity = LinkedIdentity::create(&organization, first.clone(), staging()).unwrap();

        let result = identity.add_link(&organization, &first, proven(there, &alice), staging());

        assert!(matches!(result, Err(DomainError::Conflict(_))));
        assert_eq!(identity.tenant_count(), 1);
    }

    /// A stored group links one account under two tenants. Loading it is
    /// refused as a corrupt row.
    #[test]
    fn a_stored_group_linking_one_account_twice_is_refused() {
        let mut row = stored(&group().identity);
        let again = TenantLink {
            tenant_id: TenantId::new(),
            ..row.links[0].clone()
        };
        row.links.push(again);

        assert!(refused_as_corrupt(&LinkedIdentity::reconstitute(row)));
    }

    /// An account with a different address cannot join Alice's group, which
    /// retains its one original link.
    #[test]
    fn an_account_under_another_address_cannot_be_linked() {
        let mut group = group();
        let victim = group.link("victim@acme.com");

        let result = group.add(victim);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(group.identity.tenant_count(), 1);
    }

    /// A matching verified address cannot link an account from another
    /// organization's tenant into Alice's group.
    #[test]
    fn an_account_in_another_organizations_tenant_cannot_be_linked() {
        let mut group = group();
        let outside = proven_in(&mut organization(), "alice@acme.com");

        let result = group.add(outside);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Naming another organization cannot authorize adding its tenant's
    /// account to Acme's linked group.
    #[test]
    fn a_group_is_not_grown_through_another_organization() {
        let mut group = group();
        let mut other = organization();
        let outside = proven_in(&mut other, "alice@acme.com");

        let result = group
            .identity
            .add_link(&other, &group.first, outside, staging());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A group is started in Acme from an account in another organization's
    /// tenant. It is refused.
    #[test]
    fn a_group_does_not_start_in_another_organizations_tenant() {
        let outside = proven_in(&mut organization(), "alice@acme.com");

        let result = LinkedIdentity::create(&organization(), outside, staging());

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A signed-in account with an unverified address cannot produce the
    /// proof required for linking.
    #[test]
    fn an_account_with_an_unverified_address_cannot_be_linked() {
        let unverified = account("alice@acme.com", false);
        let signed_in = signed_in_as::<ResolvedTenant>(*unverified.id());

        assert!(ProvenAccount::of(TenantId::new(), &unverified, &signed_in).is_err());
    }

    /// Alice, signed in to her first account, unlinks her second tenant. The
    /// group no longer reaches it, and removing it again reports there was
    /// nothing to remove.
    #[test]
    fn remove_link_drops_only_that_tenant() {
        let mut group = group();
        let next = group.link("alice@acme.com");
        let tenant = *next.tenant_id();
        group.add(next).unwrap();
        let alice = group.first.clone();

        assert!(
            group
                .identity
                .remove_link(&tenant, LinkRemoval::Holder(&alice), staging())
                .unwrap()
        );
        assert!(!group.identity.is_linked_to(&tenant));
        assert!(
            !group
                .identity
                .remove_link(&tenant, LinkRemoval::Holder(&alice), staging())
                .unwrap()
        );
    }

    /// Alice is linked in a second tenant. Asking the group for that tenant
    /// gives her account there.
    #[test]
    fn link_for_tenant_returns_correct_user() {
        let mut group = group();
        let next = group.link("alice@acme.com");
        let (tenant, user) = (*next.tenant_id(), next.user_id);
        group.add(next).unwrap();

        assert_eq!(
            *group.identity.link_for_tenant(&tenant).unwrap().user_id(),
            user
        );
    }

    /// Asking the group for a tenant it has no link in gives nothing.
    #[test]
    fn link_for_unknown_tenant_returns_none() {
        assert!(group().identity.link_for_tenant(&TenantId::new()).is_none());
    }

    /// Alice is linked in two tenants. The group lists both.
    #[test]
    fn tenant_ids_lists_all() {
        let mut group = group();
        let next = group.link("alice@acme.com");
        group.add(next).unwrap();

        assert_eq!(group.identity.tenant_ids().len(), 2);
    }

    struct Linked {
        organization: Organization,
        identity: LinkedIdentity,
        source: (TenantId, User<ResolvedTenant>),
        target: (TenantId, User<ResolvedTenant>),
        target_tenant: Tenant,
    }

    /// An open workspace with `id`, taking password sign-ins from anywhere.
    fn workspace(id: TenantId) -> Tenant {
        let limits = crate::shared::config::DomainLimits::default();
        let mut tenant = Tenant::provision(
            ProvisionTenantParams {
                id,
                platform_label: PlatformLabel::new("k7f3q9").unwrap(),
                organization_id: OrganizationId::new(),
                slug: TenantSlug::new("acme", &limits.slug).unwrap(),
                display_name: DisplayName::new("Acme", &limits.display_name).unwrap(),
                contact_email: Email::new("admin@acme.com").unwrap(),
                timezone: Timezone::new("UTC").unwrap(),
                locale: Locale::new("en-US").unwrap(),
                residency: TenantResidency::shared_on_platform(DeploymentRegion::EuCentral1),
            },
            &crate::domains::tenant::compliance_limits::ComplianceLimits::default(),
            ActedBy::Platform,
        )
        .unwrap();
        tenant.activate(ActedBy::Platform).unwrap();
        tenant
    }

    fn linked_pair() -> Linked {
        let mut organization = organization();
        let source = (TenantId::new(), account("alice@acme.com", true));
        let target = (TenantId::new(), account("alice@acme.com", true));
        organization
            .add_tenant(&tenant_with(source.0), ActedBy::Platform)
            .unwrap();
        organization
            .add_tenant(&tenant_with(target.0), ActedBy::Platform)
            .unwrap();
        let first = proven(source.0, &source.1);
        let mut identity = LinkedIdentity::create(&organization, first.clone(), staging()).unwrap();
        identity
            .add_link(
                &organization,
                &first,
                proven(target.0, &target.1),
                staging(),
            )
            .unwrap();
        let target_tenant = workspace(target.0);
        Linked {
            organization,
            identity,
            source,
            target,
            target_tenant,
        }
    }

    /// The switch made on `signed_in`, into a target asking `policy` whose
    /// account owes nothing more.
    fn switch_on(
        linked: &Linked,
        signed_in: &SignedIn<ResolvedTenant>,
        policy: &StepUpPolicy,
    ) -> Result<MaySignIn<ResolvedTenant>, DomainError> {
        switch_owing(linked, signed_in, policy, SecondFactor::NotOwed)
    }

    /// The switch made on `signed_in`, into a target asking `policy`, whose
    /// account owes `owed` at a sign-in of its own.
    fn switch_owing(
        linked: &Linked,
        signed_in: &SignedIn<ResolvedTenant>,
        policy: &StepUpPolicy,
        owed: SecondFactor,
    ) -> Result<MaySignIn<ResolvedTenant>, DomainError> {
        linked.identity.switch_target(&TenantSwitch {
            organization: &linked.organization,
            from: LinkedMemberAccount {
                tenant_id: linked.source.0,
                user: &linked.source.1,
            },
            to: LinkedMemberAccount {
                tenant_id: linked.target.0,
                user: &linked.target.1,
            },
            target_tenant: &linked.target_tenant,
            target_policy: policy,
            signed_in,
            target_owes: owed,
            client_ip: Fact::Unknown,
        })
    }

    /// Switching from a password sign-in to an account owing its second
    /// factor leaves the target sign-in incomplete with verification owed.
    #[test]
    fn a_switch_asks_for_the_target_accounts_own_factor() {
        let linked = linked_pair();
        let holder = signed_in_as(*linked.source.1.id());

        let landed = switch_owing(
            &linked,
            &holder,
            &StepUpPolicy::relaxed(),
            SecondFactor::Verify,
        )
        .unwrap();

        assert_eq!(landed.progress().owed(), SecondFactor::Verify);
        assert!(!landed.progress().is_complete());
    }

    /// The switch made on the source account's holder's own password
    /// sign-in, into a target with a relaxed policy.
    fn switch(linked: &Linked) -> Result<MaySignIn<ResolvedTenant>, DomainError> {
        let holder = signed_in_as(*linked.source.1.id());
        switch_on(linked, &holder, &StepUpPolicy::relaxed())
    }

    /// Another person's sign-in cannot authorize a switch from Alice's
    /// source account.
    #[test]
    fn a_switch_rests_on_the_callers_own_sign_in_to_the_source() {
        let linked = linked_pair();
        let mallory = signed_in_as(UserId::new());

        let switched = switch_on(&linked, &mallory, &StepUpPolicy::relaxed());

        assert!(matches!(switched, Err(DomainError::Forbidden(_))));
    }

    /// A source sign-in that still owes its second factor cannot switch to
    /// a linked account.
    #[test]
    fn a_sign_in_still_owing_a_step_switches_nowhere() {
        let linked = linked_pair();
        let owing = SignInProgress::begin(
            LocalMethod::Password,
            SecondFactor::Verify,
            &StepUpPolicy::relaxed(),
        )
        .unwrap();
        let half_done = SignedIn::of((*linked.source.1.id()).into(), owing);

        let switched = switch_on(&linked, &half_done, &StepUpPolicy::relaxed());

        assert!(matches!(switched, Err(DomainError::Forbidden(_))));
    }

    /// A password-only source sign-in cannot switch into a target whose
    /// strict baseline requires stronger assurance.
    #[test]
    fn a_switch_meets_the_targets_baseline() {
        let linked = linked_pair();
        let holder = signed_in_as(*linked.source.1.id());

        let switched = switch_on(&linked, &holder, &StepUpPolicy::strict());

        assert!(matches!(switched, Err(DomainError::Forbidden(_))));
    }

    /// Alice switches into a linked workspace that has been suspended. It is
    /// refused, since a switch is a sign-in and a suspended workspace takes none.
    #[test]
    fn a_switch_into_a_suspended_workspace_is_refused() {
        let mut linked = linked_pair();
        linked.target_tenant.suspend(ActedBy::Platform).unwrap();

        assert!(matches!(switch(&linked), Err(DomainError::Forbidden(_))));
    }

    /// Admission from a different workspace cannot authorize a switch into
    /// the linked target tenant.
    #[test]
    fn a_switch_checked_against_another_workspace_is_refused() {
        let mut linked = linked_pair();
        linked.target_tenant = workspace(TenantId::new());

        assert!(matches!(switch(&linked), Err(DomainError::Forbidden(_))));
    }

    /// Alice switches from one linked tenant to the other. The switch lands
    /// on her linked account there, carrying her password sign-in, without
    /// signing in again.
    #[test]
    fn a_switch_lands_on_the_linked_account() {
        let linked = linked_pair();

        let switched = switch(&linked).unwrap();

        assert_eq!(switched.user_id(), linked.target.1.id());
        assert_eq!(switched.progress().method(), AuthMethod::Password);
        assert!(switched.progress().is_complete());
    }

    /// Changing the linked target's address to Bob's prevents a switch into
    /// that account.
    #[test]
    fn a_target_whose_address_changed_since_linking_is_refused() {
        let mut linked = linked_pair();
        linked
            .target
            .1
            .change_email(
                Email::new("bob@acme.com").unwrap(),
                &crate::domains::identity::account::user::tests::control_over(&linked.target.1),
            )
            .unwrap();

        assert!(matches!(switch(&linked), Err(DomainError::Forbidden(_))));
    }

    /// Changing the source account's address prevents it from switching
    /// through the group linked under Alice's address.
    #[test]
    fn a_caller_whose_own_address_changed_cannot_use_the_group() {
        let mut linked = linked_pair();
        linked
            .source
            .1
            .change_email(
                Email::new("mallory@acme.com").unwrap(),
                &crate::domains::identity::account::user::tests::control_over(&linked.source.1),
            )
            .unwrap();

        assert!(matches!(switch(&linked), Err(DomainError::Forbidden(_))));
    }

    /// A different target account is refused even when its verified address
    /// matches the linked account's address.
    #[test]
    fn an_account_the_link_does_not_name_is_refused() {
        let mut linked = linked_pair();
        linked.target.1 = account("alice@acme.com", true);

        assert!(matches!(switch(&linked), Err(DomainError::Forbidden(_))));
    }

    /// Alice's account in the target tenant was deactivated. A switch into it
    /// is refused, as a sign-in would be.
    #[test]
    fn a_target_that_cannot_sign_in_is_refused() {
        let mut linked = linked_pair();
        linked
            .target
            .1
            .deactivate(
                &crate::domains::identity::account::user::tests::control_over(&linked.target.1),
            )
            .unwrap();

        assert!(matches!(switch(&linked), Err(DomainError::Forbidden(_))));
    }

    /// A switch names a target tenant Acme does not own. It is refused.
    #[test]
    fn a_tenant_outside_the_group_is_refused() {
        let mut linked = linked_pair();
        linked.target.0 = TenantId::new();

        assert!(matches!(switch(&linked), Err(DomainError::Forbidden(_))));
    }

    /// Acme removes the target tenant, but the stored link remains. A switch
    /// into it is refused, since the tenant took its accounts with it.
    #[test]
    fn a_tenant_that_left_the_organization_is_refused() {
        let mut linked = linked_pair();
        let target = linked.target.0;
        linked
            .organization
            .remove_tenant(&target, ActedBy::Platform)
            .unwrap();

        assert!(matches!(switch(&linked), Err(DomainError::Forbidden(_))));
    }

    /// Alice's group is made in Acme. It names Acme as its organization,
    /// since the same address elsewhere is a different person.
    #[test]
    fn a_linked_identity_names_the_organization_it_belongs_to() {
        let group = group();

        assert_eq!(group.identity.organization_id(), group.organization.id());
    }

    fn stored(identity: &LinkedIdentity) -> LinkedIdentityRow {
        LinkedIdentityRow {
            id: identity.id,
            organization_id: identity.organization_id,
            email: identity.email.clone(),
            links: identity.links.clone(),
            created_at: identity.created_at,
        }
    }

    /// Alice's group is stored as it stands and loaded again. It loads
    /// without error.
    #[test]
    fn a_stored_group_reads_back() {
        assert!(LinkedIdentity::reconstitute(stored(&group().identity)).is_ok());
    }

    /// A stored group says `mallory@acme.com` while its link holds Alice's
    /// address. Loading it is refused as a corrupt row.
    #[test]
    fn a_stored_group_with_a_link_under_another_address_is_refused() {
        let mut row = stored(&group().identity);
        row.email = Email::new("mallory@acme.com").unwrap();

        assert!(refused_as_corrupt(&LinkedIdentity::reconstitute(row)));
    }

    /// One stored group links the same tenant twice, and another has no
    /// link. Loading either is refused as a corrupt row.
    #[test]
    fn a_stored_group_with_two_links_to_one_tenant_or_none_is_refused() {
        let mut twice = stored(&group().identity);
        twice.links.push(twice.links[0].clone());
        let mut none = stored(&group().identity);
        none.links.clear();

        for row in [twice, none] {
            assert!(refused_as_corrupt(&LinkedIdentity::reconstitute(row)));
        }
    }
}
