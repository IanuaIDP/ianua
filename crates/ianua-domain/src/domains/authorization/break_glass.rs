mod checks;
mod records;
mod row;

use time::{Duration, OffsetDateTime};

use crate::domains::authorization::authority::TenantAuthority;
use crate::domains::authorization::break_glass::checks::{ensure_grantable, settled_approval};
use crate::domains::authorization::break_glass::row::ensure_consistent;
use crate::domains::authorization::granter::{Handout, HeldByGranter};
use crate::domains::authorization::permission::{CustomPermission, SystemPermission, UserAction};
use crate::domains::identity::account::user::User;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::raised::RaisedEvents;
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::distinct::{first_repeat, without_repeats};
use crate::types::{
    BreakGlassGrantId, EventLabel, Human, HumanAccount, PersonKey, Revocation, TenantId, Text,
    UserId,
};

/// The longest a break-glass grant may last, whatever a tenant's policy
/// says. Emergency access is for an emergency, not a standing role.
pub(crate) const MAX_BREAK_GLASS_LENGTH: Duration = Duration::hours(24);

/// The right that changes what users may give themselves, and that someone
/// approving another person's grant needs: both hand users rights.
const HANDS_USERS_RIGHTS: SystemPermission = SystemPermission::Users(UserAction::Update);

/// Who approved an emergency access grant, or that its user did.
#[derive(Debug, Clone)]
pub enum GrantApproval {
    /// The user granted it to themselves, as break-glass access allows.
    SelfApproved,
    /// This person, through this account, approved it.
    ApprovedBy(Human),
}

impl GrantApproval {
    /// The approval a stored column records: none means self-approved.
    #[must_use]
    pub fn from_stored(approver: Option<Human>) -> Self {
        approver.map_or(Self::SelfApproved, Self::ApprovedBy)
    }

    /// The approver, when someone else approved. This is the value storage keeps.
    #[must_use]
    pub fn approver(&self) -> Option<&Human> {
        match self {
            Self::SelfApproved => None,
            Self::ApprovedBy(approver) => Some(approver),
        }
    }
}

/// Who approves a new grant, signed in to its tenant.
#[derive(Debug, Clone, Copy)]
pub enum RequestedApproval<'a> {
    /// The user asks for it and approves it themselves, as the tenant's
    /// [`BreakGlassPolicy`] lets them.
    SelfApproved(&'a TenantAuthority),
    /// Someone approves it, and may give no more than they hold.
    By(&'a TenantAuthority),
}

/// What a break-glass grant lets its user do for its window: the built-in
/// and app-defined permissions it adds to what they hold. Never empty, and
/// each permission named once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakGlassAccess {
    system: Vec<SystemPermission>,
    custom: Vec<CustomPermission>,
}

impl BreakGlassAccess {
    /// The access `system` and `custom` grant together.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when both are empty. A grant of nothing
    ///   could be misread as a grant of everything.
    pub fn new(
        system: Vec<SystemPermission>,
        custom: Vec<CustomPermission>,
    ) -> Result<Self, DomainError> {
        if system.is_empty() && custom.is_empty() {
            return Err(DomainError::invalid(message!(
                "authorization-a-break-glass-grant-must-name-2",
                "a break-glass grant must name what it grants"
            )));
        }
        Ok(Self {
            system: without_repeats(system),
            custom: without_repeats(custom),
        })
    }

    /// The access a stored row names, exactly as stored: nothing dropped or
    /// merged, so [`BreakGlassGrant::reconstitute`] refuses a row naming
    /// nothing or a permission twice instead of it being repaired here.
    #[must_use]
    pub fn from_stored(system: Vec<SystemPermission>, custom: Vec<CustomPermission>) -> Self {
        Self { system, custom }
    }

    /// The built-in permissions it grants.
    #[must_use]
    pub fn system(&self) -> &[SystemPermission] {
        &self.system
    }

    /// The app-defined permissions it grants.
    #[must_use]
    pub fn custom(&self) -> &[CustomPermission] {
        &self.custom
    }

    fn is_well_formed(&self) -> bool {
        let names_something = !self.system.is_empty() || !self.custom.is_empty();
        names_something
            && first_repeat(&self.system).is_none()
            && first_repeat(&self.custom).is_none()
    }

    fn handout(&self) -> Handout<'_> {
        Handout {
            system: &self.system,
            custom: &self.custom,
        }
    }
}

/// What a tenant's users may give themselves in an emergency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfService {
    /// Nothing: every grant needs someone else's approval.
    Off,
    /// This access, and no more.
    UpTo(BreakGlassAccess),
}

impl SelfService {
    /// What a self-approved grant may give at most.
    fn handout(&self) -> Handout<'_> {
        match self {
            Self::Off => Handout::NOTHING,
            Self::UpTo(access) => access.handout(),
        }
    }

    /// Whether any access it lets names something, each permission once.
    fn is_well_formed(&self) -> bool {
        match self {
            Self::Off => true,
            Self::UpTo(access) => access.is_well_formed(),
        }
    }
}

/// What one tenant lets its users give themselves in an emergency, with
/// nobody else approving.
///
/// Ann is on call at 3am and the production database is down. Nobody who
/// could approve her is awake. The tenant decided beforehand what she may
/// give herself, and she gives herself that and no more. Without a policy
/// written down, whoever asked for a self-approved grant chose its limit
/// too. A tenant starts with [`SelfService::Off`].
#[derive(Debug)]
pub struct BreakGlassPolicy {
    tenant_id: TenantId,
    self_service: SelfService,
    updated_at: OffsetDateTime,
    /// What the policy raised and has not handed over yet.
    raised: RaisedEvents,
}

/// A [`BreakGlassPolicy`] as storage holds it, read back through
/// [`BreakGlassPolicy::reconstitute`].
pub struct BreakGlassPolicyRow {
    /// The tenant it applies in.
    pub tenant_id: TenantId,
    /// What its users may give themselves.
    pub self_service: SelfService,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

impl BreakGlassPolicy {
    /// The policy of `tenant_id` before anyone set one: nobody gives
    /// themselves anything.
    #[must_use]
    pub fn off(tenant_id: TenantId) -> Self {
        Self {
            tenant_id,
            self_service: SelfService::Off,
            updated_at: crate::shared::clock::now(),
            raised: RaisedEvents::default(),
        }
    }

    /// Rebuilds a policy from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row lets users give
    ///   themselves nothing as a grant, or a permission twice.
    pub fn reconstitute(row: BreakGlassPolicyRow) -> Result<Self, DomainError> {
        RowCheck::of("break-glass policy")
            .holds(
                row.self_service.is_well_formed(),
                "self-service access that grants nothing, or a permission twice",
            )
            .finish()?;
        Ok(Self {
            tenant_id: row.tenant_id,
            self_service: row.self_service,
            updated_at: row.updated_at,
            raised: RaisedEvents::default(),
        })
    }

    /// The tenant it applies in.
    #[must_use]
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// What its users may give themselves.
    #[must_use]
    pub fn self_service(&self) -> &SelfService {
        &self.self_service
    }

    /// When it last changed.
    #[must_use]
    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Changes what users may give themselves, as `by` decides. Raises
    /// `authorization.break_glass_policy_changed` with what was let before
    /// and what is let now.
    ///
    /// Letting every user give themselves an access hands it to each of
    /// them, so `by` needs the right to update users and must hold what is
    /// let. Taking it away takes it from each of them, so `by` must hold
    /// what was let before too. Sam may update users and view them. Without
    /// this, he lets everyone give themselves "manage roles" for a day, and
    /// gives it to himself.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` was worked out in another
    ///   tenant.
    /// - [`DomainError::Forbidden`] when `by` may not update users, or holds
    ///   less than the policy lets now or would let.
    pub fn change_self_service(
        &mut self,
        self_service: SelfService,
        by: &TenantAuthority,
    ) -> Result<(), DomainError> {
        by.ensure_within(&self.tenant_id)?;
        let held = by.standing();
        held.ensure_controls(HANDS_USERS_RIGHTS, &self.self_service.handout())?;
        held.ensure_may_give(&self_service.handout())?;
        let previous = std::mem::replace(&mut self.self_service, self_service);
        self.updated_at = crate::shared::clock::now();
        self.raise_changed(previous);
        Ok(())
    }

    /// The most a self-approved grant may give in this tenant.
    fn ceiling(&self) -> HeldByGranter<'_> {
        let most = self.self_service.handout();
        HeldByGranter::new(most.system, most.custom)
    }
}

/// Emergency access given to a tenant user for a short time.
///
/// Ann is on call and must fix production during an incident. She does not
/// normally hold that access. A break-glass grant gives it to her for a few
/// hours. While it is active, the authorizer adds its access to what she holds.
///
/// A grant keeps these rules:
/// - It names what it gives, a [`BreakGlassAccess`], and never more than the
///   approver may hand out, or than the tenant's [`BreakGlassPolicy`] lets a
///   user give themselves.
/// - It ends. The use case caps the length by policy, and no grant lasts
///   longer than `MAX_BREAK_GLASS_LENGTH`.
/// - It carries a written reason.
/// - It records who approved it. A user who approves through any of their
///   accounts is recorded as [`GrantApproval::SelfApproved`].
/// - It cannot be extended. A longer need takes a new grant.
///
/// Granting and revoking are audited and raise critical notifications.
///
/// This differs from operator impersonation. There, a platform operator acts
/// as a tenant user. Here, a tenant user raises their own access.
#[derive(Debug)]
pub struct BreakGlassGrant {
    id: BreakGlassGrantId,
    tenant_id: TenantId,
    user_id: UserId,
    grantee_person: PersonKey,
    access: BreakGlassAccess,
    reason: Text,
    approved_by: GrantApproval,
    expires_at: OffsetDateTime,
    /// Whether it was revoked, and when.
    revocation: Revocation,
    created_at: OffsetDateTime,
    /// What the grant raised and has not handed over yet.
    raised: RaisedEvents,
}

/// Who gets emergency access, to what, why, who approves it, and until when.
pub struct NewBreakGlass<'a, T: TenantScope> {
    /// The tenant it applies in.
    pub tenant_id: TenantId,
    /// Who gets it, as their account stands now.
    pub grantee: &'a User<T>,
    /// What it lets them do.
    pub access: BreakGlassAccess,
    /// Why.
    pub reason: Text,
    /// Who approves it, or that the user approves it themselves.
    pub approval: RequestedApproval<'a>,
    /// When it ends.
    pub expires_at: OffsetDateTime,
}

impl BreakGlassGrant {
    /// Creates a new emergency access grant. Raises
    /// `authentication.break_glass_granted`, naming the user by their display
    /// name, the reason and when it ends.
    ///
    /// The most the grant may give depends on who approves it. When someone
    /// else approves, it is what that approver holds. For a self-approved
    /// grant, it is what `policy`, the tenant's break-glass policy, lets a
    /// user give themselves.
    ///
    /// Only the user approves their own grant. Mallory may not ask for a
    /// self-approved grant in Ann's name and leave a record that Ann did.
    /// An approver who is the user, through any of their accounts, counts as
    /// a self-approval. Ann approves her own grant from her organization
    /// account, which holds far more. Without this, the record shows a
    /// second person's sign-off and the grant goes past what policy lets Ann
    /// give herself.
    ///
    /// Someone else approving hands the user rights, as giving them a role
    /// does. So the approver also needs the right to update users. Bob may
    /// view users. Without this, he signs off a day of "view users" for Ann,
    /// though he may not change what anyone holds.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] for a nonfuture expiry, a lifetime beyond
    /// `MAX_BREAK_GLASS_LENGTH`, or empty or duplicate permissions.
    /// Returns [`DomainError::Forbidden`] for policy or approver rights from another
    /// tenant, self-approval by another user, an external approver without user-update
    /// rights, or access beyond the approver's holdings or the self-approval policy.
    pub fn create<T: TenantScope>(
        grant: NewBreakGlass<'_, T>,
        policy: &BreakGlassPolicy,
    ) -> Result<Self, DomainError> {
        let now = crate::shared::clock::now();
        ensure_grantable(&grant, policy, now)?;
        let grantee = grantee_of(*grant.grantee.id(), &PersonKey::of(grant.grantee.email()));
        let (approved_by, ceiling) = settled_approval(&grant, &grantee, policy)?;
        ensure_approver_may_give(&approved_by, &ceiling)?;
        ceiling.ensure_may_hand_out(grant.access.system(), grant.access.custom())?;
        let mut created = Self {
            id: BreakGlassGrantId::new(),
            tenant_id: grant.tenant_id,
            user_id: *grant.grantee.id(),
            grantee_person: grantee.person().clone(),
            access: grant.access,
            reason: grant.reason,
            approved_by,
            expires_at: grant.expires_at,
            revocation: Revocation::InForce,
            created_at: now,
            raised: RaisedEvents::default(),
        };
        created.raise_granted(EventLabel::of(grant.grantee.display_name().as_str()));
        Ok(created)
    }

    /// Rebuilds a break-glass grant from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row ends or is revoked
    ///   before it was granted.
    /// - [`DomainError::Infrastructure`] when it lasts longer than
    ///   `MAX_BREAK_GLASS_LENGTH`.
    /// - [`DomainError::Infrastructure`] when it grants nothing, or a
    ///   permission twice.
    /// - [`DomainError::Infrastructure`] when it records the user's own
    ///   approval, through any of their accounts, as someone's sign-off.
    pub fn reconstitute(row: BreakGlassGrantRow) -> Result<Self, DomainError> {
        ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            tenant_id: row.tenant_id,
            user_id: row.user_id,
            grantee_person: row.grantee_person,
            access: row.access,
            reason: row.reason,
            approved_by: row.approved_by,
            expires_at: row.expires_at,
            revocation: row.revocation,
            created_at: row.created_at,
            raised: RaisedEvents::default(),
        })
    }

    /// Unique grant identifier.
    #[must_use]
    pub fn id(&self) -> &BreakGlassGrantId {
        &self.id
    }

    /// The tenant where emergency access was granted.
    #[must_use]
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The user who received emergency access.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// The person behind the user, as they were known when the grant was made.
    #[must_use]
    pub fn grantee_person(&self) -> &PersonKey {
        &self.grantee_person
    }

    /// What the grant lets its user do while it is active.
    #[must_use]
    pub fn access(&self) -> &BreakGlassAccess {
        &self.access
    }

    /// The documented justification for emergency access.
    #[must_use]
    pub fn reason(&self) -> &Text {
        &self.reason
    }

    /// Who approved the grant, or that its user approved it themselves.
    #[must_use]
    pub fn approved_by(&self) -> &GrantApproval {
        &self.approved_by
    }

    /// When the grant expires.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// When the grant was revoked, if at all.
    #[must_use]
    pub fn revoked_at(&self) -> Option<OffsetDateTime> {
        self.revocation.revoked_at()
    }

    /// When the grant was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Whether this grant is currently active.
    #[must_use]
    pub fn is_active(&self, now: OffsetDateTime) -> bool {
        !self.revocation.is_revoked() && now < self.expires_at
    }

    /// Whether this was a self-approved grant.
    #[must_use]
    pub fn is_self_approved(&self) -> bool {
        matches!(self.approved_by, GrantApproval::SelfApproved)
    }

    /// Revokes the grant at once, for the person `by` names. Idempotent.
    ///
    /// The user may end their own access early, and whoever approved it may
    /// take it back. Anyone else needs the right to update users. Sam may
    /// view users. Without this, he ends Ann's access in the middle of the
    /// incident she was given it for.
    ///
    /// The first revocation raises `authentication.break_glass_revoked`,
    /// naming the user as `holder`; revoking again raises nothing.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is neither the user nor the
    ///   approver, and may not update users.
    pub fn revoke(&mut self, by: &TenantAuthority, holder: EventLabel) -> Result<(), DomainError> {
        if !self.may_be_revoked_by(by) {
            return Err(DomainError::forbidden(message!(
                "authorization-only-the-user-their-approver-or",
                "only the user, their approver or someone who may update users ends this access"
            )));
        }
        self.end_early(holder);
        Ok(())
    }

    /// Whether `by` may end this grant: its user, through any of their
    /// accounts, whoever approved it, or someone who may update users.
    #[must_use]
    pub fn may_be_revoked_by(&self, by: &TenantAuthority) -> bool {
        let person = by.who();
        let grantee = grantee_of(self.user_id, &self.grantee_person);
        let approved_it = self
            .approved_by
            .approver()
            .is_some_and(|approver| approver.is_same_person_as(person));
        person.is_same_person_as(&grantee) || approved_it || by.holds(HANDS_USERS_RIGHTS)
    }
}

/// Whether `requester` may ask for emergency access for `grantee` at all:
/// for themselves, through any of their accounts, or for someone else when
/// they may update users. What the access may be is
/// [`BreakGlassGrant::create`]'s to decide.
#[must_use]
pub fn may_ask_for<T: TenantScope>(requester: &TenantAuthority, grantee: &User<T>) -> bool {
    let person = grantee_of(*grantee.id(), &PersonKey::of(grantee.email()));
    requester.who().is_same_person_as(&person) || requester.holds(HANDS_USERS_RIGHTS)
}

/// Refuses an approval by someone else who may not change what users hold.
/// A self-approval is bounded by the tenant's policy instead.
fn ensure_approver_may_give(
    approval: &GrantApproval,
    ceiling: &HeldByGranter<'_>,
) -> Result<(), DomainError> {
    match approval {
        GrantApproval::SelfApproved => Ok(()),
        GrantApproval::ApprovedBy(_) => ceiling.ensure_holds(HANDS_USERS_RIGHTS),
    }
}

/// A [`BreakGlassGrant`] as storage holds it, read back through
/// [`BreakGlassGrant::reconstitute`].
pub struct BreakGlassGrantRow {
    /// Unique grant identifier.
    pub id: BreakGlassGrantId,
    /// The tenant where emergency access was granted.
    pub tenant_id: TenantId,
    /// The user who received emergency access.
    pub user_id: UserId,
    /// The person behind the user when the grant was made.
    pub grantee_person: PersonKey,
    /// What the grant lets its user do.
    pub access: BreakGlassAccess,
    /// The documented justification for emergency access.
    pub reason: Text,
    /// Who approved the grant, or that it was self-approved.
    pub approved_by: GrantApproval,
    /// When the grant expires.
    pub expires_at: OffsetDateTime,
    /// Whether it was revoked, and when.
    pub revocation: Revocation,
    /// When the grant was created.
    pub created_at: OffsetDateTime,
}

/// The grantee as a human: their tenant account and the person behind it.
fn grantee_of(user_id: UserId, person: &PersonKey) -> Human {
    Human::new(HumanAccount::User(user_id), person.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::events::raised::RaisesComplete;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::authority::assumed_authority;
    use crate::test_support::builders::user;
    use crate::test_support::events::raised_complete_names;
    use crate::types::{Email, OrgUserId};

    const VIEW_USERS: SystemPermission = SystemPermission::Users(UserAction::View);

    fn text(s: &str) -> Text {
        Text::new("reason", s).unwrap()
    }

    fn person(address: &str) -> PersonKey {
        PersonKey::of(&Email::new(address).unwrap())
    }

    /// Acme, the tenant every test grant is in.
    fn acme() -> TenantId {
        TenantId::from_uuid(uuid::Uuid::from_u128(1))
    }

    fn access() -> BreakGlassAccess {
        BreakGlassAccess::new(vec![VIEW_USERS], Vec::new()).unwrap()
    }

    /// Ann, the on-call user every test grant is for.
    fn ann() -> &'static User<ResolvedTenant> {
        Box::leak(Box::new(user(
            UserId::from_uuid(uuid::Uuid::from_u128(2)),
            "ann@corp.com",
        )))
    }

    /// `who`, signed in to Acme and holding `system`.
    fn in_acme(who: &Human, system: &[SystemPermission]) -> &'static TenantAuthority {
        assumed_authority(who, acme(), system, &[])
    }

    /// Ann, signed in to Acme through her own account, holding nothing.
    fn ann_herself() -> &'static TenantAuthority {
        in_acme(
            &Human::new(HumanAccount::User(*ann().id()), person("ann@corp.com")),
            &[],
        )
    }

    /// Bob, a colleague with a tenant account, approving and holding
    /// `system`.
    fn bob_approves(system: &[SystemPermission]) -> RequestedApproval<'static> {
        let bob = Human::new(HumanAccount::User(UserId::new()), person("bob@corp.com"));
        RequestedApproval::By(in_acme(&bob, system))
    }

    /// Acme's policy, letting users give themselves `self_service`.
    fn policy(self_service: SelfService) -> BreakGlassPolicy {
        let mut policy = BreakGlassPolicy::off(acme());
        let root = Human::new(HumanAccount::User(UserId::new()), person("root@corp.com"));
        policy
            .change_self_service(self_service, in_acme(&root, SystemPermission::all()))
            .unwrap();
        policy
    }

    /// A policy letting users give themselves `access()`.
    fn lets_view() -> BreakGlassPolicy {
        policy(SelfService::UpTo(access()))
    }

    /// Ann asks for `lasting` of emergency access, approved as `approval`.
    fn request(
        approval: RequestedApproval<'static>,
        lasting: Duration,
    ) -> NewBreakGlass<'static, ResolvedTenant> {
        NewBreakGlass {
            tenant_id: acme(),
            grantee: ann(),
            access: access(),
            reason: text("Production incident INC-1234"),
            approval,
            expires_at: crate::shared::clock::now() + lasting,
        }
    }

    fn self_approved(lasting: Duration) -> BreakGlassGrant {
        BreakGlassGrant::create(
            request(RequestedApproval::SelfApproved(ann_herself()), lasting),
            &lets_view(),
        )
        .unwrap()
    }

    /// A colleague approves four hours of emergency access for a user. The
    /// grant is active at once, is not self-approved, and keeps its reason
    /// and access.
    #[test]
    fn create_active_grant() {
        let grant = BreakGlassGrant::create(
            request(bob_approves(SystemPermission::all()), Duration::hours(4)),
            &BreakGlassPolicy::off(acme()),
        )
        .unwrap();

        assert!(grant.is_active(crate::shared::clock::now()));
        assert!(!grant.is_self_approved());
        assert_eq!(grant.reason().as_str(), "Production incident INC-1234");
        assert_eq!(grant.access(), &access());
    }

    /// A user grants themselves one hour of emergency access, within what
    /// Acme's policy lets. The grant reads as self-approved.
    #[test]
    fn self_approved_grant() {
        let grant = self_approved(Duration::hours(1));

        assert!(grant.is_self_approved());
    }

    /// Emergency access with neither built-in nor custom permissions is rejected.
    #[test]
    fn a_grant_of_nothing_is_refused() {
        assert!(matches!(
            BreakGlassAccess::new(Vec::new(), Vec::new()),
            Err(DomainError::Validation(_))
        ));
    }

    /// A caller with no rights cannot approve Ann's emergency access, and Ann
    /// cannot approve her own access while self-service is disabled.
    #[test]
    fn a_grant_is_never_more_than_its_ceiling() {
        let approved =
            BreakGlassGrant::create(request(bob_approves(&[]), Duration::hours(1)), &lets_view());
        let self_served = BreakGlassGrant::create(
            request(
                RequestedApproval::SelfApproved(ann_herself()),
                Duration::hours(1),
            ),
            &BreakGlassPolicy::off(acme()),
        );

        assert!(matches!(approved, Err(DomainError::Forbidden(_))));
        assert!(matches!(self_served, Err(DomainError::Forbidden(_))));
    }

    /// Mallory cannot request self-approved emergency access on Ann's behalf.
    #[test]
    fn only_the_user_approves_their_own_grant() {
        let mallory = Human::new(
            HumanAccount::User(UserId::new()),
            person("mallory@corp.com"),
        );

        let result = BreakGlassGrant::create(
            request(
                RequestedApproval::SelfApproved(in_acme(&mallory, SystemPermission::all())),
                Duration::hours(1),
            ),
            &lets_view(),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Acme's emergency-access request cannot use another tenant's self-service policy.
    #[test]
    fn a_grant_is_held_to_its_own_tenants_policy() {
        let globex_id = TenantId::new();
        let mut globex = BreakGlassPolicy::off(globex_id);
        let root = Human::new(HumanAccount::User(UserId::new()), person("root@globex.com"));
        let globex_root = assumed_authority(&root, globex_id, SystemPermission::all(), &[]);
        globex
            .change_self_service(SelfService::UpTo(access()), globex_root)
            .unwrap();

        let result = BreakGlassGrant::create(
            request(
                RequestedApproval::SelfApproved(ann_herself()),
                Duration::hours(1),
            ),
            &globex,
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A twenty-five-hour emergency grant exceeds the maximum lifetime and is rejected.
    #[test]
    fn a_grant_lasting_longer_than_a_day_is_refused() {
        let result = BreakGlassGrant::create(
            request(
                RequestedApproval::SelfApproved(ann_herself()),
                Duration::hours(25),
            ),
            &lets_view(),
        );

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A user asks for a grant that expired a second ago. It is refused, so
    /// the audit trail never shows access that could not be used.
    #[test]
    fn a_grant_that_has_already_ended_is_refused() {
        let ended = BreakGlassGrant::create(
            request(
                RequestedApproval::SelfApproved(ann_herself()),
                -Duration::seconds(1),
            ),
            &lets_view(),
        );

        assert!(matches!(ended, Err(DomainError::Validation(_))));
    }

    /// Naming Ann as the approver of her own grant records it as self-approved.
    #[test]
    fn a_user_approving_their_own_grant_is_recorded_as_self_approved() {
        let grant = BreakGlassGrant::create(
            request(RequestedApproval::By(ann_herself()), Duration::hours(1)),
            &lets_view(),
        )
        .unwrap();

        assert!(grant.is_self_approved());
    }

    /// Ann approving through her organization account, which holds
    /// everything.
    fn ann_through_her_org_account() -> RequestedApproval<'static> {
        let ann_org = Human::new(
            HumanAccount::OrgUser(OrgUserId::new()),
            person("ann+org@corp.com"),
        );
        RequestedApproval::By(in_acme(&ann_org, SystemPermission::all()))
    }

    /// Ann's organization account counts as her own approval: access beyond the
    /// self-service policy is refused, while permitted access is recorded as self-approved.
    #[test]
    fn a_user_approving_through_another_account_is_a_self_approval() {
        let manage =
            BreakGlassAccess::new(vec![SystemPermission::ManageUsers], Vec::new()).unwrap();

        let past_policy = BreakGlassGrant::create(
            NewBreakGlass {
                access: manage,
                ..request(ann_through_her_org_account(), Duration::hours(1))
            },
            &lets_view(),
        );
        let within = BreakGlassGrant::create(
            request(ann_through_her_org_account(), Duration::hours(1)),
            &lets_view(),
        )
        .unwrap();

        assert!(matches!(past_policy, Err(DomainError::Forbidden(_))));
        assert!(within.is_self_approved());
    }

    /// An admin who may do everything, signed in.
    fn as_admin() -> &'static TenantAuthority {
        let root = Human::new(HumanAccount::User(UserId::new()), person("root@corp.com"));
        in_acme(&root, SystemPermission::all())
    }

    /// An admin revokes a grant with hours left. It stops being active at
    /// once and records when it was revoked.
    #[test]
    fn revoke_makes_inactive() {
        let mut grant = self_approved(Duration::hours(4));

        grant.revoke(as_admin(), EventLabel::of("Ann")).unwrap();

        assert!(!grant.is_active(crate::shared::clock::now()));
        assert!(grant.revoked_at().is_some());
    }

    /// An admin revokes a grant twice. The second revoke keeps the first
    /// revoke's time, so the record shows when access really ended.
    #[test]
    fn revoke_is_idempotent() {
        let mut grant = self_approved(Duration::hours(4));

        grant.revoke(as_admin(), EventLabel::of("Ann")).unwrap();
        let first = grant.revoked_at().unwrap();
        grant.revoke(as_admin(), EventLabel::of("Ann")).unwrap();
        let second = grant.revoked_at().unwrap();

        assert_eq!(first, second);
    }

    /// Sam's view-only rights cannot revoke Ann's grant, which remains active.
    /// Ann can then revoke it herself and end the access.
    #[test]
    fn only_the_user_the_approver_or_a_user_manager_ends_a_grant() {
        let mut grant = self_approved(Duration::hours(4));
        let sam = Human::new(HumanAccount::User(UserId::new()), person("sam@corp.com"));

        let by_sam = grant.revoke(in_acme(&sam, &[VIEW_USERS]), EventLabel::of("Ann"));
        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(grant.is_active(crate::shared::clock::now()));

        grant.revoke(ann_herself(), EventLabel::of("Ann")).unwrap();
        assert!(!grant.is_active(crate::shared::clock::now()));
    }

    /// Holding user-viewing rights does not authorize approving them as emergency
    /// access for another person without user-update rights.
    #[test]
    fn an_approver_needs_the_right_to_update_users() {
        let result = BreakGlassGrant::create(
            request(bob_approves(&[VIEW_USERS]), Duration::hours(1)),
            &BreakGlassPolicy::off(acme()),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Bob approves Ann's emergency access. The grant names the tenant, Ann
    /// and Bob, so the audit can say who got what and who signed it off.
    #[test]
    fn a_grant_names_the_tenant_the_user_and_the_approver() {
        let bob = Human::new(HumanAccount::User(UserId::new()), person("bob@corp.com"));
        let asked = request(
            RequestedApproval::By(in_acme(&bob, SystemPermission::all())),
            Duration::hours(4),
        );

        let grant = BreakGlassGrant::create(asked, &BreakGlassPolicy::off(acme())).unwrap();

        assert_eq!(grant.tenant_id(), &acme());
        assert_eq!(grant.user_id(), ann().id());
        assert_eq!(grant.grantee_person(), &person("ann@corp.com"));
        assert_eq!(
            grant.approved_by().approver(),
            Some(&bob),
            "an approved grant must not read as self-approved"
        );
        assert!(!grant.id().as_uuid().is_nil());
    }

    /// A grant is still active one second before it expires and inactive at
    /// the expiry instant. So access never lasts a moment longer than given.
    #[test]
    fn a_grant_is_inactive_from_the_instant_it_expires() {
        let grant = self_approved(Duration::hours(4));

        assert!(grant.is_active(grant.expires_at() - Duration::seconds(1)));
        assert!(!grant.is_active(grant.expires_at()));
    }

    /// Sam cannot enable self-service user management when he lacks that right;
    /// the policy remains off.
    #[test]
    fn a_policy_lets_users_give_themselves_only_what_its_author_holds() {
        let mut policy = BreakGlassPolicy::off(acme());
        let sam = Human::new(HumanAccount::User(UserId::new()), person("sam@corp.com"));
        let manage =
            BreakGlassAccess::new(vec![SystemPermission::ManageUsers], Vec::new()).unwrap();

        let result = policy.change_self_service(
            SelfService::UpTo(manage),
            in_acme(&sam, &[HANDS_USERS_RIGHTS, VIEW_USERS]),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(policy.self_service(), &SelfService::Off);
    }

    /// Rita cannot disable self-service with view-only rights, and the policy
    /// continues to allow user-viewing access.
    #[test]
    fn changing_the_policy_needs_the_right_to_update_users() {
        let mut policy = lets_view();
        let rita = Human::new(HumanAccount::User(UserId::new()), person("rita@corp.com"));

        let result = policy.change_self_service(SelfService::Off, in_acme(&rita, &[VIEW_USERS]));

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(policy.self_service(), &SelfService::UpTo(access()));
    }

    /// Root lets Acme's users give themselves "view users". The change is
    /// raised for Acme, with what was let before and after.
    #[test]
    fn changing_the_policy_raises_what_was_let_before_and_after() {
        let mut policy = BreakGlassPolicy::off(acme());
        let root = Human::new(HumanAccount::User(UserId::new()), person("root@corp.com"));

        policy
            .change_self_service(
                SelfService::UpTo(access()),
                in_acme(&root, SystemPermission::all()),
            )
            .unwrap();

        let raised = policy.take_events();
        assert_eq!(raised.len(), 1);
        assert_eq!(
            raised[0].event_type().as_str(),
            "authorization.break_glass_policy_changed"
        );
        assert_eq!(raised[0].tenant_id(), Some(&acme()));
        assert!(raised[0].payload().value("self_service").is_some());
    }

    /// A user viewer's refused attempt to disable self-service raises no event.
    #[test]
    fn a_refused_policy_change_raises_nothing() {
        let mut policy = lets_view();
        raised_complete_names(&mut policy);
        let rita = Human::new(HumanAccount::User(UserId::new()), person("rita@corp.com"));

        let refused = policy.change_self_service(SelfService::Off, in_acme(&rita, &[VIEW_USERS]));

        assert!(refused.is_err());
        assert!(raised_complete_names(&mut policy).is_empty());
    }

    /// A policy read back from storage has raised nothing.
    #[test]
    fn a_policy_read_back_from_storage_has_raised_nothing() {
        let mut policy = BreakGlassPolicy::reconstitute(BreakGlassPolicyRow {
            tenant_id: acme(),
            self_service: SelfService::UpTo(access()),
            updated_at: crate::shared::clock::now(),
        })
        .unwrap();

        assert!(raised_complete_names(&mut policy).is_empty());
    }

    /// A stored policy that lets users give themselves a permission twice
    /// is refused as a corrupt row. One that lets nothing loads.
    #[test]
    fn a_stored_policy_is_checked_when_read() {
        let twice = BreakGlassAccess {
            system: vec![VIEW_USERS, VIEW_USERS],
            custom: Vec::new(),
        };
        let row = |self_service| BreakGlassPolicyRow {
            tenant_id: acme(),
            self_service,
            updated_at: crate::shared::clock::now(),
        };

        let repeated = BreakGlassPolicy::reconstitute(row(SelfService::UpTo(twice)));
        let nothing = BreakGlassPolicy::reconstitute(row(SelfService::Off));

        assert!(refused_as_corrupt(&repeated));
        assert!(nothing.is_ok());
    }

    fn stored(grant: &BreakGlassGrant) -> BreakGlassGrantRow {
        BreakGlassGrantRow {
            id: *grant.id(),
            tenant_id: *grant.tenant_id(),
            user_id: *grant.user_id(),
            grantee_person: grant.grantee_person().clone(),
            access: grant.access().clone(),
            reason: grant.reason().clone(),
            approved_by: grant.approved_by().clone(),
            expires_at: grant.expires_at(),
            revocation: Revocation::from_stored(grant.revoked_at()),
            created_at: grant.created_at(),
        }
    }

    fn granted() -> BreakGlassGrant {
        self_approved(Duration::hours(1))
    }

    /// A freshly created grant is written to storage and read back. The
    /// row passes every check.
    #[test]
    fn a_stored_grant_reads_back() {
        assert!(BreakGlassGrant::reconstitute(stored(&granted())).is_ok());
    }

    /// A grant Bob approved is written to storage and read back. The row
    /// passes every check and still names Bob.
    #[test]
    fn a_stored_sign_off_by_someone_else_reads_back() {
        let grant = BreakGlassGrant::create(
            request(bob_approves(SystemPermission::all()), Duration::hours(1)),
            &BreakGlassPolicy::off(acme()),
        )
        .unwrap();

        let read = BreakGlassGrant::reconstitute(stored(&grant)).unwrap();

        assert!(!read.is_self_approved());
    }

    /// A stored grant expires a second before it was created. Reading it
    /// back is refused as a corrupt row.
    #[test]
    fn a_stored_grant_that_ends_before_it_began_is_refused() {
        let mut row = stored(&granted());
        row.expires_at = row.created_at - Duration::SECOND;

        assert!(refused_as_corrupt(&BreakGlassGrant::reconstitute(row)));
    }

    /// A stored grant lasts one second past [`MAX_BREAK_GLASS_LENGTH`].
    /// Reading it back is refused as a corrupt row.
    #[test]
    fn a_stored_grant_lasting_longer_than_any_may_is_refused() {
        let mut row = stored(&granted());
        row.expires_at = row.created_at + MAX_BREAK_GLASS_LENGTH + Duration::SECOND;

        assert!(refused_as_corrupt(&BreakGlassGrant::reconstitute(row)));
    }

    /// A stored grant says it was revoked a second before it was created.
    /// Reading it back is refused as a corrupt row.
    #[test]
    fn a_stored_grant_revoked_before_it_began_is_refused() {
        let mut row = stored(&granted());
        row.revocation = Revocation::Revoked {
            at: row.created_at - Duration::SECOND,
        };

        assert!(refused_as_corrupt(&BreakGlassGrant::reconstitute(row)));
    }

    /// Stored grants recording the holder's tenant or organization account as
    /// another person's approval are rejected as corrupt.
    #[test]
    fn a_stored_self_approval_written_as_a_sign_off_is_refused() {
        let grant = granted();
        for account in [
            HumanAccount::User(*grant.user_id()),
            HumanAccount::OrgUser(OrgUserId::new()),
        ] {
            let mut row = stored(&grant);
            row.approved_by =
                GrantApproval::ApprovedBy(Human::new(account, row.grantee_person.clone()));

            assert!(refused_as_corrupt(&BreakGlassGrant::reconstitute(row)));
        }
    }

    /// Ann gives herself four hours of emergency access. The grant raises
    /// `authentication.break_glass_granted` for Acme, naming her by her
    /// display name.
    #[test]
    fn granting_raises_the_grant_for_its_tenant() {
        let mut grant = self_approved(Duration::hours(4));

        let events = grant.take_events();

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().as_str(),
            "authentication.break_glass_granted"
        );
        assert_eq!(events[0].tenant_id(), Some(&acme()));
        let Some(crate::shared::events::data::FieldValue::Reference(user)) =
            events[0].payload().value("user").cloned()
        else {
            panic!("the grant names its user");
        };
        assert_eq!(user.label(), "Test User");
    }

    /// An admin ends Ann's grant and then ends it again. Only the first
    /// raises `authentication.break_glass_revoked`.
    #[test]
    fn only_the_first_revocation_is_raised() {
        let mut grant = self_approved(Duration::hours(4));
        let _ = grant.take_events();

        grant.revoke(as_admin(), EventLabel::of("Ann")).unwrap();
        grant.revoke(as_admin(), EventLabel::of("Ann")).unwrap();

        assert_eq!(
            raised_complete_names(&mut grant),
            ["authentication.break_glass_revoked"]
        );
    }

    /// A user viewer's refused revocation of Ann's emergency grant raises no event.
    #[test]
    fn a_refused_revocation_raises_nothing() {
        let mut grant = self_approved(Duration::hours(4));
        let _ = grant.take_events();
        let sam = Human::new(HumanAccount::User(UserId::new()), person("sam@corp.com"));

        let refused = grant.revoke(in_acme(&sam, &[VIEW_USERS]), EventLabel::of("Ann"));

        assert!(refused.is_err());
        assert!(grant.take_events().is_empty());
    }

    /// Ann asks for emergency access for herself, and Carol, who may update
    /// users, asks for it for Ann. Sam, who may only view users, may not
    /// ask for it for Ann.
    #[test]
    fn only_the_user_or_someone_who_updates_users_asks_for_access() {
        let carol = Human::new(HumanAccount::User(UserId::new()), person("carol@corp.com"));
        let sam = Human::new(HumanAccount::User(UserId::new()), person("sam@corp.com"));
        let updates_users = [SystemPermission::Users(UserAction::Update)];

        assert!(may_ask_for(ann_herself(), ann()));
        assert!(may_ask_for(in_acme(&carol, &updates_users), ann()));
        assert!(!may_ask_for(in_acme(&sam, &[VIEW_USERS]), ann()));
    }

    /// A grant read back from storage has raised nothing.
    #[test]
    fn a_grant_read_back_has_raised_nothing() {
        let mut grant = BreakGlassGrant::reconstitute(stored(&granted())).unwrap();

        assert!(grant.take_events().is_empty());
    }
}
