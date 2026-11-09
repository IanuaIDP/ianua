//! Who acts on the organization plane, and what they act through.
//!
//! A change names the member who makes it. The domain then checks two
//! things. Their role must allow it, as [`OrgRole::grants`] says. And what
//! they act through must carry it: their own signed-in session carries the
//! whole role, an API key they minted carries only its scopes.
//!
//! [`OrgRole::grants`]: crate::domains::organization::members::membership::OrgRole::grants

use crate::domains::audit::access::{AuditLogAccess, AuditLogOf, LogReach, OrgLogView};
use crate::domains::identity::sealed::Sealed;
use crate::domains::organization::access::api_key::OrgApiKey;
use crate::domains::organization::access::session::OrgSession;
use crate::domains::organization::access::session_check::CheckedOrgSession;
use crate::domains::organization::members::membership::TenantReach;
use crate::domains::organization::members::org_user::OrgUser;
use crate::domains::organization::members::org_user_status::OrgUserStatus;
use crate::domains::organization::members::permission::{
    OrgAuditAction, OrgPermission, TenantAction,
};
use crate::domains::organization::status::OrgStanding;
use crate::domains::tenant::control::{LifecycleStep, OrgSteward};
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::{ActedBy, ActorRef, OrgUserId, OrganizationId, TenantId};

/// What a member acts through.
#[derive(Debug, Clone, Copy)]
pub enum Carried<'a> {
    /// A session they signed in to, checked as it is used. It carries their
    /// whole role.
    Session(CheckedOrgSession<'a>),
    /// A key they minted. It carries only its scopes, and never more than
    /// their role holds today.
    Key(&'a OrgApiKey),
}

/// A member acting on the organization plane, with what they act through.
///
/// Sam is a plain member. Without this, any active member resets another
/// member's password, invites people or mints keys, because the domain only
/// asked whether he belongs to the organization.
///
/// It is made from the organization as it stands, so a member acts on an
/// open organization only. While it is suspended only owners act, and once
/// it is closed nobody does. A session opened before the platform suspended
/// Acme does not keep a plain member working in it.
#[derive(Debug, Clone, Copy)]
pub struct OrgControl<'a> {
    organization: OrgStanding,
    by: &'a OrgUser,
    carries: Carried<'a>,
}

impl<'a> OrgControl<'a> {
    /// `by` acting through `carries` on the organization `organization`
    /// stands for.
    #[must_use]
    pub fn new(organization: OrgStanding, by: &'a OrgUser, carries: Carried<'a>) -> Self {
        Self {
            organization,
            by,
            carries,
        }
    }

    /// The member acting, as they stand now.
    #[must_use]
    pub fn by(&self) -> &'a OrgUser {
        self.by
    }

    /// What they act through.
    #[must_use]
    pub fn carries(&self) -> Carried<'a> {
        self.carries
    }

    /// Refuses `permission` in `organization_id` unless the member may use it
    /// there now.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the check in
    ///   [`ensure_genuine`](Self::ensure_genuine) fails.
    /// - [`DomainError::Forbidden`] when their role, or the key they use,
    ///   does not carry `permission`.
    pub fn ensure_may(
        &self,
        organization_id: &OrganizationId,
        permission: OrgPermission,
    ) -> Result<(), DomainError> {
        self.ensure_genuine(organization_id)?;
        if !self.holds(&permission) {
            return Err(DomainError::forbidden(message!(
                "organization-this-needs-the-right-which-the",
                format!("this needs the {permission} right, which the member does not carry")
            )));
        }
        Ok(())
    }

    /// Refuses a member who is not an active member of `organization_id`,
    /// who acts through a session or key that is not theirs or no longer
    /// works, or whom the organization's status keeps out.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] in each of those cases.
    pub fn ensure_genuine(&self, organization_id: &OrganizationId) -> Result<(), DomainError> {
        let member = self.by;
        let belongs = member.organization_id() == organization_id
            && self.organization.id() == organization_id;
        if !belongs || member.status() != OrgUserStatus::Active {
            return Err(DomainError::forbidden(message!(
                "organization-only-an-active-member-of-the-2",
                "only an active member of the organization acts on it"
            )));
        }
        self.organization.ensure_admits(member.role())?;
        if !self.carried_is_theirs() {
            return Err(DomainError::forbidden(message!(
                "organization-the-session-or-key-is-not",
                "the session or key is not this member's, or no longer works"
            )));
        }
        Ok(())
    }

    /// Whether the member's role and what they act through both carry
    /// `permission`.
    #[must_use]
    pub fn holds(&self, permission: &OrgPermission) -> bool {
        self.by.role().grants(permission) && self.carried_admits(permission)
    }

    /// Every permission the member carries right now, for handing on to a
    /// key they mint.
    #[must_use]
    pub fn held(&self) -> Vec<OrgPermission> {
        OrgPermission::ALL_VARIANTS
            .iter()
            .copied()
            .filter(|permission| self.holds(permission))
            .collect()
    }

    /// Whether the member acting is `member`.
    #[must_use]
    pub fn is_member(&self, member: &OrgUserId) -> bool {
        self.by.id() == member
    }

    /// The proof that the member may export the audit log of
    /// `organization_id` and download the file.
    ///
    /// Exporting needs its own right, not only the right to view the log:
    /// a key scoped to read entries one page at a time does not take every
    /// record of every tenant in one file.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the check in
    ///   [`ensure_may`](Self::ensure_may) fails for exporting the audit
    ///   log.
    ///
    /// The file holds the organization's own records and those of the
    /// tenants the member's role reaches, `granted` being the ones they
    /// were let into.
    pub fn audit_log_export(
        &self,
        organization_id: &OrganizationId,
        granted: &[TenantId],
    ) -> Result<AuditLogAccess, DomainError> {
        self.ensure_may(
            organization_id,
            OrgPermission::AuditLog(OrgAuditAction::Export),
        )?;
        Ok(AuditLogAccess::granted(
            AuditLogOf::Organization(*organization_id),
            ActorRef::OrgUser(*self.by.id()),
        )
        .within(self.log_reach(granted)))
    }

    /// What the member is shown of the organization's log, on a page or in
    /// a calendar: its own records, and those of the tenants their role
    /// reaches, `granted` being the ones they were let into.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the check in
    ///   [`ensure_may`](Self::ensure_may) fails for viewing the audit log.
    pub fn audit_log_view(
        &self,
        organization_id: &OrganizationId,
        granted: &[TenantId],
    ) -> Result<OrgLogView, DomainError> {
        self.ensure_may(
            organization_id,
            OrgPermission::AuditLog(OrgAuditAction::View),
        )?;
        Ok(OrgLogView::new(*organization_id, self.log_reach(granted)))
    }

    /// How far into the tenants the member's role shows them a log. A
    /// grant counts only for a role that reaches tenants one by one: one
    /// handed to a billing contact by mistake shows them nothing.
    fn log_reach(&self, granted: &[TenantId]) -> LogReach {
        match self.by.role().tenant_reach() {
            TenantReach::Every => LogReach::Every,
            TenantReach::Granted => LogReach::Tenants(granted.to_vec()),
            TenantReach::Nothing => LogReach::Tenants(Vec::new()),
        }
    }

    /// The session the member acts through, when it is one.
    #[must_use]
    pub fn session(&self) -> Option<&'a OrgSession> {
        match self.carries {
            Carried::Session(checked) => Some(checked.session()),
            Carried::Key(_) => None,
        }
    }

    fn carried_is_theirs(&self) -> bool {
        let member = self.by;
        match self.carries {
            Carried::Session(checked) => {
                let session = checked.session();
                session.organization_id() == member.organization_id() && session.counts_for(member)
            }
            Carried::Key(key) => {
                key.created_by() == member.id()
                    && key.organization_id() == member.organization_id()
                    && key.is_active()
            }
        }
    }

    fn carried_admits(&self, permission: &OrgPermission) -> bool {
        match self.carries {
            Carried::Session(_) => true,
            Carried::Key(key) => permission.granted_by(key.scopes()),
        }
    }
}

/// Refuses `by` unless it is the platform, or a member who may use
/// `permission` in `organization_id`.
///
/// # Errors
///
/// - [`DomainError::Forbidden`] when a member acts without the right. See
///   [`OrgControl::ensure_may`].
pub(crate) fn ensure_platform_or_may(
    by: ActedBy<OrgControl<'_>>,
    organization_id: &OrganizationId,
    permission: OrgPermission,
) -> Result<(), DomainError> {
    match by {
        ActedBy::Platform => Ok(()),
        ActedBy::By(control) => control.ensure_may(organization_id, permission),
    }
}

impl Sealed for OrgControl<'_> {}

impl OrgSteward for OrgControl<'_> {
    fn may_take(&self, organization: &OrganizationId, step: LifecycleStep) -> bool {
        self.ensure_may(organization, OrgPermission::Tenants(tenant_right_for(step)))
            .is_ok()
    }
}

/// The organization right a step in a tenant's life needs. Making one
/// creates it; freezing and thawing a tenant change it; closing and wiping
/// it remove it.
fn tenant_right_for(step: LifecycleStep) -> TenantAction {
    match step {
        LifecycleStep::Provision => TenantAction::Create,
        LifecycleStep::Suspend | LifecycleStep::Reactivate => TenantAction::Update,
        LifecycleStep::Archive | LifecycleStep::Restore | LifecycleStep::Delete => {
            TenantAction::Delete
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::domains::authentication::methods::AuthMethod;
    use crate::domains::authentication::mfa::owed::SecondFactor;
    use crate::domains::authentication::sessions::mfa_factor::FactorProved;
    use crate::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
    use crate::domains::authentication::sessions::status::SessionStatus;
    use crate::domains::organization::access::api_key::{
        MintedThrough, OrgApiKeyRow, OrgApiKeyStatus,
    };
    use crate::domains::organization::access::session::{OrgSessionRow, SessionPlace};
    use crate::domains::organization::lifecycle::tests::founding_of;
    use crate::domains::organization::members::membership::OrgRole;
    use crate::domains::organization::members::org_user::{
        AddedBy, CreateOrgUserParams, OrgPassword,
    };
    use crate::domains::organization::members::permission::{MemberAction, OrgBillingAction};
    use crate::domains::organization::status::OrganizationStatus;
    use crate::shared::config::DisplayNameLimits;
    use crate::types::{
        CredentialChange, DisplayName, Email, Expiry, Fact, KeyPrefix, Label, OrgApiKeyId, Scope,
        SessionId, TenantId, TokenHash,
    };

    /// A finished, valid session of `member`, signed in with a password.
    pub(crate) fn session_of(member: &OrgUser) -> OrgSession {
        session_at(member, SessionPlace::Tenant(TenantId::new()))
    }

    /// A finished, valid session of `member` working at `place`, signed in
    /// with a password.
    pub(crate) fn session_at(member: &OrgUser, place: SessionPlace) -> OrgSession {
        let now = crate::shared::clock::now();
        OrgSession::reconstitute(OrgSessionRow {
            id: SessionId::new(),
            org_user_id: *member.id(),
            organization_id: *member.organization_id(),
            place,
            refresh_token_hash: TokenHash::from_stored("refresh".to_owned()),
            progress: SignInProgressRow {
                method: AuthMethod::Password,
                factor: FactorProved::NoneYet,
                owed: SecondFactor::NotOwed,
            },
            ip_address: Fact::Unknown,
            user_agent: Fact::Unknown,
            status: SessionStatus::Active,
            created_at: now,
            last_active_at: now,
            expires_at: now + time::Duration::hours(8),
            kept_through: CredentialChange::Never,
        })
        .unwrap()
    }

    /// The tenant a session [`session_of`] made works in.
    pub(crate) fn tenant_of(session: &OrgSession) -> TenantId {
        let SessionPlace::Tenant(tenant) = session.place() else {
            panic!("a test session works in a tenant");
        };
        tenant
    }

    /// An active key `member` minted with `scopes`.
    pub(crate) fn key_of(member: &OrgUser, scopes: &[&str]) -> OrgApiKey {
        OrgApiKey::reconstitute(OrgApiKeyRow {
            id: OrgApiKeyId::new(),
            organization_id: *member.organization_id(),
            name: Label::new("key_name", "CI Pipeline").unwrap(),
            key_prefix: KeyPrefix::new("oak_acme_01J").unwrap(),
            key_hash: TokenHash::from_stored("hash".to_owned()),
            scopes: scopes.iter().map(|s| Scope::new(*s).unwrap()).collect(),
            created_by: *member.id(),
            minted_through: MintedThrough::Session,
            expires_at: Expiry::Never,
            last_used_at: None,
            status: OrgApiKeyStatus::Active,
            created_at: crate::shared::clock::now(),
        })
        .unwrap()
    }

    /// `member` acting through `session`.
    pub(crate) fn acting<'a>(member: &'a OrgUser, session: &'a OrgSession) -> OrgControl<'a> {
        OrgControl::new(
            OrgStanding::new(*member.organization_id(), OrganizationStatus::Active),
            member,
            Carried::Session(CheckedOrgSession::assumed(session)),
        )
    }

    fn params(organization_id: OrganizationId, role: OrgRole) -> CreateOrgUserParams {
        CreateOrgUserParams {
            id: OrgUserId::new(),
            organization_id,
            email: Email::new("someone@acme.com").unwrap(),
            display_name: DisplayName::new("Someone", &DisplayNameLimits::default()).unwrap(),
            password_hash: OrgPassword::NotSet,
            role,
        }
    }

    /// The founding owner of a new organization.
    pub(crate) fn founder() -> OrgUser {
        let organization_id = OrganizationId::new();
        OrgUser::create(
            params(organization_id, OrgRole::Owner),
            AddedBy::Founding(founding_of(organization_id)),
        )
        .unwrap()
    }

    /// A plain member of `founder`'s organization.
    pub(crate) fn member_of(founder: &OrgUser) -> OrgUser {
        joined_as(founder, OrgRole::Member)
    }

    /// Someone `founder` brought into their organization with `role`.
    pub(crate) fn joined_as(founder: &OrgUser, role: OrgRole) -> OrgUser {
        let session = session_of(founder);
        OrgUser::create(
            params(*founder.organization_id(), role),
            AddedBy::Member(acting(founder, &session)),
        )
        .unwrap()
    }

    const UPDATE_MEMBERS: OrgPermission = OrgPermission::Members(MemberAction::Update);

    /// Sam's member session cannot authorize a member update, while Ann's
    /// owner session can.
    #[test]
    fn a_change_needs_the_role_to_carry_it() {
        let ann = founder();
        let sam = member_of(&ann);
        let (ann_session, sam_session) = (session_of(&ann), session_of(&sam));

        let by_sam = acting(&sam, &sam_session).ensure_may(sam.organization_id(), UPDATE_MEMBERS);
        let by_ann = acting(&ann, &ann_session).ensure_may(ann.organization_id(), UPDATE_MEMBERS);

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(by_ann.is_ok());
    }

    /// An owner's key scoped to view tenants cannot update members, but
    /// still authorizes viewing tenants.
    #[test]
    fn a_key_carries_only_its_scopes() {
        let ann = founder();
        let key = key_of(&ann, &["org:tenants:view"]);
        let by = OrgControl::new(
            OrgStanding::new(*ann.organization_id(), OrganizationStatus::Active),
            &ann,
            Carried::Key(&key),
        );

        assert!(matches!(
            by.ensure_may(ann.organization_id(), UPDATE_MEMBERS),
            Err(DomainError::Forbidden(_))
        ));
        assert!(
            by.ensure_may(
                ann.organization_id(),
                OrgPermission::Tenants(TenantAction::View)
            )
            .is_ok()
        );
    }

    /// Presenting Sam's session as Ann's cannot authorize an owner-level
    /// member update.
    #[test]
    fn a_session_of_someone_else_carries_nothing() {
        let ann = founder();
        let sam = member_of(&ann);
        let sams = session_of(&sam);

        let result = acting(&ann, &sams).ensure_may(ann.organization_id(), UPDATE_MEMBERS);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// An owner's valid session cannot authorize member updates in another
    /// organization.
    #[test]
    fn an_owner_of_another_organization_acts_on_nothing_here() {
        let ann = founder();
        let session = session_of(&ann);

        let result = acting(&ann, &session).ensure_may(&OrganizationId::new(), UPDATE_MEMBERS);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Members cannot archive tenants and owners can. An owner's
    /// update-scoped key permits suspension but not archival.
    #[test]
    fn a_step_in_a_tenants_life_needs_the_organization_right_for_it() {
        let ann = founder();
        let sam = member_of(&ann);
        let (ann_session, sam_session) = (session_of(&ann), session_of(&sam));
        let key = key_of(&ann, &["org:tenants:update"]);
        let by_key = OrgControl::new(
            OrgStanding::new(*ann.organization_id(), OrganizationStatus::Active),
            &ann,
            Carried::Key(&key),
        );
        let org = ann.organization_id();

        assert!(!acting(&sam, &sam_session).may_take(org, LifecycleStep::Archive));
        assert!(acting(&ann, &ann_session).may_take(org, LifecycleStep::Archive));
        assert!(by_key.may_take(org, LifecycleStep::Suspend));
        assert!(!by_key.may_take(org, LifecycleStep::Archive));
    }

    /// Members lack tenant-provisioning authority. An owner's create-scoped
    /// key permits provisioning but not suspension.
    #[test]
    fn making_a_tenant_needs_the_organization_right_to_create_one() {
        let ann = founder();
        let sam = member_of(&ann);
        let sam_session = session_of(&sam);
        let key = key_of(&ann, &["org:tenants:create"]);
        let by_key = OrgControl::new(
            OrgStanding::new(*ann.organization_id(), OrganizationStatus::Active),
            &ann,
            Carried::Key(&key),
        );
        let org = ann.organization_id();

        assert!(!acting(&sam, &sam_session).may_take(org, LifecycleStep::Provision));
        assert!(by_key.may_take(org, LifecycleStep::Provision));
        assert!(!by_key.may_take(org, LifecycleStep::Suspend));
    }

    /// An owner's session cannot authorize tenant suspension in another
    /// organization.
    #[test]
    fn an_owner_of_another_organization_moves_none_of_its_tenants() {
        let ann = founder();
        let session = session_of(&ann);

        let allowed =
            acting(&ann, &session).may_take(&OrganizationId::new(), LifecycleStep::Suspend);

        assert!(!allowed);
    }

    /// Revoking an owner's member-update key prevents it from authorizing
    /// that update.
    #[test]
    fn a_revoked_key_carries_nothing() {
        let ann = founder();
        let mut key = key_of(&ann, &["org:members:update"]);
        key.revoke(ActedBy::Platform).unwrap();
        let by = OrgControl::new(
            OrgStanding::new(*ann.organization_id(), OrganizationStatus::Active),
            &ann,
            Carried::Key(&key),
        );

        assert!(matches!(
            by.ensure_may(ann.organization_id(), UPDATE_MEMBERS),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// `member` acting through `session` on their organization while it
    /// stands at `status`.
    fn acting_while<'a>(
        status: OrganizationStatus,
        member: &'a OrgUser,
        session: &'a OrgSession,
    ) -> OrgControl<'a> {
        let standing = OrgStanding::new(*member.organization_id(), status);
        OrgControl::new(
            standing,
            member,
            Carried::Session(CheckedOrgSession::assumed(session)),
        )
    }

    /// Suspension prevents Sam's member session from viewing tenants;
    /// Ann's owner session retains that permission.
    #[test]
    fn while_an_organization_is_suspended_only_its_owners_act() {
        let ann = founder();
        let sam = member_of(&ann);
        let (ann_session, sam_session) = (session_of(&ann), session_of(&sam));
        let viewing = OrgPermission::Tenants(TenantAction::View);
        let org = ann.organization_id();

        let by_sam = acting_while(OrganizationStatus::Suspended, &sam, &sam_session)
            .ensure_may(org, viewing);
        let by_ann = acting_while(OrganizationStatus::Suspended, &ann, &ann_session)
            .ensure_may(org, viewing);

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        assert!(by_ann.is_ok());
    }

    /// While the platform holds Acme suspended over an unpaid bill, Bob, its
    /// billing contact, still opens the billing page to pay it. Ann, an
    /// admin, waits.
    #[test]
    fn while_an_organization_is_suspended_its_billing_contact_acts() {
        let founder = founder();
        let bob = joined_as(&founder, OrgRole::Billing);
        let ann = joined_as(&founder, OrgRole::Admin);
        let (bob_session, ann_session) = (session_of(&bob), session_of(&ann));
        let paying = OrgPermission::Billing(OrgBillingAction::Update);
        let org = founder.organization_id();

        let by_bob =
            acting_while(OrganizationStatus::Suspended, &bob, &bob_session).ensure_may(org, paying);
        let by_ann =
            acting_while(OrganizationStatus::Suspended, &ann, &ann_session).ensure_may(org, paying);

        assert!(by_bob.is_ok());
        assert!(matches!(by_ann, Err(DomainError::Forbidden(_))));
    }

    /// Ann, the owner, is shown every tenant's records; Max, a member, the
    /// tenants he was granted; Vic, a viewer granted one by mistake, none.
    /// Each reads the organization's log.
    #[test]
    fn a_member_is_shown_the_log_as_far_as_their_role_reaches() {
        let ann = founder();
        let (max, vic) = (member_of(&ann), joined_as(&ann, OrgRole::Viewer));
        let (ann_session, max_session, vic_session) =
            (session_of(&ann), session_of(&max), session_of(&vic));
        let tenant = TenantId::new();
        let org = ann.organization_id();

        let of_ann = acting(&ann, &ann_session).audit_log_view(org, &[]).unwrap();
        let of_max = acting(&max, &max_session)
            .audit_log_view(org, &[tenant])
            .unwrap();
        let of_vic = acting(&vic, &vic_session)
            .audit_log_view(org, &[tenant])
            .unwrap();

        assert_eq!(*of_ann.reach(), LogReach::Every);
        assert_eq!(*of_max.reach(), LogReach::Tenants(vec![tenant]));
        assert_eq!(*of_vic.reach(), LogReach::Tenants(Vec::new()));
    }

    /// Max's export reaches only the tenant he was granted, so the file
    /// made for him holds no other's records.
    #[test]
    fn an_export_is_narrowed_to_what_its_asker_reaches() {
        let ann = founder();
        let max = member_of(&ann);
        let session = session_of(&max);
        let tenant = TenantId::new();

        let access = acting(&max, &session)
            .audit_log_export(ann.organization_id(), &[tenant])
            .unwrap();

        assert_eq!(*access.reach(), LogReach::Tenants(vec![tenant]));
    }

    /// Bob, the billing contact, reads no log however far his role reaches.
    #[test]
    fn a_billing_contact_is_shown_no_log() {
        let ann = founder();
        let bob = joined_as(&ann, OrgRole::Billing);
        let session = session_of(&bob);

        let refused = acting(&bob, &session).audit_log_view(ann.organization_id(), &[]);

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// A closed organization refuses member updates even through its
    /// owner's session.
    #[test]
    fn nobody_acts_on_a_closed_organization() {
        let ann = founder();
        let session = session_of(&ann);

        let acted = acting_while(OrganizationStatus::Closed, &ann, &session)
            .ensure_may(ann.organization_id(), UPDATE_MEMBERS);

        assert!(matches!(acted, Err(DomainError::Forbidden(_))));
    }
}
