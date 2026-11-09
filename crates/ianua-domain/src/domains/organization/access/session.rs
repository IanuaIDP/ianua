//! Org sessions on the management plane.
//!
//! One is created when an org user signs in and picks a tenant to manage.
//! It carries both who the org user is and the tenant they are working in.
//! A billing contact or a viewer reaches no tenant, and a plain member may
//! not hold a grant yet, so theirs works on the organization alone.

use time::{Duration, OffsetDateTime};

use crate::domains::authentication::methods::AuthMethod;
use crate::domains::authentication::mfa::owed::SecondFactor;
use crate::domains::authentication::risk_engine::assurance::AssuranceLevel;
use crate::domains::authentication::risk_engine::step_up::StepUpPolicy;
use crate::domains::authentication::sessions::fresh_sign_in::EnrolmentProof;
use crate::domains::authentication::sessions::mfa_factor::FactorProved;
use crate::domains::authentication::sessions::proved_factor::ProvedFactor;
use crate::domains::authentication::sessions::sign_in_progress::{
    SignInProgress, SignInProgressRow, SignInRefused, SignedIn,
};
use crate::domains::authentication::sessions::status::SessionStatus;
use crate::domains::authentication::sign_in_limits::MAX_SESSION_SECS;
use crate::domains::organization::access::session_check::OrgSessionCheck;
use crate::domains::organization::access::sign_in_start::OrgSignInStart;
use crate::domains::organization::events::access::OrgSessionRevoked;
use crate::domains::organization::lifecycle::Organization;
use crate::domains::organization::members::control::{OrgControl, ensure_platform_or_may};
use crate::domains::organization::members::membership::TenantReach;
use crate::domains::organization::members::org_user::OrgUser;
use crate::domains::organization::members::permission::{MemberAction, OrgPermission};
use crate::domains::organization::members::tenant_grant::OrgTenantGrant;
use crate::isolation::organization::scope::ResolvedOrganization;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{RaisedEvents, RaisesComplete};
use crate::shared::model::row_check::RowCheck;
use crate::types::{
    ActedBy, CredentialChange, Fact, IpAddress, Lifetime, OrgUserId, OrganizationId, PrincipalId,
    SessionId, TenantId, TokenHash, UserAgent,
};

mod kept_through;
mod switch;

/// Where an organization session works: in one tenant, or on the
/// organization alone.
///
/// Bob is Acme's billing contact. Without a place of his own, his session
/// sits in a tenant it may not touch, and every tenant check has to know
/// that his role holds nothing there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPlace {
    /// It manages this tenant of the organization.
    Tenant(TenantId),
    /// It works on the organization alone and enters no tenant.
    Organization,
}

/// Parameters for creating a new org session, beside who it is for and the
/// sign-in begun for them.
pub struct CreateOrgSessionParams {
    /// Unique session identifier.
    pub id: SessionId,
    /// Where the session works.
    pub place: SessionPlace,
    /// One-way hash of the refresh token.
    pub refresh_token_hash: TokenHash,
    /// The client's IP address.
    pub ip_address: Fact<IpAddress>,
    /// The client's User-Agent.
    pub user_agent: Fact<UserAgent>,
    /// How long the session lasts from now.
    pub lifetime: Lifetime,
}

/// Who a new session is for, and what lets them into its tenant.
#[derive(Debug, Clone, Copy)]
pub struct SessionEntry<'a> {
    /// The member signing in, as they stand now.
    pub member: &'a OrgUser,
    /// Their organization, as it stands now.
    pub organization: &'a Organization,
    /// The member's tenant grants. An owner needs none.
    pub grants: &'a [OrgTenantGrant],
}

/// Where a session moves to: the new session's id, tenant and refresh
/// token, and what lets its member into that tenant.
#[derive(Debug)]
pub struct SessionSwitch<'a> {
    /// The new session's identifier.
    pub id: SessionId,
    /// The tenant the member moves to.
    pub tenant_id: TenantId,
    /// One-way hash of the new session's refresh token.
    pub refresh_token_hash: TokenHash,
    /// The member, their organization and their grants, as they stand now.
    pub entry: SessionEntry<'a>,
}

/// A session as stored, for rebuilding it with [`OrgSession::reconstitute`].
pub struct OrgSessionRow {
    /// Unique session identifier.
    pub id: SessionId,
    /// The authenticated org user.
    pub org_user_id: OrgUserId,
    /// The org user's organization.
    pub organization_id: OrganizationId,
    /// Where the session works.
    pub place: SessionPlace,
    /// One-way hash of the refresh token.
    pub refresh_token_hash: TokenHash,
    /// The way in, the factor proved and what is still owed.
    pub progress: SignInProgressRow,
    /// The client's IP address.
    pub ip_address: Fact<IpAddress>,
    /// The client's User-Agent.
    pub user_agent: Fact<UserAgent>,
    /// Current lifecycle status.
    pub status: SessionStatus,
    /// When this session was created.
    pub created_at: OffsetDateTime,
    /// When the session was last used.
    pub last_active_at: OffsetDateTime,
    /// When this session expires.
    pub expires_at: OffsetDateTime,
    /// The change of how the member signs in this session was kept
    /// through, or [`CredentialChange::Never`].
    pub kept_through: CredentialChange,
}

/// A management plane session.
///
/// Proves an org user has signed in and is managing one tenant, or the
/// organization alone. The bearer token resolves to this session, which
/// gives the org user, the organization and where it works.
#[derive(Debug)]
pub struct OrgSession {
    id: SessionId,
    org_user_id: OrgUserId,
    organization_id: OrganizationId,
    place: SessionPlace,
    refresh_token_hash: TokenHash,
    progress: SignInProgress,
    ip_address: Fact<IpAddress>,
    user_agent: Fact<UserAgent>,
    status: SessionStatus,
    created_at: OffsetDateTime,
    last_active_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    kept_through: CredentialChange,
    raised: RaisedEvents,
}

impl OrgSession {
    /// Creates a new active org session for `entry.member`, where `params`
    /// places it, holding the sign-in `start` began for that member.
    ///
    /// A session in a tenant lets its holder manage that tenant. So the
    /// member must be able to sign in, the organization must still be open
    /// and own the tenant, and a plain member must hold a grant for it. Sam
    /// is a plain member granted only `staging`. Without this check, he
    /// picks `production` at sign-in and manages it. Any active member may
    /// open a session on the organization alone: a billing contact or a
    /// viewer always does, since their role reaches no tenant, and so does
    /// a plain member nobody granted a tenant yet. Such a session enters no
    /// tenant. A session that owes nothing has already met the
    /// organization's baseline.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `start` was begun for another
    ///   member than `entry.member`.
    /// - [`DomainError::Forbidden`] when the member may not sign in, is in
    ///   another organization, or may not reach the tenant.
    /// - [`DomainError::Forbidden`] when the organization is closed, or does
    ///   not own the tenant.
    /// - [`DomainError::Forbidden`] when the organization is suspended and
    ///   the member is not an owner.
    /// - [`DomainError::Validation`] when `params.lifetime` is longer than
    ///   `MAX_SESSION_SECS`, the longest an organization may set.
    pub fn create(
        params: CreateOrgSessionParams,
        entry: SessionEntry<'_>,
        start: OrgSignInStart,
    ) -> Result<Self, DomainError> {
        let (member, progress) = start.into_parts();
        if member != *entry.member.id() {
            return Err(DomainError::forbidden(message!(
                "organization-the-sign-in-was-begun-for",
                "the sign-in was begun for another member"
            )));
        }
        params.lifetime.ensure_at_most(
            Duration::seconds(i64::from(MAX_SESSION_SECS)),
            "an organization session",
        )?;
        ensure_may_enter(&entry, params.place)?;
        let now = crate::shared::clock::now();
        Ok(Self {
            id: params.id,
            org_user_id: *entry.member.id(),
            organization_id: *entry.organization.id(),
            place: params.place,
            refresh_token_hash: params.refresh_token_hash,
            progress,
            ip_address: params.ip_address,
            user_agent: params.user_agent,
            status: SessionStatus::Active,
            created_at: now,
            last_active_at: now,
            expires_at: params.lifetime.ends_after(now),
            kept_through: CredentialChange::Never,
            raised: RaisedEvents::default(),
        })
    }

    /// Rebuilds an organization session from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says the session was
    ///   used, or expires, before it was created.
    /// - [`DomainError::Infrastructure`] when the row holds a sign-in progress
    ///   no sign-in reaches.
    pub fn reconstitute(row: OrgSessionRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            org_user_id: row.org_user_id,
            organization_id: row.organization_id,
            place: row.place,
            refresh_token_hash: row.refresh_token_hash,
            progress: SignInProgress::reconstitute(row.progress)?,
            ip_address: row.ip_address,
            user_agent: row.user_agent,
            status: row.status,
            created_at: row.created_at,
            last_active_at: row.last_active_at,
            expires_at: row.expires_at,
            kept_through: row.kept_through,
            raised: RaisedEvents::default(),
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &OrgSessionRow) -> Result<(), DomainError> {
        RowCheck::of("organization session")
            .in_order(
                row.created_at,
                row.last_active_at,
                "used before it was created",
            )
            .in_order(
                row.created_at,
                row.expires_at,
                "expires before it was created",
            )
            .finish()
    }

    /// Unique session identifier.
    #[must_use]
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// The authenticated org user.
    #[must_use]
    pub fn org_user_id(&self) -> &OrgUserId {
        &self.org_user_id
    }

    /// The org user's organization.
    #[must_use]
    pub fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// Where the session works: the tenant it manages, or the organization
    /// alone.
    #[must_use]
    pub fn place(&self) -> SessionPlace {
        self.place
    }

    /// One-way hash of the refresh token.
    #[must_use]
    pub fn refresh_token_hash(&self) -> &TokenHash {
        &self.refresh_token_hash
    }

    /// How far the sign-in has come.
    #[must_use]
    pub fn progress(&self) -> &SignInProgress {
        &self.progress
    }

    /// How the administrator signed in.
    #[must_use]
    pub fn auth_method(&self) -> AuthMethod {
        self.progress.method()
    }

    /// Leave to set up the second factor the organization requires, while
    /// this sign-in waits for it and began moments ago.
    ///
    /// Setting up a factor asks for a fresh proof. A member who must set one
    /// up before they are let in has just proved what the sign-in asked, so
    /// the sign-in itself lets them set it up for a few minutes, and nothing
    /// else. A passkey-only member gets in this way, with no password to
    /// prove again.
    #[must_use]
    pub fn enrolment_proof(&self, now: OffsetDateTime) -> Option<EnrolmentProof> {
        let waiting = self.status == SessionStatus::Active
            && now < self.expires_at
            && self.progress.owed() == SecondFactor::Enrol;
        if !waiting {
            return None;
        }
        EnrolmentProof::of_sign_in(self.org_user_id.into(), self.created_at, now)
    }

    /// Whether the sign-in owes nothing more, and so met the baseline.
    #[must_use]
    pub fn mfa_satisfied(&self) -> bool {
        self.progress.is_complete()
    }

    /// The strongest second factor proved, or that none was.
    #[must_use]
    pub fn mfa_method(&self) -> FactorProved {
        self.progress.factor()
    }

    /// What the sign-in still owes.
    #[must_use]
    pub fn owed(&self) -> SecondFactor {
        self.progress.owed()
    }

    /// The assurance the sign-in has reached.
    #[must_use]
    pub fn assurance_level(&self) -> AssuranceLevel {
        self.progress.assurance_level()
    }

    /// The client's IP address.
    #[must_use]
    pub fn ip_address(&self) -> Fact<&IpAddress> {
        self.ip_address.as_ref()
    }

    /// The client's User-Agent.
    #[must_use]
    pub fn user_agent(&self) -> Fact<&UserAgent> {
        self.user_agent.as_ref()
    }

    /// Current lifecycle status.
    #[must_use]
    pub fn status(&self) -> SessionStatus {
        self.status
    }

    /// When this session was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// When the session was last used.
    #[must_use]
    pub fn last_active_at(&self) -> OffsetDateTime {
        self.last_active_at
    }

    /// When this session expires.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// Whether this session is valid. It must be active, not expired, and
    /// owe nothing more to finish signing in.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.status == SessionStatus::Active
            && self.expires_at > crate::shared::clock::now()
            && self.progress.is_complete()
    }

    /// Whether this session still counts for `member` as they stand now.
    ///
    /// It must be valid on its own and be `member`'s. The member must still
    /// be able to sign in, and must not have changed how they sign in since
    /// it opened, unless that change is the one it was kept through. A new
    /// password ends every session opened before it, so whoever held the
    /// old one is out.
    #[must_use]
    pub fn counts_for(&self, member: &OrgUser) -> bool {
        let changed = member.credentials_changed_at();
        self.is_valid()
            && member.id() == &self.org_user_id
            && member.status().can_authenticate()
            && (!changed.since(self.created_at) || changed == self.kept_through)
    }

    /// The member and their finished sign-in, while this session still
    /// counts under `check`.
    #[must_use]
    pub fn signed_in(&self, check: &OrgSessionCheck<'_>) -> Option<SignedIn<ResolvedOrganization>> {
        check
            .admits(self)
            .then(|| SignedIn::of(self.org_user_id.into(), self.progress.carried()))
    }

    /// Revokes this session, as `by` decides: the member signing out, a
    /// member who may update members, or the platform, as after a password
    /// change. Raises `organization.org_session_revoked`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when someone else revokes it without the
    ///   right to update members.
    /// - [`DomainError::InvalidTransition`] if it is already revoked.
    pub fn revoke(&mut self, by: ActedBy<OrgControl<'_>>) -> Result<(), DomainError> {
        self.ensure_may_revoke(by)?;
        self.status = self.status.try_transition(SessionStatus::Revoked)?;
        self.raised.raise_organization(OrgSessionRevoked {
            organization_id: self.organization_id,
            org_user_id: self.org_user_id,
            session_id: self.id,
            occurred_at: crate::shared::clock::now(),
        });
        Ok(())
    }

    /// Refuses `by` ending this session unless it is the session's own
    /// member, the platform, or a member who may update members.
    fn ensure_may_revoke(&self, by: ActedBy<OrgControl<'_>>) -> Result<(), DomainError> {
        match by {
            ActedBy::By(control) if control.is_member(&self.org_user_id) => {
                control.ensure_genuine(&self.organization_id)
            }
            ActedBy::By(_) | ActedBy::Platform => ensure_platform_or_may(
                by,
                &self.organization_id,
                OrgPermission::Members(MemberAction::Update),
            ),
        }
    }

    /// Records activity on this session.
    pub fn touch(&mut self) {
        self.last_active_at = crate::shared::clock::now();
    }

    /// Records the factor the administrator proved, under the
    /// organization's `policy`. `member` is the session's member, as they
    /// stand now. The session is unchanged when the answer is refused.
    ///
    /// Setting up a factor is a change of how the member signs in, and such
    /// a change ends every session opened before it. A sign-in that owed a
    /// factor to set up is answered by the factor it just set up. So that
    /// answer keeps the session through the member's latest change, or the
    /// sign-in would end the moment it finished.
    ///
    /// # Errors
    ///
    /// - [`SignInRefused::ForAnotherAccount`] when the factor was proved for
    ///   another member, or `member` is not this session's. Mallory's own
    ///   code never finishes Ann's sign-in.
    /// - [`SignInRefused`] when the factor does not answer what is owed.
    /// - [`SignInRefused`] when it would not raise a finished sign-in.
    /// - [`SignInRefused`] when it would finish the sign-in below the baseline.
    pub fn answer(
        &mut self,
        member: &OrgUser,
        proof: ProvedFactor,
        policy: &StepUpPolicy,
    ) -> Result<(), SignInRefused> {
        let own = PrincipalId::from(self.org_user_id);
        if *member.id() != self.org_user_id {
            return Err(SignInRefused::ForAnotherAccount);
        }
        let factor = proof.for_account(own)?;
        let was_owed = self.progress.owed();
        self.progress = self.progress.answer(factor, policy)?;
        if was_owed == SecondFactor::Enrol {
            self.kept_through = member.credentials_changed_at();
        }
        Ok(())
    }
}

impl RaisesComplete for OrgSession {
    fn take_events(&mut self) -> Vec<DomainEvent> {
        self.raised.take()
    }
}

/// Refuses `entry` opening a session at `place` unless the member may sign
/// in, belongs to the open organization, and reaches the tenant `place`
/// names, if it names one. While the organization is suspended, by anyone,
/// only owners and the billing contact sign in, so they can settle what
/// caused it.
fn ensure_may_enter(entry: &SessionEntry<'_>, place: SessionPlace) -> Result<(), DomainError> {
    let (member, organization) = (entry.member, entry.organization);
    if !member.status().can_authenticate() || member.organization_id() != organization.id() {
        return Err(DomainError::forbidden(message!(
            "organization-only-an-active-member-of-the-3",
            "only an active member of the organization signs in to it"
        )));
    }
    organization.standing().ensure_admits(member.role())?;
    match place {
        SessionPlace::Organization => Ok(()),
        SessionPlace::Tenant(tenant_id) => ensure_reaches(entry, &tenant_id),
    }
}

/// Refuses `entry`'s member a session in `tenant_id` unless the
/// organization owns it and the member reaches it: an owner or admin
/// reaches every tenant, a member those they were granted, a billing
/// contact or a viewer none.
///
/// Bob is the billing contact. Without this, his session sits in a tenant
/// and every check inside it has to remember that he holds nothing there.
fn ensure_reaches(entry: &SessionEntry<'_>, tenant_id: &TenantId) -> Result<(), DomainError> {
    if !entry.organization.owns_tenant(tenant_id) {
        return Err(DomainError::forbidden(message!(
            "organization-the-tenant-is-not-one-of",
            "the tenant is not one of the organization's"
        )));
    }
    match entry.member.role().tenant_reach() {
        TenantReach::Every => Ok(()),
        TenantReach::Granted if holds_grant(entry, tenant_id) => Ok(()),
        TenantReach::Granted => Err(DomainError::forbidden(message!(
            "organization-the-member-holds-no-grant-for",
            "the member holds no grant for this tenant"
        ))),
        TenantReach::Nothing => Err(DomainError::forbidden(message!(
            "organization-the-member-s-role-reaches-no",
            "the member's role reaches no tenant, so their session works on the organization alone"
        ))),
    }
}

/// Whether the entry's grants give its member `tenant_id`.
fn holds_grant(entry: &SessionEntry<'_>, tenant_id: &TenantId) -> bool {
    entry
        .grants
        .iter()
        .any(|grant| grant.org_user_id() == entry.member.id() && grant.tenant_id() == tenant_id)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::domains::authentication::credentials::password::PasswordHasher;
    use crate::domains::authentication::sessions::fresh_sign_in::fresh_proof_of;
    use crate::domains::authentication::sessions::mfa_factor::MfaFactor;
    use crate::domains::authentication::sessions::proved_factor::proved;
    use crate::domains::authentication::sessions::sign_in_progress::{
        LocalMethod, finished_sign_in_of,
    };
    use crate::domains::authentication::sessions::way_in::WayIn;
    use crate::domains::organization::access::auth_config::{
        OrganizationAuthConfig, OrganizationAuthSettings,
    };
    use crate::domains::organization::billing::plan::OrganizationPlan;
    use crate::domains::organization::lifecycle::CreateOrganizationParams;
    use crate::domains::organization::lifecycle::tests::tenant_with;
    use crate::domains::organization::members::control::tests::{acting, session_of};
    use crate::domains::organization::members::membership::OrgRole;
    use crate::domains::organization::members::org_user::{
        AddedBy, CreateOrgUserParams, OrgPassword,
    };
    use crate::domains::organization::members::org_user_status::OrgUserStatus;
    use crate::domains::organization::members::owners::Owners;
    use crate::domains::organization::members::tenant_grant::OrgTenantGrantRow;
    use crate::domains::organization::status::{OrgStanding, OrganizationStatus};
    use crate::shared::config::{DisplayNameLimits, SlugLimits};
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::builders::org_user;
    use crate::test_support::fakes::FakeHasher;
    use crate::types::{DisplayName, Email, Label, RoleId, Seconds, TenantSlug};

    /// Acme on Business, owning `tenant`, with its founder.
    pub(crate) fn acme_with(tenant: TenantId) -> (Organization, OrgUser) {
        let (mut organization, founding) = Organization::create(CreateOrganizationParams {
            id: OrganizationId::new(),
            slug: TenantSlug::new("acme", &SlugLimits::default()).unwrap(),
            name: Label::new("org_name", "Acme").unwrap(),
            contact_email: Email::new("admin@acme.com").unwrap(),
            display_name: DisplayName::new("Acme", &DisplayNameLimits::default()).unwrap(),
            plan: OrganizationPlan::Business,
        })
        .unwrap();
        organization
            .add_tenant(&tenant_with(tenant), ActedBy::Platform)
            .unwrap();
        let founder = OrgUser::create(
            user_params(&organization, OrgRole::Owner),
            AddedBy::Founding(founding),
        )
        .unwrap();
        (organization, founder)
    }

    fn user_params(organization: &Organization, role: OrgRole) -> CreateOrgUserParams {
        CreateOrgUserParams {
            id: OrgUserId::new(),
            organization_id: *organization.id(),
            email: Email::new("ann@acme.com").unwrap(),
            display_name: DisplayName::new("Ann", &DisplayNameLimits::default()).unwrap(),
            password_hash: OrgPassword::NotSet,
            role,
        }
    }

    /// A plain member of `organization`, added by `founder`.
    pub(crate) fn plain_member(organization: &Organization, founder: &OrgUser) -> OrgUser {
        let session = session_of(founder);
        OrgUser::create(
            user_params(organization, OrgRole::Member),
            AddedBy::Member(acting(founder, &session)),
        )
        .unwrap()
    }

    /// A grant of `tenant` to `member`, made by `by`.
    fn grant_of(member: &OrgUser, tenant: TenantId, by: &OrgUser) -> OrgTenantGrant {
        OrgTenantGrant::reconstitute(OrgTenantGrantRow {
            org_user_id: *member.id(),
            tenant_id: tenant,
            role_id: RoleId::new(),
            granted_by: ActedBy::By(*by.id()),
            granted_at: crate::shared::clock::now(),
        })
        .unwrap()
    }

    /// An organization's sign-in settings with a relaxed step-up policy.
    fn relaxed_config() -> OrganizationAuthConfig {
        OrganizationAuthConfig::new(OrganizationAuthSettings {
            step_up_policy: StepUpPolicy::relaxed(),
            ..OrganizationAuthSettings::default()
        })
        .unwrap()
    }

    /// A password sign-in begun for `member`, owing `owed`.
    fn start_for(member: &OrgUser, owed: SecondFactor) -> OrgSignInStart {
        let way_in = WayIn::by_password((*member.id()).into());
        OrgSignInStart::new(member, way_in, owed, &relaxed_config()).unwrap()
    }

    /// `member` of `organization`, without grants, entering with `params`
    /// on a sign-in that owes nothing.
    fn entered(
        params: CreateOrgSessionParams,
        member: &OrgUser,
        organization: &Organization,
    ) -> Result<OrgSession, DomainError> {
        OrgSession::create(
            params,
            SessionEntry {
                member,
                organization,
                grants: &[],
            },
            start_for(member, SecondFactor::NotOwed),
        )
    }

    /// A session opened with `params` for the founder of an Acme that owns
    /// the tenant it names, on a sign-in that still owes `owed`.
    fn opened(params: CreateOrgSessionParams, owed: SecondFactor) -> OrgSession {
        let SessionPlace::Tenant(tenant) = params.place else {
            panic!("a test session opens in a tenant");
        };
        let (organization, owner) = acme_with(tenant);
        OrgSession::create(
            params,
            SessionEntry {
                member: &owner,
                organization: &organization,
                grants: &[],
            },
            start_for(&owner, owed),
        )
        .unwrap()
    }

    fn create_params() -> CreateOrgSessionParams {
        CreateOrgSessionParams {
            id: SessionId::new(),
            place: SessionPlace::Tenant(TenantId::new()),
            refresh_token_hash: TokenHash::from_stored("hash_0".to_owned()),
            ip_address: Fact::Unknown,
            user_agent: Fact::Unknown,
            lifetime: Lifetime::seconds(3600).unwrap(),
        }
    }

    /// Ann enters her password and still owes a second factor. Her session is
    /// active but not valid. A sign-in that owes nothing is valid at once.
    #[test]
    fn create_produces_active_session() {
        let owing = opened(create_params(), SecondFactor::Verify);
        let signed_in = opened(create_params(), SecondFactor::NotOwed);

        assert_eq!(owing.status(), SessionStatus::Active);
        assert!(!owing.mfa_satisfied());
        assert!(!owing.is_valid());
        assert!(signed_in.is_valid());
    }

    /// Ann's sign-in asks for a session of a year. The longest an
    /// organization may set is thirty days, so no session opens.
    #[test]
    fn a_session_longer_than_any_organization_may_set_is_refused() {
        let tenant = TenantId::new();
        let (organization, owner) = acme_with(tenant);

        let result = OrgSession::create(
            CreateOrgSessionParams {
                place: SessionPlace::Tenant(tenant),
                lifetime: Lifetime::seconds(365 * 86_400).unwrap(),
                ..create_params()
            },
            SessionEntry {
                member: &owner,
                organization: &organization,
                grants: &[],
            },
            start_for(&owner, SecondFactor::NotOwed),
        );

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// The platform revokes Ann's session after her password changed. It
    /// reads as revoked and is no longer valid.
    #[test]
    fn revoke_transitions_to_revoked() {
        let mut session = opened(create_params(), SecondFactor::Verify);

        session.revoke(ActedBy::Platform).unwrap();

        assert_eq!(session.status(), SessionStatus::Revoked);
        assert!(!session.is_valid());
    }

    /// A plain member cannot enter an ungranted tenant; granting that tenant permits entry.
    #[test]
    fn a_plain_member_enters_only_a_tenant_they_hold_a_grant_for() {
        let production = TenantId::new();
        let (organization, founder) = acme_with(production);
        let sam = plain_member(&organization, &founder);
        let grant = grant_of(&sam, production, &founder);
        let params = || CreateOrgSessionParams {
            place: SessionPlace::Tenant(production),
            ..create_params()
        };
        let with_grant = SessionEntry {
            member: &sam,
            organization: &organization,
            grants: std::slice::from_ref(&grant),
        };

        let without = entered(params(), &sam, &organization);
        let with = OrgSession::create(params(), with_grant, start_for(&sam, SecondFactor::NotOwed));

        assert!(matches!(without, Err(DomainError::Forbidden(_))));
        assert_eq!(*with.unwrap().org_user_id(), *sam.id());
    }

    /// An organization owner cannot open a session for another organization's tenant.
    #[test]
    fn a_session_names_only_a_tenant_of_the_organization() {
        let (organization, ann) = acme_with(TenantId::new());

        let result = entered(create_params(), &ann, &organization);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A closed organization refuses even its owner's sign-in.
    #[test]
    fn nobody_signs_in_to_a_closed_organization() {
        let tenant = TenantId::new();
        let (mut organization, ann) = acme_with(tenant);
        organization
            .change_status(OrganizationStatus::Closed, ActedBy::Platform)
            .unwrap();
        let params = CreateOrgSessionParams {
            place: SessionPlace::Tenant(tenant),
            ..create_params()
        };

        let result = entered(params, &ann, &organization);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// Owning another organization does not authorize a session in Acme.
    #[test]
    fn an_owner_of_another_organization_does_not_sign_in_here() {
        let tenant = TenantId::new();
        let (acme, _) = acme_with(tenant);
        let (_, mallory) = acme_with(TenantId::new());
        let params = CreateOrgSessionParams {
            place: SessionPlace::Tenant(tenant),
            ..create_params()
        };

        let result = entered(params, &mallory, &acme);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A locked member cannot open a session despite holding a tenant grant.
    #[test]
    fn a_locked_member_does_not_sign_in() {
        let production = TenantId::new();
        let (organization, founder) = acme_with(production);
        let mut sam = plain_member(&organization, &founder);
        let grant = grant_of(&sam, production, &founder);
        let session = session_of(&founder);
        sam.change_status(
            OrgUserStatus::Locked,
            &acting(&founder, &session),
            Owners::of(std::slice::from_ref(&founder)),
        )
        .unwrap();

        let result = OrgSession::create(
            CreateOrgSessionParams {
                place: SessionPlace::Tenant(production),
                ..create_params()
            },
            SessionEntry {
                member: &sam,
                organization: &organization,
                grants: std::slice::from_ref(&grant),
            },
            start_for(&sam, SecondFactor::NotOwed),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A sign-in begun for Mallory cannot open a session for Ann.
    #[test]
    fn a_sign_in_begun_for_one_member_opens_no_session_for_another() {
        let tenant = TenantId::new();
        let (organization, ann) = acme_with(tenant);
        let mallory = plain_member(&organization, &ann);

        let result = OrgSession::create(
            CreateOrgSessionParams {
                place: SessionPlace::Tenant(tenant),
                ..create_params()
            },
            SessionEntry {
                member: &ann,
                organization: &organization,
                grants: &[],
            },
            start_for(&mallory, SecondFactor::NotOwed),
        );

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// A password proof for Mallory cannot begin Ann's sign-in.
    #[test]
    fn a_way_in_proved_for_another_member_begins_no_sign_in() {
        let (organization, ann) = acme_with(TenantId::new());
        let mallory = plain_member(&organization, &ann);
        let mallorys = WayIn::by_password((*mallory.id()).into());

        let refused = OrgSignInStart::new(&ann, mallorys, SecondFactor::NotOwed, &relaxed_config());

        assert_eq!(refused.err(), Some(SignInRefused::ForAnotherAccount));
    }

    /// Ann types her password. It makes a password way into her account,
    /// and a wrong one makes none.
    #[test]
    fn a_members_own_password_makes_a_way_in() {
        let (organization, founder) = acme_with(TenantId::new());
        let session = session_of(&founder);
        let ann = OrgUser::create(
            CreateOrgUserParams {
                password_hash: OrgPassword::Set(FakeHasher.hash("right").unwrap()),
                ..user_params(&organization, OrgRole::Member)
            },
            AddedBy::Member(acting(&founder, &session)),
        )
        .unwrap();

        let way_in = ann.sign_in_with_password("right", &FakeHasher).unwrap();
        let wrong = ann.sign_in_with_password("guess", &FakeHasher);

        assert_eq!(way_in.account(), PrincipalId::from(*ann.id()));
        assert_eq!(way_in.method(), LocalMethod::Password);
        assert!(matches!(wrong, Err(DomainError::Forbidden(_))));
    }

    /// A plain member cannot revoke Ann's session, while Ann can end it herself.
    #[test]
    fn only_the_holder_or_a_manager_ends_a_session() {
        let tenant = TenantId::new();
        let (organization, ann) = acme_with(tenant);
        let sam = plain_member(&organization, &ann);
        let params = CreateOrgSessionParams {
            place: SessionPlace::Tenant(tenant),
            ..create_params()
        };
        let mut anns = entered(params, &ann, &organization).unwrap();
        let sams = session_of(&sam);
        let own = session_of(&ann);

        let by_sam = anns.revoke(ActedBy::By(acting(&sam, &sams)));
        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        anns.revoke(ActedBy::By(acting(&ann, &own))).unwrap();

        assert_eq!(anns.status(), SessionStatus::Revoked);
    }

    /// `factor`, proved for the session's own member.
    fn for_member(session: &OrgSession, factor: MfaFactor) -> ProvedFactor {
        proved((*session.org_user_id()).into(), factor)
    }

    /// The session's own member, who never changed how they sign in.
    fn member_of(session: &OrgSession) -> OrgUser {
        org_user(*session.org_user_id(), "ann@acme.com")
    }

    /// `session` answered with `proof`, for its own member.
    fn answered(
        session: &mut OrgSession,
        proof: ProvedFactor,
        policy: &StepUpPolicy,
    ) -> Result<(), SignInRefused> {
        let member = member_of(session);
        session.answer(&member, proof, policy)
    }

    /// Ann owes a second factor and enters a TOTP code under a strict policy.
    /// Her sign-in is finished at AAL2 with TOTP recorded.
    #[test]
    fn answering_what_is_owed_completes_the_session() {
        let mut session = opened(create_params(), SecondFactor::Verify);

        let totp = for_member(&session, MfaFactor::Totp);
        answered(&mut session, totp, &StepUpPolicy::strict()).unwrap();

        assert!(session.mfa_satisfied());
        assert_eq!(session.mfa_method(), FactorProved::Proved(MfaFactor::Totp));
        assert_eq!(session.assurance_level(), AssuranceLevel::Aal2);
    }

    /// A recovery code below the assurance baseline leaves sign-in unfinished and requires enrollment.
    #[test]
    fn a_recovery_code_below_the_baseline_does_not_finish_the_sign_in() {
        let mut session = opened(create_params(), SecondFactor::Verify);

        let code = for_member(&session, MfaFactor::RecoveryCode);
        answered(&mut session, code, &StepUpPolicy::strict()).unwrap();

        assert!(!session.mfa_satisfied());
        assert_eq!(session.owed(), SecondFactor::Enrol);
    }

    /// Ann owes a second factor and offers an email confirmation, which does
    /// not answer it. The answer is refused and her session is unchanged.
    #[test]
    fn a_refused_answer_leaves_the_session_as_it_was() {
        let mut session = opened(create_params(), SecondFactor::Verify);

        let link = for_member(&session, MfaFactor::EmailConfirmation);
        let refused = answered(&mut session, link, &StepUpPolicy::relaxed());

        assert!(refused.is_err());
        assert!(!session.mfa_satisfied());
        assert_eq!(session.auth_method(), AuthMethod::Password);
    }

    /// A session opened for an hour is checked an hour after it opened. It
    /// ends its lifetime after it opened, so it is no longer valid.
    #[test]
    fn expired_session_is_not_valid() {
        let session = opened(create_params(), SecondFactor::NotOwed);
        let _later = crate::shared::clock::freeze(session.created_at() + time::Duration::hours(1));

        assert_eq!(
            session.expires_at(),
            session.created_at() + time::Duration::hours(1)
        );
        assert!(!session.is_valid());
    }

    /// A finished passkey sign-in with a hardware key is loaded from storage.
    /// Its ids, method, factor and token hash come back as stored.
    #[test]
    fn reconstitute_preserves_all_fields() {
        let row = stored_passkey_session();
        let (id, org_user_id, org_id, place) =
            (row.id, row.org_user_id, row.organization_id, row.place);

        let session = OrgSession::reconstitute(row).unwrap();

        assert_eq!(*session.id(), id);
        assert_eq!(*session.org_user_id(), org_user_id);
        assert_eq!(*session.organization_id(), org_id);
        assert_eq!(session.place(), place);
        assert!(session.mfa_satisfied());
        assert_eq!(session.auth_method(), AuthMethod::Passkey);
        assert_eq!(
            session.mfa_method(),
            FactorProved::Proved(MfaFactor::HardwareKey)
        );
        assert_eq!(session.refresh_token_hash().as_str(), "stored_hash");
    }

    /// Ann signs in from `10.0.0.1` with a Mozilla browser. Her session
    /// reports both. A session opened with neither reports them as unknown.
    #[test]
    fn a_session_reports_the_address_and_client_it_was_opened_from() {
        let mut p = create_params();
        p.ip_address = Fact::Known(IpAddress::new("10.0.0.1").unwrap());
        p.user_agent = Fact::Known(UserAgent::new("Mozilla/5.0").unwrap());

        let session = opened(p, SecondFactor::Verify);

        assert_eq!(session.ip_address().known().unwrap().as_str(), "10.0.0.1");
        assert_eq!(
            session.user_agent().known().unwrap().as_str(),
            "Mozilla/5.0"
        );
        assert!(opened(create_params(), SecondFactor::Verify).ip_address() == Fact::Unknown);
    }

    /// A signed-in session is checked one second before its expiry and at
    /// the expiry itself. It is valid before and not valid at that instant.
    #[test]
    fn a_session_stops_being_valid_at_the_instant_it_expires() {
        let session = opened(create_params(), SecondFactor::NotOwed);
        let expiry = session.expires_at();

        {
            let _frozen = crate::shared::clock::freeze(expiry - time::Duration::seconds(1));
            assert!(session.is_valid());
        }

        let _frozen = crate::shared::clock::freeze(expiry);
        assert!(!session.is_valid());
    }

    /// Ann uses her session five minutes after signing in. Its last activity
    /// moves to then and its creation time stays, so the idle timeout counts
    /// from her last use.
    #[test]
    fn recording_activity_moves_the_last_active_timestamp() {
        let mut session = opened(create_params(), SecondFactor::Verify);
        let opened = session.last_active_at();
        let later = opened + time::Duration::minutes(5);

        let _frozen = crate::shared::clock::freeze(later);
        session.touch();

        assert_eq!(session.last_active_at(), later);
        assert_eq!(session.created_at(), opened);
    }

    /// A stored row says the session was last used a second before it was
    /// created. Loading it is refused as a corrupt row.
    #[test]
    fn a_stored_session_used_before_it_was_created_is_refused() {
        let now = crate::shared::clock::now();

        let session = OrgSession::reconstitute(OrgSessionRow {
            id: SessionId::new(),
            org_user_id: OrgUserId::new(),
            organization_id: OrganizationId::new(),
            place: SessionPlace::Tenant(TenantId::new()),
            refresh_token_hash: TokenHash::from_stored("stored_hash".to_owned()),
            progress: SignInProgressRow {
                method: AuthMethod::Passkey,
                factor: FactorProved::NoneYet,
                owed: SecondFactor::NotOwed,
            },
            ip_address: Fact::Unknown,
            user_agent: Fact::Unknown,
            status: SessionStatus::Active,
            created_at: now,
            last_active_at: now - time::Duration::SECOND,
            expires_at: now + time::Duration::hours(2),
            kept_through: CredentialChange::Never,
        });

        assert!(refused_as_corrupt(&session));
    }

    /// Another member's factor proof is refused and leaves Ann's factor requirement outstanding.
    #[test]
    fn a_factor_proved_for_another_member_finishes_nothing() {
        let mut session = opened(create_params(), SecondFactor::Verify);
        let mallorys = proved(OrgUserId::new().into(), MfaFactor::Totp);

        let refused = answered(&mut session, mallorys, &StepUpPolicy::strict());

        assert_eq!(refused, Err(SignInRefused::ForAnotherAccount));
        assert!(!session.mfa_satisfied());
    }

    /// `session`'s member, who changed how they sign in a second after it
    /// opened. The clock stays a second on while the guard lives.
    fn changed_after(session: &OrgSession) -> (OrgUser, crate::shared::clock::FrozenClock) {
        let later = crate::shared::clock::freeze(session.created_at() + time::Duration::SECOND);
        let mut member = member_of(session);
        member.record_credential_change();
        (member, later)
    }

    /// Olivia's organization requires a second factor she has none of. She
    /// signs in, sets up TOTP, which records a change of how she signs in,
    /// and answers with it. Her session counts, rather than ending the
    /// moment her sign-in finished.
    #[test]
    fn a_member_sign_in_finished_by_the_factor_it_set_up_still_counts() {
        let mut session = opened(create_params(), SecondFactor::Enrol);
        let (olivia, _later) = changed_after(&session);
        let code = for_member(&session, MfaFactor::Totp);

        session
            .answer(&olivia, code, &StepUpPolicy::relaxed())
            .unwrap();

        assert!(session.counts_for(&olivia));
    }

    /// Completing factor verification without setting up credentials does not
    /// mark the session as surviving a credential change.
    #[test]
    fn a_member_sign_in_that_set_up_nothing_is_not_kept_through_a_change() {
        let mut session = opened(create_params(), SecondFactor::Verify);
        let (olivia, _later) = changed_after(&session);
        let code = for_member(&session, MfaFactor::Totp);

        session
            .answer(&olivia, code, &StepUpPolicy::relaxed())
            .unwrap();

        assert!(!session.counts_for(&olivia));
    }

    /// Olivia adds a passkey from her laptop's session, having proved who
    /// she is again. The laptop's session stays through the change.
    #[test]
    fn the_session_a_member_added_a_passkey_from_is_kept_through_it() {
        let mut laptop = opened(create_params(), SecondFactor::NotOwed);
        let (olivia, _later) = changed_after(&laptop);
        let proof = fresh_proof_of((*olivia.id()).into());

        laptop.keep_through_own_change(&olivia, &proof).unwrap();

        assert!(laptop.counts_for(&olivia));
    }

    /// Another member's fresh proof cannot preserve Olivia's session through a password change.
    #[test]
    fn a_member_session_is_not_kept_through_a_change_on_someone_elses_proof() {
        let mut stolen = opened(create_params(), SecondFactor::NotOwed);
        let (olivia, _later) = changed_after(&stolen);
        let mallorys = fresh_proof_of(OrgUserId::new().into());

        let result = stolen.keep_through_own_change(&olivia, &mallorys);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(!stolen.counts_for(&olivia));
    }

    /// Olivia removes a passkey she lost from her laptop's session. The
    /// laptop's session stays.
    #[test]
    fn the_session_a_member_removed_a_passkey_from_is_kept_through_it() {
        let mut laptop = opened(create_params(), SecondFactor::NotOwed);
        let (olivia, _later) = changed_after(&laptop);
        let holder = finished_sign_in_of((*olivia.id()).into());

        laptop.keep_through_own_removal(&olivia, &holder).unwrap();

        assert!(laptop.counts_for(&olivia));
        assert_eq!(laptop.kept_through(), olivia.credentials_changed_at());
    }

    /// Another member's sign-in cannot preserve Olivia's session through passkey removal.
    #[test]
    fn a_member_session_is_not_kept_through_a_removal_on_someone_elses_sign_in() {
        let mut session = opened(create_params(), SecondFactor::NotOwed);
        let (olivia, _later) = changed_after(&session);
        let mallorys = finished_sign_in_of(OrgUserId::new().into());

        let result = session.keep_through_own_removal(&olivia, &mallorys);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(!session.counts_for(&olivia));
    }

    /// Olivia sets up an authenticator app from her laptop's session and
    /// confirms it with its code. The laptop's session stays.
    #[test]
    fn the_session_a_member_set_up_a_factor_from_is_kept_through_it() {
        let mut laptop = opened(create_params(), SecondFactor::NotOwed);
        let (olivia, _later) = changed_after(&laptop);
        let code = proved((*olivia.id()).into(), MfaFactor::Totp);

        laptop
            .keep_through_own_factor_addition(&olivia, code)
            .unwrap();

        assert!(laptop.counts_for(&olivia));
        assert_eq!(laptop.kept_through(), olivia.credentials_changed_at());
    }

    /// Another member's factor proof cannot preserve Olivia's session through factor enrollment.
    #[test]
    fn a_member_session_is_not_kept_through_a_new_factor_on_someone_elses_code() {
        let mut stolen = opened(create_params(), SecondFactor::NotOwed);
        let (olivia, _later) = changed_after(&stolen);
        let mallorys = proved(OrgUserId::new().into(), MfaFactor::Totp);

        let result = stolen.keep_through_own_factor_addition(&olivia, mallorys);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert!(!stolen.counts_for(&olivia));
    }

    /// An unfinished sign-in cannot be preserved through factor enrollment as an already completed session.
    #[test]
    fn an_unfinished_member_sign_in_is_not_kept_through_a_new_factor() {
        let mut waiting = opened(create_params(), SecondFactor::Enrol);
        let (olivia, _later) = changed_after(&waiting);
        let code = proved((*olivia.id()).into(), MfaFactor::Totp);

        let result = waiting.keep_through_own_factor_addition(&olivia, code);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
        assert_eq!(waiting.kept_through(), CredentialChange::Never);
    }

    /// The platform suspends Acme over an unpaid bill. Its owner still signs
    /// in to settle it. Sam, a plain member with a grant, is refused until
    /// Acme is active again.
    #[test]
    fn only_owners_sign_in_to_a_suspended_organization() {
        let production = TenantId::new();
        let (mut organization, founder) = acme_with(production);
        let sam = plain_member(&organization, &founder);
        let grant = grant_of(&sam, production, &founder);
        organization
            .change_status(OrganizationStatus::Suspended, ActedBy::Platform)
            .unwrap();
        let params = || CreateOrgSessionParams {
            place: SessionPlace::Tenant(production),
            ..create_params()
        };

        let owner = entered(params(), &founder, &organization);
        let member = OrgSession::create(
            params(),
            SessionEntry {
                member: &sam,
                organization: &organization,
                grants: std::slice::from_ref(&grant),
            },
            start_for(&sam, SecondFactor::NotOwed),
        );

        assert!(owner.is_ok());
        assert!(matches!(member, Err(DomainError::Forbidden(_))));
    }

    /// Bob, Acme's billing contact, added by its founder.
    fn billing_contact(organization: &Organization, founder: &OrgUser) -> OrgUser {
        let session = session_of(founder);
        OrgUser::create(
            user_params(organization, OrgRole::Billing),
            AddedBy::Member(acting(founder, &session)),
        )
        .unwrap()
    }

    /// Bob, Acme's billing contact, signs in. His session works on the
    /// organization alone.
    #[test]
    fn a_billing_contacts_session_works_on_the_organization_alone() {
        let (organization, founder) = acme_with(TenantId::new());
        let bob = billing_contact(&organization, &founder);
        let params = CreateOrgSessionParams {
            place: SessionPlace::Organization,
            ..create_params()
        };

        let session = entered(params, &bob, &organization).unwrap();

        assert_eq!(session.place(), SessionPlace::Organization);
    }

    /// A billing contact cannot open a tenant session.
    #[test]
    fn a_billing_contact_opens_no_session_in_a_tenant() {
        let production = TenantId::new();
        let (organization, founder) = acme_with(production);
        let bob = billing_contact(&organization, &founder);
        let params = CreateOrgSessionParams {
            place: SessionPlace::Tenant(production),
            ..create_params()
        };

        let result = entered(params, &bob, &organization);

        assert!(matches!(result, Err(DomainError::Forbidden(_))));
    }

    /// `member`'s sessions checked now, against their organization at
    /// `status`.
    fn checked_while(status: OrganizationStatus, member: &OrgUser) -> OrgSessionCheck<'_> {
        OrgSessionCheck {
            organization: OrgStanding::new(*member.organization_id(), status),
            member,
            idle_timeout: Seconds::new(3600),
            now: crate::shared::clock::now(),
        }
    }

    /// Sam signed in to Acme and keeps working. His session counts.
    #[test]
    fn a_members_session_counts_while_the_organization_is_open() {
        let (organization, founder) = acme_with(TenantId::new());
        let sam = plain_member(&organization, &founder);
        let session = session_of(&sam);

        assert!(checked_while(OrganizationStatus::Active, &sam).admits(&session));
    }

    /// Suspension invalidates a plain member's session while retaining the
    /// owner's; closing the organization invalidates the owner's session too.
    #[test]
    fn a_suspension_ends_every_session_but_the_owners() {
        let (organization, founder) = acme_with(TenantId::new());
        let sam = plain_member(&organization, &founder);
        let (sams, founders) = (session_of(&sam), session_of(&founder));

        assert!(!checked_while(OrganizationStatus::Suspended, &sam).admits(&sams));
        assert!(checked_while(OrganizationStatus::Suspended, &founder).admits(&founders));
        assert!(!checked_while(OrganizationStatus::Closed, &founder).admits(&founders));
    }

    /// After two idle hours against a one-hour timeout, a session provides no
    /// acting authority; a fresh session still does.
    #[test]
    fn a_session_idle_past_the_timeout_carries_nothing() {
        let (organization, founder) = acme_with(TenantId::new());
        let sam = plain_member(&organization, &founder);
        let session = session_of(&sam);
        let two_hours_on = crate::shared::clock::now() + time::Duration::hours(2);

        let fresh = checked_while(OrganizationStatus::Active, &sam).checked(&session);
        let idle = OrgSessionCheck {
            now: two_hours_on,
            ..checked_while(OrganizationStatus::Active, &sam)
        }
        .checked(&session);

        assert!(fresh.is_some());
        assert!(idle.is_none());
    }

    /// Acme owning `staging` and `production`, with its founder Ann and Sam,
    /// a plain member granted `staging` only.
    struct TwoTenants {
        organization: Organization,
        ann: OrgUser,
        sam: OrgUser,
        staging: TenantId,
        production: TenantId,
        grants: Vec<OrgTenantGrant>,
    }

    fn two_tenants() -> TwoTenants {
        let (staging, production) = (TenantId::new(), TenantId::new());
        let (mut organization, ann) = acme_with(staging);
        organization
            .add_tenant(&tenant_with(production), ActedBy::Platform)
            .unwrap();
        let sam = plain_member(&organization, &ann);
        let grants = vec![grant_of(&sam, staging, &ann)];
        TwoTenants {
            organization,
            ann,
            sam,
            staging,
            production,
            grants,
        }
    }

    impl TwoTenants {
        /// A finished session of `member` in `staging`.
        fn in_staging(&self, member: &OrgUser) -> OrgSession {
            OrgSession::create(
                CreateOrgSessionParams {
                    place: SessionPlace::Tenant(self.staging),
                    ..create_params()
                },
                self.entry(member),
                start_for(member, SecondFactor::NotOwed),
            )
            .unwrap()
        }

        /// A finished session of `member` on the organization alone.
        fn on_organization(&self, member: &OrgUser) -> OrgSession {
            OrgSession::create(
                CreateOrgSessionParams {
                    place: SessionPlace::Organization,
                    ..create_params()
                },
                self.entry(member),
                start_for(member, SecondFactor::NotOwed),
            )
            .unwrap()
        }

        fn entry<'a>(&'a self, member: &'a OrgUser) -> SessionEntry<'a> {
            SessionEntry {
                member,
                organization: &self.organization,
                grants: &self.grants,
            }
        }

        /// `from`, moved by `member` to `tenant`.
        fn moved(
            &self,
            from: &mut OrgSession,
            member: &OrgUser,
            tenant: TenantId,
        ) -> Result<OrgSession, DomainError> {
            let switch = SessionSwitch {
                id: SessionId::new(),
                tenant_id: tenant,
                refresh_token_hash: TokenHash::from_stored("hash_1".to_owned()),
                entry: self.entry(member),
            };
            OrgSession::switch_to(
                from,
                &checked_while(OrganizationStatus::Active, member),
                switch,
            )
        }
    }

    /// Ann, an owner, signed in to `staging` and moves to `production`. She
    /// gets a session there without signing in again, carrying her sign-in
    /// and ending when the old one would have. The old one is retired.
    #[test]
    fn an_owner_moves_to_another_tenant_without_signing_in() {
        let acme = two_tenants();
        let mut staging = acme.in_staging(&acme.ann);

        let production = acme
            .moved(&mut staging, &acme.ann, acme.production)
            .unwrap();

        assert_eq!(production.place(), SessionPlace::Tenant(acme.production));
        assert_eq!(production.org_user_id(), acme.ann.id());
        assert!(production.is_valid());
        assert_eq!(production.auth_method(), staging.auth_method());
        assert_eq!(production.expires_at(), staging.expires_at());
        assert_eq!(staging.status(), SessionStatus::Revoked);
    }

    /// Ann moves her session from `staging` to `production`. The new
    /// session raises the move, naming both tenants; the retired one raises
    /// nothing, its end is part of the move.
    #[test]
    fn a_move_is_raised_by_the_new_session() {
        let acme = two_tenants();
        let mut staging = acme.in_staging(&acme.ann);

        let mut production = acme
            .moved(&mut staging, &acme.ann, acme.production)
            .unwrap();

        let events = production.take_events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type().to_string(),
            "organization.org_session_moved"
        );
        assert_eq!(events[0].organization_id(), Some(acme.organization.id()));
        assert!(staging.take_events().is_empty());
    }

    /// Ann ends her own session after Sam's attempt to end it was refused.
    /// Only her end is raised.
    #[test]
    fn ending_a_session_raises_it_once_and_a_refusal_nothing() {
        let tenant = TenantId::new();
        let (organization, ann) = acme_with(tenant);
        let sam = plain_member(&organization, &ann);
        let params = CreateOrgSessionParams {
            place: SessionPlace::Tenant(tenant),
            ..create_params()
        };
        let mut anns = entered(params, &ann, &organization).unwrap();
        let (sams, own) = (session_of(&sam), session_of(&ann));

        let refused = anns.revoke(ActedBy::By(acting(&sam, &sams)));
        let refused_events = anns.take_events();
        anns.revoke(ActedBy::By(acting(&ann, &own))).unwrap();

        assert!(refused.is_err());
        assert!(refused_events.is_empty());
        assert_eq!(
            anns.take_events()
                .iter()
                .map(|e| e.event_type().to_string())
                .collect::<Vec<_>>(),
            ["organization.org_session_revoked"]
        );
    }

    /// A session is read back from storage, and a new one opened. Neither
    /// has raised anything: signing in records itself the way it finishes.
    #[test]
    fn a_stored_or_opened_session_has_raised_nothing() {
        let mut opened = opened(create_params(), SecondFactor::Verify);
        let mut stored = OrgSession::reconstitute(stored_passkey_session()).unwrap();

        assert!(opened.take_events().is_empty());
        assert!(stored.take_events().is_empty());
    }

    /// An active two-hour session whose hardware passkey completed sign-in.
    fn stored_passkey_session() -> OrgSessionRow {
        let now = crate::shared::clock::now();
        OrgSessionRow {
            id: SessionId::new(),
            org_user_id: OrgUserId::new(),
            organization_id: OrganizationId::new(),
            place: SessionPlace::Tenant(TenantId::new()),
            refresh_token_hash: TokenHash::from_stored("stored_hash".to_owned()),
            progress: SignInProgressRow {
                method: AuthMethod::Passkey,
                factor: FactorProved::Proved(MfaFactor::HardwareKey),
                owed: SecondFactor::NotOwed,
            },
            ip_address: Fact::Unknown,
            user_agent: Fact::Unknown,
            status: SessionStatus::Active,
            created_at: now,
            last_active_at: now,
            expires_at: now + time::Duration::hours(2),
            kept_through: CredentialChange::Never,
        }
    }

    /// Switching to an ungranted tenant is refused and leaves the staging session valid.
    #[test]
    fn a_plain_member_moves_only_to_a_tenant_they_hold_a_grant_for() {
        let acme = two_tenants();
        let mut staging = acme.in_staging(&acme.sam);

        let moved = acme.moved(&mut staging, &acme.sam, acme.production);

        assert!(matches!(moved, Err(DomainError::Forbidden(_))));
        assert!(staging.is_valid());
    }

    /// An unfinished second-factor requirement prevents switching the session's tenant.
    #[test]
    fn a_session_that_does_not_count_moves_nowhere() {
        let acme = two_tenants();
        let mut owing = OrgSession::create(
            CreateOrgSessionParams {
                place: SessionPlace::Tenant(acme.staging),
                ..create_params()
            },
            acme.entry(&acme.ann),
            start_for(&acme.ann, SecondFactor::Verify),
        )
        .unwrap();

        let moved = acme.moved(&mut owing, &acme.ann, acme.production);

        assert!(matches!(moved, Err(DomainError::Forbidden(_))));
    }

    /// Another member's entry cannot switch Ann's session to a different tenant.
    #[test]
    fn a_session_moves_only_its_own_member() {
        let acme = two_tenants();
        let mut anns = acme.in_staging(&acme.ann);
        let switch = SessionSwitch {
            id: SessionId::new(),
            tenant_id: acme.production,
            refresh_token_hash: TokenHash::from_stored("hash_1".to_owned()),
            entry: acme.entry(&acme.sam),
        };

        let moved = OrgSession::switch_to(
            &mut anns,
            &checked_while(OrganizationStatus::Active, &acme.ann),
            switch,
        );

        assert!(matches!(moved, Err(DomainError::Forbidden(_))));
        assert!(anns.is_valid());
    }

    /// Ann switches to `staging`, where her session already works. It is
    /// refused, so the switch does not retire a session for nothing.
    #[test]
    fn a_switch_to_the_same_tenant_is_refused() {
        let acme = two_tenants();
        let mut staging = acme.in_staging(&acme.ann);

        let moved = acme.moved(&mut staging, &acme.ann, acme.staging);

        assert!(matches!(moved, Err(DomainError::Validation(_))));
        assert!(staging.is_valid());
    }

    /// An owner cannot switch a session into another organization's tenant.
    #[test]
    fn a_switch_reaches_only_the_organizations_tenants() {
        let acme = two_tenants();
        let mut staging = acme.in_staging(&acme.ann);

        let moved = acme.moved(&mut staging, &acme.ann, TenantId::new());

        assert!(matches!(moved, Err(DomainError::Forbidden(_))));
    }

    /// Sam signed in before anyone granted him a tenant, so his session
    /// works on the organization alone. Ann grants him `staging`, and he
    /// moves into it without signing in again. The move names no tenant
    /// it came from.
    #[test]
    fn a_session_on_the_organization_alone_moves_into_a_granted_tenant() {
        let acme = two_tenants();
        let mut on_organization = acme.on_organization(&acme.sam);

        let mut staging = acme
            .moved(&mut on_organization, &acme.sam, acme.staging)
            .unwrap();

        assert_eq!(staging.place(), SessionPlace::Tenant(acme.staging));
        assert_eq!(staging.expires_at(), on_organization.expires_at());
        assert_eq!(on_organization.status(), SessionStatus::Revoked);
        let events = staging.take_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].payload().get("source_tenant"), None);
    }

    /// An organization-only session cannot move into an ungranted tenant and
    /// remains valid on the organization after refusal.
    #[test]
    fn a_session_on_the_organization_alone_moves_into_no_ungranted_tenant() {
        let acme = two_tenants();
        let mut on_organization = acme.on_organization(&acme.sam);

        let moved = acme.moved(&mut on_organization, &acme.sam, acme.production);

        assert!(matches!(moved, Err(DomainError::Forbidden(_))));
        assert!(on_organization.is_valid());
    }

    /// Ann signs in to an organization that requires a second factor she
    /// has not set up. For a few minutes her waiting sign-in lets her set
    /// one up. A sign-in that owes nothing, or one that went stale, gives no
    /// such leave.
    #[test]
    fn a_sign_in_waiting_on_a_factor_lets_it_be_set_up_for_a_few_minutes() {
        let waiting = opened(create_params(), SecondFactor::Enrol);
        let finished = opened(create_params(), SecondFactor::NotOwed);
        let now = crate::shared::clock::now();

        assert!(waiting.enrolment_proof(now).is_some());
        assert!(finished.enrolment_proof(now).is_none());
        assert!(
            waiting
                .enrolment_proof(now + time::Duration::hours(1))
                .is_none()
        );
    }
}
