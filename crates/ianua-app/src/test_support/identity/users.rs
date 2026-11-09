//! An in-memory user store, and the users tests seed it with.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::identity::account::address::AddressStanding;
use ianua_domain::domains::identity::account::user::{User, UserRow};
use ianua_domain::domains::identity::account::user_profile::UserProfile;
use ianua_domain::domains::identity::account::user_status::UserStatus;
use ianua_domain::domains::identity::account::vouching::Vouching;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::config::DisplayNameLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    CredentialChange, DisplayName, Email, Joining, Locale, Preference, TenantId, UserId,
};
use time::OffsetDateTime;

use crate::listing::{Page, PageRequest};
use crate::ports::TenantScoped;
use crate::ports::identity::{TimeSpan, UserFilter, UserOrdering, UserStore};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;
use crate::test_support::identity::held::{TenantRows, seeded_tenant};
use crate::test_support::identity::invitations::FakeInvitationStore;
use crate::test_support::listing::page;

/// In-memory user store: keeps every user saved under its tenant and finds
/// them by id and address in that tenant only.
///
/// Its seeding helpers file users under the tenant [`test_ctx`] carries.
/// Listings filter on status, address, name, ids and times; custom
/// attribute filters are left to the metadata store, and role and group
/// filters to the access records, and are ignored here. An attribute order
/// pages by the user's id alone, since the row holds no attribute values.
///
/// [`test_ctx`]: crate::test_support::test_ctx
#[derive(Default)]
pub struct FakeUserStore {
    users: TenantRows<User<ResolvedTenant>>,
    id_reads: Mutex<Vec<Vec<UserId>>>,
    invitations: Arc<FakeInvitationStore>,
}

impl TenantScoped for FakeUserStore {}

impl FakeUserStore {
    /// Uses these invitation records when selecting users by invitation state.
    #[must_use]
    pub fn reading_invitations(self, invitations: Arc<FakeInvitationStore>) -> Self {
        Self {
            invitations,
            ..self
        }
    }

    /// The user ids requested in each lookup, preserving batch boundaries.
    #[must_use]
    pub fn id_reads(&self) -> Vec<Vec<UserId>> {
        self.id_reads.lock().unwrap().clone()
    }

    /// Creates an empty store.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store holding one active user with a verified address.
    #[must_use]
    pub fn with_user(user_id: UserId, email: &str) -> Self {
        let store = Self::empty();
        store.add_active_user(user_id, email);
        store
    }

    /// A store holding one user who registered and has not yet verified
    /// their address.
    #[must_use]
    pub fn with_unverified_user(user_id: UserId, email: &str) -> Self {
        let store = Self::empty();
        store.add(stored_user(user_id, email, UserStatus::PendingVerification));
        store
    }

    /// A store holding one user who was invited and has not yet joined.
    #[must_use]
    pub fn with_invited_user(user_id: UserId, email: &str) -> Self {
        let store = Self::empty();
        store.add(stored_user(user_id, email, UserStatus::Invited));
        store
    }

    /// Adds an active user with a verified address.
    pub fn add_active_user(&self, user_id: UserId, email: &str) {
        self.add(stored_user(user_id, email, UserStatus::Active));
    }

    /// Adds `user` to the seeded tenant.
    pub fn add(&self, user: User<ResolvedTenant>) {
        self.users.insert(seeded_tenant(), user);
    }

    /// Adds `user` to `tenant`.
    pub fn add_in(&self, tenant: TenantId, user: User<ResolvedTenant>) {
        self.users.insert(tenant, user);
    }

    /// Returns the number of stored users, across every tenant.
    #[must_use]
    pub fn count(&self) -> usize {
        self.users.count()
    }

    /// The status of the seeded tenant's user `id`.
    #[must_use]
    pub fn get_status(&self, id: &UserId) -> Option<UserStatus> {
        self.read(id, User::status)
    }

    /// The address of the seeded tenant's user `id`.
    #[must_use]
    pub fn get_email(&self, id: &UserId) -> Option<Email> {
        self.read(id, |user| user.email().clone())
    }

    /// The display name of the seeded tenant's user `id`.
    #[must_use]
    pub fn get_display_name(&self, id: &UserId) -> Option<DisplayName> {
        self.read(id, |user| user.display_name().clone())
    }

    fn read<R>(&self, id: &UserId, read: impl Fn(&User<ResolvedTenant>) -> R) -> Option<R> {
        self.users
            .find(&seeded_tenant(), |user| user.id() == id, read)
    }

    fn matching(
        &self,
        tenant: &TenantId,
        filter: &UserFilter,
    ) -> Result<Vec<User<ResolvedTenant>>, DomainError> {
        self.users
            .collect(
                tenant,
                |user| {
                    matches_filter(user, filter)
                        && filter.invitation.is_none_or(|wanted| {
                            self.invitations.matches_state(tenant, user.id(), wanted)
                        })
                },
                copy_user,
            )
            .into_iter()
            .collect()
    }
}

#[async_trait]
impl UserStore for FakeUserStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &UserId,
    ) -> Result<Option<User<ResolvedTenant>>, DomainError> {
        self.id_reads.lock().unwrap().push(vec![*id]);
        self.users
            .find(tenant_id, |user| user.id() == id, copy_user)
            .transpose()
    }

    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[UserId],
    ) -> Result<Vec<User<ResolvedTenant>>, DomainError> {
        self.id_reads.lock().unwrap().push(ids.to_vec());
        self.users
            .collect(tenant_id, |user| ids.contains(user.id()), copy_user)
            .into_iter()
            .collect()
    }

    async fn find_by_email(
        &self,
        tenant_id: &ScopedTenant,
        email: &Email,
    ) -> Result<Option<User<ResolvedTenant>>, DomainError> {
        self.users
            .find(tenant_id, |user| user.email() == email, copy_user)
            .transpose()
    }

    async fn email_exists(
        &self,
        tenant_id: &ScopedTenant,
        email: &Email,
    ) -> Result<bool, DomainError> {
        Ok(self
            .users
            .find(tenant_id, |user| user.email() == email, |_| ())
            .is_some())
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
        filter: &UserFilter,
        ordering: &UserOrdering,
        request: &PageRequest,
    ) -> Result<Page<User<ResolvedTenant>>, DomainError> {
        page(self.matching(tenant_id, filter)?, ordering, request)
    }

    async fn count(
        &self,
        tenant_id: &ScopedTenant,
        filter: &UserFilter,
    ) -> Result<u64, DomainError> {
        Ok(self.matching(tenant_id, filter)?.len() as u64)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        user: &User<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let kept = copy_user(user)?;
        self.users
            .upsert(**tenant_id, |held| held.id() == user.id(), kept);
        Ok(())
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &UserId) -> Result<(), DomainError> {
        self.users.remove(tenant_id, |user| user.id() == id);
        Ok(())
    }
}

impl Fake for Arc<dyn UserStore> {
    fn fake() -> Self {
        Arc::new(FakeUserStore::empty())
    }
}

/// A user as storage keeps it, standing at `status`: joined once active,
/// with a verified address once past verification.
///
/// # Panics
///
/// If `email` is not a valid address. Tests pass literals that are.
#[must_use]
pub fn stored_user(user_id: UserId, email: &str, status: UserStatus) -> User<ResolvedTenant> {
    User::reconstitute(stored_row(user_id, email, status)).expect("a test user is a consistent row")
}

/// An active user with a verified address who reads mail in `locale`.
///
/// # Panics
///
/// If `email` or `locale` is not valid. Tests pass literals that are.
#[must_use]
pub fn user_reading(user_id: UserId, email: &str, locale: &str) -> User<ResolvedTenant> {
    User::reconstitute(UserRow {
        locale: Preference::Own(Locale::new(locale).expect("a valid locale")),
        ..stored_row(user_id, email, UserStatus::Active)
    })
    .expect("a test user is a consistent row")
}

/// An active user with a verified address, named `name`.
///
/// # Panics
///
/// If `email` or `name` is not valid. Tests pass literals that are.
#[must_use]
pub fn user_named(user_id: UserId, email: &str, name: &str) -> User<ResolvedTenant> {
    User::reconstitute(UserRow {
        display_name: DisplayName::new(name, &DisplayNameLimits::default()).expect("a valid name"),
        ..stored_row(user_id, email, UserStatus::Active)
    })
    .expect("a test user is a consistent row")
}

/// An active user with a verified address, holding `profile`.
///
/// # Panics
///
/// If `email` is not a valid address. Tests pass literals that are.
#[must_use]
pub fn user_with_profile(
    user_id: UserId,
    email: &str,
    profile: UserProfile,
) -> User<ResolvedTenant> {
    User::reconstitute(UserRow {
        profile,
        ..stored_row(user_id, email, UserStatus::Active)
    })
    .expect("a test user is a consistent row")
}

/// The row storage keeps for a user standing at `status`.
fn stored_row(user_id: UserId, email: &str, status: UserStatus) -> UserRow {
    let now = clock::now();
    let (email_standing, joining) = onboarding_at(status, now);
    UserRow {
        id: user_id,
        email: Email::new(email).expect("a valid address"),
        display_name: DisplayName::new("Test User", &DisplayNameLimits::default())
            .expect("a valid name"),
        status,
        email_standing,
        locale: Preference::Inherited,
        timezone: Preference::Inherited,
        profile: UserProfile::default(),
        created_at: now,
        updated_at: now,
        last_login_at: None,
        joining,
        credentials_changed_at: CredentialChange::Never,
        vouching: Vouching::Absent,
    }
}

/// How far a user standing at `status` got by `now`: one still waiting to
/// join has neither proved an address nor joined, any other has done both.
fn onboarding_at(status: UserStatus, now: OffsetDateTime) -> (AddressStanding, Joining) {
    match status {
        UserStatus::Invited | UserStatus::PendingVerification => {
            (AddressStanding::Unverified, Joining::NotYet)
        }
        UserStatus::Active | UserStatus::Locked | UserStatus::Deactivated | UserStatus::Closing => {
            (AddressStanding::Verified, Joining::Joined { at: now })
        }
    }
}

/// A copy of `user`, which does not implement `Clone`, read back as a real
/// store would.
///
/// # Errors
///
/// Returns the domain's refusal when the copied row no longer rebuilds,
/// which no stored user gives.
pub fn copy_user(user: &User<ResolvedTenant>) -> Result<User<ResolvedTenant>, DomainError> {
    User::reconstitute(UserRow {
        id: *user.id(),
        email: user.email().clone(),
        display_name: user.display_name().clone(),
        status: user.status(),
        email_standing: user.address().standing(),
        locale: user.locale().clone(),
        timezone: user.timezone().clone(),
        profile: user.profile().clone(),
        created_at: user.created_at(),
        updated_at: user.updated_at(),
        last_login_at: user.last_login_at(),
        joining: Joining::from_stored(user.joined_at()),
        credentials_changed_at: user.credentials_changed_at(),
        vouching: user.vouching(),
    })
}

fn matches_filter(user: &User<ResolvedTenant>, filter: &UserFilter) -> bool {
    let status = filter.status.is_none_or(|wanted| user.status() == wanted);
    let email = filter
        .email_contains
        .as_ref()
        .is_none_or(|part| contains_ignoring_case(user.email().as_str(), part));
    let id = filter
        .ids
        .as_ref()
        .is_none_or(|ids| ids.contains(user.id()));
    status && email && id && matches_name_and_times(user, filter)
}

/// Whether `user`'s name and times meet `filter`.
fn matches_name_and_times(user: &User<ResolvedTenant>, filter: &UserFilter) -> bool {
    let name = filter
        .name_contains
        .as_ref()
        .is_none_or(|part| contains_ignoring_case(user.display_name().as_str(), part));
    let created = filter.created.holds(user.created_at());
    let signed_in = filter.last_login == TimeSpan::any()
        || user
            .last_login_at()
            .is_some_and(|at| filter.last_login.holds(at));
    name && created && signed_in
}

fn contains_ignoring_case(text: &str, part: &str) -> bool {
    text.to_lowercase().contains(&part.to_lowercase())
}
