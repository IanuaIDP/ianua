//! Fakes for the notifications use cases, and the notifications and readers
//! their tests share.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::domains::notifications::category::NotificationCategory;
use ianua_domain::domains::notifications::channel::NotificationChannel;
use ianua_domain::domains::notifications::notification::{
    AboutResource, CreateNotificationParams, Notification,
};
use ianua_domain::domains::notifications::preference::NotificationPreference;
use ianua_domain::domains::notifications::reach::ToldAs;
use ianua_domain::domains::notifications::severity::NotificationSeverity;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::event_type::{CryptoEvent, IdentityEvent};
use ianua_domain::types::{
    EventType, KeyPrefix, Label, NotificationId, OperatorId, OrgUserId, OrganizationId, TenantId,
    UserId,
};
use time::OffsetDateTime;

use crate::context::{CallerIdentity, OperatorCaller};
use crate::listing::{Listing, Page, PageRequest, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::notifications::{
    Kept, NotificationPreferenceStore, NotificationSortField, OrgNotificationStore,
    PlatformNotificationStore, ReadFilter, TenantNotificationFilter, TenantNotificationStore,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::listing::page;
use crate::test_support::{Fake, test_ctx};

/// An unread notification of `severity` that a user registered, which
/// anyone who may view users sees.
#[must_use]
pub fn user_registered(severity: NotificationSeverity) -> Notification {
    notification_about(IdentityEvent::UserRegistered.into(), severity)
}

/// An unread notification that a signing key was rotated, which only
/// someone who may view keys sees.
#[must_use]
pub fn key_rotated() -> Notification {
    notification_about(CryptoEvent::KeyRotated.into(), NotificationSeverity::Info)
}

/// An unread notification to its subject that their own account was
/// locked, which they see whatever they hold.
#[must_use]
pub fn own_account_locked() -> Notification {
    told(
        IdentityEvent::UserStatusChanged.into(),
        NotificationSeverity::Warning,
        ToldAs::Subject,
    )
}

/// An unread notification to an admin that someone's account was locked,
/// which only someone who may view users sees.
#[must_use]
pub fn someone_elses_account_locked() -> Notification {
    told(
        IdentityEvent::UserStatusChanged.into(),
        NotificationSeverity::Warning,
        ToldAs::Overseer,
    )
}

fn notification_about(event_type: EventType, severity: NotificationSeverity) -> Notification {
    told(event_type, severity, ToldAs::Overseer)
}

fn told(event_type: EventType, severity: NotificationSeverity, told_as: ToldAs) -> Notification {
    Notification::create(CreateNotificationParams {
        id: NotificationId::new(),
        event_type,
        severity,
        title: Label::new("title", "Something happened").unwrap(),
        body: None,
        resource_id: AboutResource::from_stored(None),
        told_as,
    })
}

/// The tenant user every [`test_ctx`] caller is.
#[must_use]
pub fn test_ctx_user() -> UserId {
    let CallerIdentity::TenantUser(user) = *test_ctx().identity() else {
        unreachable!("the test caller is a tenant user");
    };
    user
}

/// An operator calling with their own key.
#[must_use]
pub fn operator_caller(operator: OperatorId) -> OperatorCaller {
    OperatorCaller::new(operator, KeyPrefix::new("op_live_abc").unwrap())
}

/// In-memory notifications, each kept under the recipient `K` it was saved
/// for: an operator, an organization's user, or a tenant's user.
pub struct FakeInbox<K> {
    /// Stored notifications, with their recipient.
    pub notifications: Mutex<Vec<(K, Notification)>>,
}

/// Platform notifications, kept per operator.
pub type FakePlatformNotificationStore = FakeInbox<OperatorId>;

/// Organization notifications, kept per organization and org user.
pub type FakeOrgNotificationStore = FakeInbox<(OrganizationId, OrgUserId)>;

/// Tenant notifications, kept per tenant and user.
pub type FakeTenantNotificationStore = FakeInbox<(TenantId, UserId)>;

impl<K> Default for FakeInbox<K> {
    fn default() -> Self {
        Self {
            notifications: Mutex::new(Vec::new()),
        }
    }
}

impl TenantScoped for FakeTenantNotificationStore {}

impl<K: PartialEq + Copy> FakeInbox<K> {
    /// Creates an empty store.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    fn listed(
        &self,
        recipient: K,
        shown: impl Fn(&Notification) -> bool,
        sort: &SortOrder<NotificationSortField>,
        request: &PageRequest,
    ) -> Result<Page<Notification>, DomainError> {
        let found = self
            .notifications
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, notification)| *owner == recipient && shown(notification))
            .map(|(_, notification)| notification.clone())
            .collect();
        page(found, sort, request)
    }

    fn count(&self, recipient: K, counted: impl Fn(&Notification) -> bool) -> u64 {
        self.notifications
            .lock()
            .unwrap()
            .iter()
            .filter(|(owner, notification)| *owner == recipient && counted(notification))
            .count() as u64
    }

    fn mark(&self, recipient: K, marked: impl Fn(&Notification) -> bool) -> u64 {
        let mut items = self.notifications.lock().unwrap();
        let mut count = 0;
        for (_, notification) in items
            .iter_mut()
            .filter(|(owner, notification)| *owner == recipient && marked(notification))
        {
            notification.mark_read();
            count += 1;
        }
        count
    }

    fn purged(&self, cutoff: OffsetDateTime, within: impl Fn(&K) -> bool) -> u64 {
        let mut held = self.notifications.lock().unwrap();
        let before = held.len();
        held.retain(|(owner, notification)| !within(owner) || notification.created_at() >= cutoff);
        (before - held.len()) as u64
    }

    fn keep(&self, recipient: K, notification: &Notification) -> Kept {
        let mut held = self.notifications.lock().unwrap();
        if held.iter().any(|(_, kept)| kept.id() == notification.id()) {
            return Kept::AlreadyKept;
        }
        held.push((recipient, notification.clone()));
        Kept::New
    }
}

fn passes(reads: ReadFilter, notification: &Notification) -> bool {
    match reads {
        ReadFilter::All => true,
        ReadFilter::UnreadOnly => !notification.is_read(),
    }
}

fn visible_to(permissions: &[SystemPermission], notification: &Notification) -> bool {
    notification.shows_to(permissions)
}

fn with_id(id: &NotificationId) -> impl Fn(&Notification) -> bool + '_ {
    move |notification| notification.id() == *id
}

#[async_trait]
impl PlatformNotificationStore for FakePlatformNotificationStore {
    async fn list_for_operator(
        &self,
        operator_id: &OperatorId,
        reads: ReadFilter,
        sort: &SortOrder<NotificationSortField>,
        request: &PageRequest,
    ) -> Result<Page<Notification>, DomainError> {
        self.listed(*operator_id, |n| passes(reads, n), sort, request)
    }

    async fn unread_count(&self, operator_id: &OperatorId) -> Result<u64, DomainError> {
        Ok(self.count(*operator_id, |n| !n.is_read()))
    }

    async fn mark_read(
        &self,
        operator_id: &OperatorId,
        notification_id: &NotificationId,
    ) -> Result<bool, DomainError> {
        Ok(self.mark(*operator_id, with_id(notification_id)) > 0)
    }

    async fn mark_all_read(&self, operator_id: &OperatorId) -> Result<u64, DomainError> {
        Ok(self.mark(*operator_id, |n| !n.is_read()))
    }

    async fn save(
        &self,
        operator_id: &OperatorId,
        notification: &Notification,
    ) -> Result<Kept, DomainError> {
        Ok(self.keep(*operator_id, notification))
    }

    async fn purge_before(&self, cutoff: OffsetDateTime) -> Result<u64, DomainError> {
        Ok(self.purged(cutoff, |_| true))
    }
}

#[async_trait]
impl OrgNotificationStore for FakeOrgNotificationStore {
    async fn list_for_user(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
        listing: Listing<'_, ReadFilter, NotificationSortField>,
    ) -> Result<Page<Notification>, DomainError> {
        let recipient = (*organization_id, *org_user_id);
        let reads = listing.filter;
        self.listed(recipient, |n| passes(reads, n), listing.sort, listing.page)
    }

    async fn unread_count(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
    ) -> Result<u64, DomainError> {
        Ok(self.count((*organization_id, *org_user_id), |n| !n.is_read()))
    }

    async fn mark_read(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
        notification_id: &NotificationId,
    ) -> Result<bool, DomainError> {
        let recipient = (*organization_id, *org_user_id);
        Ok(self.mark(recipient, with_id(notification_id)) > 0)
    }

    async fn mark_all_read(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
    ) -> Result<u64, DomainError> {
        Ok(self.mark((*organization_id, *org_user_id), |n| !n.is_read()))
    }

    async fn save(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
        notification: &Notification,
    ) -> Result<Kept, DomainError> {
        Ok(self.keep((*organization_id, *org_user_id), notification))
    }

    async fn purge_before(&self, cutoff: OffsetDateTime) -> Result<u64, DomainError> {
        Ok(self.purged(cutoff, |_| true))
    }
}

#[async_trait]
impl TenantNotificationStore for FakeTenantNotificationStore {
    async fn list_for_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        listing: Listing<'_, &TenantNotificationFilter<'_>, NotificationSortField>,
    ) -> Result<Page<Notification>, DomainError> {
        let filter = listing.filter;
        let shown = |n: &Notification| passes(filter.reads, n) && visible_to(filter.permissions, n);
        self.listed((**tenant_id, *user_id), shown, listing.sort, listing.page)
    }

    async fn unread_count(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        permissions: &[SystemPermission],
    ) -> Result<u64, DomainError> {
        let counted = |n: &Notification| !n.is_read() && visible_to(permissions, n);
        Ok(self.count((**tenant_id, *user_id), counted))
    }

    async fn mark_read(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        notification_id: &NotificationId,
    ) -> Result<bool, DomainError> {
        Ok(self.mark((**tenant_id, *user_id), with_id(notification_id)) > 0)
    }

    async fn mark_all_read(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<u64, DomainError> {
        Ok(self.mark((**tenant_id, *user_id), |n| !n.is_read()))
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        notification: &Notification,
    ) -> Result<Kept, DomainError> {
        Ok(self.keep((**tenant_id, *user_id), notification))
    }

    async fn purge_before(
        &self,
        tenant_id: &ScopedTenant,
        cutoff: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        Ok(self.purged(cutoff, |(tenant, _)| tenant == &**tenant_id))
    }
}

/// One user's preferences in one tenant, as the fake keeps them.
pub type HeldPreferences = ((TenantId, UserId), Vec<NotificationPreference>);

/// In-memory preference store for tests, keeping each user's preferences
/// under their tenant.
#[derive(Default)]
pub struct FakeNotificationPreferenceStore {
    /// Stored preferences, with the tenant and user they belong to.
    pub prefs: Mutex<Vec<HeldPreferences>>,
}

impl TenantScoped for FakeNotificationPreferenceStore {}

impl FakeNotificationPreferenceStore {
    /// Creates an empty store.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Creates a store holding `prefs` for `user` in `tenant`.
    #[must_use]
    pub fn with_prefs(tenant: TenantId, user: UserId, prefs: Vec<NotificationPreference>) -> Self {
        Self {
            prefs: Mutex::new(vec![((tenant, user), prefs)]),
        }
    }
}

#[async_trait]
impl NotificationPreferenceStore for FakeNotificationPreferenceStore {
    async fn get(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<NotificationPreference>, DomainError> {
        let owner = (**tenant_id, *user_id);
        Ok(self
            .prefs
            .lock()
            .unwrap()
            .iter()
            .find(|(held, _)| *held == owner)
            .map(|(_, prefs)| prefs.clone())
            .unwrap_or_default())
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        preferences: &[NotificationPreference],
    ) -> Result<(), DomainError> {
        let owner = (**tenant_id, *user_id);
        let mut prefs = self.prefs.lock().unwrap();
        prefs.retain(|(held, _)| *held != owner);
        prefs.push((owner, preferences.to_vec()));
        Ok(())
    }

    async fn chosen_channels(
        &self,
        tenant_id: &ScopedTenant,
        category: NotificationCategory,
    ) -> Result<Vec<(UserId, NotificationChannel)>, DomainError> {
        let prefs = self.prefs.lock().unwrap();
        Ok(prefs
            .iter()
            .filter(|((tenant, _), _)| *tenant == **tenant_id)
            .filter_map(|((_, user), held)| {
                held.iter()
                    .find(|pref| pref.category() == category)
                    .map(|pref| (*user, pref.channel()))
            })
            .collect())
    }
}

impl Fake for Arc<dyn NotificationPreferenceStore> {
    fn fake() -> Self {
        Arc::new(FakeNotificationPreferenceStore::empty())
    }
}

impl Fake for Arc<dyn OrgNotificationStore> {
    fn fake() -> Self {
        Arc::new(FakeOrgNotificationStore::empty())
    }
}

impl Fake for Arc<dyn PlatformNotificationStore> {
    fn fake() -> Self {
        Arc::new(FakePlatformNotificationStore::empty())
    }
}

impl Fake for Arc<dyn TenantNotificationStore> {
    fn fake() -> Self {
        Arc::new(FakeTenantNotificationStore::empty())
    }
}
