//! Notification ports: one store per tier of recipient, preferences, and
//! the places outside the app an organization's notifications go to.

use async_trait::async_trait;
use ianua_domain::domains::agents::identity::token_attack::TokenAttack;
use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::domains::notifications::category::NotificationCategory;
use ianua_domain::domains::notifications::channel::NotificationChannel;
use ianua_domain::domains::notifications::destination::{
    DestinationEndpoint, NotificationDestination,
};
use ianua_domain::domains::notifications::notification::Notification;
use ianua_domain::domains::notifications::personal::{
    MemberNotificationPreferences, OperatorNotificationPreferences,
};
use ianua_domain::domains::notifications::preference::NotificationPreference;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    AgentId, EventType, NotificationDestinationId, NotificationId, OperatorId, OrgUserId,
    OrganizationId, TenantId, UserId,
};
use time::{Duration, OffsetDateTime};

use crate::define_sort_field;
use crate::listing::{Listing, Page, PageRequest, SortKey, SortKeys, SortOrder};
use crate::ports::TenantScoped;
use crate::ports::authentication::{SealOwner, SealedField, SealedFor};
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// Field a notification listing can be ordered by.
    pub enum NotificationSortField {
        /// Order by creation time.
        CreatedAt => "created_at",
        /// Order by severity level.
        Severity => "severity",
        /// Order by category.
        Category => "category",
    }
    default = CreatedAt;
    default direction = Desc;
}

impl SortKeys<NotificationSortField> for Notification {
    fn sort_key(&self, field: NotificationSortField) -> SortKey {
        match field {
            NotificationSortField::CreatedAt => self.created_at().into(),
            NotificationSortField::Severity => SortKey::Integer(i64::from(self.severity().rank())),
            NotificationSortField::Category => self.category().as_str().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// Dyn-safe port for platform-tier notifications (shared schema).
///
/// Recipients are operators. Stores in the shared `platform_notifications` table.
#[async_trait]
pub trait PlatformNotificationStore: Send + Sync {
    /// Lists notifications for an operator with ordering and pagination.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn list_for_operator(
        &self,
        operator_id: &OperatorId,
        reads: ReadFilter,
        sort: &SortOrder<NotificationSortField>,
        page: &PageRequest,
    ) -> Result<Page<Notification>, DomainError>;

    /// Counts unread notifications.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn unread_count(&self, operator_id: &OperatorId) -> Result<u64, DomainError>;

    /// Marks a single notification as read. Returns `true` if found.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn mark_read(
        &self,
        operator_id: &OperatorId,
        notification_id: &NotificationId,
    ) -> Result<bool, DomainError>;

    /// Marks all notifications as read. Returns the count marked.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn mark_all_read(&self, operator_id: &OperatorId) -> Result<u64, DomainError>;

    /// Keeps a new notification, or leaves the one already kept under its
    /// id as it is, read or not.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn save(
        &self,
        operator_id: &OperatorId,
        notification: &Notification,
    ) -> Result<Kept, DomainError>;

    /// Removes every operator's notifications made before `cutoff`, read
    /// or not, and returns how many went.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure; nothing is removed then.
    async fn purge_before(&self, cutoff: OffsetDateTime) -> Result<u64, DomainError>;
}

/// Dyn-safe port for org-tier notifications (shared schema).
///
/// Recipients are org users. Scoped to a specific organization.
#[async_trait]
pub trait OrgNotificationStore: Send + Sync {
    /// Lists notifications for an org user with ordering and pagination.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn list_for_user(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
        listing: Listing<'_, ReadFilter, NotificationSortField>,
    ) -> Result<Page<Notification>, DomainError>;

    /// Counts unread notifications.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn unread_count(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
    ) -> Result<u64, DomainError>;

    /// Marks a single notification as read. Returns `true` if found.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn mark_read(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
        notification_id: &NotificationId,
    ) -> Result<bool, DomainError>;

    /// Marks all notifications as read. Returns the count marked.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn mark_all_read(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
    ) -> Result<u64, DomainError>;

    /// Keeps a new notification, or leaves the one already kept under its
    /// id as it is, read or not.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn save(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
        notification: &Notification,
    ) -> Result<Kept, DomainError>;

    /// Removes every organization member's notifications made before
    /// `cutoff`, read or not, and returns how many went.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure; nothing is removed then.
    async fn purge_before(&self, cutoff: OffsetDateTime) -> Result<u64, DomainError>;
}

/// What saving a notification did.
///
/// Notification ids come from the event and the recipient, so a fan-out run
/// again for the same event saves the same notification again. The store
/// keeps the first and says so, and the recipient is told once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kept {
    /// It was new and is now kept.
    New,
    /// One with its id was already kept; nothing changed.
    AlreadyKept,
}

/// Which notifications a listing returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadFilter {
    /// Read and unread alike.
    All,
    /// Only those not yet read.
    UnreadOnly,
}

/// Filter criteria for listing a tenant user's notifications.
pub struct TenantNotificationFilter<'a> {
    /// The system permissions the caller holds, each wider one with all it
    /// covers. A notification shows as
    /// [`Notification::shows_to`] says: to someone holding its
    /// `required_permission`, or, when it reaches them on their own
    /// account, whatever they hold.
    pub permissions: &'a [SystemPermission],
    /// Whether only unread notifications are returned.
    pub reads: ReadFilter,
}

/// Dyn-safe port for tenant-tier notifications (per-tenant schema).
///
/// Recipients are tenant users. The filter's `permissions` gate notifications
/// by the caller's granted system permissions, except a notification that
/// reaches its reader on their own account, which shows whatever they hold:
/// [`Notification::shows_to`] is the rule every store answers.
#[async_trait]
pub trait TenantNotificationStore: Send + Sync + TenantScoped {
    /// Lists notifications visible to a user given their permissions, with
    /// ordering and pagination.
    ///
    /// The store works out which categories the permissions let the reader
    /// see and filters: `WHERE user_id = ? AND (reach = 'own_account' OR
    /// category = ANY(?))`, the same rule as [`Notification::shows_to`].
    /// Only the user's own inbox is read, so a notice on someone else's
    /// account never shows to them.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn list_for_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        listing: Listing<'_, &TenantNotificationFilter<'_>, NotificationSortField>,
    ) -> Result<Page<Notification>, DomainError>;

    /// Counts unread notifications visible to a user, by the same rule as
    /// [`list_for_user`](Self::list_for_user).
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn unread_count(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        permissions: &[SystemPermission],
    ) -> Result<u64, DomainError>;

    /// Marks a single notification as read. Returns `true` if found.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn mark_read(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        notification_id: &NotificationId,
    ) -> Result<bool, DomainError>;

    /// Marks all of the user's unread notifications as read, whatever
    /// permission they need to be seen. Returns the count marked.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn mark_all_read(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<u64, DomainError>;

    /// Keeps a new notification for a tenant user, or leaves the one
    /// already kept under its id as it is, read or not.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        notification: &Notification,
    ) -> Result<Kept, DomainError>;

    /// Removes the tenant's notifications made before `cutoff`, read or
    /// not, and returns how many went.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure; nothing is removed then.
    async fn purge_before(
        &self,
        tenant_id: &ScopedTenant,
        cutoff: OffsetDateTime,
    ) -> Result<u64, DomainError>;
}

/// Dyn-safe port for notification preferences (per-tenant schema).
#[async_trait]
pub trait NotificationPreferenceStore: Send + Sync + TenantScoped {
    /// Loads all preferences for a user.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn get(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Vec<NotificationPreference>, DomainError>;

    /// Saves all preferences for a user (replaces existing).
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        preferences: &[NotificationPreference],
    ) -> Result<(), DomainError>;

    /// Every user of the tenant who chose a channel for `category`, with
    /// the channel. A user not among them gets it in the app only.
    ///
    /// One read for a whole tenant, so telling everyone about an event does
    /// not read each user's preferences in turn.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` on persistence failure.
    async fn chosen_channels(
        &self,
        tenant_id: &ScopedTenant,
        category: NotificationCategory,
    ) -> Result<Vec<(UserId, NotificationChannel)>, DomainError>;
}

/// Dyn-safe port for organization members' notification choices.
#[async_trait]
pub trait MemberPreferenceStore: Send + Sync {
    /// The member's choices, or `None` when they never chose anything.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure, or when the
    /// stored row chooses for one category twice.
    async fn find(
        &self,
        organization_id: &OrganizationId,
        org_user_id: &OrgUserId,
    ) -> Result<Option<MemberNotificationPreferences>, DomainError>;

    /// Saves the member's choices, replacing those kept.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(&self, preferences: &MemberNotificationPreferences) -> Result<(), DomainError>;

    /// Every member of the organization who chose a channel for
    /// `category`, with the channel, in one read.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn chosen_channels(
        &self,
        organization_id: &OrganizationId,
        category: NotificationCategory,
    ) -> Result<Vec<(OrgUserId, NotificationChannel)>, DomainError>;
}

/// Dyn-safe port for operators' notification choices.
#[async_trait]
pub trait OperatorPreferenceStore: Send + Sync {
    /// The operator's choices, or `None` when they never chose anything.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure, or when the
    /// stored row chooses for one category twice.
    async fn find(
        &self,
        operator_id: &OperatorId,
    ) -> Result<Option<OperatorNotificationPreferences>, DomainError>;

    /// Saves the operator's choices, replacing those kept.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(&self, preferences: &OperatorNotificationPreferences) -> Result<(), DomainError>;

    /// Every operator who chose a channel for `category`, with the channel,
    /// in one read.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn chosen_channels(
        &self,
        category: NotificationCategory,
    ) -> Result<Vec<(OperatorId, NotificationChannel)>, DomainError>;
}

/// Dyn-safe port for the places outside the app an organization's
/// notifications go to.
#[async_trait]
pub trait NotificationDestinationStore: Send + Sync {
    /// The organization's destination `id`, or `None` when it has none.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure, or when the
    /// stored row breaks a rule the destination keeps.
    async fn find(
        &self,
        organization_id: &OrganizationId,
        id: &NotificationDestinationId,
    ) -> Result<Option<NotificationDestination>, DomainError>;

    /// Every destination of the organization, oldest first.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure.
    async fn list(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Vec<NotificationDestination>, DomainError>;

    /// Saves a new or changed destination.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(&self, destination: &NotificationDestination) -> Result<(), DomainError>;

    /// Deletes the organization's destination `id`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(
        &self,
        organization_id: &OrganizationId,
        id: &NotificationDestinationId,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port making the secret a webhook destination's posts are
/// signed with.
#[async_trait]
pub trait DestinationSecretGenerator: Send + Sync {
    /// A new random signing secret, at least 32 bytes from a secure
    /// source.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when no secret can be made.
    async fn generate(&self) -> Result<Secret, DomainError>;
}

/// Where `organization`'s destination `destination` keeps its sealed
/// address and signing secret.
#[must_use]
pub fn destination_endpoint_place(
    organization: &OrganizationId,
    destination: &NotificationDestinationId,
) -> SealedFor {
    SealedFor::new(
        SealOwner::Organization(*organization),
        SealedField::NotificationEndpoint,
        destination,
    )
}

/// Dyn-safe port posting one notification to a destination: a Slack or
/// Teams channel, or a webhook of the organization's own.
///
/// The adapter must:
/// - bound every post with a timeout, connecting and in all, so a channel
///   that hangs never holds the fan-out;
/// - resolve the host again on every post and refuse an address that is not
///   public, so a name that once pointed outside cannot be turned inward;
/// - follow no redirect;
/// - unseal a Slack or Teams address, or a webhook's signing secret, only to
///   post, sign a webhook post with it, and never log either.
#[async_trait]
pub trait DestinationPoster: Send + Sync {
    /// Posts `notification` to `endpoint`, whose sealed address and secret
    /// are opened for `sealed_for`, as [`destination_endpoint_place`] names
    /// it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Validation` when the host no longer resolves to
    /// a public address, and `DomainError::Infrastructure` when a sealed
    /// part does not open there, or the destination cannot be reached in
    /// time or refuses the post.
    async fn post(
        &self,
        endpoint: &DestinationEndpoint,
        sealed_for: &SealedFor,
        notification: &Notification,
    ) -> Result<(), DomainError>;
}

/// The plane one kind of security alert is held back on: a tenant, an
/// organization, or the platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertPlane {
    /// A tenant's people.
    Tenant(TenantId),
    /// An organization's admins and owners.
    Organization(OrganizationId),
    /// The platform's operators.
    Platform,
}

/// One kind of security alert on one plane, about one thing, which the
/// throttle holds back together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AlertKey {
    /// Where it is told.
    pub plane: AlertPlane,
    /// The event it is about.
    pub event_type: EventType,
    /// What within its kind it is held back for.
    pub about: AlertAbout,
}

/// What within one kind of alert on a plane is held back together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertAbout {
    /// The whole kind: one alert a window, whatever it is about.
    Kind,
    /// One agent attacked one way: an attack on another agent, or another
    /// kind of attack on this one, is held back apart.
    AgentAttack {
        /// The agent the attempts were made as.
        agent_id: AgentId,
        /// The kind of attack.
        attack: TokenAttack,
    },
}

/// What the throttle answers for one occurrence of an alert's event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertTurn {
    /// The alert goes out now.
    Raise {
        /// How many occurrences there were since the last alert of its
        /// kind, this one included, or `None` when no earlier alert is
        /// known.
        since_last: Option<u64>,
    },
    /// An alert of its kind went out within the window; the occurrence is
    /// counted and only recorded.
    HeldBack,
}

/// Dyn-safe port holding back repeats of a security alert: the first
/// occurrence of a kind on a plane is told, then at most one per window.
///
/// The adapter must count every occurrence, so the next alert can say how
/// many came since the last, and must decide on its own when its state
/// cannot answer: neither silencing every alert while it is down nor
/// letting each occurrence through, so an attacker repeating a request
/// cannot flood anyone by taking the state down.
#[async_trait]
pub trait AlertThrottle: Send + Sync {
    /// Counts one occurrence of `key`'s event and answers whether its alert
    /// goes out now: the first within `window` does, the rest are held
    /// back.
    async fn admit(&self, key: &AlertKey, window: Duration) -> AlertTurn;
}
