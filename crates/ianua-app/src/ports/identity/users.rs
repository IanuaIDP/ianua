//! The tenant's users: storing them, and how a listing filters and orders
//! them.

use async_trait::async_trait;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::account::user_status::UserStatus;
use ianua_domain::domains::identity::attribute::resolved::SortDirection as AttributeSortDirection;
use ianua_domain::domains::identity::attribute::{ResolvedAttributeFilter, ResolvedAttributeSort};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, GroupId, RoleId, UserId};
use time::OffsetDateTime;

use crate::define_sort_field;
use crate::listing::{
    KeyOrder, Page, PageRequest, RowKeys, SortDirection, SortKey, SortKeys, SortOrder,
};
use crate::ports::TenantScoped;
use crate::ports::identity::InvitationFilter;
use crate::tenancy::ScopedTenant;

define_sort_field! {
    /// Field a user listing can be ordered by.
    pub enum UserSortField {
        /// Order by creation time.
        CreatedAt => "created_at",
        /// Order by last update time.
        UpdatedAt => "updated_at",
        /// Order by email address.
        Email => "email",
        /// Order by display name.
        DisplayName => "display_name",
        /// Order by account status.
        Status => "status",
        /// Order by most recent login.
        LastLoginAt => "last_login_at",
    }
    default = CreatedAt;
    default direction = Desc;
}

/// Dyn-safe port for persisting and retrieving users.
#[async_trait]
pub trait UserStore: Send + Sync + TenantScoped {
    /// Finds a user by ID.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &UserId,
    ) -> Result<Option<User<ResolvedTenant>>, DomainError>;

    /// The users among `ids`, in one read. An id the tenant has no user for
    /// is left out, so the answer may be shorter than `ids`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[UserId],
    ) -> Result<Vec<User<ResolvedTenant>>, DomainError>;

    /// Finds a user by email.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find_by_email(
        &self,
        tenant_id: &ScopedTenant,
        email: &Email,
    ) -> Result<Option<User<ResolvedTenant>>, DomainError>;

    /// Checks whether an email is already taken.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn email_exists(
        &self,
        tenant_id: &ScopedTenant,
        email: &Email,
    ) -> Result<bool, DomainError>;

    /// One page of the users `filter` matches, in `ordering`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure, or a
    /// validation error when the page's cursor was made for another order.
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
        filter: &UserFilter,
        ordering: &UserOrdering,
        page: &PageRequest,
    ) -> Result<Page<User<ResolvedTenant>>, DomainError>;

    /// How many users `filter` matches: one count query, never a read of
    /// the users themselves. For a rule that depends on everyone, such as
    /// whether every user holds a required attribute; a list never needs it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn count(
        &self,
        tenant_id: &ScopedTenant,
        filter: &UserFilter,
    ) -> Result<u64, DomainError>;

    /// Saves a new or updated user.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        user: &User<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Permanently deletes a user. Dependent rows (sessions, role
    /// assignments, credentials and so on) are removed by database cascade.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(&self, tenant_id: &ScopedTenant, id: &UserId) -> Result<(), DomainError>;
}

/// Filter criteria for listing users.
pub struct UserFilter {
    /// Filter by status. `None` returns all statuses.
    pub status: Option<UserStatus>,
    /// Filter by email substring (case-insensitive search).
    pub email_contains: Option<String>,
    /// Filter by a substring of the display name, or of the given or family
    /// name, ignoring case.
    pub name_contains: Option<String>,
    /// Only users holding this role, given to them or to a group they are
    /// in, or one above it.
    pub role: Option<RoleId>,
    /// Only members of this group, or of one below it.
    pub group: Option<GroupId>,
    /// Only users whose last sign-in falls in this span. A user who never
    /// signed in falls in no span.
    pub last_login: TimeSpan,
    /// Only users created in this span.
    pub created: TimeSpan,
    /// Restrict to these users. `None` places no restriction; an empty set
    /// matches nobody.
    pub ids: Option<Vec<UserId>>,
    /// Only users with an open invitation in this state, evaluated before paging.
    pub invitation: Option<InvitationFilter>,
    /// Narrow by the tenant's own custom attributes. Every predicate must
    /// hold.
    ///
    /// Each one has already been checked against the declared schema, and
    /// the type is the only way to say so. That is what lets an adapter read
    /// a column name off it and bind the rest without deciding anything
    /// again.
    pub attributes: Vec<ResolvedAttributeFilter>,
}

impl UserFilter {
    /// No filter: returns all users.
    #[must_use]
    pub fn all() -> Self {
        Self {
            status: None,
            email_contains: None,
            name_contains: None,
            role: None,
            group: None,
            last_login: TimeSpan::any(),
            created: TimeSpan::any(),
            ids: None,
            invitation: None,
            attributes: Vec::new(),
        }
    }

    /// Whether any custom attribute is being filtered on.
    #[must_use]
    pub fn touches_attributes(&self) -> bool {
        !self.attributes.is_empty()
    }
}

/// A span of time a listing narrows a moment to: at or after `from`, and
/// before `until`. An open end narrows nothing on its side.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TimeSpan {
    /// The earliest moment that falls in the span.
    pub from: Option<OffsetDateTime>,
    /// The first moment past the span.
    pub until: Option<OffsetDateTime>,
}

impl TimeSpan {
    /// A span open at both ends, which every moment falls in.
    #[must_use]
    pub fn any() -> Self {
        Self::default()
    }

    /// Whether `at` falls in the span.
    #[must_use]
    pub fn holds(&self, at: OffsetDateTime) -> bool {
        self.from.is_none_or(|from| at >= from) && self.until.is_none_or(|until| at < until)
    }
}

/// How a user listing is ordered.
///
/// A column of the user row and a custom attribute are ordered by different
/// machinery. One names a column known at compile time, the other joins a
/// table and binds a key. So the two are distinct rather than a sort field
/// with a string in it. Keeping them apart is what leaves
/// [`UserSortField`]'s guarantee intact: every one of its columns is a
/// constant no caller can influence.
pub enum UserOrdering {
    /// Order by columns of the user row.
    Column(SortOrder<UserSortField>),
    /// Order by one of the tenant's custom attributes.
    ///
    /// Users holding no value for it sort last, whichever direction is asked
    /// for, so that a page of results is not filled with blanks.
    Attribute(ResolvedAttributeSort),
}

impl UserOrdering {
    /// The ordering applied when a caller asks for none.
    #[must_use]
    pub fn default_column() -> Self {
        Self::Column(SortOrder::default())
    }

    /// The custom attribute being ordered by, if any.
    #[must_use]
    pub fn attribute(&self) -> Option<&ResolvedAttributeSort> {
        match self {
            Self::Attribute(sort) => Some(sort),
            Self::Column(_) => None,
        }
    }
}

impl Default for UserOrdering {
    fn default() -> Self {
        Self::default_column()
    }
}

/// A column order pages as any sort order does. An attribute order is
/// `attr:` and the attribute's name, after a `-` when it descends, sorting
/// first by whether the user holds a value, those who do first whichever
/// way, then by the value and then the user's id.
impl KeyOrder for UserOrdering {
    fn signature(&self) -> String {
        match self {
            Self::Column(sort) => sort.signature(),
            Self::Attribute(sort) => format!(
                "{}attr:{}.{}",
                attribute_sign(sort.direction()),
                sort.namespace().as_str(),
                sort.key().as_str()
            ),
        }
    }

    fn directions(&self) -> Vec<SortDirection> {
        match self {
            Self::Column(sort) => sort.directions(),
            Self::Attribute(sort) => {
                let direction = attribute_direction(sort.direction());
                vec![SortDirection::Asc, direction, direction]
            }
        }
    }
}

/// A user row does not carry its custom attributes, so an attribute order
/// reads only the id off the row; the store that joins the value pages with
/// [`Keyset::seal_by`](crate::listing::Keyset::seal_by).
impl RowKeys<User<ResolvedTenant>> for UserOrdering {
    fn row_keys(&self, user: &User<ResolvedTenant>) -> Vec<SortKey> {
        match self {
            Self::Column(sort) => sort.row_keys(user),
            Self::Attribute(_) => vec![SortKey::Missing, SortKey::Missing, user.tiebreak()],
        }
    }
}

/// The listing direction an attribute sort runs in.
fn attribute_direction(direction: AttributeSortDirection) -> SortDirection {
    match direction {
        AttributeSortDirection::Ascending => SortDirection::Asc,
        AttributeSortDirection::Descending => SortDirection::Desc,
    }
}

/// The sign an attribute sort carries in its signature.
fn attribute_sign(direction: AttributeSortDirection) -> &'static str {
    match direction {
        AttributeSortDirection::Ascending => "",
        AttributeSortDirection::Descending => "-",
    }
}

impl SortKeys<UserSortField> for User<ResolvedTenant> {
    fn sort_key(&self, field: UserSortField) -> SortKey {
        match field {
            UserSortField::CreatedAt => self.created_at().into(),
            UserSortField::UpdatedAt => self.updated_at().into(),
            UserSortField::Email => self.email().as_str().into(),
            UserSortField::DisplayName => self.display_name().as_str().into(),
            UserSortField::Status => user_status_word(self.status()).into(),
            UserSortField::LastLoginAt => self.last_login_at().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id().as_uuid().into()
    }
}

/// The word a user's status sorts by, as it is stored.
fn user_status_word(status: UserStatus) -> &'static str {
    match status {
        UserStatus::Invited => "invited",
        UserStatus::PendingVerification => "pending_verification",
        UserStatus::Active => "active",
        UserStatus::Locked => "locked",
        UserStatus::Deactivated => "deactivated",
        UserStatus::Closing => "closing",
    }
}
