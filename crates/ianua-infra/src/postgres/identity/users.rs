//! A tenant's users, each table row under row-level security.
//!
//! Every read of a user goes through one checked query by ids, or by
//! address, and one mapping into the aggregate. A list first reads the ids
//! of its page, filtered and ordered in SQL, then reads those rows the same
//! way. A list sorted by a custom attribute joins the attribute's value,
//! and those with no value come last whichever way it runs.

mod filters;
pub(crate) mod record;
mod words;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortKey, SortKeys as _, SortOrder};
use ianua_app::ports::TenantScoped;
use ianua_app::ports::identity::{UserFilter, UserOrdering, UserSortField, UserStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::identity::account::user::User;
use ianua_domain::domains::identity::attribute::{ResolvedAttributeSort, ValueType};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, TenantId, UserId};
use sqlx::PgConnection;
use sqlx::postgres::PgQueryResult;
use uuid::Uuid;

use self::filters::narrowed;
use self::record::{UserColumns, UserRecord};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::paging::{Count, Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps an address to one user of a tenant.
const EMAIL_KEY: &str = "users_email_key";

/// The value of the attribute a list is sorted by, beside each user. The
/// bound array holds its namespace and key.
const SORTED_VALUE: &str = "LEFT JOIN user_metadata sorted ON sorted.tenant_id = users.tenant_id \
    AND sorted.user_id = users.id AND ARRAY[sorted.namespace, sorted.key] = ?";

/// The Postgres user store.
pub struct PgUserStore {
    databases: Arc<Databases>,
    limits: DomainLimits,
}

/// The tenant, predicates and cursor shared by either form of user ordering.
struct UserPage<'a> {
    /// Restricts the read to the selected tenant.
    tenant: &'a ScopedTenant,
    /// Narrows the users before ordering and paging.
    filter: &'a UserFilter,
    /// Bounds the result and identifies its cursor position.
    request: &'a PageRequest,
}

impl TenantScoped for PgUserStore {}

impl PgUserStore {
    /// A store keeping users in `databases`, checking each stored name
    /// against `limits` as it is read back.
    #[must_use]
    pub fn new(databases: Arc<Databases>, limits: DomainLimits) -> Self {
        Self { databases, limits }
    }

    fn rebuilt_all(
        &self,
        records: Vec<UserRecord>,
    ) -> Result<Vec<User<ResolvedTenant>>, DomainError> {
        records
            .into_iter()
            .map(|record| record.into_user(&self.limits))
            .collect()
    }

    /// Reads the selected user page in the columns named by `sort`.
    async fn column_page(
        &self,
        page: &UserPage<'_>,
        sort: &SortOrder<UserSortField>,
    ) -> Result<Page<User<ResolvedTenant>>, DomainError> {
        let keyset = page.request.keyset(sort)?;
        let listed = narrowed(
            PageQuery::ids("users.id", "users"),
            page.tenant,
            page.filter,
        )?;
        let records = scoped(
            &self.databases,
            RowScope::from(page.tenant),
            async |connection| {
                let ids = listed.fetch(&keyset, &mut *connection).await?;
                records_in_order(connection, page.tenant, &ids).await
            },
        )
        .await?;
        Ok(keyset.seal(self.rebuilt_all(records)?))
    }

    /// Reads the selected user page by its resolved attribute ordering.
    async fn attribute_page(
        &self,
        page: &UserPage<'_>,
        ordering: &UserOrdering,
        sort: &ResolvedAttributeSort,
    ) -> Result<Page<User<ResolvedTenant>>, DomainError> {
        let keyset = page.request.keyset(ordering)?;
        let sorted_by = sorted_by(sort.value_type())?;
        let attribute = vec![
            sort.namespace().as_str().to_owned(),
            sort.key().as_str().to_owned(),
        ];
        let joined = PageQuery::joined("users.id", "users", SORTED_VALUE, attribute);
        let listed = narrowed(joined, page.tenant, page.filter)?;
        let (records, values) = scoped(
            &self.databases,
            RowScope::from(page.tenant),
            async |connection| {
                let ids = listed
                    .fetch_by(&keyset, &sorted_by, &mut *connection)
                    .await?;
                let values = sort_values(connection, page.tenant, &ids, sort).await?;
                let records = records_in_order(connection, page.tenant, &ids).await?;
                Ok((records, values))
            },
        )
        .await?;
        let users = self.rebuilt_all(records)?;
        Ok(keyset.seal_by(users, |user| {
            sort_keys(values.get(user.id().as_uuid()), sort.value_type(), user)
        }))
    }
}

/// The records of the users `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    tenant: &TenantId,
    ids: &[Uuid],
) -> Result<Vec<UserRecord>, sqlx::Error> {
    sqlx::query_file_as!(
        UserRecord,
        "queries/users/by_ids.sql",
        tenant.as_uuid(),
        ids
    )
    .fetch_all(connection)
    .await
}

/// The records of the users `ids` names, in the order of `ids`.
async fn records_in_order(
    connection: &mut PgConnection,
    tenant: &TenantId,
    ids: &[Uuid],
) -> Result<Vec<UserRecord>, sqlx::Error> {
    let records = records_of(connection, tenant, ids).await?;
    Ok(in_page_order(ids, records, |record| record.id))
}

/// One stored value of the attribute a list is sorted by.
struct SortValue {
    user_id: Uuid,
    value_text: Option<String>,
    value_int: Option<i64>,
    value_float: Option<f64>,
    value_bool: Option<bool>,
}

/// The value the attribute `sort` names holds for each of `ids`, by user.
async fn sort_values(
    connection: &mut PgConnection,
    tenant: &TenantId,
    ids: &[Uuid],
    sort: &ResolvedAttributeSort,
) -> Result<HashMap<Uuid, SortValue>, sqlx::Error> {
    let values = sqlx::query_file_as!(
        SortValue,
        "queries/user_metadata/sort_values.sql",
        tenant.as_uuid(),
        ids,
        sort.namespace().as_str(),
        sort.key().as_str()
    )
    .fetch_all(connection)
    .await?;
    Ok(values
        .into_iter()
        .map(|value| (value.user_id, value))
        .collect())
}

/// The order a number attribute sorts in, as a whole number: the bits of
/// the number, with those of a negative one turned so a larger one sorts
/// later, the same key [`float_sort_key`] gives the cursor, so a list
/// sorted by a decimal attribute pages by it exactly.
const FLOAT_SORT_KEY: &str = "(SELECT CASE WHEN bits < 0 THEN bits # 9223372036854775807 ELSE bits END \
     FROM (SELECT ('x' || encode(float8send(coalesce(sorted.value_float, sorted.value_int::float8)), \
     'hex'))::bit(64)::bigint AS bits) raw)";

/// The expressions a list sorted by an attribute of `value_type` is
/// ordered by: whether a user holds no value, so those holding one come
/// first whichever way, then the value as a key the cursor can hold.
fn sorted_by(value_type: ValueType) -> Result<[(&'static str, Nullable); 2], DomainError> {
    let value = match value_type {
        ValueType::Text => ("num_nulls(sorted.value_text)", "sorted.value_text"),
        ValueType::Integer => ("num_nulls(sorted.value_int)", "sorted.value_int"),
        ValueType::Number => (
            "num_nulls(coalesce(sorted.value_float, sorted.value_int::float8))",
            FLOAT_SORT_KEY,
        ),
        ValueType::Boolean => ("num_nulls(sorted.value_bool)", "sorted.value_bool::int"),
        ValueType::TextArray => {
            return Err(DomainError::invalid(message!(
                "infra-a-list-of-text-cannot-be",
                "a list of text cannot be sorted by"
            )));
        }
    };
    Ok([(value.0, Nullable::Never), (value.1, Nullable::Maybe)])
}

/// The keys `user` sorts by, as [`sorted_by`] orders them, from its stored
/// `value`.
fn sort_keys(
    value: Option<&SortValue>,
    value_type: ValueType,
    user: &User<ResolvedTenant>,
) -> Vec<SortKey> {
    let key = value.map_or(SortKey::Missing, |value| key_of(value, value_type));
    let missing = SortKey::Integer(i64::from(key == SortKey::Missing));
    vec![missing, key, user.tiebreak()]
}

/// The key one stored value sorts by, read as `value_type` stores it.
fn key_of(value: &SortValue, value_type: ValueType) -> SortKey {
    match value_type {
        ValueType::Text => SortKey::from(value.value_text.clone()),
        ValueType::Integer => SortKey::from(value.value_int),
        ValueType::Number => SortKey::from(number_of(value).map(float_sort_key)),
        ValueType::Boolean => SortKey::from(value.value_bool.map(i64::from)),
        ValueType::TextArray => SortKey::Missing,
    }
}

/// The number a number attribute holds, from whichever column holds it.
fn number_of(value: &SortValue) -> Option<f64> {
    value
        .value_float
        .or(value.value_int.map(|whole| whole as f64))
}

/// The whole number that sorts as `number` does, as [`FLOAT_SORT_KEY`]
/// writes it in the query: the bits of the number, with those of a negative
/// one turned so that a larger one sorts later.
fn float_sort_key(number: f64) -> i64 {
    let bits = i64::from_be_bytes(number.to_be_bytes());
    if bits < 0 {
        return bits ^ i64::MAX;
    }
    bits
}

impl SortColumns for UserSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "users.created_at",
            Self::UpdatedAt => "users.updated_at",
            Self::Email => "users.email",
            Self::DisplayName => "users.display_name",
            Self::Status => "users.status",
            Self::LastLoginAt => "users.last_login_at",
        }
    }

    fn nullable(self) -> Nullable {
        match self {
            Self::LastLoginAt => Nullable::Maybe,
            Self::CreatedAt | Self::UpdatedAt | Self::Email | Self::DisplayName | Self::Status => {
                Nullable::Never
            }
        }
    }
}

#[async_trait]
impl UserStore for PgUserStore {
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &UserId,
    ) -> Result<Option<User<ResolvedTenant>>, DomainError> {
        let found = self
            .find_by_ids(tenant_id, std::slice::from_ref(id))
            .await?;
        Ok(found.into_iter().next())
    }

    async fn find_by_ids(
        &self,
        tenant_id: &ScopedTenant,
        ids: &[UserId],
    ) -> Result<Vec<User<ResolvedTenant>>, DomainError> {
        let ids: Vec<Uuid> = ids.iter().map(|id| *id.as_uuid()).collect();
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| records_of(connection, tenant_id, &ids).await,
        )
        .await?;
        self.rebuilt_all(records)
    }

    async fn find_by_email(
        &self,
        tenant_id: &ScopedTenant,
        email: &Email,
    ) -> Result<Option<User<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    UserRecord,
                    "queries/users/by_email.sql",
                    tenant_id.as_uuid(),
                    email.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record
            .map(|record| record.into_user(&self.limits))
            .transpose()
    }

    async fn email_exists(
        &self,
        tenant_id: &ScopedTenant,
        email: &Email,
    ) -> Result<bool, DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/users/email_taken.sql",
                    tenant_id.as_uuid(),
                    email.as_str()
                )
                .fetch_one(connection)
                .await
            },
        )
        .await
    }

    async fn list(
        &self,
        tenant_id: &ScopedTenant,
        filter: &UserFilter,
        ordering: &UserOrdering,
        page: &PageRequest,
    ) -> Result<Page<User<ResolvedTenant>>, DomainError> {
        let selected = UserPage {
            tenant: tenant_id,
            filter,
            request: page,
        };
        match ordering {
            UserOrdering::Column(sort) => self.column_page(&selected, sort).await,
            UserOrdering::Attribute(sort) => self.attribute_page(&selected, ordering, sort).await,
        }
    }

    async fn count(
        &self,
        tenant_id: &ScopedTenant,
        filter: &UserFilter,
    ) -> Result<u64, DomainError> {
        let counted = narrowed(PageQuery::<Count>::counted("users"), tenant_id, filter)?;
        let count = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| counted.count(connection).await,
        )
        .await?;
        u64::try_from(count).map_err(DomainError::infra)
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        user: &User<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = UserColumns::of(user);
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                unique_on(write_user(connection, tenant_id, &columns).await, EMAIL_KEY)
            },
        )
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-another-user-of-the-tenant-already",
                "another user of the tenant already has this address"
            ))),
        }
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &UserId) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/users/delete.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid()
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }
}

/// Writes every mapped user column in one tenant-scoped statement.
async fn write_user(
    connection: &mut PgConnection,
    tenant: &ScopedTenant,
    columns: &UserColumns<'_>,
) -> Result<PgQueryResult, sqlx::Error> {
    sqlx::query_file!(
        "queries/users/save.sql",
        columns.id,
        tenant.as_uuid(),
        columns.email,
        columns.display_name,
        columns.status,
        columns.email_verified,
        columns.locale,
        columns.timezone,
        columns.given_name,
        columns.family_name,
        columns.preferred_username,
        columns.picture,
        columns.phone_number,
        columns.external_id,
        columns.department,
        columns.manager_id,
        columns.employee_number,
        columns.created_at,
        columns.updated_at,
        columns.last_login_at,
        columns.joined_at,
        columns.credentials_changed_at,
        columns.route_vouches,
    )
    .execute(connection)
    .await
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{Limit, Sort};
    use ianua_app::ports::authorization::{
        GroupMembershipStore, GroupStore, RoleAssignmentStore, RoleStore,
    };
    use ianua_app::ports::identity::{MetadataStore, TimeSpan, UserAttributeStore};
    use ianua_domain::domains::authorization::group::GroupPlace;
    use ianua_domain::domains::identity::account::profile_values::{FamilyName, GivenName};
    use ianua_domain::domains::identity::account::user::UserRow;
    use ianua_domain::domains::identity::account::user_profile::{
        DirectoryRecords, PersonalDetails, UserProfile,
    };
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::identity::account::vouching::Vouching;
    use ianua_domain::domains::identity::attribute::definition::{Filtering, Sorting};
    use ianua_domain::domains::identity::attribute::resolved::SortDirection as AttributeDirection;
    use ianua_domain::domains::identity::attribute::{
        AttributeClearance, AttributeDefinition, AttributeDefinitionRow, AttributeFilterRequest,
        AttributeKey, AttributeKind, AttributeNamespace, AttributeOperator, AttributeSortRequest,
        AttributeVisibility, MetadataSchema, ResolvedAttributeFilter,
    };
    use ianua_domain::domains::identity::metadata_value::MetadataValue;
    use ianua_domain::types::{GroupId, Joining, Label, PrincipalRef, RoleId, Setting};

    use super::*;
    use crate::postgres::authorization::{
        PgGroupMembershipStore, PgGroupStore, PgRoleAssignmentStore, PgRoleStore,
    };
    use crate::postgres::identity::{PgMetadataStore, PgUserAttributeStore};
    use crate::test_support::TestDb;
    use crate::test_support::rows::identity::{attribute_row, user_row, user_row_standing};
    use crate::test_support::rows::{at, authorization};

    struct Fixture {
        db: TestDb,
        store: PgUserStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, the store on it, and one tenant to keep users in.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            store: PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default()),
            tenant: ScopedTenant::for_background(TenantId::new()),
            db,
        }
    }

    fn user(row: UserRow) -> User<ResolvedTenant> {
        User::reconstitute(row).unwrap()
    }

    fn active(email: &str) -> User<ResolvedTenant> {
        user(user_row(email))
    }

    impl Fixture {
        async fn save_all(&self, users: &[&User<ResolvedTenant>]) {
            for user in users {
                self.store.save(&self.tenant, user).await.unwrap();
            }
        }

        async fn listed(
            &self,
            filter: &UserFilter,
            ordering: &UserOrdering,
            page: &PageRequest,
        ) -> Page<User<ResolvedTenant>> {
            self.store
                .list(&self.tenant, filter, ordering, page)
                .await
                .unwrap()
        }

        async fn emails_matching(&self, filter: &UserFilter) -> Vec<String> {
            let page = self.listed(filter, &by_email(), &first(50)).await;
            emails(&page)
        }

        /// Lists addresses containing literal text through the production substring filter.
        async fn emails_containing(&self, part: &str) -> Vec<String> {
            self.emails_matching(&UserFilter {
                email_contains: Some(part.to_owned()),
                ..UserFilter::all()
            })
            .await
        }
    }

    fn by(field: UserSortField) -> UserOrdering {
        UserOrdering::Column(SortOrder::single(Sort::ascending(field)))
    }

    fn by_email() -> UserOrdering {
        by(UserSortField::Email)
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    fn after(page: &Page<User<ResolvedTenant>>, limit: u32) -> PageRequest {
        PageRequest::new(page.next.clone(), Limit::new(limit).unwrap())
    }

    fn emails(page: &Page<User<ResolvedTenant>>) -> Vec<String> {
        page.items
            .iter()
            .map(|user| user.email().as_str().to_owned())
            .collect()
    }

    /// Ann, with her own details and a manager, is found by her id, among
    /// several ids, and by her address, as she was saved.
    #[tokio::test]
    async fn a_saved_user_is_found_by_id_and_by_address() {
        let db = fixture().await;
        let boss = active("boss@acme.example");
        let ann = ann_with_manager(*boss.id());
        db.save_all(&[&boss, &ann]).await;

        let by_id = db
            .store
            .find_by_id(&db.tenant, ann.id())
            .await
            .unwrap()
            .unwrap();
        let by_email = db
            .store
            .find_by_email(&db.tenant, ann.email())
            .await
            .unwrap()
            .unwrap();
        let by_ids = db
            .store
            .find_by_ids(&db.tenant, &[*ann.id(), UserId::new()])
            .await
            .unwrap();

        for found in [&by_id, &by_email] {
            assert_eq!(found.id(), ann.id());
            assert_eq!(found.profile(), ann.profile());
            assert_eq!(found.last_login_at(), Some(at(10)));
            assert_eq!(found.joined_at(), ann.joined_at());
            assert!(found.email_verified());
        }
        assert_eq!(by_ids.len(), 1);
    }

    /// Restores Ann's named profile, manager and recorded sign-in for lookup comparisons.
    fn ann_with_manager(manager: UserId) -> User<ResolvedTenant> {
        user(UserRow {
            profile: UserProfile {
                details: PersonalDetails {
                    given_name: Setting::Set(GivenName::new("Ann").unwrap()),
                    family_name: Setting::Set(FamilyName::new("Lovelace").unwrap()),
                    ..PersonalDetails::default()
                },
                records: DirectoryRecords {
                    manager: Setting::Set(manager),
                    ..DirectoryRecords::default()
                },
            },
            last_login_at: Some(at(10)),
            ..user_row("ann@acme.example")
        })
    }

    /// Ann just accepted her invitation, so it vouches for her first
    /// sign-in. Saved and read back, it still does; once she signs in and
    /// is saved again, it no longer does. She joined before the clock's
    /// now, which her sign-in is dated at.
    #[tokio::test]
    async fn what_an_invitation_vouches_for_is_kept_until_the_first_sign_in() {
        let db = fixture().await;
        let joined = at(-40_000_000);
        let mut ann = user(UserRow {
            created_at: joined,
            updated_at: joined,
            joining: Joining::Joined { at: joined },
            vouching: Vouching::Fresh,
            ..user_row("ann@acme.example")
        });
        db.save_all(&[&ann]).await;

        let vouched = db
            .store
            .find_by_id(&db.tenant, ann.id())
            .await
            .unwrap()
            .unwrap();
        ann.record_login();
        db.save_all(&[&ann]).await;
        let spent = db
            .store
            .find_by_email(&db.tenant, ann.email())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(vouched.vouching(), Vouching::Fresh);
        assert_eq!(spent.vouching(), Vouching::Absent);
    }

    /// An id or address nobody has finds nothing, rather than failing.
    #[tokio::test]
    async fn an_unknown_user_is_not_found() {
        let db = fixture().await;
        let nobody = Email::new("nobody@acme.example").unwrap();

        assert!(
            db.store
                .find_by_id(&db.tenant, &UserId::new())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.store
                .find_by_email(&db.tenant, &nobody)
                .await
                .unwrap()
                .is_none()
        );
        assert!(!db.store.email_exists(&db.tenant, &nobody).await.unwrap());
    }

    /// Saving another user with Ann's email returns a conflict, and the
    /// address remains reported as taken.
    #[tokio::test]
    async fn an_address_another_user_has_is_refused() {
        let db = fixture().await;
        let ann = active("ann@acme.example");
        db.save_all(&[&ann]).await;

        let second = db.store.save(&db.tenant, &active("ann@acme.example")).await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
        assert!(
            db.store
                .email_exists(&db.tenant, ann.email())
                .await
                .unwrap()
        );
    }

    /// Another tenant may hold the same address, and sees none of Acme's
    /// users by id, by address or in a list.
    #[tokio::test]
    async fn another_tenants_users_are_invisible() {
        let db = fixture().await;
        let ann = active("ann@acme.example");
        db.save_all(&[&ann]).await;
        let other = ScopedTenant::for_background(TenantId::new());

        let theirs = active("ann@acme.example");
        db.store.save(&other, &theirs).await.unwrap();
        let by_id = db.store.find_by_id(&other, ann.id()).await.unwrap();
        let listed = db
            .store
            .list(&other, &UserFilter::all(), &by_email(), &first(10))
            .await
            .unwrap();

        assert!(by_id.is_none());
        assert_eq!(listed.items.len(), 1);
        assert_eq!(listed.items[0].id(), theirs.id());
    }

    /// Acme's users are read page by page by address: each page follows the
    /// last, and the last says nothing follows.
    #[tokio::test]
    async fn a_list_is_read_page_by_page_in_its_order() {
        let db = fixture().await;
        let users = ["cid@acme.example", "ann@acme.example", "bob@acme.example"].map(active);
        db.save_all(&users.iter().collect::<Vec<_>>()).await;

        let page_one = db.listed(&UserFilter::all(), &by_email(), &first(2)).await;
        let page_two = db
            .listed(&UserFilter::all(), &by_email(), &after(&page_one, 2))
            .await;

        assert_eq!(emails(&page_one), ["ann@acme.example", "bob@acme.example"]);
        assert_eq!(emails(&page_two), ["cid@acme.example"]);
        assert!(!page_two.has_next());
    }

    /// Paging by status returns the active user first, then the invited
    /// and locked users in stored-word order, without repeats or omissions.
    #[tokio::test]
    async fn a_list_sorted_by_status_pages_by_the_stored_word() {
        let db = fixture().await;
        let locked = user(user_row_standing("ann@acme.example", UserStatus::Locked));
        let active = active("bob@acme.example");
        let invited = user(user_row_standing("cid@acme.example", UserStatus::Invited));
        db.save_all(&[&locked, &active, &invited]).await;
        let order = by(UserSortField::Status);

        let page_one = db.listed(&UserFilter::all(), &order, &first(1)).await;
        let rest = db
            .listed(&UserFilter::all(), &order, &after(&page_one, 5))
            .await;

        assert_eq!(emails(&page_one), ["bob@acme.example"]);
        assert_eq!(emails(&rest), ["cid@acme.example", "ann@acme.example"]);
    }

    /// Sorted by last sign-in, those who never signed in come after the
    /// rest, and a page boundary among them loses no one.
    #[tokio::test]
    async fn a_list_by_last_sign_in_pages_past_those_who_never_signed_in() {
        let db = fixture().await;
        let signed_in = user(UserRow {
            last_login_at: Some(at(5)),
            ..user_row("ann@acme.example")
        });
        let never = [active("bob@acme.example"), active("cid@acme.example")];
        db.save_all(&[&signed_in, &never[0], &never[1]]).await;
        let order = by(UserSortField::LastLoginAt);

        let page_one = db.listed(&UserFilter::all(), &order, &first(2)).await;
        let page_two = db
            .listed(&UserFilter::all(), &order, &after(&page_one, 2))
            .await;

        assert_eq!(emails(&page_one)[0], "ann@acme.example");
        assert_eq!(page_one.items.len() + page_two.items.len(), 3);
        assert!(!page_two.has_next());
    }

    /// A list narrows to a status, to part of an address, and to part of a
    /// name, given or shown.
    #[tokio::test]
    async fn a_list_narrows_by_status_address_and_name() {
        let db = fixture().await;
        let ann = user_with_family("ann@acme.example", "Lovelace");
        let bob = active("bob_smith@globex.example");
        let cid = user(user_row_standing("cid@acme.example", UserStatus::Locked));
        db.save_all(&[&ann, &bob, &cid]).await;

        let locked = db
            .emails_matching(&UserFilter {
                status: Some(UserStatus::Locked),
                ..UserFilter::all()
            })
            .await;
        let at_acme = db.emails_containing("ACME").await;
        let underscored = db.emails_containing("b_s").await;
        let wildcard = db.emails_containing("a_n").await;
        let named = db
            .emails_matching(&UserFilter {
                name_contains: Some("love".to_owned()),
                ..UserFilter::all()
            })
            .await;

        assert_eq!(locked, ["cid@acme.example"]);
        assert_eq!(at_acme, ["ann@acme.example", "cid@acme.example"]);
        assert_eq!(underscored, ["bob_smith@globex.example"]);
        assert!(wildcard.is_empty());
        assert_eq!(named, ["ann@acme.example"]);
    }

    /// Adds a family name without changing the default user's other profile fields.
    fn user_with_family(email: &str, family: &str) -> User<ResolvedTenant> {
        user(UserRow {
            profile: UserProfile {
                details: PersonalDetails {
                    family_name: Setting::Set(FamilyName::new(family).unwrap()),
                    ..PersonalDetails::default()
                },
                ..UserProfile::default()
            },
            ..user_row(email)
        })
    }

    /// A list narrows to when users were created and when they last signed
    /// in; one who never signed in falls in no sign-in span.
    #[tokio::test]
    async fn a_list_narrows_by_time_spans() {
        let db = fixture().await;
        let old = active("ann@acme.example");
        let new = recently_joined_bob();
        db.save_all(&[&old, &new]).await;
        let span = TimeSpan {
            from: Some(at(50)),
            until: Some(at(200)),
        };

        let created = db
            .emails_matching(&UserFilter {
                created: span,
                ..UserFilter::all()
            })
            .await;
        let signed_in = db
            .emails_matching(&UserFilter {
                last_login: TimeSpan {
                    from: Some(at(0)),
                    until: None,
                },
                ..UserFilter::all()
            })
            .await;

        assert_eq!(created, ["bob@acme.example"]);
        assert_eq!(signed_in, ["bob@acme.example"]);
    }

    /// Restores Bob as joining at the later timestamp and signing in after joining.
    fn recently_joined_bob() -> User<ResolvedTenant> {
        user(UserRow {
            created_at: at(100),
            updated_at: at(100),
            last_login_at: Some(at(150)),
            joining: Joining::Joined { at: at(100) },
            ..user_row("bob@acme.example")
        })
    }

    /// A list kept to some users shows only those, and kept to none shows
    /// nobody; a count asks the same filter.
    #[tokio::test]
    async fn a_list_kept_to_some_ids_shows_only_those_and_counts_them() {
        let db = fixture().await;
        let ann = active("ann@acme.example");
        let bob = active("bob@acme.example");
        db.save_all(&[&ann, &bob]).await;
        let only_ann = UserFilter {
            ids: Some(vec![*ann.id()]),
            ..UserFilter::all()
        };
        let nobody = UserFilter {
            ids: Some(Vec::new()),
            ..UserFilter::all()
        };

        assert_eq!(db.emails_matching(&only_ann).await, ["ann@acme.example"]);
        assert!(db.emails_matching(&nobody).await.is_empty());
        assert_eq!(db.store.count(&db.tenant, &only_ann).await.unwrap(), 1);
        assert_eq!(
            db.store
                .count(&db.tenant, &UserFilter::all())
                .await
                .unwrap(),
            2
        );
        assert_eq!(db.store.count(&db.tenant, &nobody).await.unwrap(), 0);
    }

    /// Ann holds the role herself, Bob through the parent of the group he is
    /// in, Dee through that parent group itself, and Cid held it only until
    /// yesterday: the role keeps Ann, Bob and Dee, and each group keeps its
    /// own members and those of the groups below it.
    #[tokio::test]
    async fn a_list_narrows_by_role_and_by_group() {
        let db = fixture().await;
        let GroupRoles {
            role,
            parent,
            child,
        } = role_membership_fixture(&db).await;

        let holding = db
            .emails_matching(&UserFilter {
                role: Some(role),
                ..UserFilter::all()
            })
            .await;
        let in_parent = db
            .emails_matching(&UserFilter {
                group: Some(parent),
                ..UserFilter::all()
            })
            .await;
        let in_child = db
            .emails_matching(&UserFilter {
                group: Some(child),
                ..UserFilter::all()
            })
            .await;

        assert_eq!(
            holding,
            ["ann@acme.example", "bob@acme.example", "dee@acme.example"]
        );
        assert_eq!(in_parent, ["bob@acme.example", "dee@acme.example"]);
        assert_eq!(in_child, ["bob@acme.example"]);
    }

    /// Identifies the role inherited through a parent and child group.
    struct GroupRoles {
        role: RoleId,
        parent: GroupId,
        child: GroupId,
    }

    /// Saves direct, inherited and expired role holdings for the four test users.
    async fn role_membership_fixture(db: &Fixture) -> GroupRoles {
        let people = [
            "ann@acme.example",
            "bob@acme.example",
            "cid@acme.example",
            "dee@acme.example",
        ]
        .map(active);
        db.save_all(&people.iter().collect::<Vec<_>>()).await;
        let roles = save_role_groups(db).await;
        save_group_members(db, &roles, &people).await;
        roles
    }

    /// Saves a reviewer role held by engineering and inherited by its platform subgroup.
    async fn save_role_groups(db: &Fixture) -> GroupRoles {
        let databases = &db.db.databases;
        let reviewer = authorization::role("reviewer");
        let role = *reviewer.id();
        let parent_group = authorization::group("engineering", vec![role]);
        let parent = *parent_group.id();
        let child_group = authorization::group_under("platform", GroupPlace::Under(parent));
        let child = *child_group.id();
        PgRoleStore::new(Arc::clone(databases))
            .save(&db.tenant, &reviewer)
            .await
            .unwrap();
        let groups = PgGroupStore::new(Arc::clone(databases));
        groups.save(&db.tenant, &parent_group).await.unwrap();
        groups.save(&db.tenant, &child_group).await.unwrap();
        GroupRoles {
            role,
            parent,
            child,
        }
    }

    /// Gives Ann the role, expires Cid's grant and enrolls Bob and Dee in the groups.
    async fn save_group_members(
        db: &Fixture,
        roles: &GroupRoles,
        people: &[User<ResolvedTenant>; 4],
    ) {
        let [ann, bob, cid, dee] = people;
        let databases = &db.db.databases;
        let assignments = PgRoleAssignmentStore::new(Arc::clone(databases));
        let held = authorization::assignment(PrincipalRef::User(*ann.id()), roles.role);
        let ended = authorization::ended_assignment(PrincipalRef::User(*cid.id()), roles.role);
        assignments.save(&db.tenant, &held).await.unwrap();
        assignments.save(&db.tenant, &ended).await.unwrap();
        PgGroupMembershipStore::new(Arc::clone(databases))
            .save_all(
                &db.tenant,
                &[
                    authorization::membership(PrincipalRef::User(*bob.id()), roles.child),
                    authorization::membership(PrincipalRef::User(*dee.id()), roles.parent),
                ],
            )
            .await
            .unwrap();
    }

    /// Declares `name` in the app namespace, holding `kind`, open for
    /// filtering and sorting, and gives each of `values` its value.
    async fn an_attribute(
        db: &Fixture,
        name: &str,
        kind: AttributeKind,
        values: &[(&User<ResolvedTenant>, MetadataValue)],
    ) -> AttributeDefinition<ResolvedTenant> {
        let definition = AttributeDefinition::reconstitute(AttributeDefinitionRow {
            visibility: AttributeVisibility {
                filterable: Filtering::Filterable,
                sortable: Sorting::Sortable,
                ..AttributeVisibility::default()
            },
            ..attribute_row(name, AttributeNamespace::App, kind)
        })
        .unwrap();
        PgUserAttributeStore::new(Arc::clone(&db.db.databases))
            .save(&db.tenant, &definition)
            .await
            .unwrap();
        let metadata = PgMetadataStore::new(Arc::clone(&db.db.databases));
        let key = Label::new("metadata_key", name).unwrap();
        for (user, value) in values {
            metadata
                .set_app_value(&db.tenant, user.id(), &key, value)
                .await
                .unwrap();
        }
        definition
    }

    fn resolved(
        definition: AttributeDefinition<ResolvedTenant>,
        operator: AttributeOperator,
        operands: Vec<MetadataValue>,
    ) -> ResolvedAttributeFilter {
        let request = AttributeFilterRequest {
            namespace: AttributeNamespace::App,
            key: definition.key().clone(),
            operator,
            operands,
        };
        MetadataSchema::new(vec![definition])
            .resolve_filter(&request, AttributeClearance::Sensitive)
            .unwrap()
    }

    fn with_attributes(attributes: Vec<ResolvedAttributeFilter>) -> UserFilter {
        UserFilter {
            attributes,
            ..UserFilter::all()
        }
    }

    /// A list narrows by a custom attribute: a text equal to a value, a
    /// number above one whether stored whole or not, and nobody holding a
    /// value.
    #[tokio::test]
    async fn a_list_narrows_by_custom_attributes() {
        let db = fixture().await;
        let [ann, bob, cid] =
            ["ann@acme.example", "bob@acme.example", "cid@acme.example"].map(active);
        db.save_all(&[&ann, &bob, &cid]).await;
        let tier = filtering_tiers(&db, &ann, &bob).await;
        let score = filtering_scores(&db, &ann, &bob).await;
        let gold = resolved(
            tier.clone(),
            AttributeOperator::Is,
            vec![MetadataValue::from("gold")],
        );
        let high = resolved(
            score,
            AttributeOperator::GreaterThan,
            vec![MetadataValue::Number(5.0)],
        );
        let untiered = resolved(tier, AttributeOperator::IsAbsent, Vec::new());

        assert_eq!(
            db.emails_matching(&with_attributes(vec![gold])).await,
            ["ann@acme.example"]
        );
        assert_eq!(
            db.emails_matching(&with_attributes(vec![high])).await,
            ["ann@acme.example"]
        );
        assert_eq!(
            db.emails_matching(&with_attributes(vec![untiered])).await,
            ["cid@acme.example"]
        );
    }

    /// Gives Ann gold and Bob silver tiers while leaving other users without a tier.
    async fn filtering_tiers(
        db: &Fixture,
        ann: &User<ResolvedTenant>,
        bob: &User<ResolvedTenant>,
    ) -> AttributeDefinition<ResolvedTenant> {
        an_attribute(
            db,
            "tier",
            AttributeKind::Text,
            &[
                (ann, MetadataValue::from("gold")),
                (bob, MetadataValue::from("silver")),
            ],
        )
        .await
    }

    /// Stores Ann's score as an integer and Bob's as a decimal for numeric filtering.
    async fn filtering_scores(
        db: &Fixture,
        ann: &User<ResolvedTenant>,
        bob: &User<ResolvedTenant>,
    ) -> AttributeDefinition<ResolvedTenant> {
        an_attribute(
            db,
            "score",
            AttributeKind::Decimal,
            &[
                (ann, MetadataValue::Integer(9)),
                (bob, MetadataValue::Number(2.5)),
            ],
        )
        .await
    }

    fn ordered_by(
        name: &str,
        definition: AttributeDefinition<ResolvedTenant>,
        direction: AttributeDirection,
    ) -> UserOrdering {
        let request = AttributeSortRequest {
            namespace: AttributeNamespace::App,
            key: AttributeKey::new(name).unwrap(),
            direction,
        };
        UserOrdering::Attribute(
            MetadataSchema::new(vec![definition])
                .resolve_sort(&request, AttributeClearance::Sensitive)
                .unwrap(),
        )
    }

    /// Sorted by a number either way, those holding a value come first in
    /// its order, and those holding none come last; paging loses no one.
    #[tokio::test]
    async fn a_list_sorted_by_an_attribute_puts_those_without_a_value_last() {
        let db = fixture().await;
        let score = sorting_scores(&db).await;
        let rising = ordered_by("score", score.clone(), AttributeDirection::Ascending);
        let falling = ordered_by("score", score, AttributeDirection::Descending);

        let up_one = db.listed(&UserFilter::all(), &rising, &first(2)).await;
        let up_two = db
            .listed(&UserFilter::all(), &rising, &after(&up_one, 2))
            .await;
        let down_one = db.listed(&UserFilter::all(), &falling, &first(3)).await;
        let down_two = db
            .listed(&UserFilter::all(), &falling, &after(&down_one, 3))
            .await;

        assert_eq!(emails(&up_one), ["ann@acme.example", "cid@acme.example"]);
        assert_eq!(emails(&up_two), ["bob@acme.example", "dee@acme.example"]);
        assert_eq!(
            emails(&down_one),
            ["bob@acme.example", "cid@acme.example", "ann@acme.example"]
        );
        assert_eq!(emails(&down_two), ["dee@acme.example"]);
        assert!(!down_two.has_next());
    }

    /// Saves mixed numeric scores for three users and leaves Dee without a value.
    async fn sorting_scores(db: &Fixture) -> AttributeDefinition<ResolvedTenant> {
        let [ann, bob, cid, dee] = [
            "ann@acme.example",
            "bob@acme.example",
            "cid@acme.example",
            "dee@acme.example",
        ]
        .map(active);
        db.save_all(&[&ann, &bob, &cid, &dee]).await;
        an_attribute(
            db,
            "score",
            AttributeKind::Decimal,
            &[
                (&ann, MetadataValue::Number(-1.5)),
                (&bob, MetadataValue::Integer(3)),
                (&cid, MetadataValue::Number(2.25)),
            ],
        )
        .await
    }

    /// Ann is locked out: saving her again keeps the new status, and the
    /// time she was created stays.
    #[tokio::test]
    async fn saving_again_keeps_the_new_values() {
        let db = fixture().await;
        let ann = active("ann@acme.example");
        db.save_all(&[&ann]).await;
        let locked = user(UserRow {
            id: *ann.id(),
            updated_at: at(5),
            ..user_row_standing("ann@acme.example", UserStatus::Locked)
        });

        db.save_all(&[&locked]).await;

        let found = db
            .store
            .find_by_id(&db.tenant, ann.id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.status(), UserStatus::Locked);
        assert_eq!(found.updated_at(), at(5));
        assert_eq!(found.created_at(), ann.created_at());
    }

    /// Deleting Ann removes her and, by cascade, the values she held.
    #[tokio::test]
    async fn deleting_a_user_removes_what_belongs_to_them() {
        let db = fixture().await;
        let ann = active("ann@acme.example");
        db.save_all(&[&ann]).await;
        an_attribute(
            &db,
            "tier",
            AttributeKind::Text,
            &[(&ann, MetadataValue::from("gold"))],
        )
        .await;

        db.store.delete(&db.tenant, ann.id()).await.unwrap();

        let metadata = PgMetadataStore::new(Arc::clone(&db.db.databases));
        let (_, app) = metadata.find_by_user(&db.tenant, ann.id()).await.unwrap();
        assert!(
            db.store
                .find_by_id(&db.tenant, ann.id())
                .await
                .unwrap()
                .is_none()
        );
        assert!(app.is_empty());
    }

    /// A user with an invalid stored email address fails to load as corrupt
    /// storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_user_is_refused() {
        let db = fixture().await;
        let ann = active("ann@acme.example");
        db.save_all(&[&ann]).await;
        db.db
            .tamper("UPDATE users SET email = 'not an address'")
            .await;

        let read = db.store.find_by_id(&db.tenant, ann.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
