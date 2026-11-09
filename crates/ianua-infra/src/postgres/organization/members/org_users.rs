//! Organization members, kept in the platform database.
//!
//! An address is unique within one organization, not across the platform,
//! so the same person may hold an account in several. Every read goes
//! through one checked query and one mapping into the aggregate; a list
//! first reads the ids of its page, then reads those rows by id.

mod reach;
mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::listing::{Page, PageRequest, SortOrder};
use ianua_app::ports::organization::{OrgUserFilter, OrgUserSortField, OrgUserStore};
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::message;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, OrgUserId, OrganizationId};
use sqlx::PgConnection;
use uuid::Uuid;

pub use self::reach::PgMemberStandings;
use self::record::OrgUserColumns;
pub(crate) use self::record::OrgUserRecord;
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::paging::{Nullable, PageQuery, SortColumns, in_page_order};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::stored::StoredWord as _;
use crate::postgres::foundation::unit::{scoped, scoped_holding};

/// The constraint that keeps an address to one member of an organization.
const EMAIL_KEY: &str = "org_users_email_key";

/// The Postgres organization member store.
pub struct PgOrgUserStore {
    databases: Arc<Databases>,
    limits: DomainLimits,
}

impl PgOrgUserStore {
    /// A store keeping members in `databases`, checking each stored name
    /// against `limits` as it is read back.
    #[must_use]
    pub fn new(databases: Arc<Databases>, limits: DomainLimits) -> Self {
        Self { databases, limits }
    }

    fn rebuilt(&self, record: OrgUserRecord) -> Result<OrgUser, DomainError> {
        record.into_org_user(&self.limits)
    }

    fn rebuilt_all(&self, records: Vec<OrgUserRecord>) -> Result<Vec<OrgUser>, DomainError> {
        records
            .into_iter()
            .map(|record| self.rebuilt(record))
            .collect()
    }

    fn first(&self, record: Option<OrgUserRecord>) -> Result<Option<OrgUser>, DomainError> {
        record.map(|record| self.rebuilt(record)).transpose()
    }
}

/// The records of the members `ids` names, in no order.
async fn records_of(
    connection: &mut PgConnection,
    ids: &[Uuid],
) -> Result<Vec<OrgUserRecord>, sqlx::Error> {
    sqlx::query_file_as!(OrgUserRecord, "queries/org_users/by_ids.sql", ids)
        .fetch_all(connection)
        .await
}

/// Writes the member's columns and distinguishes an address already held in the organization.
async fn write_member(
    connection: &mut PgConnection,
    columns: &OrgUserColumns<'_>,
) -> Result<Uniqueness, sqlx::Error> {
    let attempt = sqlx::query_file!(
        "queries/org_users/save.sql",
        columns.id,
        columns.organization_id,
        columns.email,
        columns.display_name,
        columns.password_hash,
        columns.status,
        columns.role,
        columns.email_standing,
        columns.locale,
        columns.timezone,
        columns.joined_at,
        columns.credentials_changed_at,
        columns.route_vouches,
        columns.created_at,
        columns.updated_at,
    )
    .execute(connection)
    .await;
    unique_on(attempt, EMAIL_KEY)
}

impl SortColumns for OrgUserSortField {
    fn column(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::UpdatedAt => "updated_at",
            Self::Email => "email",
            Self::DisplayName => "display_name",
            Self::Status => "status",
        }
    }

    fn nullable(self) -> Nullable {
        Nullable::Never
    }
}

/// The ids of the members of `organization_id` that pass `filter`.
fn listed(organization_id: &OrganizationId, filter: &OrgUserFilter) -> PageQuery<'static> {
    let members =
        PageQuery::ids("id", "org_users").filter("organization_id = ?", *organization_id.as_uuid());
    let members = in_status(members, filter);
    let members = with_address_part(members, filter);
    among(members, filter)
}

fn in_status(listed: PageQuery<'static>, filter: &OrgUserFilter) -> PageQuery<'static> {
    let Some(status) = filter.status else {
        return listed;
    };
    listed.filter("status = ?", status.word())
}

/// `listed` narrowed to addresses holding the part asked for, in any case.
/// Addresses are stored in lower case, so the part is lowered to match.
fn with_address_part(listed: PageQuery<'static>, filter: &OrgUserFilter) -> PageQuery<'static> {
    let Some(part) = &filter.email_contains else {
        return listed;
    };
    listed.filter("strpos(email, ?) > 0", part.to_lowercase())
}

fn among(listed: PageQuery<'static>, filter: &OrgUserFilter) -> PageQuery<'static> {
    let Some(ids) = &filter.ids else {
        return listed;
    };
    let ids: Vec<Uuid> = ids.iter().map(|id| *id.as_uuid()).collect();
    listed.filter("id = ANY(?)", ids)
}

#[async_trait]
impl OrgUserStore for PgOrgUserStore {
    async fn find_by_ids(&self, ids: &[OrgUserId]) -> Result<Vec<OrgUser>, DomainError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<Uuid> = ids.iter().map(|id| *id.as_uuid()).collect();
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            records_of(connection, &ids).await
        })
        .await?;
        self.rebuilt_all(records)
    }

    async fn find_by_id(&self, id: &OrgUserId) -> Result<Option<OrgUser>, DomainError> {
        let ids = [*id.as_uuid()];
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            records_of(connection, &ids).await
        })
        .await?;
        self.first(records.into_iter().next())
    }

    async fn find_by_id_in_org(
        &self,
        organization_id: &OrganizationId,
        id: &OrgUserId,
    ) -> Result<Option<OrgUser>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                OrgUserRecord,
                "queries/org_users/by_id_in_organization.sql",
                id.as_uuid(),
                organization_id.as_uuid()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        self.first(record)
    }

    async fn hold_by_id_in_org(
        &self,
        organization_id: &OrganizationId,
        id: &OrgUserId,
    ) -> Result<Option<OrgUser>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                OrgUserRecord,
                "queries/org_users/hold_in_organization.sql",
                id.as_uuid(),
                organization_id.as_uuid()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        self.first(record)
    }

    async fn hold_ownership(&self, organization_id: &OrganizationId) -> Result<(), DomainError> {
        scoped_holding(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_scalar!(
                "queries/org_users/hold_ownership.sql",
                organization_id.as_uuid()
            )
            .fetch_one(connection)
            .await
            .map(|_| ())
        })
        .await
    }

    async fn list_owners(
        &self,
        organization_id: &OrganizationId,
    ) -> Result<Vec<OrgUser>, DomainError> {
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                OrgUserRecord,
                "queries/org_users/owners.sql",
                organization_id.as_uuid()
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        self.rebuilt_all(records)
    }

    async fn find_by_email(
        &self,
        organization_id: &OrganizationId,
        email: &Email,
    ) -> Result<Option<OrgUser>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                OrgUserRecord,
                "queries/org_users/by_email.sql",
                organization_id.as_uuid(),
                email.as_str()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        self.first(record)
    }

    async fn find_all_by_email(&self, email: &Email) -> Result<Vec<OrgUser>, DomainError> {
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                OrgUserRecord,
                "queries/org_users/by_address.sql",
                email.as_str()
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        self.rebuilt_all(records)
    }

    async fn email_exists(&self, email: &Email) -> Result<bool, DomainError> {
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_scalar!("queries/org_users/address_taken.sql", email.as_str())
                .fetch_one(connection)
                .await
        })
        .await
    }

    async fn list_by_org(
        &self,
        organization_id: &OrganizationId,
        filter: &OrgUserFilter,
        sort: &SortOrder<OrgUserSortField>,
        page: &PageRequest,
    ) -> Result<Page<OrgUser>, DomainError> {
        let keyset = page.keyset(sort)?;
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            let ids = listed(organization_id, filter)
                .fetch(&keyset, &mut *connection)
                .await?;
            let records = records_of(connection, &ids).await?;
            Ok(in_page_order(&ids, records, |record| record.id))
        })
        .await?;
        Ok(keyset.seal(self.rebuilt_all(records)?))
    }

    async fn save(&self, user: &OrgUser) -> Result<(), DomainError> {
        let columns = OrgUserColumns::of(user);
        let written = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            write_member(connection, &columns).await
        })
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-another-member-of-this-organization-already",
                "another member of this organization already has this address"
            ))),
        }
    }

    async fn delete(&self, id: &OrgUserId) -> Result<(), DomainError> {
        scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!("queries/org_users/delete.sql", id.as_uuid())
                .execute(connection)
                .await?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ianua_app::listing::{Limit, Sort};
    use ianua_app::ports::organization::OrganizationStore;
    use ianua_app::ports::runtime::{Settlement, atomically};
    use ianua_domain::domains::identity::account::vouching::Vouching;
    use ianua_domain::domains::organization::lifecycle::Organization;
    use ianua_domain::domains::organization::members::membership::OrgRole;
    use ianua_domain::domains::organization::members::org_user::{OrgPassword, OrgUserRow};
    use ianua_domain::domains::organization::members::org_user_status::OrgUserStatus;
    use ianua_domain::types::{CredentialChange, Joining, Locale, PasswordHash, Preference};
    use tokio::sync::oneshot;

    use super::*;
    use crate::postgres::foundation::unit::PgUnitOfWork;
    use crate::postgres::organization::PgOrganizationStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::organization::{org_user_row, organization_row};

    struct Fixture {
        db: TestDb,
        store: PgOrgUserStore,
        acme: OrganizationId,
    }

    /// A fresh database holding Acme, and the store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let acme = an_organization(&db, "acme").await;
        let store = PgOrgUserStore::new(Arc::clone(&db.databases), DomainLimits::default());
        Fixture { db, store, acme }
    }

    /// Saves an organization under `slug` through its store.
    async fn an_organization(db: &TestDb, slug: &str) -> OrganizationId {
        let organization = Organization::reconstitute(organization_row(slug, slug)).unwrap();
        PgOrganizationStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&organization)
            .await
            .unwrap();
        *organization.id()
    }

    fn member(row: OrgUserRow) -> OrgUser {
        OrgUser::reconstitute(row).unwrap()
    }

    fn at_address(organization: OrganizationId, email: &str) -> OrgUser {
        member(org_user_row(organization, email))
    }

    fn owner(organization: OrganizationId, email: &str) -> OrgUser {
        member(OrgUserRow {
            role: OrgRole::Owner,
            ..org_user_row(organization, email)
        })
    }

    fn by(field: OrgUserSortField) -> SortOrder<OrgUserSortField> {
        SortOrder::single(Sort::ascending(field))
    }

    fn first(limit: u32) -> PageRequest {
        PageRequest::first(Limit::new(limit).unwrap())
    }

    fn email(address: &str) -> Email {
        Email::new(address).unwrap()
    }

    fn addresses(page: &Page<OrgUser>) -> Vec<&str> {
        page.items
            .iter()
            .map(|user| user.email().as_str())
            .collect()
    }

    async fn save_all(store: &PgOrgUserStore, members: &[&OrgUser]) {
        for member in members {
            store.save(member).await.unwrap();
        }
    }

    /// A held lookup finds no member under another organization, while
    /// Acme's lookup returns Ann's ID, organization and owner role.
    #[tokio::test]
    async fn a_held_member_is_confined_to_the_organization_named() {
        let fx = fixture().await;
        let ann = owner(fx.acme, "ann@acme.example");
        fx.store.save(&ann).await.unwrap();
        let other = an_organization(&fx.db, "other").await;

        assert!(
            fx.store
                .hold_by_id_in_org(&other, ann.id())
                .await
                .unwrap()
                .is_none()
        );
        let held = fx
            .store
            .hold_by_id_in_org(&fx.acme, ann.id())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(held.id(), ann.id());
        assert_eq!(held.organization_id(), &fx.acme);
        assert_eq!(held.role(), OrgRole::Owner);
    }

    /// Ann joins Acme: she is found again by her id, by her id within Acme
    /// and by her address, as she was saved.
    #[tokio::test]
    async fn a_saved_member_is_found_by_id_and_by_address() {
        let fx = fixture().await;
        let ann = member(OrgUserRow {
            password_hash: OrgPassword::Set(PasswordHash::from_stored("argon2-hash".to_owned())),
            locale: Preference::Own(Locale::new("de-DE").unwrap()),
            credentials_changed_at: CredentialChange::At { at: at(3) },
            updated_at: at(3),
            ..org_user_row(fx.acme, "ann@acme.example")
        });

        fx.store.save(&ann).await.unwrap();

        let by_id = fx.store.find_by_id(ann.id()).await.unwrap().unwrap();
        let in_org = fx
            .store
            .find_by_id_in_org(&fx.acme, ann.id())
            .await
            .unwrap()
            .unwrap();
        let by_email = fx
            .store
            .find_by_email(&fx.acme, ann.email())
            .await
            .unwrap()
            .unwrap();
        for found in [&by_id, &in_org, &by_email] {
            assert_member_values(found, &ann);
        }
    }

    /// Each lookup preserves the member's identity, credentials, preferences and joining time.
    fn assert_member_values(found: &OrgUser, saved: &OrgUser) {
        assert_eq!(found.id(), saved.id());
        assert_eq!(found.password_hash(), saved.password_hash());
        assert_eq!(found.locale(), saved.locale());
        assert_eq!(found.timezone(), saved.timezone());
        assert_eq!(found.role(), saved.role());
        assert_eq!(found.address(), saved.address());
        assert_eq!(found.joined_at(), saved.joined_at());
        assert_eq!(
            found.credentials_changed_at(),
            saved.credentials_changed_at()
        );
    }

    /// Already authorized member ids can be named across organizations in
    /// one batch. Duplicate and missing ids do not add records, and unrelated
    /// members stay out even when they share an address.
    #[tokio::test]
    async fn member_batches_read_only_requested_identities() {
        let fx = fixture().await;
        let globex = an_organization(&fx.db, "globex").await;
        let ann = at_address(fx.acme, "ann@example.com");
        let other_ann = at_address(globex, "ann@example.com");
        let bob = at_address(fx.acme, "bob@example.com");
        save_all(&fx.store, &[&ann, &other_ann, &bob]).await;

        let found = fx
            .store
            .find_by_ids(&[*ann.id(), *other_ann.id(), *ann.id(), OrgUserId::new()])
            .await
            .unwrap();

        assert_eq!(found.len(), 2);
        assert!(
            found.iter().any(
                |user| user.id() == ann.id() && user.organization_id() == ann.organization_id()
            )
        );
        assert!(found.iter().any(|user| user.id() == other_ann.id()
            && user.organization_id() == other_ann.organization_id()));
        assert!(fx.store.find_by_ids(&[]).await.unwrap().is_empty());
    }

    /// Olive was just confirmed by the install's setup token, so it vouches
    /// for her first sign-in. Saved and read back, it still does; once she
    /// signs in and is saved again, it no longer does. She joined before
    /// the clock's now, which her sign-in is dated at.
    #[tokio::test]
    async fn what_a_route_vouches_for_is_kept_until_the_first_sign_in() {
        let fx = fixture().await;
        let joined = at(-40_000_000);
        let mut olive = member(OrgUserRow {
            created_at: joined,
            updated_at: joined,
            joining: Joining::Joined { at: joined },
            vouching: Vouching::Fresh,
            ..org_user_row(fx.acme, "olive@acme.example")
        });
        fx.store.save(&olive).await.unwrap();

        let vouched = fx.store.find_by_id(olive.id()).await.unwrap().unwrap();
        olive.record_sign_in();
        fx.store.save(&olive).await.unwrap();
        let spent = fx.store.find_by_id(olive.id()).await.unwrap().unwrap();

        assert_eq!(vouched.vouching(), Vouching::Fresh);
        assert_eq!(spent.vouching(), Vouching::Absent);
    }

    /// An id or address nobody has finds nothing, rather than failing.
    #[tokio::test]
    async fn an_unknown_member_is_not_found() {
        let fx = fixture().await;
        let nobody = email("nobody@acme.example");

        assert!(
            fx.store
                .find_by_id(&OrgUserId::new())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            fx.store
                .find_by_email(&fx.acme, &nobody)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            fx.store
                .find_all_by_email(&nobody)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(!fx.store.email_exists(&nobody).await.unwrap());
    }

    /// Looking up Ann's Acme member ID within Globex finds no member.
    #[tokio::test]
    async fn a_member_of_another_organization_is_not_found_by_id() {
        let fx = fixture().await;
        let globex = an_organization(&fx.db, "globex").await;
        let ann = at_address(fx.acme, "ann@acme.example");
        fx.store.save(&ann).await.unwrap();

        let found = fx.store.find_by_id_in_org(&globex, ann.id()).await.unwrap();

        assert!(found.is_none());
    }

    /// Ann has an account in Acme and in Globex under one address: both are
    /// found by it, and the address reads as taken.
    #[tokio::test]
    async fn one_address_finds_an_account_in_each_organization() {
        let fx = fixture().await;
        let globex = an_organization(&fx.db, "globex").await;
        save_all(
            &fx.store,
            &[
                &at_address(fx.acme, "ann@example.com"),
                &at_address(globex, "ann@example.com"),
                &at_address(fx.acme, "bob@example.com"),
            ],
        )
        .await;

        let accounts = fx
            .store
            .find_all_by_email(&email("ann@example.com"))
            .await
            .unwrap();

        let mut organizations: Vec<OrganizationId> = accounts
            .iter()
            .map(|user| *user.organization_id())
            .collect();
        organizations.sort_by_key(|id| *id.as_uuid());
        let mut expected = vec![fx.acme, globex];
        expected.sort_by_key(|id| *id.as_uuid());
        assert_eq!(organizations, expected);
        assert!(
            fx.store
                .email_exists(&email("ann@example.com"))
                .await
                .unwrap()
        );
    }

    /// Saving a second Acme member with Ann's stored address returns a conflict.
    #[tokio::test]
    async fn an_address_another_member_has_is_refused() {
        let fx = fixture().await;
        fx.store
            .save(&at_address(fx.acme, "ann@acme.example"))
            .await
            .unwrap();

        let second = fx
            .store
            .save(&at_address(fx.acme, "ann@acme.example"))
            .await;

        assert!(matches!(second, Err(DomainError::Conflict(_))));
    }

    /// Ann is locked out: saving her again keeps the new status, and never
    /// moves her to another organization or changes when she was made.
    #[tokio::test]
    async fn saving_again_keeps_the_new_values() {
        let fx = fixture().await;
        let globex = an_organization(&fx.db, "globex").await;
        let ann = at_address(fx.acme, "ann@acme.example");
        fx.store.save(&ann).await.unwrap();
        let locked = member(OrgUserRow {
            id: *ann.id(),
            status: OrgUserStatus::Locked,
            updated_at: at(9),
            ..org_user_row(globex, "ann@acme.example")
        });

        fx.store.save(&locked).await.unwrap();

        let found = fx.store.find_by_id(ann.id()).await.unwrap().unwrap();
        assert_eq!(found.status(), OrgUserStatus::Locked);
        assert_eq!(found.updated_at(), at(9));
        assert_eq!(found.organization_id(), &fx.acme);
    }

    /// A competing ownership change waits for the first request's commit and
    /// then reads its remaining owner, rather than the previous two owners.
    #[tokio::test]
    async fn ownership_changes_wait_and_read_committed_owners() {
        let fx = fixture().await;
        let ann = owner(fx.acme, "ann@acme.example");
        let bea = owner(fx.acme, "bea@acme.example");
        save_all(&fx.store, &[&ann, &bea]).await;
        let next = PgOrgUserStore::new(Arc::clone(&fx.db.databases), DomainLimits::default());
        let organization = fx.acme;
        let (held, begin) = oneshot::channel();
        let mut waiting = spawn_owner_reader(next, organization, begin);
        atomically(
            &PgUnitOfWork,
            async {
                fx.store.hold_ownership(&organization).await.unwrap();
                held.send(()).expect("the competing transaction is waiting");
                fx.store.delete(ann.id()).await.unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(30), &mut waiting)
                        .await
                        .is_err()
                );
            },
            |_| Settlement::Commit,
        )
        .await
        .unwrap();

        let remaining = waiting.await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id(), bea.id());
    }

    /// Starts a competing unit that reads owners only after it acquires their lock.
    fn spawn_owner_reader(
        store: PgOrgUserStore,
        organization: OrganizationId,
        begin: oneshot::Receiver<()>,
    ) -> tokio::task::JoinHandle<Vec<OrgUser>> {
        tokio::spawn(async move {
            begin.await.expect("the first transaction holds ownership");
            atomically(
                &PgUnitOfWork,
                async {
                    store.hold_ownership(&organization).await.unwrap();
                    store.list_owners(&organization).await.unwrap()
                },
                |_| Settlement::Commit,
            )
            .await
            .unwrap()
        })
    }

    /// Acme's owners are read of every status, and no plain member or other
    /// organization's owner among them.
    #[tokio::test]
    async fn the_owners_of_an_organization_are_listed() {
        let fx = fixture().await;
        let globex = an_organization(&fx.db, "globex").await;
        let ann = owner(fx.acme, "ann@acme.example");
        let bea = member(OrgUserRow {
            role: OrgRole::Owner,
            status: OrgUserStatus::Deactivated,
            ..org_user_row(fx.acme, "bea@acme.example")
        });
        save_all(
            &fx.store,
            &[
                &ann,
                &bea,
                &at_address(fx.acme, "sam@acme.example"),
                &owner(globex, "gus@globex.example"),
            ],
        )
        .await;

        let owners = fx.store.list_owners(&fx.acme).await.unwrap();

        let mut found: Vec<OrgUserId> = owners.iter().map(|user| *user.id()).collect();
        found.sort_by_key(|id| *id.as_uuid());
        let mut expected = vec![*ann.id(), *bea.id()];
        expected.sort_by_key(|id| *id.as_uuid());
        assert_eq!(found, expected);
    }

    /// An admin pages through Acme's members by address: each page follows
    /// the last, the last says nothing follows, and Globex's are not listed.
    #[tokio::test]
    async fn members_are_listed_page_by_page() {
        let fx = fixture().await;
        let globex = an_organization(&fx.db, "globex").await;
        save_paging_members(&fx, globex).await;
        let order = by(OrgUserSortField::Email);
        let all = OrgUserFilter::all();

        let page_one = fx
            .store
            .list_by_org(&fx.acme, &all, &order, &first(2))
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let page_two = fx
            .store
            .list_by_org(&fx.acme, &all, &order, &after)
            .await
            .unwrap();

        assert_eq!(
            addresses(&page_one),
            ["ann@acme.example", "bob@acme.example"]
        );
        assert_eq!(addresses(&page_two), ["cat@acme.example"]);
        assert!(!page_two.has_next());
    }

    /// Saves three out-of-order Acme addresses and one excluded Globex address.
    async fn save_paging_members(fx: &Fixture, globex: OrganizationId) {
        save_all(
            &fx.store,
            &[
                &at_address(fx.acme, "cat@acme.example"),
                &at_address(fx.acme, "ann@acme.example"),
                &at_address(fx.acme, "bob@acme.example"),
                &at_address(globex, "abe@globex.example"),
            ],
        )
        .await;
    }

    /// A list narrowed to one status shows only members in it.
    #[tokio::test]
    async fn a_list_narrowed_to_a_status_shows_only_that_status() {
        let fx = fixture().await;
        let invited = member(OrgUserRow {
            status: OrgUserStatus::Invited,
            joining: Joining::NotYet,
            ..org_user_row(fx.acme, "new@acme.example")
        });
        save_all(
            &fx.store,
            &[&invited, &at_address(fx.acme, "ann@acme.example")],
        )
        .await;
        let filter = OrgUserFilter {
            status: Some(OrgUserStatus::Invited),
            ..OrgUserFilter::all()
        };

        let page = fx
            .store
            .list_by_org(&fx.acme, &filter, &by(OrgUserSortField::Email), &first(10))
            .await
            .unwrap();

        assert_eq!(addresses(&page), ["new@acme.example"]);
    }

    /// A search for part of an address finds it in any case, and a part
    /// with a percent sign is matched as written, not as a wildcard.
    #[tokio::test]
    async fn a_list_narrowed_to_part_of_an_address_ignores_case() {
        let fx = fixture().await;
        save_all(
            &fx.store,
            &[
                &at_address(fx.acme, "ann.smith@acme.example"),
                &at_address(fx.acme, "bob@acme.example"),
            ],
        )
        .await;
        let search = |part: &str| OrgUserFilter {
            email_contains: Some(part.to_owned()),
            ..OrgUserFilter::all()
        };
        let order = by(OrgUserSortField::Email);

        let found = fx
            .store
            .list_by_org(&fx.acme, &search("SMITH"), &order, &first(10))
            .await
            .unwrap();
        let wildcard = fx
            .store
            .list_by_org(&fx.acme, &search("%"), &order, &first(10))
            .await
            .unwrap();

        assert_eq!(addresses(&found), ["ann.smith@acme.example"]);
        assert!(wildcard.items.is_empty());
    }

    /// A list narrowed to some members shows only them, and narrowed to
    /// nobody shows nobody.
    #[tokio::test]
    async fn a_list_narrowed_to_some_members_shows_only_them() {
        let fx = fixture().await;
        let ann = at_address(fx.acme, "ann@acme.example");
        save_all(&fx.store, &[&ann, &at_address(fx.acme, "bob@acme.example")]).await;
        let among = |ids: Vec<OrgUserId>| OrgUserFilter {
            ids: Some(ids),
            ..OrgUserFilter::all()
        };
        let order = by(OrgUserSortField::Email);

        let some = fx
            .store
            .list_by_org(&fx.acme, &among(vec![*ann.id()]), &order, &first(10))
            .await
            .unwrap();
        let none = fx
            .store
            .list_by_org(&fx.acme, &among(Vec::new()), &order, &first(10))
            .await
            .unwrap();

        assert_eq!(addresses(&some), ["ann@acme.example"]);
        assert!(none.items.is_empty());
    }

    /// Paging by stored status words returns the active, closing and locked
    /// members in order, with each member appearing once.
    #[tokio::test]
    async fn a_list_sorted_by_status_pages_by_the_stored_word() {
        let fx = fixture().await;
        let locked = member(OrgUserRow {
            status: OrgUserStatus::Locked,
            ..org_user_row(fx.acme, "lee@acme.example")
        });
        let closing = member(OrgUserRow {
            status: OrgUserStatus::Closing,
            ..org_user_row(fx.acme, "cal@acme.example")
        });
        save_all(
            &fx.store,
            &[&locked, &closing, &at_address(fx.acme, "ann@acme.example")],
        )
        .await;
        let order = by(OrgUserSortField::Status);
        let all = OrgUserFilter::all();

        let page_one = fx
            .store
            .list_by_org(&fx.acme, &all, &order, &first(1))
            .await
            .unwrap();
        let after = PageRequest::new(page_one.next.clone(), Limit::new(2).unwrap());
        let rest = fx
            .store
            .list_by_org(&fx.acme, &all, &order, &after)
            .await
            .unwrap();

        assert_eq!(addresses(&page_one), ["ann@acme.example"]);
        assert_eq!(addresses(&rest), ["cal@acme.example", "lee@acme.example"]);
    }

    /// A removed member is gone, and their address is free again.
    #[tokio::test]
    async fn a_deleted_member_is_gone() {
        let fx = fixture().await;
        let ann = at_address(fx.acme, "ann@acme.example");
        fx.store.save(&ann).await.unwrap();

        fx.store.delete(ann.id()).await.unwrap();

        assert!(fx.store.find_by_id(ann.id()).await.unwrap().is_none());
        assert!(!fx.store.email_exists(ann.email()).await.unwrap());
    }

    /// Reading an active member whose stored join date is missing returns
    /// an infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_member_is_refused() {
        let fx = fixture().await;
        let ann = at_address(fx.acme, "ann@acme.example");
        fx.store.save(&ann).await.unwrap();
        fx.db
            .tamper("ALTER TABLE org_users DROP CONSTRAINT org_users_joining_fits_status")
            .await;
        fx.db.tamper("UPDATE org_users SET joined_at = NULL").await;

        let read = fx.store.find_by_id(ann.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// Reading a member with an invalid stored email address returns an
    /// infrastructure error.
    #[tokio::test]
    async fn a_stored_value_that_breaks_its_rules_is_refused() {
        let fx = fixture().await;
        let ann = at_address(fx.acme, "ann@acme.example");
        fx.store.save(&ann).await.unwrap();
        fx.db
            .tamper("UPDATE org_users SET email = 'not an address'")
            .await;

        let read = fx.store.find_by_id(ann.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
