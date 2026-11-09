//! The custom attributes a tenant declares for its users, and the values
//! its users hold: the stores of `ports/identity/attributes.rs`.
//!
//! A declaration is one row of `user_attribute_definitions`. A value is one
//! row of `user_metadata`, in the one column its type keeps it in, so a
//! filter or a count by an attribute reads an index on that column.

mod holders;
mod record;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::identity::{HeldValues, MetadataStore, StoredAttribute, UserAttributeStore};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::identity::attribute::{
    AttributeDefinition, AttributeKey, AttributeNamespace,
};
use ianua_domain::domains::identity::metadata_value::MetadataValue;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Label, UserId};
use sqlx::PgConnection;
use uuid::Uuid;

use self::holders::{AttributeAt, holders};
use self::record::{
    AttributeColumns, AttributeRecord, Metadata, MetadataRecord, ValueColumns, by_namespace,
    by_user,
};
use crate::postgres::foundation::errors::{Uniqueness, unique_on};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The constraint that keeps a key to one declaration in a namespace.
const KEY_KEY: &str = "user_attribute_definitions_key_key";

/// The Postgres store of a tenant's declared attributes.
pub struct PgUserAttributeStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgUserAttributeStore {}

impl PgUserAttributeStore {
    /// A store keeping declarations in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

/// Writes one complete declaration and reports a key held by another declaration.
async fn write_definition(
    connection: &mut PgConnection,
    tenant_id: &ScopedTenant,
    columns: &AttributeColumns<'_>,
) -> Result<Uniqueness, sqlx::Error> {
    let attempt = sqlx::query_file!(
        "queries/user_attribute_definitions/save.sql",
        columns.id,
        tenant_id.as_uuid(),
        columns.namespace,
        columns.key,
        columns.kind,
        columns.control,
        columns.display_name,
        columns.description,
        &columns.options,
        columns.max_length,
        columns.minimum,
        columns.maximum,
        columns.required,
        columns.sensitive,
        columns.filterable,
        columns.sortable,
        columns.listed,
        columns.archived,
        columns.created_at,
        columns.updated_at,
    )
    .execute(connection)
    .await;
    unique_on(attempt, KEY_KEY)
}

#[async_trait]
impl UserAttributeStore for PgUserAttributeStore {
    async fn load_schema(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<AttributeDefinition<ResolvedTenant>>, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    AttributeRecord,
                    "queries/user_attribute_definitions/schema.sql",
                    tenant_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        records
            .into_iter()
            .map(AttributeRecord::into_definition)
            .collect()
    }

    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        namespace: AttributeNamespace,
        key: &AttributeKey,
    ) -> Result<Option<AttributeDefinition<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    AttributeRecord,
                    "queries/user_attribute_definitions/by_key.sql",
                    tenant_id.as_uuid(),
                    namespace.as_str(),
                    key.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(AttributeRecord::into_definition).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        definition: &AttributeDefinition<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = AttributeColumns::of(definition)?;
        let written = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| write_definition(connection, tenant_id, &columns).await,
        )
        .await?;
        match written {
            Uniqueness::Kept => Ok(()),
            Uniqueness::Taken => Err(DomainError::conflict(message!(
                "infra-the-tenant-already-declares-an-attribute",
                "the tenant already declares an attribute under this key"
            ))),
        }
    }

    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        namespace: AttributeNamespace,
        key: &AttributeKey,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/user_attribute_definitions/delete.sql",
                    tenant_id.as_uuid(),
                    namespace.as_str(),
                    key.as_str()
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }

    async fn count(&self, tenant_id: &ScopedTenant) -> Result<u64, DomainError> {
        let count = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_scalar!(
                    "queries/user_attribute_definitions/count.sql",
                    tenant_id.as_uuid()
                )
                .fetch_one(connection)
                .await
            },
        )
        .await?;
        u64::try_from(count).map_err(DomainError::infra)
    }
}

/// The Postgres store of the values a tenant's users hold.
pub struct PgMetadataStore {
    databases: Arc<Databases>,
}

/// One value written under a user's key in a specific namespace.
struct MetadataWrite<'a> {
    user_id: &'a UserId,
    namespace: AttributeNamespace,
    key: &'a Label,
    value: &'a MetadataValue,
}

impl TenantScoped for PgMetadataStore {}

impl PgMetadataStore {
    /// A store keeping values in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }

    /// Keeps the named value within the tenant's scope.
    async fn set(
        &self,
        tenant_id: &ScopedTenant,
        write: &MetadataWrite<'_>,
    ) -> Result<(), DomainError> {
        let columns = ValueColumns::of(write.value);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/user_metadata/set.sql",
                    tenant_id.as_uuid(),
                    write.user_id.as_uuid(),
                    write.namespace.as_str(),
                    write.key.as_str(),
                    columns.value_type,
                    columns.value_text,
                    columns.value_int,
                    columns.value_float,
                    columns.value_bool,
                    columns.value_array,
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }
}

#[async_trait]
impl MetadataStore for PgMetadataStore {
    async fn find_by_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<Metadata, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    MetadataRecord,
                    "queries/user_metadata/of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        by_namespace(records)
    }

    async fn set_user_value(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        key: &Label,
        value: &MetadataValue,
    ) -> Result<(), DomainError> {
        self.set(
            tenant_id,
            &MetadataWrite {
                user_id,
                namespace: AttributeNamespace::User,
                key,
                value,
            },
        )
        .await
    }

    async fn set_app_value(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        key: &Label,
        value: &MetadataValue,
    ) -> Result<(), DomainError> {
        self.set(
            tenant_id,
            &MetadataWrite {
                user_id,
                namespace: AttributeNamespace::App,
                key,
                value,
            },
        )
        .await
    }

    async fn delete_for_user(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/user_metadata/delete_of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }

    async fn find_for_users(
        &self,
        tenant_id: &ScopedTenant,
        user_ids: &[UserId],
        keys: &[(AttributeNamespace, AttributeKey)],
    ) -> Result<HashMap<UserId, Vec<StoredAttribute>>, DomainError> {
        let ids: Vec<Uuid> = user_ids.iter().map(|id| *id.as_uuid()).collect();
        let namespaces: Vec<String> = keys
            .iter()
            .map(|(namespace, _)| namespace.as_str().to_owned())
            .collect();
        let names: Vec<String> = keys
            .iter()
            .map(|(_, key)| key.as_str().to_owned())
            .collect();
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    MetadataRecord,
                    "queries/user_metadata/of_users.sql",
                    tenant_id.as_uuid(),
                    &ids,
                    &namespaces,
                    &names
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        by_user(records)
    }

    async fn delete_value(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        namespace: AttributeNamespace,
        key: &AttributeKey,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/user_metadata/delete_value.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid(),
                    namespace.as_str(),
                    key.as_str()
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }

    async fn count_holders(
        &self,
        tenant_id: &ScopedTenant,
        namespace: AttributeNamespace,
        key: &AttributeKey,
        held: HeldValues<'_>,
    ) -> Result<u64, DomainError> {
        let attribute = AttributeAt {
            tenant: tenant_id.as_uuid(),
            namespace: namespace.as_str(),
            key: key.as_str(),
        };
        let count = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| holders(connection, &attribute, held).await,
        )
        .await?;
        u64::try_from(count).map_err(DomainError::infra)
    }

    async fn purge_attribute(
        &self,
        tenant_id: &ScopedTenant,
        namespace: AttributeNamespace,
        key: &AttributeKey,
    ) -> Result<u64, DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/user_metadata/purge.sql",
                    tenant_id.as_uuid(),
                    namespace.as_str(),
                    key.as_str()
                )
                .execute(connection)
                .await
                .map(|done| done.rows_affected())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::UserStore;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::domains::identity::attribute::definition::Listing;
    use ianua_domain::domains::identity::attribute::{
        AttributeDefinitionRow, AttributeKind, AttributeVisibility,
    };
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::identity::{attribute_row, user_row};

    struct Fixture {
        db: TestDb,
        attributes: PgUserAttributeStore,
        values: PgMetadataStore,
        tenant: ScopedTenant,
    }

    /// A fresh database, its two stores, and one tenant to keep rows in.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        Fixture {
            attributes: PgUserAttributeStore::new(Arc::clone(&db.databases)),
            values: PgMetadataStore::new(Arc::clone(&db.databases)),
            tenant: ScopedTenant::for_background(TenantId::new()),
            db,
        }
    }

    /// Saves a user at `email` in `tenant` through the user store.
    async fn a_user(db: &TestDb, tenant: &ScopedTenant, email: &str) -> UserId {
        let user: User<ResolvedTenant> = User::reconstitute(user_row(email)).unwrap();
        PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(tenant, &user)
            .await
            .unwrap();
        *user.id()
    }

    fn declared(row: AttributeDefinitionRow) -> AttributeDefinition<ResolvedTenant> {
        AttributeDefinition::reconstitute(row).unwrap()
    }

    fn key(name: &str) -> AttributeKey {
        AttributeKey::new(name).unwrap()
    }

    fn label(name: &str) -> Label {
        Label::new("metadata_key", name).unwrap()
    }

    /// Saves a text value in the fixture's app namespace.
    async fn save_app_text(db: &Fixture, user: &UserId, name: &str, value: &str) {
        db.values
            .set_app_value(&db.tenant, user, &label(name), &MetadataValue::from(value))
            .await
            .unwrap();
    }

    /// A later-declared size attribute with two ordered choices.
    fn size_definition() -> AttributeDefinition<ResolvedTenant> {
        declared(AttributeDefinitionRow {
            options: vec![label("s"), label("m")],
            created_at: at(1),
            updated_at: at(1),
            ..attribute_row(
                "size",
                AttributeNamespace::User,
                AttributeKind::SingleChoice,
            )
        })
    }

    /// A representative stored value of each metadata type.
    fn every_value_type() -> [(&'static str, MetadataValue); 6] {
        [
            ("nickname", MetadataValue::from("annie")),
            ("age", MetadataValue::Integer(36)),
            ("height", MetadataValue::Number(1.72)),
            ("remote", MetadataValue::Bool(true)),
            (
                "tags",
                MetadataValue::StringArray(vec!["a".to_owned(), "b".to_owned()]),
            ),
            ("unset", MetadataValue::Null),
        ]
    }

    /// Acme declares two attributes: each is found by its key, and the
    /// schema lists both in the order they were declared.
    #[tokio::test]
    async fn declarations_are_found_by_key_and_listed_in_declared_order() {
        let db = fixture().await;
        let tier = declared(AttributeDefinitionRow {
            visibility: AttributeVisibility {
                listed: Listing::Listed,
                ..AttributeVisibility::default()
            },
            ..attribute_row("tier", AttributeNamespace::App, AttributeKind::Text)
        });
        let size = size_definition();
        db.attributes.save(&db.tenant, &size).await.unwrap();
        db.attributes.save(&db.tenant, &tier).await.unwrap();

        let found = db
            .attributes
            .find(&db.tenant, AttributeNamespace::User, &key("size"))
            .await
            .unwrap()
            .unwrap();
        let schema = db.attributes.load_schema(&db.tenant).await.unwrap();

        assert_eq!(found.options(), size.options());
        assert_eq!(found.kind(), AttributeKind::SingleChoice);
        let keys: Vec<&str> = schema
            .iter()
            .map(|declared| declared.key().as_str())
            .collect();
        assert_eq!(keys, ["tier", "size"]);
        assert!(schema[0].is_listed());
        assert_eq!(db.attributes.count(&db.tenant).await.unwrap(), 2);
    }

    /// The same key in the other namespace is another attribute, and a key
    /// nobody declared finds nothing.
    #[tokio::test]
    async fn a_key_is_found_only_in_its_own_namespace() {
        let db = fixture().await;
        let tier = declared(attribute_row(
            "tier",
            AttributeNamespace::App,
            AttributeKind::Text,
        ));
        db.attributes.save(&db.tenant, &tier).await.unwrap();

        let in_user = db
            .attributes
            .find(&db.tenant, AttributeNamespace::User, &key("tier"))
            .await
            .unwrap();

        assert!(in_user.is_none());
    }

    /// Saving a second attribute declaration under the same tenant,
    /// namespace and key returns a conflict.
    #[tokio::test]
    async fn a_key_declared_twice_is_refused() {
        let db = fixture().await;
        let first = declared(attribute_row(
            "tier",
            AttributeNamespace::App,
            AttributeKind::Text,
        ));
        let second = declared(attribute_row(
            "tier",
            AttributeNamespace::App,
            AttributeKind::Text,
        ));
        db.attributes.save(&db.tenant, &first).await.unwrap();

        let saved = db.attributes.save(&db.tenant, &second).await;

        assert!(matches!(saved, Err(DomainError::Conflict(_))));
    }

    /// Saving a declaration again keeps its new name; deleting it removes
    /// it.
    #[tokio::test]
    async fn a_declaration_is_changed_and_deleted() {
        let db = fixture().await;
        let row = attribute_row("tier", AttributeNamespace::App, AttributeKind::Text);
        let tier = declared(row.clone());
        db.attributes.save(&db.tenant, &tier).await.unwrap();
        let renamed = declared(AttributeDefinitionRow {
            display_name: Label::new("display_name", "Plan tier").unwrap(),
            updated_at: at(5),
            ..row
        });

        db.attributes.save(&db.tenant, &renamed).await.unwrap();
        let found = db
            .attributes
            .find(&db.tenant, AttributeNamespace::App, &key("tier"))
            .await
            .unwrap()
            .unwrap();
        db.attributes
            .delete(&db.tenant, AttributeNamespace::App, &key("tier"))
            .await
            .unwrap();

        assert_eq!(found.display_name().as_str(), "Plan tier");
        assert!(
            db.attributes
                .load_schema(&db.tenant)
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Another tenant sees none of Acme's declarations or values.
    #[tokio::test]
    async fn another_tenants_attributes_and_values_are_invisible() {
        let db = fixture().await;
        let ann = a_user(&db.db, &db.tenant, "ann@acme.example").await;
        let tier = declared(attribute_row(
            "tier",
            AttributeNamespace::App,
            AttributeKind::Text,
        ));
        db.attributes.save(&db.tenant, &tier).await.unwrap();
        db.values
            .set_app_value(
                &db.tenant,
                &ann,
                &label("tier"),
                &MetadataValue::from("gold"),
            )
            .await
            .unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let schema = db.attributes.load_schema(&other).await.unwrap();
        let (user, app) = db.values.find_by_user(&other, &ann).await.unwrap();

        assert!(schema.is_empty());
        assert!(user.is_empty() && app.is_empty());
        assert_eq!(db.attributes.count(&other).await.unwrap(), 0);
    }

    /// An unknown stored attribute kind makes the schema read fail as
    /// corrupt storage.
    #[tokio::test]
    async fn a_declaration_of_an_unknown_kind_is_refused() {
        let db = fixture().await;
        let tier = declared(attribute_row(
            "tier",
            AttributeNamespace::App,
            AttributeKind::Text,
        ));
        db.attributes.save(&db.tenant, &tier).await.unwrap();
        db.db
            .tamper("UPDATE user_attribute_definitions SET kind = 'hologram'")
            .await;

        let read = db.attributes.load_schema(&db.tenant).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }

    /// Ann's values of every type read back as they were set, each in its
    /// namespace, and a value set again is replaced.
    #[tokio::test]
    async fn values_of_every_type_read_back_in_their_namespace() {
        let db = fixture().await;
        let ann = a_user(&db.db, &db.tenant, "ann@acme.example").await;
        let held = every_value_type();
        for (name, value) in &held {
            db.values
                .set_user_value(&db.tenant, &ann, &label(name), value)
                .await
                .unwrap();
        }
        save_app_text(&db, &ann, "tier", "silver").await;
        save_app_text(&db, &ann, "tier", "gold").await;

        let (user, app) = db.values.find_by_user(&db.tenant, &ann).await.unwrap();

        for (name, value) in &held {
            assert_eq!(user.get(&label(name)), Some(value));
        }
        assert_eq!(app.len(), 1);
        assert_eq!(app.get(&label("tier")), Some(&MetadataValue::from("gold")));
    }

    /// Removing one value leaves the rest; removing a user's metadata
    /// leaves nothing.
    #[tokio::test]
    async fn one_value_or_all_of_them_are_removed() {
        let db = fixture().await;
        let ann = a_user(&db.db, &db.tenant, "ann@acme.example").await;
        for name in ["tier", "plan"] {
            db.values
                .set_app_value(&db.tenant, &ann, &label(name), &MetadataValue::from("x"))
                .await
                .unwrap();
        }

        db.values
            .delete_value(&db.tenant, &ann, AttributeNamespace::App, &key("tier"))
            .await
            .unwrap();
        let (_, after_one) = db.values.find_by_user(&db.tenant, &ann).await.unwrap();
        db.values.delete_for_user(&db.tenant, &ann).await.unwrap();
        let (_, after_all) = db.values.find_by_user(&db.tenant, &ann).await.unwrap();

        assert_eq!(
            after_one.keys().map(Label::as_str).collect::<Vec<_>>(),
            ["plan"]
        );
        assert!(after_all.is_empty());
    }

    /// A page of users carries only the attributes it shows, and a user
    /// holding none of them is left out.
    #[tokio::test]
    async fn several_users_values_are_read_for_the_named_attributes_only() {
        let db = fixture().await;
        let ann = a_user(&db.db, &db.tenant, "ann@acme.example").await;
        let bob = a_user(&db.db, &db.tenant, "bob@acme.example").await;
        let cid = a_user(&db.db, &db.tenant, "cid@acme.example").await;
        save_app_text(&db, &ann, "tier", "gold").await;
        save_app_text(&db, &ann, "hidden", "x").await;
        db.values
            .set_user_value(
                &db.tenant,
                &bob,
                &label("tier"),
                &MetadataValue::from("mine"),
            )
            .await
            .unwrap();

        let found = db
            .values
            .find_for_users(
                &db.tenant,
                &[ann, bob, cid],
                &[(AttributeNamespace::App, key("tier"))],
            )
            .await
            .unwrap();

        assert_eq!(found.len(), 1);
        let anns = &found[&ann];
        assert_eq!(anns.len(), 1);
        assert_eq!(anns[0].key.as_str(), "tier");
        assert_eq!(anns[0].value, MetadataValue::from("gold"));
    }

    /// Holders are counted as each question asks: any value, one of some
    /// options, a text too long, a number too low or too high.
    #[tokio::test]
    async fn holders_are_counted_by_what_they_hold() {
        let db = fixture().await;
        save_holder_values(&db).await;
        let options = [label("small"), label("large")];

        assert_eq!(holders_of(&db, "size", HeldValues::Any).await, 3);
        assert_eq!(
            holders_of(&db, "size", HeldValues::OneOf(&options)).await,
            2
        );
        assert_eq!(holders_of(&db, "size", HeldValues::LongerThan(5)).await, 1);
        assert_eq!(holders_of(&db, "score", HeldValues::Below(5.0)).await, 1);
        assert_eq!(holders_of(&db, "score", HeldValues::Above(5.0)).await, 1);
    }

    /// The three sizes cover scalar options, array options and an overlong text.
    fn size_values() -> [(&'static str, MetadataValue); 3] {
        [
            ("ann@acme.example", MetadataValue::from("small")),
            (
                "bob@acme.example",
                MetadataValue::StringArray(vec!["large".to_owned()]),
            ),
            ("cid@acme.example", MetadataValue::from("medium-ish")),
        ]
    }

    /// Saves the size and numeric values used by each holder predicate.
    async fn save_holder_values(db: &Fixture) {
        let size = size_values();
        let score = [
            ("ann@acme.example", MetadataValue::Integer(3)),
            ("bob@acme.example", MetadataValue::Number(7.5)),
        ];
        let mut users = HashMap::new();
        for (email, _) in &size {
            users.insert(*email, a_user(&db.db, &db.tenant, email).await);
        }
        for (email, value) in &size {
            db.values
                .set_app_value(&db.tenant, &users[email], &label("size"), value)
                .await
                .unwrap();
        }
        for (email, value) in &score {
            db.values
                .set_app_value(&db.tenant, &users[email], &label("score"), value)
                .await
                .unwrap();
        }
    }

    async fn holders_of(db: &Fixture, name: &str, held: HeldValues<'_>) -> u64 {
        db.values
            .count_holders(&db.tenant, AttributeNamespace::App, &key(name), held)
            .await
            .unwrap()
    }

    /// Discarding an attribute removes every value under it, says how many,
    /// and leaves the other attributes' values.
    #[tokio::test]
    async fn purging_an_attribute_removes_its_values_only() {
        let db = fixture().await;
        let ann = a_user(&db.db, &db.tenant, "ann@acme.example").await;
        let bob = a_user(&db.db, &db.tenant, "bob@acme.example").await;
        for user in [ann, bob] {
            db.values
                .set_app_value(&db.tenant, &user, &label("tier"), &MetadataValue::from("x"))
                .await
                .unwrap();
        }
        db.values
            .set_app_value(&db.tenant, &ann, &label("plan"), &MetadataValue::from("y"))
            .await
            .unwrap();

        let purged = db
            .values
            .purge_attribute(&db.tenant, AttributeNamespace::App, &key("tier"))
            .await
            .unwrap();

        let (_, left) = db.values.find_by_user(&db.tenant, &ann).await.unwrap();
        assert_eq!(purged, 2);
        assert_eq!(left.keys().map(Label::as_str).collect::<Vec<_>>(), ["plan"]);
    }

    /// A metadata value stored under a blank key makes the user's values
    /// fail to load as corrupt storage.
    #[tokio::test]
    async fn a_value_under_a_key_that_is_no_label_is_refused() {
        let db = fixture().await;
        let ann = a_user(&db.db, &db.tenant, "ann@acme.example").await;
        db.values
            .set_app_value(&db.tenant, &ann, &label("tier"), &MetadataValue::from("x"))
            .await
            .unwrap();
        db.db.tamper("UPDATE user_metadata SET key = ''").await;

        let read = db.values.find_by_user(&db.tenant, &ann).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
