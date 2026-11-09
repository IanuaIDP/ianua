//! Counting the users who hold a value under one attribute, by what they
//! hold: the questions a change to a declaration asks before it strands
//! anybody.

use ianua_app::ports::identity::HeldValues;
use ianua_domain::types::Label;
use sqlx::PgConnection;
use uuid::Uuid;

/// The scoped attribute whose stored values a count examines.
pub(super) struct AttributeAt<'a> {
    pub(super) tenant: &'a Uuid,
    pub(super) namespace: &'a str,
    pub(super) key: &'a str,
}

/// How many values of the scoped attribute meet the requested predicate.
pub(super) async fn holders(
    connection: &mut PgConnection,
    attribute: &AttributeAt<'_>,
    held: HeldValues<'_>,
) -> Result<i64, sqlx::Error> {
    match held {
        HeldValues::Any => attribute.any(connection).await,
        HeldValues::OneOf(options) => attribute.one_of(connection, options).await,
        HeldValues::LongerThan(limit) => attribute.longer_than(connection, limit).await,
        HeldValues::Below(floor) => attribute.below(connection, floor).await,
        HeldValues::Above(ceiling) => attribute.above(connection, ceiling).await,
    }
}

impl AttributeAt<'_> {
    /// Counts every stored value for this scoped attribute.
    async fn any(&self, connection: &mut PgConnection) -> Result<i64, sqlx::Error> {
        let Self {
            tenant,
            namespace,
            key,
        } = *self;
        sqlx::query_file_scalar!(
            "queries/user_metadata/count_holders.sql",
            tenant,
            namespace,
            key
        )
        .fetch_one(connection)
        .await
    }

    /// Counts values that include one of the named options.
    async fn one_of(
        &self,
        connection: &mut PgConnection,
        options: &[Label],
    ) -> Result<i64, sqlx::Error> {
        let Self {
            tenant,
            namespace,
            key,
        } = *self;
        let options: Vec<String> = options
            .iter()
            .map(|option| option.as_str().to_owned())
            .collect();
        sqlx::query_file_scalar!(
            "queries/user_metadata/count_one_of.sql",
            tenant,
            namespace,
            key,
            &options
        )
        .fetch_one(connection)
        .await
    }

    /// Counts text values beyond the proposed length limit.
    async fn longer_than(
        &self,
        connection: &mut PgConnection,
        limit: u32,
    ) -> Result<i64, sqlx::Error> {
        let Self {
            tenant,
            namespace,
            key,
        } = *self;
        let limit = i32::try_from(limit).unwrap_or(i32::MAX);
        sqlx::query_file_scalar!(
            "queries/user_metadata/count_longer_than.sql",
            tenant,
            namespace,
            key,
            limit
        )
        .fetch_one(connection)
        .await
    }

    /// Counts numeric values below the proposed lower bound.
    async fn below(&self, connection: &mut PgConnection, floor: f64) -> Result<i64, sqlx::Error> {
        let Self {
            tenant,
            namespace,
            key,
        } = *self;
        sqlx::query_file_scalar!(
            "queries/user_metadata/count_below.sql",
            tenant,
            namespace,
            key,
            floor
        )
        .fetch_one(connection)
        .await
    }

    /// Counts numeric values above the proposed upper bound.
    async fn above(&self, connection: &mut PgConnection, ceiling: f64) -> Result<i64, sqlx::Error> {
        let Self {
            tenant,
            namespace,
            key,
        } = *self;
        sqlx::query_file_scalar!(
            "queries/user_metadata/count_above.sql",
            tenant,
            namespace,
            key,
            ceiling
        )
        .fetch_one(connection)
        .await
    }
}
