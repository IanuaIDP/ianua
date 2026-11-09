//! Where each person has signed in from before: one row per country, with
//! the place and time of the latest sign-in from it, so a history stays as
//! small as the countries a person signs in from.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::SignInHistoryStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authentication::risk_engine::assessment::IpGeolocation;
use ianua_domain::domains::authentication::risk_engine::history::SignInHistory;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::UserId;
use time::OffsetDateTime;

use self::record::{CountryRecord, history_from};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of where people signed in from.
pub struct PgSignInHistoryStore {
    databases: Arc<Databases>,
}

impl PgSignInHistoryStore {
    /// A store keeping sign-in places in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgSignInHistoryStore {}

#[async_trait]
impl SignInHistoryStore for PgSignInHistoryStore {
    async fn history(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
    ) -> Result<SignInHistory, DomainError> {
        let records = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    CountryRecord,
                    "queries/sign_in_countries/of_user.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        history_from(records)
    }

    async fn record(
        &self,
        tenant_id: &ScopedTenant,
        user_id: &UserId,
        place: &IpGeolocation,
        at: OffsetDateTime,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/sign_in_countries/record.sql",
                    tenant_id.as_uuid(),
                    user_id.as_uuid(),
                    place.country_code().as_str(),
                    place.latitude(),
                    place.longitude(),
                    place.city(),
                    at
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::UserStore;
    use ianua_domain::domains::authentication::risk_engine::step_up::Familiarity;
    use ianua_domain::domains::identity::account::user::User;
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{CountryCode, Fact};

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::identity::user_row;

    /// A fresh database holding Ann in Acme, and the store on it.
    async fn fixture() -> (TestDb, PgSignInHistoryStore, ScopedTenant, UserId) {
        let db = TestDb::fresh().await;
        let acme = tenant();
        let ann = User::reconstitute(user_row("ann@acme.example")).unwrap();
        PgUserStore::new(Arc::clone(&db.databases), DomainLimits::default())
            .save(&acme, &ann)
            .await
            .unwrap();
        let store = PgSignInHistoryStore::new(Arc::clone(&db.databases));
        (db, store, acme, *ann.id())
    }

    fn place(country: &str, city: &str) -> IpGeolocation {
        IpGeolocation::new(
            52.5,
            13.4,
            CountryCode::new(country).unwrap(),
            Some(city.to_owned()),
        )
        .unwrap()
    }

    /// Ann signed in from Berlin, then Rio, then Munich: Germany and Brazil
    /// are known, and her last sign-in is Munich.
    #[tokio::test]
    async fn the_history_holds_each_country_and_the_last_sign_in() {
        let (_db, store, acme, ann) = fixture().await;
        store
            .record(&acme, &ann, &place("DE", "Berlin"), at(0))
            .await
            .unwrap();
        store
            .record(&acme, &ann, &place("BR", "Rio"), at(10))
            .await
            .unwrap();
        store
            .record(&acme, &ann, &place("DE", "Munich"), at(20))
            .await
            .unwrap();

        let history = store.history(&acme, &ann).await.unwrap();

        let Fact::Known((last, when)) = history.last() else {
            panic!("Ann's last sign-in is known");
        };
        assert_eq!(last.city(), Some("Munich"));
        assert_eq!(when, at(20));
        assert_eq!(
            history.country_familiarity(Fact::Known(&place("BR", "Rio"))),
            Familiarity::Known
        );
        assert_eq!(
            history.country_familiarity(Fact::Known(&place("JP", "Tokyo"))),
            Familiarity::New
        );
    }

    /// A sign-in recorded late, older than the one already kept for its
    /// country, does not move the country's latest sign-in back.
    #[tokio::test]
    async fn an_older_sign_in_does_not_replace_a_later_one() {
        let (_db, store, acme, ann) = fixture().await;
        store
            .record(&acme, &ann, &place("DE", "Munich"), at(20))
            .await
            .unwrap();

        store
            .record(&acme, &ann, &place("DE", "Berlin"), at(5))
            .await
            .unwrap();

        let history = store.history(&acme, &ann).await.unwrap();
        let Fact::Known((last, when)) = history.last() else {
            panic!("Ann's last sign-in is known");
        };
        assert_eq!(last.city(), Some("Munich"));
        assert_eq!(when, at(20));
    }

    /// Someone who never signed in has an empty history, with no last
    /// sign-in.
    #[tokio::test]
    async fn a_first_sign_in_has_no_history() {
        let (_db, store, acme, ann) = fixture().await;

        let history = store.history(&acme, &ann).await.unwrap();

        assert!(matches!(history.last(), Fact::Unknown));
    }

    /// Reading Ann's history from another tenant reveals no last sign-in.
    #[tokio::test]
    async fn another_tenants_history_is_invisible() {
        let (_db, store, acme, ann) = fixture().await;
        store
            .record(&acme, &ann, &place("DE", "Berlin"), at(0))
            .await
            .unwrap();

        let history = store.history(&tenant(), &ann).await.unwrap();

        assert!(matches!(history.last(), Fact::Unknown));
    }

    /// A stored sign-in with an unknown country code makes the history
    /// read fail as corrupt storage.
    #[tokio::test]
    async fn a_place_in_no_country_is_refused() {
        let (db, store, acme, ann) = fixture().await;
        store
            .record(&acme, &ann, &place("DE", "Berlin"), at(0))
            .await
            .unwrap();
        db.tamper("UPDATE sign_in_countries SET country_code = 'XX'")
            .await;

        let read = store.history(&acme, &ann).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
