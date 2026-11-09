//! The logins stream routes open to workflows sign in with, kept in
//! `stream_route_logins`, a table of its own the gateway's role is never
//! granted. The password is kept as it was sealed, for its route.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::routing::StreamRouteLogins;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::routing::stream::WorkflowLogin;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::StreamRouteId;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

mod record;

use self::record::{LoginRecord, TlsColumns};

/// The Postgres store of stream routes' workflow logins.
pub struct PgStreamRouteLogins {
    databases: Arc<Databases>,
}

impl PgStreamRouteLogins {
    /// A store keeping logins in the database each tenant lives in.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

impl TenantScoped for PgStreamRouteLogins {}

#[async_trait]
impl StreamRouteLogins for PgStreamRouteLogins {
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        id: &StreamRouteId,
    ) -> Result<Option<WorkflowLogin>, DomainError> {
        let record: Option<LoginRecord> = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    LoginRecord,
                    "queries/stream_route_logins/find.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid(),
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(LoginRecord::into_login).transpose()
    }

    async fn keep(
        &self,
        tenant_id: &ScopedTenant,
        id: &StreamRouteId,
        login: &WorkflowLogin,
    ) -> Result<(), DomainError> {
        let tls = TlsColumns::from(login.tls());
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/stream_route_logins/keep.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid(),
                    login.user().as_str(),
                    login.password().as_str(),
                    tls.word,
                    tls.authority,
                    tls.server_name,
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }

    async fn forget(
        &self,
        tenant_id: &ScopedTenant,
        id: &StreamRouteId,
    ) -> Result<(), DomainError> {
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/stream_route_logins/forget.sql",
                    tenant_id.as_uuid(),
                    id.as_uuid(),
                )
                .execute(connection)
                .await
                .map(|_| ())
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::routing::StreamRouteStore as _;
    use ianua_domain::domains::routing::stream::{
        LoginTls, LoginUser, StreamRoute, TlsAuthority, TlsCheck,
    };
    use ianua_domain::types::{HostName, SealedSecret};

    use super::*;
    use crate::postgres::routing::PgStreamRouteStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::domain::saved_tenant;
    use crate::test_support::rows::routing::stream_route_row;

    fn login(user: &str) -> WorkflowLogin {
        WorkflowLogin::new(
            LoginUser::new(user).unwrap(),
            SealedSecret::new("v1.AAECAwQF").unwrap(),
            LoginTls::Required(TlsCheck::new(
                TlsAuthority::PublicRoots,
                HostName::new("db.internal").unwrap(),
            )),
        )
    }

    /// The orders database's workflow login is kept apart from the route,
    /// read back as kept, replaced by the next, and forgotten; a deleted
    /// route takes its login with it.
    #[tokio::test]
    async fn a_stream_route_login_is_kept_replaced_and_forgotten() {
        let database = TestDb::fresh().await;
        let tenant = saved_tenant(&database.databases).await;
        let routes = PgStreamRouteStore::new(Arc::clone(&database.databases));
        let logins = PgStreamRouteLogins::new(Arc::clone(&database.databases));
        let orders = StreamRoute::reconstitute(stream_route_row("orders-db", 15432)).unwrap();
        routes.save(&tenant, &orders).await.unwrap();

        logins
            .keep(&tenant, orders.id(), &login("reader"))
            .await
            .unwrap();
        logins
            .keep(&tenant, orders.id(), &login("writer"))
            .await
            .unwrap();
        let kept = logins.find(&tenant, orders.id()).await.unwrap();
        logins.forget(&tenant, orders.id()).await.unwrap();
        let forgotten = logins.find(&tenant, orders.id()).await.unwrap();
        logins
            .keep(&tenant, orders.id(), &login("reader"))
            .await
            .unwrap();
        routes.delete(&tenant, orders.id()).await.unwrap();
        let after_delete = logins.find(&tenant, orders.id()).await.unwrap();

        assert_eq!(kept, Some(login("writer")));
        assert_eq!(forgotten, None);
        assert_eq!(after_delete, None);
    }
}
