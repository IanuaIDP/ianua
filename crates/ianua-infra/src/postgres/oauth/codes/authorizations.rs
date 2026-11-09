//! A tenant's authorization codes, each found by its hash, under
//! row-level security.
//!
//! Only a code's hash is kept. Redeeming is one `UPDATE` that holds only
//! while the code is unused, so of two exchanges of one code arriving
//! together only one gets the tokens; a save never undoes a use.

mod record;
mod words;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::oauth::{AuthCodeStore, ConsentedSession};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::oauth::grants::authorization_code::AuthorizationCode;
use ianua_domain::domains::oauth::grants::logout_notice::SignedOut;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TokenHash;
use sqlx::PgConnection;
use uuid::Uuid;

use self::record::{AuthCodeColumns, AuthCodeRecord, ConsentedSessionRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// Writes the authorization code's mapped columns without changing an earlier consumption.
async fn write_columns(
    connection: &mut PgConnection,
    tenant: &Uuid,
    columns: &AuthCodeColumns<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query_file!(
        "queries/oauth_codes/save.sql",
        tenant,
        columns.code_hash,
        columns.client_id,
        columns.user_id,
        columns.redirect_uri,
        columns.scopes.as_slice(),
        columns.code_challenge,
        columns.code_challenge_method,
        columns.nonce,
        columns.session_id,
        columns.auth_method,
        columns.second_factor,
        columns.authenticated_at,
        columns.created_at,
        columns.expires_at,
        columns.consumed_at,
    )
    .execute(connection)
    .await
    .map(|_| ())
}

/// The Postgres store of authorization codes.
pub struct PgAuthCodeStore {
    databases: Arc<Databases>,
}

impl TenantScoped for PgAuthCodeStore {}

impl PgAuthCodeStore {
    /// A store keeping authorization codes in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl AuthCodeStore for PgAuthCodeStore {
    async fn find_by_hash(
        &self,
        tenant_id: &ScopedTenant,
        code_hash: &TokenHash,
    ) -> Result<Option<AuthorizationCode<ResolvedTenant>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    AuthCodeRecord,
                    "queries/oauth_codes/by_hash.sql",
                    tenant_id.as_uuid(),
                    code_hash.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        record.map(AuthCodeRecord::into_code).transpose()
    }

    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        code: &AuthorizationCode<ResolvedTenant>,
    ) -> Result<(), DomainError> {
        let columns = AuthCodeColumns::of(code);
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| write_columns(connection, tenant_id.as_uuid(), &columns).await,
        )
        .await
    }

    async fn redeem(
        &self,
        tenant_id: &ScopedTenant,
        code: &AuthorizationCode<ResolvedTenant>,
    ) -> Result<bool, DomainError> {
        let Some(used_at) = code.consumed_at() else {
            return Err(DomainError::invalid(message!(
                "infra-only-a-code-just-used-up",
                "only a code just used up is redeemed"
            )));
        };
        let redeemed = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/oauth_codes/redeem.sql",
                    tenant_id.as_uuid(),
                    code.code_hash().as_str(),
                    used_at
                )
                .execute(connection)
                .await
            },
        )
        .await?;
        Ok(redeemed.rows_affected() == 1)
    }

    async fn consented_sessions(
        &self,
        tenant_id: &ScopedTenant,
        signed_out: SignedOut,
    ) -> Result<Vec<ConsentedSession>, DomainError> {
        let pairs = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| consented_records(connection, tenant_id.as_uuid(), signed_out).await,
        )
        .await?;
        Ok(pairs
            .into_iter()
            .map(ConsentedSessionRecord::into_pair)
            .collect())
    }
}

/// Reads the client/session pairs selected by a session or account-wide logout.
async fn consented_records(
    connection: &mut PgConnection,
    tenant: &Uuid,
    signed_out: SignedOut,
) -> Result<Vec<ConsentedSessionRecord>, sqlx::Error> {
    match signed_out {
        SignedOut::Session { person, session } => {
            sqlx::query_file_as!(
                ConsentedSessionRecord,
                "queries/oauth_codes/consented_session.sql",
                tenant,
                person.as_uuid(),
                session.as_uuid()
            )
            .fetch_all(connection)
            .await
        }
        SignedOut::Everywhere { person } => {
            sqlx::query_file_as!(
                ConsentedSessionRecord,
                "queries/oauth_codes/consented_sessions.sql",
                tenant,
                person.as_uuid()
            )
            .fetch_all(connection)
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::identity::UserStore;
    use ianua_domain::domains::authentication::methods::AuthMethod;
    use ianua_domain::domains::authentication::sessions::mfa_factor::{FactorProved, MfaFactor};
    use ianua_domain::domains::oauth::clients::client::{GrantType, OAuthClient};
    use ianua_domain::domains::oauth::grants::authorization_code::{AuthCodeRow, NonceSent};
    use ianua_domain::shared::config::DomainLimits;
    use ianua_domain::types::{Nonce, SessionId, Usage, UserId};

    use super::*;
    use crate::postgres::identity::PgUserStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::authentication::session_of;
    use crate::test_support::rows::authorization::tenant;
    use crate::test_support::rows::oauth::{a_client, a_person, code_row, hash, oauth_client_row};

    struct Fixture {
        db: TestDb,
        store: PgAuthCodeStore,
        tenant: ScopedTenant,
        client: OAuthClient<ResolvedTenant>,
        ann: UserId,
    }

    /// A fresh database, the store on it, and a tenant with a client and a
    /// person to issue codes for.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let tenant = tenant();
        let client = a_client(
            &db,
            &tenant,
            oauth_client_row("portal", &[GrantType::AuthorizationCode]),
        )
        .await;
        let ann = a_person(&db, &tenant, "ann@acme.example").await;
        Fixture {
            store: PgAuthCodeStore::new(Arc::clone(&db.databases)),
            db,
            tenant,
            client,
            ann,
        }
    }

    fn code(row: AuthCodeRow) -> AuthorizationCode<ResolvedTenant> {
        AuthorizationCode::reconstitute(row).unwrap()
    }

    fn used(row: AuthCodeRow) -> AuthorizationCode<ResolvedTenant> {
        code(AuthCodeRow {
            usage: Usage::Used { at: at(5) },
            ..row
        })
    }

    impl Fixture {
        fn row(&self, session: SessionId, raw: &str) -> AuthCodeRow {
            code_row(&self.client, self.ann, session, raw)
        }

        /// A session of Ann, saved through its store.
        async fn session(&self) -> SessionId {
            session_of(&self.db.databases, &self.tenant, self.ann).await
        }

        /// Reads logout recipients for the supplied tenant and sign-out selection.
        async fn consented(
            &self,
            tenant: &ScopedTenant,
            selection: SignedOut,
        ) -> Vec<ConsentedSession> {
            self.store
                .consented_sessions(tenant, selection)
                .await
                .unwrap()
        }

        /// Saves issued codes for Ann's sessions, including repeated consent to one client.
        async fn save_codes(&self, codes: &[(SessionId, &str)]) {
            for &(session, raw) in codes {
                self.store
                    .save(&self.tenant, &code(self.row(session, raw)))
                    .await
                    .unwrap();
            }
        }
    }

    /// A saved code, with its nonce and the factor its session proved, is
    /// found by its hash as it was saved.
    #[tokio::test]
    async fn a_saved_code_is_found_by_its_hash() {
        let db = fixture().await;
        let issued = code(AuthCodeRow {
            nonce: NonceSent::Sent(Nonce::new("n-0S6_WzA2Mj-4fd8a").unwrap()),
            auth_method: AuthMethod::Passkey,
            second_factor: FactorProved::Proved(MfaFactor::HardwareKey),
            ..db.row(db.session().await, "code-1")
        });

        db.store.save(&db.tenant, &issued).await.unwrap();

        let found = db
            .store
            .find_by_hash(&db.tenant, issued.code_hash())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.client_id(), issued.client_id());
        assert_eq!(found.user_id(), issued.user_id());
        assert_eq!(found.redirect_uri(), issued.redirect_uri());
        assert_eq!(found.scopes(), issued.scopes());
        assert_eq!(found.code_challenge(), issued.code_challenge());
        assert_eq!(found.nonce(), issued.nonce());
        assert_eq!(found.session_id(), issued.session_id());
        assert_eq!(found.auth_method(), AuthMethod::Passkey);
        assert_eq!(found.second_factor(), issued.second_factor());
        assert_eq!(found.expires_at(), issued.expires_at());
        assert!(!found.is_consumed());
    }

    /// Unknown authorization-code hashes and lookups from another tenant return
    /// nothing.
    #[tokio::test]
    async fn a_code_is_found_only_by_its_tenant() {
        let db = fixture().await;
        let issued = code(db.row(db.session().await, "code-1"));
        db.store.save(&db.tenant, &issued).await.unwrap();

        let unknown = db
            .store
            .find_by_hash(&db.tenant, &hash("nobody"))
            .await
            .unwrap();
        let theirs = db
            .store
            .find_by_hash(&tenant(), issued.code_hash())
            .await
            .unwrap();

        assert!(unknown.is_none());
        assert!(theirs.is_none());
    }

    /// Redeeming an authorization code succeeds once; the next attempt returns
    /// false and the stored code retains its consumption time.
    #[tokio::test]
    async fn a_code_is_redeemed_once() {
        let db = fixture().await;
        let session = db.session().await;
        db.store
            .save(&db.tenant, &code(db.row(session, "code-1")))
            .await
            .unwrap();
        let spent = used(db.row(session, "code-1"));

        let first = db.store.redeem(&db.tenant, &spent).await.unwrap();
        let second = db.store.redeem(&db.tenant, &spent).await.unwrap();

        assert!(first);
        assert!(!second);
        let found = db
            .store
            .find_by_hash(&db.tenant, spent.code_hash())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.consumed_at(), Some(at(5)));
    }

    /// Redeeming an authorization code that was never saved returns false.
    #[tokio::test]
    async fn a_code_not_kept_is_not_redeemed() {
        let db = fixture().await;
        let spent = used(db.row(db.session().await, "code-1"));

        let redeemed = db.store.redeem(&db.tenant, &spent).await.unwrap();

        assert!(!redeemed);
    }

    /// Saving an unused copy leaves the stored authorization code consumed.
    #[tokio::test]
    async fn a_save_never_undoes_a_use() {
        let db = fixture().await;
        let session = db.session().await;
        db.store
            .save(&db.tenant, &used(db.row(session, "code-1")))
            .await
            .unwrap();

        db.store
            .save(&db.tenant, &code(db.row(session, "code-1")))
            .await
            .unwrap();

        let found = db
            .store
            .find_by_hash(&db.tenant, &hash("code-1"))
            .await
            .unwrap()
            .unwrap();
        assert!(found.is_consumed());
    }

    /// Ann consented to the portal twice in one session and once in
    /// another: each pair is named once, and Bob's codes are left out.
    #[tokio::test]
    async fn the_sessions_a_person_consented_in_are_named_once() {
        let db = fixture().await;
        let bob = a_person(&db.db, &db.tenant, "bob@acme.example").await;
        let (morning, evening) = (db.session().await, db.session().await);
        db.save_codes(&[(morning, "a"), (morning, "b"), (evening, "c")])
            .await;
        let bobs = code(code_row(
            &db.client,
            bob,
            session_of(&db.db.databases, &db.tenant, bob).await,
            "d",
        ));
        db.store.save(&db.tenant, &bobs).await.unwrap();

        let mut sessions: Vec<SessionId> = db
            .store
            .consented_sessions(&db.tenant, SignedOut::Everywhere { person: db.ann })
            .await
            .unwrap()
            .into_iter()
            .map(|pair| pair.session)
            .collect();
        sessions.sort_by_key(|session| *session.as_uuid());
        let mut expected = vec![morning, evening];
        expected.sort_by_key(|session| *session.as_uuid());

        assert_eq!(sessions, expected);
    }

    /// Session logout finds one client pair for the selected session despite
    /// duplicate codes, excludes the person's other session, and returns nothing
    /// for another tenant or person.
    #[tokio::test]
    async fn a_session_logout_reads_only_its_client_pairs() {
        let db = fixture().await;
        let morning = db.session().await;
        let evening = db.session().await;
        db.save_codes(&[(morning, "a"), (morning, "b"), (evening, "c")])
            .await;
        let selection = SignedOut::Session {
            person: db.ann,
            session: morning,
        };

        let pairs = db.consented(&db.tenant, selection).await;
        let foreign = db.consented(&tenant(), selection).await;
        let wrong_person = db
            .consented(
                &db.tenant,
                SignedOut::Session {
                    person: UserId::new(),
                    session: morning,
                },
            )
            .await;

        assert_eq!(
            pairs,
            [ConsentedSession {
                client: *db.client.id(),
                session: morning
            }]
        );
        assert!(foreign.is_empty());
        assert!(wrong_person.is_empty());
    }

    /// Deleting Ann takes the codes issued for her with her account.
    #[tokio::test]
    async fn a_persons_codes_go_with_their_account() {
        let db = fixture().await;
        let issued = code(db.row(db.session().await, "code-1"));
        db.store.save(&db.tenant, &issued).await.unwrap();

        PgUserStore::new(Arc::clone(&db.db.databases), DomainLimits::default())
            .delete(&db.tenant, &db.ann)
            .await
            .unwrap();

        let found = db
            .store
            .find_by_hash(&db.tenant, issued.code_hash())
            .await
            .unwrap();
        assert!(found.is_none());
    }

    /// Reading a password sign-in code with a stored provider second factor
    /// returns an infrastructure error.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_code_is_refused() {
        let db = fixture().await;
        let issued = code(db.row(db.session().await, "code-1"));
        db.store.save(&db.tenant, &issued).await.unwrap();
        db.db
            .tamper("UPDATE oauth_codes SET second_factor = 'provider_multi_factor'")
            .await;

        let read = db.store.find_by_hash(&db.tenant, issued.code_hash()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
