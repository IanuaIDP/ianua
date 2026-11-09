//! Operator API keys, kept in the platform database.
//!
//! A key is found by the prefix it is shown with; only its hash is kept.
//! Its operator and hash never change once it is made, and it leaves
//! service by revocation, never by being removed.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::operator::OperatorKeyStore;
use ianua_domain::domains::operator::api_key::OperatorApiKey;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{KeyPrefix, OperatorId};
use sqlx::PgConnection;
use time::OffsetDateTime;

use self::record::{KeyColumns, KeyRecord};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of operator API keys.
pub struct PgOperatorKeyStore {
    databases: Arc<Databases>,
}

impl PgOperatorKeyStore {
    /// A store keeping operator API keys in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl OperatorKeyStore for PgOperatorKeyStore {
    async fn find_by_prefix(
        &self,
        prefix: &KeyPrefix,
    ) -> Result<Option<OperatorApiKey>, DomainError> {
        let record = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                KeyRecord,
                "queries/operator_api_keys/by_prefix.sql",
                prefix.as_str()
            )
            .fetch_optional(connection)
            .await
        })
        .await?;
        record.map(KeyRecord::into_key).transpose()
    }

    async fn list_by_operator(
        &self,
        operator_id: &OperatorId,
    ) -> Result<Vec<OperatorApiKey>, DomainError> {
        let records = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file_as!(
                KeyRecord,
                "queries/operator_api_keys/of_operator.sql",
                operator_id.as_uuid()
            )
            .fetch_all(connection)
            .await
        })
        .await?;
        records.into_iter().map(KeyRecord::into_key).collect()
    }

    async fn save(&self, key: &OperatorApiKey) -> Result<(), DomainError> {
        let columns = KeyColumns::of(key);
        let written = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            sqlx::query_file!(
                "queries/operator_api_keys/save.sql",
                columns.key_prefix,
                columns.operator_id,
                columns.key_hash,
                columns.expires_at,
                columns.revoked_at,
                columns.created_at,
            )
            .execute(connection)
            .await
            .map(|done| done.rows_affected())
        })
        .await?;
        match written {
            0 => Err(DomainError::conflict(message!(
                "infra-this-key-prefix-is-another-operator",
                "this key prefix is another operator's, or the key was revoked already"
            ))),
            _ => Ok(()),
        }
    }

    async fn revoke_together(
        &self,
        operator_id: &OperatorId,
        keys: &[OperatorApiKey],
    ) -> Result<(), DomainError> {
        let revoked = revocations_of(keys)?;
        let all_written = scoped(&self.databases, RowScope::Unscoped, async |connection| {
            write_all_or_none(connection, operator_id, &revoked).await
        })
        .await?;
        if !all_written {
            return Err(DomainError::conflict(message!(
                "infra-a-key-was-revoked-meanwhile-is",
                "a key was revoked meanwhile, is gone, or is another operator's"
            )));
        }
        Ok(())
    }
}

/// Keys revoked together, as the two arrays the write takes: their
/// prefixes and, in the same order, when each was revoked.
struct Revocations {
    prefixes: Vec<String>,
    times: Vec<OffsetDateTime>,
}

/// The prefixes of `keys` and when each was revoked.
///
/// # Errors
///
/// Returns `DomainError::Validation` when a key of `keys` is not revoked.
fn revocations_of(keys: &[OperatorApiKey]) -> Result<Revocations, DomainError> {
    let mut revoked = Revocations {
        prefixes: Vec::with_capacity(keys.len()),
        times: Vec::with_capacity(keys.len()),
    };
    for key in keys {
        let Some(at) = key.revocation().revoked_at() else {
            return Err(DomainError::invalid(message!(
                "infra-only-keys-just-revoked-are-written",
                "only keys just revoked are written"
            )));
        };
        revoked.prefixes.push(key.key_prefix().as_str().to_owned());
        revoked.times.push(at);
    }
    Ok(revoked)
}

/// Locks `operator_id`'s keys named in `revoked` still in force, and
/// writes them only when every one is: says whether it did. A key revoked
/// meanwhile, gone or another operator's leaves all of them unwritten.
async fn write_all_or_none(
    connection: &mut PgConnection,
    operator_id: &OperatorId,
    revoked: &Revocations,
) -> Result<bool, sqlx::Error> {
    let live = sqlx::query_file_scalar!(
        "queries/operator_api_keys/lock_live.sql",
        operator_id.as_uuid(),
        revoked.prefixes.as_slice()
    )
    .fetch_all(&mut *connection)
    .await?;
    if live.len() != revoked.prefixes.len() {
        return Ok(false);
    }
    sqlx::query_file!(
        "queries/operator_api_keys/revoke_together.sql",
        operator_id.as_uuid(),
        revoked.prefixes.as_slice(),
        revoked.times.as_slice()
    )
    .execute(connection)
    .await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::operator::OperatorStore;
    use ianua_domain::domains::operator::api_key::OperatorApiKeyRow;
    use ianua_domain::types::{Expiry, Revocation};

    use super::*;
    use crate::postgres::operator::PgOperatorStore;
    use crate::test_support::TestDb;
    use crate::test_support::rows::at;
    use crate::test_support::rows::operator::{active_operator, operator_key_row};

    struct Fixture {
        db: TestDb,
        store: PgOperatorKeyStore,
        olga: OperatorId,
    }

    /// A fresh database holding the operator Olga, and the store on it.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let olga = an_operator(&db, "olga@ianua.dev").await;
        Fixture {
            store: PgOperatorKeyStore::new(Arc::clone(&db.databases)),
            olga,
            db,
        }
    }

    /// Saves an operator at `email` through their store.
    async fn an_operator(db: &TestDb, email: &str) -> OperatorId {
        let operator = active_operator(email);
        PgOperatorStore::new(Arc::clone(&db.databases))
            .save(&operator)
            .await
            .unwrap();
        *operator.id()
    }

    fn key(row: OperatorApiKeyRow) -> OperatorApiKey {
        OperatorApiKey::reconstitute(row).unwrap()
    }

    fn prefix(text: &str) -> KeyPrefix {
        KeyPrefix::new(text).unwrap()
    }

    /// Olga's CLI key, expiring in a year, is found by its prefix as it was
    /// saved.
    #[tokio::test]
    async fn a_saved_key_is_found_by_its_prefix() {
        let fx = fixture().await;
        let cli = key(OperatorApiKeyRow {
            expires_at: Expiry::At(at(31_536_000)),
            ..operator_key_row(fx.olga, "opk_cli")
        });

        fx.store.save(&cli).await.unwrap();

        let found = fx
            .store
            .find_by_prefix(&prefix("opk_cli"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.operator_id(), &fx.olga);
        assert_eq!(found.key_hash(), cli.key_hash());
        assert_eq!(found.expires_at(), cli.expires_at());
        assert_eq!(found.revocation(), Revocation::InForce);
        assert_eq!(found.created_at(), cli.created_at());
    }

    /// A prefix no key has finds nothing, rather than failing.
    #[tokio::test]
    async fn an_unknown_key_is_not_found() {
        let fx = fixture().await;

        let found = fx
            .store
            .find_by_prefix(&prefix("opk_nobody"))
            .await
            .unwrap();

        assert!(found.is_none());
    }

    /// Each operator lists their own keys, revoked or not, oldest first,
    /// and never another operator's.
    #[tokio::test]
    async fn an_operator_lists_only_their_own_keys() {
        let fx = fixture().await;
        let pete = an_operator(&fx.db, "pete@ianua.dev").await;
        let older = key(operator_key_row(fx.olga, "opk_old"));
        let newer = key(OperatorApiKeyRow {
            created_at: at(5),
            revocation: Revocation::Revoked { at: at(6) },
            ..operator_key_row(fx.olga, "opk_new")
        });
        for saved in [&newer, &older, &key(operator_key_row(pete, "opk_pete"))] {
            fx.store.save(saved).await.unwrap();
        }

        let listed = fx.store.list_by_operator(&fx.olga).await.unwrap();

        let prefixes: Vec<&str> = listed.iter().map(|key| key.key_prefix().as_str()).collect();
        assert_eq!(prefixes, ["opk_old", "opk_new"]);
    }

    /// Olga revokes her key: saving it again keeps the revocation.
    #[tokio::test]
    async fn saving_again_keeps_the_revocation() {
        let fx = fixture().await;
        fx.store
            .save(&key(operator_key_row(fx.olga, "opk_cli")))
            .await
            .unwrap();
        let revoked = key(OperatorApiKeyRow {
            revocation: Revocation::Revoked { at: at(7) },
            ..operator_key_row(fx.olga, "opk_cli")
        });

        fx.store.save(&revoked).await.unwrap();

        let found = fx
            .store
            .find_by_prefix(&prefix("opk_cli"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.revocation(), Revocation::Revoked { at: at(7) });
    }

    /// Saving a stale copy of Olga's revoked key returns a conflict and
    /// preserves its revocation time.
    #[tokio::test]
    async fn a_stale_save_does_not_undo_a_revocation() {
        let fx = fixture().await;
        let in_force = key(operator_key_row(fx.olga, "opk_cli"));
        fx.store.save(&in_force).await.unwrap();
        fx.store
            .save(&key(OperatorApiKeyRow {
                revocation: Revocation::Revoked { at: at(7) },
                ..operator_key_row(fx.olga, "opk_cli")
            }))
            .await
            .unwrap();

        let stale = fx.store.save(&in_force).await;

        assert!(matches!(stale, Err(DomainError::Conflict(_))));
        let found = fx
            .store
            .find_by_prefix(&prefix("opk_cli"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.revocation(), Revocation::Revoked { at: at(7) });
    }

    /// Olga ends both her keys at once: both are written revoked, each at
    /// its own time.
    #[tokio::test]
    async fn keys_revoked_together_are_all_written() {
        let fx = fixture().await;
        for prefix in ["opk_cli", "opk_ops"] {
            fx.store
                .save(&key(operator_key_row(fx.olga, prefix)))
                .await
                .unwrap();
        }
        let revoked = [("opk_cli", 7), ("opk_ops", 8)].map(|(prefix, seconds)| {
            key(OperatorApiKeyRow {
                revocation: Revocation::Revoked { at: at(seconds) },
                ..operator_key_row(fx.olga, prefix)
            })
        });

        fx.store.revoke_together(&fx.olga, &revoked).await.unwrap();

        let listed = fx.store.list_by_operator(&fx.olga).await.unwrap();
        let times: Vec<Revocation> = listed.iter().map(OperatorApiKey::revocation).collect();
        assert!(times.contains(&Revocation::Revoked { at: at(7) }));
        assert!(times.contains(&Revocation::Revoked { at: at(8) }));
    }

    /// Revoking two keys together conflicts when one is already revoked;
    /// Olga's other key remains in force.
    #[tokio::test]
    async fn keys_revoked_together_are_all_or_none() {
        let fx = fixture().await;
        for prefix in ["opk_cli", "opk_ops"] {
            fx.store
                .save(&key(operator_key_row(fx.olga, prefix)))
                .await
                .unwrap();
        }
        fx.store
            .save(&key(OperatorApiKeyRow {
                revocation: Revocation::Revoked { at: at(5) },
                ..operator_key_row(fx.olga, "opk_cli")
            }))
            .await
            .unwrap();
        let revoked = [("opk_cli", 7), ("opk_ops", 8)].map(|(prefix, seconds)| {
            key(OperatorApiKeyRow {
                revocation: Revocation::Revoked { at: at(seconds) },
                ..operator_key_row(fx.olga, prefix)
            })
        });

        let together = fx.store.revoke_together(&fx.olga, &revoked).await;

        assert!(matches!(together, Err(DomainError::Conflict(_))));
        let ci = fx
            .store
            .find_by_prefix(&prefix("opk_ops"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ci.revocation(), Revocation::InForce);
    }

    /// Saving Olga's key under Pete's name conflicts, and the stored key
    /// still belongs to Olga.
    #[tokio::test]
    async fn a_key_never_changes_its_operator() {
        let fx = fixture().await;
        let pete = an_operator(&fx.db, "pete@ianua.dev").await;
        fx.store
            .save(&key(operator_key_row(fx.olga, "opk_cli")))
            .await
            .unwrap();

        let handed = fx.store.save(&key(operator_key_row(pete, "opk_cli"))).await;

        assert!(matches!(handed, Err(DomainError::Conflict(_))));
        let found = fx
            .store
            .find_by_prefix(&prefix("opk_cli"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.operator_id(), &fx.olga);
    }

    /// A stored key with a prefix outside the operator namespace is
    /// rejected as corrupt storage.
    #[tokio::test]
    async fn a_row_that_breaks_a_rule_of_the_key_is_refused() {
        let fx = fixture().await;
        fx.store
            .save(&key(operator_key_row(fx.olga, "opk_cli")))
            .await
            .unwrap();
        fx.db
            .tamper(
                "ALTER TABLE operator_api_keys DROP CONSTRAINT operator_api_keys_prefix_known; \
                 UPDATE operator_api_keys SET key_prefix = 'cli_key'",
            )
            .await;

        let read = fx.store.find_by_prefix(&prefix("cli_key")).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
