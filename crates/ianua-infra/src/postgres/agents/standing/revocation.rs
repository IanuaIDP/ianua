//! Whether a delegation still stands, read on every agent request so a
//! revoke takes effect on the next one. A delegation that is gone reads as
//! revoked, and so does one drawing its authority from any delegation
//! revoked or gone, so one cut from a parent while the parent's revoke ran
//! never outlives it. A task token minted with a key reads as revoked once
//! that key is revoked, so revoking a leaked key ends every token it
//! minted.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::agents::DelegationRevocationCheck;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::DelegationId;

use self::record::{ChainLink, into_revoked};
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres check of whether a delegation is revoked.
pub struct PgDelegationRevocationCheck {
    databases: Arc<Databases>,
}

impl TenantScoped for PgDelegationRevocationCheck {}

impl PgDelegationRevocationCheck {
    /// A check reading the delegations in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>) -> Self {
        Self { databases }
    }
}

#[async_trait]
impl DelegationRevocationCheck for PgDelegationRevocationCheck {
    async fn is_revoked(
        &self,
        tenant_id: &ScopedTenant,
        delegation_id: &DelegationId,
    ) -> Result<bool, DomainError> {
        let links = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ChainLink,
                    "queries/agent_delegations/status.sql",
                    tenant_id.as_uuid(),
                    delegation_id.as_uuid()
                )
                .fetch_all(connection)
                .await
            },
        )
        .await?;
        into_revoked(links)
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::agents::{AgentCredentialStore, DelegationStore};
    use ianua_domain::domains::agents::authority::delegation::Delegation;
    use ianua_domain::domains::agents::identity::credential::{
        AgentCredential, AgentCredentialRow,
    };
    use ianua_domain::domains::crypto::key_status::{KeyState, PriorRotation};
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::types::{AgentCredentialId, PrincipalRef, TenantId, UserId};

    use super::*;
    use crate::postgres::agents::{PgAgentCredentialStore, PgDelegationStore};
    use crate::test_support::TestDb;
    use crate::test_support::rows::agents::{
        child_row, credential_row, minted_row, root_row, saved_agent, saved_credential,
    };

    /// A fresh database, the check on it, one tenant, the delegation store,
    /// and a delegation it keeps.
    async fn fixture() -> (
        TestDb,
        PgDelegationRevocationCheck,
        ScopedTenant,
        PgDelegationStore,
        Delegation<ResolvedTenant>,
    ) {
        let db = TestDb::fresh().await;
        let tenant = ScopedTenant::for_background(TenantId::new());
        let agent = saved_agent(&db.databases, &tenant, "ledger").await;
        let delegations = PgDelegationStore::new(Arc::clone(&db.databases));
        let delegation =
            Delegation::reconstitute(root_row(PrincipalRef::User(UserId::new()), agent)).unwrap();
        delegations.save(&tenant, &delegation).await.unwrap();
        let check = PgDelegationRevocationCheck::new(Arc::clone(&db.databases));
        (db, check, tenant, delegations, delegation)
    }

    /// A live delegation stands, and reads as revoked from the moment it is
    /// revoked.
    #[tokio::test]
    async fn a_delegation_reads_as_revoked_once_revoked() {
        let (_db, check, tenant, delegations, delegation) = fixture().await;

        let before = check.is_revoked(&tenant, delegation.id()).await.unwrap();
        delegations
            .revoke_subtree(&tenant, delegation.id())
            .await
            .unwrap();
        let after = check.is_revoked(&tenant, delegation.id()).await.unwrap();

        assert!(!before);
        assert!(after);
    }

    /// A child saved after its parent is revoked reads as revoked, as does a
    /// delegation minted from that child.
    #[tokio::test]
    async fn a_delegation_cut_from_a_revoked_one_reads_as_revoked() {
        let (db, check, tenant, delegations, delegation) = fixture().await;
        let helper = saved_agent(&db.databases, &tenant, "helper").await;
        let key = saved_credential(&db.databases, &tenant, helper, "helper-key").await;
        delegations
            .revoke_subtree(&tenant, delegation.id())
            .await
            .unwrap();
        let child = Delegation::reconstitute(child_row(&delegation, helper)).unwrap();
        delegations.save(&tenant, &child).await.unwrap();
        let minted = Delegation::reconstitute(minted_row(helper, *key.id(), &[&child])).unwrap();
        delegations.save(&tenant, &minted).await.unwrap();

        let cut = check.is_revoked(&tenant, child.id()).await.unwrap();
        let token = check.is_revoked(&tenant, minted.id()).await.unwrap();

        assert!(cut);
        assert!(token);
    }

    /// The task token the agent holding `source` minted from it, signed in
    /// with `key`, saved.
    async fn minted_with(
        delegations: &PgDelegationStore,
        tenant: &ScopedTenant,
        source: &Delegation<ResolvedTenant>,
        key: AgentCredentialId,
    ) -> Delegation<ResolvedTenant> {
        let row = minted_row(*source.delegate(), key, &[source]);
        let minted = Delegation::reconstitute(row).unwrap();
        delegations.save(tenant, &minted).await.unwrap();
        minted
    }

    /// Revoking k2 changes its minted delegation from unrevoked to revoked;
    /// the delegation minted with k3 remains unrevoked.
    #[tokio::test]
    async fn a_token_reads_as_revoked_once_the_key_that_minted_it_is() {
        let (db, check, tenant, delegations, delegation) = fixture().await;
        let agent = *delegation.delegate();
        let k2 = saved_credential(&db.databases, &tenant, agent, "k2").await;
        let k3 = saved_credential(&db.databases, &tenant, agent, "k3").await;
        let by_k2 = minted_with(&delegations, &tenant, &delegation, *k2.id()).await;
        let by_k3 = minted_with(&delegations, &tenant, &delegation, *k3.id()).await;
        let before = check.is_revoked(&tenant, by_k2.id()).await.unwrap();
        let revoked = AgentCredential::reconstitute(AgentCredentialRow {
            id: *k2.id(),
            state: KeyState::Revoked {
                before: PriorRotation::NotRotated,
            },
            ..credential_row(agent, "k2")
        })
        .unwrap();

        PgAgentCredentialStore::new(Arc::clone(&db.databases))
            .save(&tenant, &revoked)
            .await
            .unwrap();

        assert!(!before);
        assert!(check.is_revoked(&tenant, by_k2.id()).await.unwrap());
        assert!(!check.is_revoked(&tenant, by_k3.id()).await.unwrap());
    }

    /// Recording provenance after the source is revoked makes the derived
    /// delegation read as revoked. A delegation derived from a live source
    /// remains unrevoked.
    #[tokio::test]
    async fn a_delegation_derived_from_a_revoked_one_reads_as_revoked() {
        let (db, check, tenant, delegations, delegation) = fixture().await;
        let helper = saved_agent(&db.databases, &tenant, "helper").await;
        let live =
            Delegation::reconstitute(root_row(PrincipalRef::User(UserId::new()), helper)).unwrap();
        delegations.save(&tenant, &live).await.unwrap();
        delegations
            .revoke_subtree(&tenant, delegation.id())
            .await
            .unwrap();
        let [late, sound] = [(); 2].map(|()| {
            Delegation::reconstitute(root_row(PrincipalRef::User(UserId::new()), helper)).unwrap()
        });
        for (derived, source) in [(&late, delegation.id()), (&sound, live.id())] {
            delegations.save(&tenant, derived).await.unwrap();
            delegations
                .record_provenance(&tenant, derived.id(), &[*source])
                .await
                .unwrap();
        }

        let revoked = check.is_revoked(&tenant, late.id()).await.unwrap();
        let standing = check.is_revoked(&tenant, sound.id()).await.unwrap();

        assert!(revoked);
        assert!(!standing);
    }

    /// Unknown delegations and delegations belonging to another tenant both
    /// read as revoked.
    #[tokio::test]
    async fn a_missing_or_foreign_delegation_reads_as_revoked() {
        let (_db, check, tenant, _delegations, delegation) = fixture().await;
        let other = ScopedTenant::for_background(TenantId::new());

        let unknown = check
            .is_revoked(&tenant, &DelegationId::new())
            .await
            .unwrap();
        let foreign = check.is_revoked(&other, delegation.id()).await.unwrap();

        assert!(unknown);
        assert!(foreign);
    }

    /// Checking revocation rejects an unknown stored delegation status as
    /// corrupt.
    #[tokio::test]
    async fn a_row_with_an_unknown_status_is_refused() {
        let (db, check, tenant, _delegations, delegation) = fixture().await;
        db.tamper("ALTER TABLE agent_delegations DROP CONSTRAINT agent_delegations_status_known")
            .await;
        db.tamper("UPDATE agent_delegations SET status = 'paused'")
            .await;

        let read = check.is_revoked(&tenant, delegation.id()).await;

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
