//! The ledgers every node shares: the nonces of sealed requests between the
//! gateway and the API and the `DPoP` proofs gateways take, each spent
//! once, and the recent agent touches on each path the convergence check
//! looks back over.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::agents::{TouchEntry, TouchLedger};
use ianua_app::ports::authentication::NonceLedger;
use ianua_app::ports::oauth::DpopReplayGuard;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::execution::convergence::{Touch, TouchKind};
use ianua_domain::domains::oauth::grants::token_binding::JwkThumbprint;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentId, Lifetime, Nonce, TokenId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::cache::state::{LogEntry, SharedState, key, micros};

/// The ledger of sealed requests' nonces, each spent once while it lasts.
pub struct CacheNonceLedger {
    state: Arc<dyn SharedState>,
}

impl CacheNonceLedger {
    /// A ledger on `state`.
    #[must_use]
    pub fn new(state: Arc<dyn SharedState>) -> Self {
        Self { state }
    }
}

#[async_trait]
impl NonceLedger for CacheNonceLedger {
    async fn spend(&self, nonce: &Nonce, ttl: Lifetime) -> bool {
        let spent = key(&["nonce", nonce.as_str()]);
        let ttl = Duration::try_from(ttl.duration()).unwrap_or(Duration::ZERO);
        self.state
            .claim_once(&spent, ttl)
            .await
            .inspect_err(|error| tracing::warn!(%error, "the nonce ledger did not answer"))
            .unwrap_or(false)
    }
}

/// The ledger of `DPoP` proofs, each spent once by its key while it lasts,
/// shared by every gateway: a proof replayed at another node is refused
/// there too.
///
/// A ledger that cannot answer is an error, never a first use: a proof
/// whose spending cannot be recorded is refused.
pub struct CacheDpopReplayGuard {
    state: Arc<dyn SharedState>,
}

impl CacheDpopReplayGuard {
    /// A ledger on `state`.
    #[must_use]
    pub fn new(state: Arc<dyn SharedState>) -> Self {
        Self { state }
    }
}

impl TenantScoped for CacheDpopReplayGuard {}

#[async_trait]
impl DpopReplayGuard for CacheDpopReplayGuard {
    async fn first_use(
        &self,
        tenant_id: &ScopedTenant,
        thumbprint: &JwkThumbprint,
        jti: &TokenId,
        until: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let tenant = tenant_id.as_uuid().simple().to_string();
        let spent = key(&["dpop", &tenant, thumbprint.as_str(), jti.as_str()]);
        let left = until
            .unix_timestamp()
            .saturating_sub(clock::now().unix_timestamp());
        let ttl = Duration::from_secs(u64::try_from(left).unwrap_or(0));
        if ttl.is_zero() {
            return Ok(false);
        }
        self.state
            .claim_once(&spent, ttl)
            .await
            .map_err(DomainError::from)
    }
}

/// A touch as a log entry: unique even beside another of the same agent
/// and kind at the same moment.
fn written(touch: &Touch) -> String {
    format!(
        "{}:{}:{}",
        touch.agent.as_uuid(),
        touch.kind.as_str(),
        Uuid::now_v7()
    )
}

/// A touch read back from its log entry, or `None` for one no release
/// writes.
fn read_back(entry: &str) -> Option<Touch> {
    let mut parts = entry.splitn(3, ':');
    let (Some(agent), Some(kind), Some(_)) = (parts.next(), parts.next(), parts.next()) else {
        return None;
    };
    let kind = match kind {
        "read" => TouchKind::Read,
        "write" => TouchKind::Write,
        _ => return None,
    };
    Some(Touch {
        agent: AgentId::from_uuid(Uuid::parse_str(agent).ok()?),
        kind,
    })
}

/// The ledger of recent agent touches on each path of a tenant.
pub struct CacheTouchLedger {
    state: Arc<dyn SharedState>,
}

impl TenantScoped for CacheTouchLedger {}

impl CacheTouchLedger {
    /// A ledger on `state`.
    #[must_use]
    pub fn new(state: Arc<dyn SharedState>) -> Self {
        Self { state }
    }
}

/// The key a tenant's touches on `path` are logged under.
fn path_key(tenant_id: &ScopedTenant, path: &str) -> String {
    key(&["touches", &tenant_id.to_string(), path])
}

#[async_trait]
impl TouchLedger for CacheTouchLedger {
    async fn since(
        &self,
        tenant_id: &ScopedTenant,
        path: &str,
        since: OffsetDateTime,
    ) -> Result<Vec<Touch>, DomainError> {
        let entries = self
            .state
            .log_since(&path_key(tenant_id, path), micros(since))
            .await?;
        Ok(entries
            .iter()
            .filter_map(|entry| read_back(entry))
            .collect())
    }

    async fn record(
        &self,
        tenant_id: &ScopedTenant,
        entry: &TouchEntry<'_>,
    ) -> Result<(), DomainError> {
        let span = entry
            .at
            .unix_timestamp()
            .saturating_sub(entry.forget_before.unix_timestamp());
        let keep = Duration::from_secs(u64::try_from(span).unwrap_or_default());
        let text = written(entry.touch);
        let logged = LogEntry {
            text: &text,
            at: micros(entry.at),
            forget_before: micros(entry.forget_before),
        };
        self.state
            .log(
                &path_key(tenant_id, entry.path),
                &logged,
                keep.max(Duration::from_secs(1)),
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::shared::clock;
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::cache::MemoryState;

    fn state() -> Arc<dyn SharedState> {
        Arc::new(MemoryState::new(1_000))
    }

    /// A DPoP proof identifier can be claimed once per key;
    /// replay fails while the same identifier under another key remains available.
    #[tokio::test]
    async fn a_dpop_proof_is_taken_once() {
        let guard = CacheDpopReplayGuard::new(state());
        let tenant = ScopedTenant::for_background(TenantId::new());
        let (ann, eve) = (
            JwkThumbprint::new("a".repeat(43)).unwrap(),
            JwkThumbprint::new("e".repeat(43)).unwrap(),
        );
        let jti = TokenId::new("proof-1").unwrap();
        let until = clock::now() + time::Duration::minutes(5);

        let first = guard.first_use(&tenant, &ann, &jti, until).await.unwrap();
        let again = guard.first_use(&tenant, &ann, &jti, until).await.unwrap();
        let other_key = guard.first_use(&tenant, &eve, &jti, until).await.unwrap();

        assert!(first);
        assert!(!again);
        assert!(other_key);
    }

    /// A proof that has already lapsed is never a first use.
    #[tokio::test]
    async fn a_lapsed_proof_is_never_a_first_use() {
        let guard = CacheDpopReplayGuard::new(state());
        let tenant = ScopedTenant::for_background(TenantId::new());
        let thumbprint = JwkThumbprint::new("a".repeat(43)).unwrap();
        let jti = TokenId::new("proof-2").unwrap();
        let until = clock::now() - time::Duration::seconds(1);

        let taken = guard
            .first_use(&tenant, &thumbprint, &jti, until)
            .await
            .unwrap();

        assert!(!taken);
    }

    /// A nonce is spent once; the second spend is refused.
    #[tokio::test]
    async fn a_nonce_is_spent_once() {
        let ledger = CacheNonceLedger::new(state());
        let nonce = Nonce::new("n-0123456789abcdef0123").unwrap();
        let ttl = Lifetime::seconds(60).unwrap();

        let first = ledger.spend(&nonce, ttl).await;
        let second = ledger.spend(&nonce, ttl).await;

        assert!(first);
        assert!(!second);
    }

    /// Touches on a path read back since a moment, oldest first, with their
    /// agents and kinds; another path holds its own.
    #[tokio::test]
    async fn touches_read_back_per_path() {
        let ledger = CacheTouchLedger::new(state());
        let tenant = ScopedTenant::for_background(TenantId::new());
        let now = clock::now();
        let (reader, writer) = (AgentId::new(), AgentId::new());
        let touches = [
            Touch {
                agent: reader,
                kind: TouchKind::Read,
            },
            Touch {
                agent: writer,
                kind: TouchKind::Write,
            },
        ];
        for (offset, touch) in [(1, &touches[0]), (2, &touches[1])] {
            let entry = TouchEntry {
                path: "/orders",
                touch,
                at: now + time::Duration::seconds(offset),
                forget_before: now - time::Duration::minutes(5),
            };
            ledger.record(&tenant, &entry).await.unwrap();
        }

        let since = ledger.since(&tenant, "/orders", now).await.unwrap();
        let elsewhere = ledger.since(&tenant, "/invoices", now).await.unwrap();

        assert_eq!(since, touches);
        assert!(elsewhere.is_empty());
    }
}
