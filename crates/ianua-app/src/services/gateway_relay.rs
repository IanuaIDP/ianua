//! Opening what the gateway relays to the API's internal listener: an app
//! sign-in request or a question about an agent's approval.
//!
//! Each arrives sealed with a key only the gateway and the API derive, one
//! key per channel. It is opened only when the seal holds, it speaks this
//! build's version, it was sent within `MAX_SKEW_SECS` of now and its
//! nonce was never used. The nonce is spent last, once everything else
//! holds, so a forged or stale request cannot use up nonces a real one
//! will need.
//!
//! The answer goes back sealed under the same channel's key and bound to
//! the request's nonce ([`AnswerSeal`]), so the gateway takes no answer
//! from anyone without the key, nor one meant for another request.

use std::sync::Arc;

use ianua_domain::shared::clock;
use ianua_domain::types::{Lifetime, Nonce};
use serde::de::DeserializeOwned;

use crate::error::AppError;
use crate::ports::agents::ApprovalWireRequest;
use crate::ports::authentication::{MAX_SKEW_SECS, NonceLedger, RequestSeal, WireRequest};

/// What the API answers a relayed request with: the answer, and the seal
/// to put on it once the request opened.
pub struct RelayReply<T> {
    /// The answer, or why the request was refused.
    pub answer: Result<T, AppError>,
    /// Seals the answer for the request it answers. `None` when the
    /// request never opened: nothing about it is trusted, its nonce
    /// included, so its answer goes unsealed and the gateway takes it for
    /// none.
    pub seal: Option<AnswerSeal>,
}

impl<T> RelayReply<T> {
    /// The reply to a request that did not open, refused for `reason`.
    pub(crate) fn unopened(reason: AppError) -> Self {
        Self {
            answer: Err(reason),
            seal: None,
        }
    }
}

/// Seals the API's answer to one relayed request: under its channel's key,
/// bound to the nonce the request carried.
pub struct AnswerSeal {
    nonce: Nonce,
    sealer: Arc<dyn RequestSeal>,
}

impl AnswerSeal {
    /// Seals answers to the request that carried `nonce`, through `sealer`.
    #[must_use]
    pub fn new(nonce: Nonce, sealer: Arc<dyn RequestSeal>) -> Self {
        Self { nonce, sealer }
    }

    /// The seal over `body`, the answer exactly as it is sent.
    #[must_use]
    pub fn seal(&self, body: &[u8]) -> String {
        self.sealer.seal_answer(&self.nonce, body)
    }
}

/// What every relayed request carries to be opened by.
pub(crate) trait Stamped {
    /// The protocol version it speaks.
    fn version(&self) -> u8;
    /// When the gateway sent it, in Unix seconds.
    fn sent_at(&self) -> i64;
    /// The value it uses once.
    fn nonce(&self) -> &Nonce;
}

impl Stamped for WireRequest {
    fn version(&self) -> u8 {
        self.v
    }

    fn sent_at(&self) -> i64 {
        self.ctx.ts
    }

    fn nonce(&self) -> &Nonce {
        &self.ctx.nonce
    }
}

impl Stamped for ApprovalWireRequest {
    fn version(&self) -> u8 {
        self.v
    }

    fn sent_at(&self) -> i64 {
        self.ts
    }

    fn nonce(&self) -> &Nonce {
        &self.nonce
    }
}

/// A relayed request as it arrived: its body, exactly as sealed, and the
/// seal the gateway sent with it, if any.
#[derive(Clone, Copy)]
pub(crate) struct Relayed<'a> {
    /// The exact received bytes covered by the gateway's seal.
    pub(crate) body: &'a [u8],
    /// The gateway's seal over it.
    pub(crate) seal: Option<&'a str>,
}

/// The request `relayed` holds, read as speaking `version`, once it is
/// sealed through `sealer`, current, and new to `nonces`.
///
/// # Errors
///
/// `AppError::Unauthenticated` when the seal is missing or wrong, the body
/// does not read, it speaks another version, it is stale, or its nonce was
/// used before. Nothing about it is trusted, so nothing more is said.
pub(crate) async fn opened<T: DeserializeOwned + Stamped>(
    sealer: &dyn RequestSeal,
    nonces: &dyn NonceLedger,
    relayed: Relayed<'_>,
    version: u8,
) -> Result<T, AppError> {
    let sealed = relayed
        .seal
        .is_some_and(|seal| sealer.verifies(relayed.body, seal));
    if !sealed {
        return Err(AppError::Unauthenticated);
    }
    let request: T = serde_json::from_slice(relayed.body).map_err(|_| AppError::Unauthenticated)?;
    if request.version() != version {
        return Err(AppError::Unauthenticated);
    }
    let now = clock::now().unix_timestamp();
    if (now - request.sent_at()).abs() > MAX_SKEW_SECS {
        return Err(AppError::Unauthenticated);
    }
    let ttl = Lifetime::seconds(MAX_SKEW_SECS * 2).map_err(|_| AppError::Unauthenticated)?;
    if !nonces.spend(request.nonce(), ttl).await {
        return Err(AppError::Unauthenticated);
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::{AgentId, DeclaredAction, DelegationId, HttpMethod, Nonce, TenantId};

    use super::*;
    use crate::ports::agents::{APPROVAL_WIRE_VERSION, ApprovalWireAction, ApprovalWireQuestion};
    use crate::test_support::authentication::{FakeNonceLedger, TagSeal};
    use crate::test_support::block_on;

    fn question(ts: i64) -> ApprovalWireRequest {
        ApprovalWireRequest {
            v: APPROVAL_WIRE_VERSION,
            tenant_id: TenantId::new(),
            ts,
            nonce: Nonce::new("n1-nonce-of-length").unwrap(),
            question: ApprovalWireQuestion::Spend(ApprovalWireAction {
                agent_id: AgentId::new(),
                delegation_id: DelegationId::new(),
                method: HttpMethod::Post,
                target: "/payments".to_owned(),
                declared: DeclaredAction::Undeclared,
            }),
        }
    }

    fn now() -> i64 {
        clock::now().unix_timestamp()
    }

    fn open_with(
        ledger: &FakeNonceLedger,
        body: &[u8],
        seal: Option<&str>,
    ) -> Result<ApprovalWireRequest, AppError> {
        block_on(opened(
            &TagSeal,
            ledger,
            Relayed { body, seal },
            APPROVAL_WIRE_VERSION,
        ))
    }

    /// The gateway asks about an approval, sealed, just now, for the first
    /// time. The question opens.
    #[test]
    fn a_sealed_current_new_question_opens() {
        let body = serde_json::to_vec(&question(now())).unwrap();

        let opened = open_with(
            &FakeNonceLedger::default(),
            &body,
            Some(&TagSeal.seal(&body)),
        );

        assert!(opened.is_ok());
    }

    /// Missing and incorrect seals both make an approval question
    /// unauthenticated without spending any nonce.
    #[test]
    fn an_unsealed_question_is_refused_and_spends_no_nonce() {
        let ledger = FakeNonceLedger::default();
        let body = serde_json::to_vec(&question(now())).unwrap();

        for seal in [None, Some("tag:0")] {
            assert!(matches!(
                open_with(&ledger, &body, seal),
                Err(AppError::Unauthenticated)
            ));
        }
        assert_eq!(ledger.spent(), 0);
    }

    /// A correctly sealed question just beyond the allowed clock skew
    /// is rejected as unauthenticated.
    #[test]
    fn a_stale_question_is_refused() {
        let body = serde_json::to_vec(&question(now() - MAX_SKEW_SECS - 1)).unwrap();

        let opened = open_with(
            &FakeNonceLedger::default(),
            &body,
            Some(&TagSeal.seal(&body)),
        );

        assert!(matches!(opened, Err(AppError::Unauthenticated)));
    }

    /// A fresh sealed question opens once. Repeating it against the same
    /// nonce ledger returns unauthenticated.
    #[test]
    fn a_question_sent_twice_is_refused_the_second_time() {
        let ledger = FakeNonceLedger::default();
        let body = serde_json::to_vec(&question(now())).unwrap();
        let seal = TagSeal.seal(&body);

        assert!(open_with(&ledger, &body, Some(&seal)).is_ok());
        assert!(matches!(
            open_with(&ledger, &body, Some(&seal)),
            Err(AppError::Unauthenticated)
        ));
    }

    /// A sealed question using the next protocol version is
    /// unauthenticated rather than interpreted as the current version.
    #[test]
    fn another_protocol_version_is_refused() {
        let mut asked = question(now());
        asked.v = APPROVAL_WIRE_VERSION + 1;
        let body = serde_json::to_vec(&asked).unwrap();

        let opened = open_with(
            &FakeNonceLedger::default(),
            &body,
            Some(&TagSeal.seal(&body)),
        );

        assert!(matches!(opened, Err(AppError::Unauthenticated)));
    }
}
