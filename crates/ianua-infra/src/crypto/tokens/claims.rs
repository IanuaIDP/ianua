//! The claims every token shares: when it may be used, whom it is for,
//! and the tenant keys it is signed and checked with.
//!
//! Times are whole seconds since the epoch, as JWT writes them. A token is
//! refused once its `exp` has passed, before its `nbf`, or when its `iat`
//! lies ahead, each by more than [`ALLOWED_SKEW`] of clock drift.

use std::sync::Arc;

use ianua_app::ports::crypto::SigningKeyStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::crypto::signing_key::{SigningKey, SigningKeySet};
use ianua_domain::domains::crypto::verifying_key::VerifyingKey;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::Lifetime;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::crypto::jws::{Compact, PrivateKey, PublicKey};

/// The clock drift a token's times are allowed, in seconds.
pub(crate) const ALLOWED_SKEW: i64 = 60;

/// A refusal of a presented token, with a reason that names no part of it.
pub(crate) fn refused(reason: &'static str) -> DomainError {
    DomainError::unauthorized(reason)
}

/// `aud` as JWT allows it: one value, or a list of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum Audiences {
    One(String),
    Many(Vec<String>),
}

impl Audiences {
    /// Whether `audience` is among them.
    pub(crate) fn names(&self, audience: &str) -> bool {
        match self {
            Self::One(one) => one == audience,
            Self::Many(many) => many.iter().any(|named| named == audience),
        }
    }

    /// Every audience named, in order.
    pub(crate) fn all(&self) -> Vec<String> {
        match self {
            Self::One(one) => vec![one.clone()],
            Self::Many(many) => many.clone(),
        }
    }
}

/// The times a token carries.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub(crate) struct Times {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) exp: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) nbf: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) iat: Option<i64>,
}

/// Why a token's times refuse it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimeFault {
    /// It names no `exp`.
    NoExpiry,
    /// It is past its `exp`.
    Expired,
    /// It is before its `nbf`.
    NotYetValid,
    /// Its `iat` lies ahead.
    IssuedAhead,
}

impl TimeFault {
    /// The reason a refusal gives, naming no part of the token.
    fn reason(self) -> &'static str {
        match self {
            Self::NoExpiry => "the token names no expiry",
            Self::Expired => "the token has expired",
            Self::NotYetValid => "the token is not valid yet",
            Self::IssuedAhead => "the token was issued in the future",
        }
    }
}

impl Times {
    /// Why the token is refused when used at `now`, or `None` when it
    /// carries `exp` and is used within its times and the allowed skew.
    pub(crate) fn fault_at(self, now: OffsetDateTime) -> Option<TimeFault> {
        let now = now.unix_timestamp();
        let Some(exp) = self.exp else {
            return Some(TimeFault::NoExpiry);
        };
        if exp.saturating_add(ALLOWED_SKEW) <= now {
            return Some(TimeFault::Expired);
        }
        let ahead = |at: Option<i64>| at.is_some_and(|at| at > now.saturating_add(ALLOWED_SKEW));
        if ahead(self.nbf) {
            return Some(TimeFault::NotYetValid);
        }
        ahead(self.iat).then_some(TimeFault::IssuedAhead)
    }

    /// Refused unless the token carries `exp` and is used, at `now`, within
    /// its times and the allowed skew.
    pub(crate) fn hold_at(self, now: OffsetDateTime) -> Result<(), DomainError> {
        self.fault_at(now)
            .map_or(Ok(()), |fault| Err(refused(fault.reason())))
    }

    /// The last moment [`hold_at`](Self::hold_at) still takes the token:
    /// its `exp` and the allowed skew. A record that spots a replay must
    /// last until then, not only until `exp`.
    pub(crate) fn accepted_until(self) -> Result<OffsetDateTime, DomainError> {
        let exp = self
            .exp
            .ok_or_else(|| refused("the token names no expiry"))?;
        OffsetDateTime::from_unix_timestamp(exp.saturating_add(ALLOWED_SKEW))
            .map_err(|_| refused("the token's expiry is no time"))
    }
}

/// The key in `keys` a token naming `kid` is checked with: one a verifier
/// may still accept at `now`, within `grace` of being rotated out.
pub(crate) fn checking_key(
    keys: &SigningKeySet<ResolvedTenant>,
    token: &Compact,
    grace: Lifetime,
    now: OffsetDateTime,
) -> Result<PublicKey, DomainError> {
    let kid = token
        .header()
        .kid
        .as_deref()
        .ok_or_else(|| refused("the token names no key"))?;
    let key = keys
        .jwks_keys(grace, now)
        .into_iter()
        .find(|key| key.kid().as_str() == kid)
        .ok_or_else(|| refused("the token names no key of the tenant"))?;
    PublicKey::from_pem(key.algorithm(), key.public_key().as_str()).map_err(DomainError::infra)
}

/// The public key of `keys` that `token` names, when a verifier may still
/// accept tokens it signed at `now`: the same choice as [`checking_key`],
/// from the public halves alone.
///
/// # Errors
///
/// Returns a refusal when the token names no key of the tenant's, and
/// `DomainError::Infrastructure` when the key named does not read.
pub(crate) fn checking_public_key(
    keys: &[VerifyingKey],
    token: &Compact,
    grace: Lifetime,
    now: OffsetDateTime,
) -> Result<PublicKey, DomainError> {
    let kid = token
        .header()
        .kid
        .as_deref()
        .ok_or_else(|| refused("the token names no key"))?;
    let key = keys
        .iter()
        .find(|key| key.kid().as_str() == kid && key.is_in_jwks(grace, now))
        .ok_or_else(|| refused("the token names no key of the tenant"))?;
    PublicKey::from_pem(key.algorithm(), key.public_key().as_str()).map_err(DomainError::infra)
}

/// A tenant's signing keys, read from their store: the one that signs now,
/// and those a token is checked with.
#[derive(Clone)]
pub(crate) struct TenantKeys {
    store: Arc<dyn SigningKeyStore>,
    grace: Lifetime,
}

/// The key that signs a tenant's tokens now, read for its algorithm.
pub(crate) struct ActiveKey {
    pub(crate) key: SigningKey,
    pub(crate) private: PrivateKey,
}

impl TenantKeys {
    /// The keys `store` keeps, a rotated key still checking tokens for
    /// `grace`.
    pub(crate) fn new(store: Arc<dyn SigningKeyStore>, grace: Lifetime) -> Self {
        Self { store, grace }
    }

    async fn set_of(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<SigningKeySet<ResolvedTenant>, DomainError> {
        self.store
            .find(tenant_id)
            .await?
            .ok_or_else(|| DomainError::infra_msg("the tenant has no signing keys"))
    }

    /// The key that signs `tenant_id`'s tokens now.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the tenant has no key
    /// that may sign, or the key does not read.
    pub(crate) async fn active(&self, tenant_id: &ScopedTenant) -> Result<ActiveKey, DomainError> {
        let set = self.set_of(tenant_id).await?;
        let key = set
            .active_key(clock::now())
            .cloned()
            .ok_or_else(|| DomainError::infra_msg("no signing key of the tenant may sign"))?;
        let private = PrivateKey::from_pem(key.algorithm(), key.private_key().expose())
            .map_err(DomainError::infra)?;
        Ok(ActiveKey { key, private })
    }

    /// The key of `tenant_id` a token is checked with.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Unauthorized` when the token names no key the
    /// tenant may still accept, and `DomainError::Infrastructure` when the
    /// keys cannot be read.
    pub(crate) async fn checking(
        &self,
        tenant_id: &ScopedTenant,
        token: &Compact,
    ) -> Result<PublicKey, DomainError> {
        let Some(set) = self.store.find(tenant_id).await? else {
            return Err(refused("the token names no key of the tenant"));
        };
        checking_key(&set, token, self.grace, clock::now())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use ianua_domain::domains::crypto::key_status::KeyState;
    use ianua_domain::domains::crypto::signing_key::{SigningAlgorithm, SigningKeyRow};
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{Expiry, KeyId, PublicKeyPem};

    use super::*;
    use crate::crypto::jws::keys_for_tests::pair;

    /// A tenant's key set of one active ES256 key `k1`, with its private
    /// key.
    pub(crate) fn key_set() -> (SigningKeySet<ResolvedTenant>, Secret) {
        let (private, public) = pair(SigningAlgorithm::Es256);
        let key = SigningKey::reconstitute(SigningKeyRow {
            kid: KeyId::new("k1").unwrap(),
            algorithm: SigningAlgorithm::Es256,
            public_key: PublicKeyPem::new(public).unwrap(),
            private_key: Secret::new(private.clone()),
            state: KeyState::Active,
            created_at: clock::now(),
            expires_at: Expiry::Never,
        })
        .unwrap();
        (
            SigningKeySet::from_keys(vec![key]).unwrap(),
            Secret::new(private),
        )
    }

    /// The grace tests give a rotated key.
    pub(crate) fn grace() -> Lifetime {
        Lifetime::seconds(3600).unwrap()
    }

    fn at(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(seconds).unwrap()
    }

    fn times(exp: Option<i64>, nbf: Option<i64>, iat: Option<i64>) -> Times {
        Times { exp, nbf, iat }
    }

    /// A token within its times holds, and one a little past its expiry
    /// still does, by the allowed skew.
    #[test]
    fn a_token_within_its_times_holds() {
        assert!(
            times(Some(1_000), Some(900), Some(900))
                .hold_at(at(950))
                .is_ok()
        );
        assert!(times(Some(1_000), None, None).hold_at(at(1_030)).is_ok());
    }

    /// Expiry beyond skew, future not-before or issue times, and a missing expiry
    /// each make token claims unauthorized.
    #[test]
    fn a_token_outside_its_times_is_refused() {
        let refused = [
            times(Some(1_000), None, None).hold_at(at(1_061)),
            times(Some(5_000), Some(2_000), None).hold_at(at(1_000)),
            times(Some(5_000), None, Some(2_000)).hold_at(at(1_000)),
            times(None, None, None).hold_at(at(1_000)),
        ];

        for read in refused {
            assert!(matches!(read, Err(DomainError::Unauthorized(_))));
        }
    }

    /// Claims remain valid just before expiry plus clock skew and fail exactly at that boundary.
    #[test]
    fn a_token_is_accepted_until_its_expiry_and_the_skew() {
        let held = times(Some(1_000), None, None);

        let until = held.accepted_until().unwrap();

        assert_eq!(until, at(1_000 + ALLOWED_SKEW));
        assert!(held.hold_at(at(1_000 + ALLOWED_SKEW - 1)).is_ok());
        assert!(held.hold_at(until).is_err());
    }

    /// `aud` reads as one value or as a list, and names what it lists.
    #[test]
    fn an_audience_reads_as_one_or_many() {
        let one: Audiences = serde_json::from_str(r#""api""#).unwrap();
        let many: Audiences = serde_json::from_str(r#"["api","admin"]"#).unwrap();

        assert!(one.names("api"));
        assert!(many.names("admin"));
        assert!(!many.names("billing"));
    }
}
