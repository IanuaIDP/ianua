//! Run passes: the token a Protected apps or Protected data step's call
//! carries to the gateway's workflow listener, made by the worker just
//! before the call.
//!
//! A pass is signed with the tenant's active key and typed as a pass, so no
//! other check takes it and it takes no other token. It names the tenant's
//! issuer (`iss`), the person the run acts for (`sub`), the tenant (`tid`),
//! the one route (`rte`) or stream route (`srt`) it reaches, never both,
//! and the call (`jti`), and lapses a minute after it is made.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::{ClaimedPass, PassReach, RunPassToken, TokenFault};
use ianua_app::ports::crypto::SigningKeyStore;
use ianua_app::ports::workflows::{RunPassGrant, RunPasses};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::crypto::jwt_type::JwtType;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    ActionCallId, Issuer, Lifetime, RouteId, StreamRouteId, TenantId, UserId,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::crypto::jws::{Compact, TokenHeader, signed};
use crate::crypto::tokens::claims::{TenantKeys, Times};
use crate::crypto::tokens::presented::{Read, expiry_of, times_hold};

/// How long a pass is taken after it is made, in seconds: long enough for
/// the one call it is made for to reach the gateway, no longer.
const PASS_LIFETIME_SECONDS: i64 = 60;

/// What a run pass says.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct PassClaims {
    iss: String,
    sub: Uuid,
    tid: Uuid,
    #[serde(flatten)]
    reach: Reach,
    jti: Uuid,
    #[serde(flatten)]
    times: Times,
}

/// What a pass reaches: a route or a stream route, named by one claim.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Reach {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rte: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    srt: Option<Uuid>,
}

impl Reach {
    /// The claims naming `reaches`.
    fn of(reaches: PassReach) -> Self {
        match reaches {
            PassReach::Route(id) => Self {
                rte: Some(*id.as_uuid()),
                srt: None,
            },
            PassReach::StreamRoute(id) => Self {
                rte: None,
                srt: Some(*id.as_uuid()),
            },
        }
    }

    /// What the claims name, or `None` when they name both or neither.
    fn reaches(&self) -> Option<PassReach> {
        match (self.rte, self.srt) {
            (Some(route), None) => Some(PassReach::Route(RouteId::from_uuid(route))),
            (None, Some(stream)) => Some(PassReach::StreamRoute(StreamRouteId::from_uuid(stream))),
            (Some(_), Some(_)) | (None, None) => None,
        }
    }
}

/// The tenant and what a pass names, read before it is checked.
#[derive(Debug, Deserialize)]
struct Named {
    tid: Uuid,
    #[serde(flatten)]
    reach: Reach,
}

/// The maker of run passes, signing with the tenant's active key.
pub struct Pkcs8RunPasses {
    keys: TenantKeys,
}

impl Pkcs8RunPasses {
    /// A maker signing with the tenant keys `signing_keys` holds, a rotated
    /// key still checking for `grace`.
    #[must_use]
    pub fn new(signing_keys: Arc<dyn SigningKeyStore>, grace: Lifetime) -> Self {
        Self {
            keys: TenantKeys::new(signing_keys, grace),
        }
    }
}

impl TenantScoped for Pkcs8RunPasses {}

#[async_trait]
impl RunPasses for Pkcs8RunPasses {
    async fn issue(
        &self,
        tenant_id: &ScopedTenant,
        issuer: &Issuer,
        grant: &RunPassGrant,
    ) -> Result<Secret, DomainError> {
        let now = clock::now().unix_timestamp();
        let claims = PassClaims {
            iss: issuer.as_str().to_owned(),
            sub: *grant.user_id.as_uuid(),
            tid: *tenant_id.as_uuid(),
            reach: Reach::of(grant.reaches),
            jti: *grant.call_id.as_uuid(),
            times: Times {
                exp: Some(now.saturating_add(PASS_LIFETIME_SECONDS)),
                nbf: None,
                iat: Some(now),
            },
        };
        let claims = serde_json::to_string(&claims).map_err(DomainError::infra)?;
        let active = self.keys.active(tenant_id).await?;
        let pass = signed(
            &claims,
            TokenHeader::new(
                JwtType::RunPass,
                active.key.kid().as_str(),
                active.key.algorithm(),
            ),
            &active.private,
        )
        .map_err(DomainError::infra)?;
        Ok(Secret::new(pass))
    }
}

/// The tenant and what `token` claims, without checking it.
pub(super) fn claimed(token: &Secret) -> Option<ClaimedPass> {
    let named: Named = Compact::parse(token.expose())
        .ok()?
        .unchecked_claims()
        .ok()?;
    Some(ClaimedPass {
        tenant_id: TenantId::from_uuid(named.tid),
        reaches: named.reach.reaches()?,
    })
}

/// What a pass's `claims`, checked out under the tenant's key, say for
/// `tenant_id` under `issuer`, at `now`.
pub(super) fn pass_of(
    tenant_id: &ScopedTenant,
    claims: &PassClaims,
    issuer: &Issuer,
    now: OffsetDateTime,
) -> Read<RunPassToken> {
    if &claims.tid != tenant_id.as_uuid() {
        return Err(TokenFault::Invalid);
    }
    if claims.iss != issuer.as_str() {
        return Err(TokenFault::WrongIssuer);
    }
    times_hold(claims.times, now)?;
    let reaches = claims.reach.reaches().ok_or(TokenFault::Invalid)?;
    Ok(RunPassToken {
        call_id: ActionCallId::from_uuid(claims.jti),
        user_id: UserId::from_uuid(claims.sub),
        reaches,
        expires_at: expiry_of(claims.times.exp)?,
    })
}
