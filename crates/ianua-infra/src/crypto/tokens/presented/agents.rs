//! An agent's task token, read whole in the shape it is minted with,
//! [`TaskTokenClaims`], so the issuer and the gateway cannot drift apart.
//!
//! The tenant's key signs it, its `tid` names the tenant and its `iss` the
//! tenant's own issuer, which must be the one the gateway expects. It must
//! name the tenant's agent audience besides the route's. Every confinement it states is read
//! into [`AgentLimits`], and one that cannot be read refuses the token,
//! since dropping it would lift it.

use ianua_app::ports::agents::task_token_audience;
use ianua_app::ports::authentication::{AgentToken, ExpectedToken, TokenFault};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::agents::authority::capability::{
    ActionApproval, RequestBudget, ResourceScope,
};
use ianua_domain::domains::agents::authority::intent::IntentEnvelope;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::oauth::grants::token_binding::JwkThumbprint;
use ianua_domain::domains::proxy::request::context::{AgentLimits, KeyBinding, Metering};
use ianua_domain::shared::model::restriction::Restriction;
use ianua_domain::types::{
    ActionClass, AgentId, DelegationId, PermissionName, PrincipalRef, Seconds,
};
use serde::Deserialize;
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::crypto::jws::{components, read_jwk, thumbprint};
use crate::crypto::tokens::claims::{Audiences, Times};
use crate::crypto::tokens::presented::{Read, expiry_of, times_hold};
use crate::crypto::tokens::tasks::TaskTokenClaims;

/// The claim only a task token carries, which tells it from a person's.
pub(super) const ACTING_FOR: &str = "obo";

/// Every data class, for reading the one `dcl` names.
const DATA_CLASSES: [DataClassLevel; 4] = [
    DataClassLevel::Public,
    DataClassLevel::Internal,
    DataClassLevel::Confidential,
    DataClassLevel::Restricted,
];

/// The key a task token is bound to, as `cnf` carries it.
#[derive(Debug, Deserialize)]
struct Confirmation {
    jwk: Value,
}

/// What the token must be presented with, and the thumbprint of the key
/// it names, if it names one.
fn key_binding(cnf: Option<Value>) -> Read<(KeyBinding, Option<JwkThumbprint>)> {
    let Some(cnf) = cnf else {
        return Ok((KeyBinding::Bearer, None));
    };
    let confirmation: Confirmation =
        serde_json::from_value(cnf).map_err(|_| TokenFault::Invalid)?;
    let jwk = read_jwk(&confirmation.jwk).map_err(|_| TokenFault::Invalid)?;
    let bound = JwkThumbprint::new(thumbprint(&jwk.key)).map_err(|_| TokenFault::Invalid)?;
    Ok((KeyBinding::Key(components(&jwk.key, "")), Some(bound)))
}

/// The budget `bmax` per `bwin` seconds puts the token under.
fn metering(most: Option<u32>, window: Option<u32>) -> Read<Metering> {
    match (most, window) {
        (None, _) => Ok(Metering::Unmetered),
        (Some(most), Some(window)) => RequestBudget::new(most, Seconds::new(window))
            .map(Metering::Metered)
            .map_err(|_| TokenFault::Invalid),
        (Some(_), None) => Err(TokenFault::Invalid),
    }
}

/// The most sensitive data class `dcl` lets the agent reach.
fn data_class(dcl: Option<&str>) -> Read<Restriction<DataClassLevel>> {
    let Some(named) = dcl else {
        return Ok(Restriction::Unrestricted);
    };
    DATA_CLASSES
        .into_iter()
        .find(|class| class.as_str() == named)
        .map(Restriction::To)
        .ok_or(TokenFault::Invalid)
}

/// The paths `rsc` holds the agent to.
fn resource_scope(rsc: Option<Vec<String>>) -> Read<Restriction<ResourceScope>> {
    let Some(prefixes) = rsc else {
        return Ok(Restriction::Unrestricted);
    };
    ResourceScope::new(prefixes)
        .map(Restriction::To)
        .map_err(|_| TokenFault::Invalid)
}

/// The action classes `ienv` holds the agent to.
fn intent_envelope(ienv: Option<Vec<ActionClass>>) -> Restriction<IntentEnvelope> {
    let Some(classes) = ienv else {
        return Restriction::Unrestricted;
    };
    Restriction::To(IntentEnvelope::new(classes))
}

/// Whether the token's `apr` has a person approve every action.
fn approval_of(claims: &TaskTokenClaims) -> ActionApproval {
    if claims.apr {
        return ActionApproval::PerAction;
    }
    ActionApproval::NotRequired
}

/// Everything `claims` confines the agent to, and the thumbprint of the
/// key it is bound to.
fn limits_of(claims: &mut TaskTokenClaims) -> Read<(AgentLimits, Option<JwkThumbprint>)> {
    let (key_binding, bound_key) = key_binding(claims.cnf.take())?;
    let limits = AgentLimits {
        intent_envelope: intent_envelope(claims.ienv.take()),
        mcp: claims.mcp.take().unwrap_or_default(),
        resource_scope: resource_scope(claims.rsc.take())?,
        max_data_class: data_class(claims.dcl.as_deref())?,
        key_binding,
        approval: approval_of(claims),
        metering: metering(claims.bmax, claims.bwin)?,
    };
    Ok((limits, bound_key))
}

/// The HTTP permissions the delegation grants.
fn permissions_of(names: Vec<String>) -> Read<Vec<PermissionName>> {
    names
        .into_iter()
        .map(|name| PermissionName::new(name).map_err(|_| TokenFault::Invalid))
        .collect()
}

/// What a task token's `claims`, checked out under a key of `tenant_id`,
/// says for `expected`, at `now`.
pub(super) fn agent_token(
    tenant_id: &ScopedTenant,
    claims: Map<String, Value>,
    expected: ExpectedToken<'_>,
    now: OffsetDateTime,
) -> Read<AgentToken> {
    let mut claims: TaskTokenClaims =
        serde_json::from_value(Value::Object(claims)).map_err(|_| TokenFault::Invalid)?;
    if &claims.tid != tenant_id.as_uuid() {
        return Err(TokenFault::WrongHost);
    }
    if claims.iss != expected.issuer.as_str() {
        return Err(TokenFault::WrongIssuer);
    }
    let audiences = Audiences::Many(std::mem::take(&mut claims.aud));
    let named = audiences.names(&task_token_audience(tenant_id))
        && audiences.names(expected.audience.as_str());
    if !named {
        return Err(TokenFault::WrongAudience);
    }
    let times = Times {
        exp: Some(claims.times.exp),
        nbf: None,
        iat: Some(claims.times.iat),
    };
    times_hold(times, now)?;
    let (limits, bound_key) = limits_of(&mut claims)?;
    Ok(AgentToken {
        agent_id: AgentId::from_uuid(claims.act),
        delegation_id: DelegationId::from_uuid(claims.jti),
        acting_for: PrincipalRef::from_label(&claims.obo).map_err(|_| TokenFault::Invalid)?,
        permissions: permissions_of(std::mem::take(&mut claims.permissions))?,
        limits,
        bound_key,
        expires_at: expiry_of(times.exp)?,
    })
}
