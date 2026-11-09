//! A person's bearer token: an access token the tenant issued under an
//! OAuth grant, or the short-lived one an app's page fetched under the
//! person's app session, which names that session in `sid`, the service
//! whose sign-in opened it in `ias`, and the trusted device it was signed
//! in from in `did`.

use std::time::Duration;

use ianua_app::ports::authentication::{
    AppSessionClaim, ExpectedToken, IssuedUnder, PersonToken, TokenFault,
};
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
use ianua_domain::domains::authorization::policy::claims::{Claim, ClaimName, ClaimValue};
use ianua_domain::types::{Fact, ServiceId, SessionId, UserId};
use serde::Deserialize;
use serde_json::{Map, Value};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::crypto::tokens::app_sessions::device_named;
use crate::crypto::tokens::claims::{Audiences, Times};
use crate::crypto::tokens::presented::{Read, ScopeClaims, expiry_of, times_hold};

/// The claims a person's token carries that are no assertion about the
/// person: what the token is, whom and what for, when, and how it is held.
const REGISTERED: &[&str] = &[
    "iss",
    "sub",
    "aud",
    "exp",
    "nbf",
    "iat",
    "jti",
    "client_id",
    "azp",
    "scope",
    "scp",
    "aal",
    "acr",
    "amr",
    "auth_time",
    "cnf",
    "act",
    "sid",
    "ias",
    "tid",
    "idl",
    "did",
];

/// What a person's token says.
#[derive(Debug, Deserialize)]
struct PersonClaims {
    iss: String,
    aud: Audiences,
    sub: String,
    #[serde(default)]
    tid: Option<Uuid>,
    #[serde(default)]
    sid: Option<Uuid>,
    #[serde(default)]
    ias: Option<Uuid>,
    #[serde(default)]
    idl: Option<u64>,
    #[serde(default)]
    did: Option<Uuid>,
    #[serde(default)]
    aal: Option<Value>,
    #[serde(default)]
    acr: Option<String>,
    #[serde(flatten)]
    scopes: ScopeClaims,
    #[serde(flatten)]
    times: Times,
}

/// How strongly the person proved who they are: from `aal`, or from the
/// `acr` an OAuth token states, or unknown when neither reads.
fn assurance_of(aal: Option<Value>, acr: Option<&str>) -> Fact<AssuranceLevel> {
    let stated = aal.and_then(|aal| serde_json::from_value(aal).ok());
    Fact::from_option(stated.or_else(|| acr.and_then(AssuranceLevel::from_acr)))
}

/// The claim `value` holds as a rule compares it, if it is one.
fn compared(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Bool(flag) => Some(flag.to_string()),
        Value::Number(number) => Some(number.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

/// The claims `claims` asserts about the person, beyond the registered
/// ones, each a rule can compare.
fn asserted(claims: &Map<String, Value>) -> Vec<Claim> {
    claims
        .iter()
        .filter(|(name, _)| !REGISTERED.contains(&name.as_str()))
        .filter_map(|(name, value)| {
            let name = ClaimName::new(name.as_str()).ok()?;
            let value = ClaimValue::new(compared(value)?).ok()?;
            Some(Claim::new(name, value))
        })
        .collect()
}

/// What the token was issued under: the app session its `sid` and `ias`
/// name, or an OAuth grant when it names neither.
fn issued_under(user_id: UserId, claims: &PersonClaims) -> Read<IssuedUnder> {
    match (claims.sid, claims.ias) {
        (Some(session), Some(owner)) => Ok(IssuedUnder::AppSession(AppSessionClaim {
            session_id: SessionId::from_uuid(session),
            user_id,
            service_id: ServiceId::from_uuid(owner),
            idle_timeout: claims.idl.map(Duration::from_secs),
            signed_in_from: device_named(claims.did),
        })),
        (None, None) => Ok(IssuedUnder::Grant),
        (Some(_), None) | (None, Some(_)) => Err(TokenFault::Invalid),
    }
}

/// What a person's token `claims`, checked out under a key of `tenant_id`,
/// says for `expected`, at `now`.
pub(super) fn person_token(
    tenant_id: &ScopedTenant,
    claims: Map<String, Value>,
    expected: ExpectedToken<'_>,
    now: OffsetDateTime,
) -> Read<PersonToken> {
    let asserted = asserted(&claims);
    let person: PersonClaims =
        serde_json::from_value(Value::Object(claims)).map_err(|_| TokenFault::Invalid)?;
    if person.iss != expected.issuer.as_str() {
        return Err(TokenFault::WrongIssuer);
    }
    if !person.aud.names(expected.audience.as_str()) {
        return Err(TokenFault::WrongAudience);
    }
    if person.tid.is_some_and(|tid| &tid != tenant_id.as_uuid()) {
        return Err(TokenFault::WrongHost);
    }
    times_hold(person.times, now)?;
    let user_id = Uuid::parse_str(&person.sub)
        .map(UserId::from_uuid)
        .map_err(|_| TokenFault::Invalid)?;
    Ok(PersonToken {
        user_id,
        issued_under: issued_under(user_id, &person)?,
        expires_at: expiry_of(person.times.exp)?,
        assurance: assurance_of(person.aal, person.acr.as_deref()),
        scopes: person.scopes.scopes()?,
        claims: asserted,
    })
}
