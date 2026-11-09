//! App session tokens: minted when a person signs in on an app's own host,
//! kept in that host's cookie, and read back when the gateway or the app
//! asks who holds it.
//!
//! Each is signed with the tenant's active key and typed
//! `ianua-app-session+jwt`, so no check of access tokens takes one for a
//! bearer token, and names the one host whose cookie it was set in. The
//! same keys mint the short-lived bearer tokens an app's pages fetch for a
//! service that accepts its sign-in by token: ordinary access tokens for
//! that service's audience. Both name the trusted device the session was
//! signed in from as `did`, when it was, so the gateway's device posture
//! check knows the device without a lookup.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::authentication::{
    AppAccessGrant, AppSessionClaim, AppSessionGrant, AppSessionTokens, IssuedAppSession,
};
use ianua_app::ports::crypto::SigningKeyStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
use ianua_domain::domains::crypto::jwt_type::JwtType;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    DomainName, Fact, Lifetime, ServiceId, SessionId, TrustedDeviceId, UserId,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::jws::{Compact, TokenHeader, signed};
use crate::crypto::tokens::claims::{TenantKeys, Times, refused};

/// What an app session token says: the one shape it is minted with, and
/// read back with here and at the gateway.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct SessionClaims {
    pub(super) iss: String,
    pub(super) aud: String,
    pub(super) host: String,
    pub(super) sub: Uuid,
    pub(super) sid: Uuid,
    pub(super) svc: Uuid,
    pub(super) tid: Uuid,
    pub(super) aal: AssuranceLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) idl: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) did: Option<Uuid>,
    #[serde(flatten)]
    pub(super) times: Times,
}

/// What a bearer token for a service that accepts an app's sign-in says.
#[derive(Debug, Serialize)]
struct AccessClaims {
    iss: String,
    aud: String,
    sub: Uuid,
    sid: Uuid,
    ias: Uuid,
    tid: Uuid,
    aal: AssuranceLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    idl: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    did: Option<Uuid>,
    #[serde(flatten)]
    times: Times,
}

/// The times of a token valid from now until `expires_at`.
fn from_now_until(expires_at: time::OffsetDateTime) -> Times {
    let now = clock::now().unix_timestamp();
    Times {
        exp: Some(expires_at.unix_timestamp()),
        nbf: Some(now),
        iat: Some(now),
    }
}

/// The minter and reader of app session tokens, with the tenant's keys.
pub struct Pkcs8AppSessionTokens {
    keys: TenantKeys,
}

impl Pkcs8AppSessionTokens {
    /// Tokens signed with the tenant keys `signing_keys` holds, a rotated
    /// key still checking for `grace`.
    #[must_use]
    pub fn new(signing_keys: Arc<dyn SigningKeyStore>, grace: Lifetime) -> Self {
        Self {
            keys: TenantKeys::new(signing_keys, grace),
        }
    }

    async fn sign<C: Serialize + Sync>(
        &self,
        tenant_id: &ScopedTenant,
        claims: &C,
        typ: JwtType,
    ) -> Result<Secret, DomainError> {
        let claims = serde_json::to_string(claims).map_err(DomainError::infra)?;
        let active = self.keys.active(tenant_id).await?;
        signed(
            &claims,
            TokenHeader::new(typ, active.key.kid().as_str(), active.key.algorithm()),
            &active.private,
        )
        .map(Secret::new)
        .map_err(DomainError::infra)
    }
}

#[async_trait]
impl AppSessionTokens for Pkcs8AppSessionTokens {
    async fn issue(
        &self,
        tenant_id: &ScopedTenant,
        grant: &AppSessionGrant,
    ) -> Result<IssuedAppSession, DomainError> {
        let claims = SessionClaims {
            iss: grant.issuer.as_str().to_owned(),
            aud: grant.audience.as_str().to_owned(),
            host: grant.host.as_str().to_owned(),
            sub: *grant.user_id.as_uuid(),
            sid: *grant.session_id.as_uuid(),
            svc: *grant.service_id.as_uuid(),
            tid: *tenant_id.as_uuid(),
            aal: grant.assurance,
            idl: grant.idle_timeout.map(|idle| idle.as_secs()),
            did: device_claim(grant.signed_in_from),
            times: from_now_until(grant.expires_at),
        };
        Ok(IssuedAppSession {
            token: self.sign(tenant_id, &claims, JwtType::AppSession).await?,
            expires_at: grant.expires_at,
        })
    }

    async fn issue_access(
        &self,
        tenant_id: &ScopedTenant,
        grant: &AppAccessGrant,
    ) -> Result<IssuedAppSession, DomainError> {
        let claims = AccessClaims {
            iss: grant.issuer.as_str().to_owned(),
            aud: grant.audience.as_str().to_owned(),
            sub: *grant.user_id.as_uuid(),
            sid: *grant.session_id.as_uuid(),
            ias: *grant.owner.as_uuid(),
            tid: *tenant_id.as_uuid(),
            aal: grant.assurance,
            idl: grant.idle_timeout.map(|idle| idle.as_secs()),
            did: device_claim(grant.signed_in_from),
            times: from_now_until(grant.expires_at),
        };
        Ok(IssuedAppSession {
            token: self.sign(tenant_id, &claims, JwtType::Access).await?,
            expires_at: grant.expires_at,
        })
    }

    async fn read(
        &self,
        tenant_id: &ScopedTenant,
        token: &Secret,
        host: &DomainName,
    ) -> Result<AppSessionClaim, DomainError> {
        let token = Compact::parse(token.expose()).map_err(|_| refused("the session is no JWT"))?;
        let key = self.keys.checking(tenant_id, &token).await?;
        let claims: SessionClaims = token
            .verified(&key, JwtType::AppSession)
            .map_err(|_| refused("the session was not signed by the tenant"))?;
        if &claims.tid != tenant_id.as_uuid() {
            return Err(refused("the session was minted for another tenant"));
        }
        if !claims.host.eq_ignore_ascii_case(host.as_str()) {
            return Err(refused("the session was minted for another host"));
        }
        claims.times.hold_at(clock::now())?;
        Ok(AppSessionClaim {
            session_id: SessionId::from_uuid(claims.sid),
            user_id: UserId::from_uuid(claims.sub),
            service_id: ServiceId::from_uuid(claims.svc),
            idle_timeout: claims.idl.map(Duration::from_secs),
            signed_in_from: device_named(claims.did),
        })
    }
}

/// The `did` a token names the trusted device its session was signed in
/// from with, when it was.
fn device_claim(device: Fact<TrustedDeviceId>) -> Option<Uuid> {
    device.known().map(|device| *device.as_uuid())
}

/// The trusted device a token's `did` names, when it names one.
pub(super) fn device_named(did: Option<Uuid>) -> Fact<TrustedDeviceId> {
    Fact::from_option(did.map(TrustedDeviceId::from_uuid))
}

#[cfg(test)]
mod tests {
    use ianua_app::test_support::crypto::FakeSigningKeyStore;
    use ianua_domain::types::{Audience, Issuer, TenantId};

    use super::*;
    use crate::crypto::tokens::claims::tests::{grace, key_set};

    struct Fixture {
        tenant: ScopedTenant,
        tokens: Pkcs8AppSessionTokens,
    }

    fn fixture() -> Fixture {
        let tenant = ScopedTenant::for_background(TenantId::new());
        let keys = Arc::new(FakeSigningKeyStore::empty());
        keys.put(*tenant, key_set().0);
        Fixture {
            tokens: Pkcs8AppSessionTokens::new(keys, grace()),
            tenant,
        }
    }

    fn host(name: &str) -> DomainName {
        DomainName::new(name).unwrap()
    }

    fn grant(minutes: i64) -> AppSessionGrant {
        AppSessionGrant {
            issuer: Issuer::new("https://acme.ianua.example").unwrap(),
            audience: Audience::new("ledger").unwrap(),
            host: host("ledger.acme.example"),
            user_id: UserId::new(),
            session_id: SessionId::new(),
            service_id: ServiceId::new(),
            assurance: AssuranceLevel::Aal2,
            expires_at: clock::now() + time::Duration::minutes(minutes),
            idle_timeout: Some(Duration::from_secs(900)),
            signed_in_from: Fact::Known(TrustedDeviceId::new()),
        }
    }

    /// A session minted on a host reads back there, with its person,
    /// session, service, idle timeout and the device it was signed in from.
    #[tokio::test]
    async fn a_session_reads_back_on_its_host() {
        let fx = fixture();
        let grant = grant(30);

        let issued = fx.tokens.issue(&fx.tenant, &grant).await.unwrap();
        let claim = fx
            .tokens
            .read(&fx.tenant, &issued.token, &host("Ledger.Acme.Example"))
            .await
            .unwrap();

        assert_eq!(claim.session_id, grant.session_id);
        assert_eq!(claim.user_id, grant.user_id);
        assert_eq!(claim.service_id, grant.service_id);
        assert_eq!(claim.idle_timeout, Some(Duration::from_secs(900)));
        assert_eq!(claim.signed_in_from, grant.signed_in_from);
    }

    /// A session signed in from no remembered device names none, and
    /// writes no `did` a reader could mistake for one.
    #[tokio::test]
    async fn a_session_from_no_remembered_device_names_none() {
        let fx = fixture();
        let grant = AppSessionGrant {
            signed_in_from: Fact::Unknown,
            ..grant(30)
        };

        let issued = fx.tokens.issue(&fx.tenant, &grant).await.unwrap();
        let claim = fx
            .tokens
            .read(&fx.tenant, &issued.token, &grant.host)
            .await
            .unwrap();

        assert_eq!(claim.signed_in_from, Fact::Unknown);
    }

    /// A session cookie is unauthorized on another host and after its expiry.
    #[tokio::test]
    async fn a_session_on_another_host_or_past_its_time_is_refused() {
        let fx = fixture();
        let live = fx.tokens.issue(&fx.tenant, &grant(30)).await.unwrap();
        let lapsed = fx.tokens.issue(&fx.tenant, &grant(-30)).await.unwrap();

        let elsewhere = fx
            .tokens
            .read(&fx.tenant, &live.token, &host("evil.acme.example"))
            .await;
        let late = fx
            .tokens
            .read(&fx.tenant, &lapsed.token, &host("ledger.acme.example"))
            .await;

        assert!(matches!(elsewhere, Err(DomainError::Unauthorized(_))));
        assert!(matches!(late, Err(DomainError::Unauthorized(_))));
    }

    /// An access bearer cannot authenticate as an application session cookie.
    #[tokio::test]
    async fn a_bearer_token_is_no_app_session() {
        let fx = fixture();
        let session = grant(30);
        let access = AppAccessGrant {
            issuer: session.issuer.clone(),
            audience: session.audience.clone(),
            user_id: session.user_id,
            session_id: session.session_id,
            owner: session.service_id,
            assurance: session.assurance,
            expires_at: session.expires_at,
            idle_timeout: None,
            signed_in_from: session.signed_in_from,
        };

        let bearer = fx.tokens.issue_access(&fx.tenant, &access).await.unwrap();
        let read = fx
            .tokens
            .read(&fx.tenant, &bearer.token, &session.host)
            .await;

        assert!(matches!(read, Err(DomainError::Unauthorized(_))));
    }
}
