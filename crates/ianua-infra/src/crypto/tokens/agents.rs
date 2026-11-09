//! An agent's self-signed assertion: a short JWT an autonomous agent signs
//! with its enrolled key to exchange for a task token.
//!
//! It is checked against the credential the platform holds for the agent,
//! with the algorithm stored beside that key. It names the agent as both
//! `iss` and `sub`, the platform as `aud`, and lives at most five minutes:
//! it is made to be exchanged at once, and one good for longer is the key
//! copied in another form.

use async_trait::async_trait;
use ianua_app::ports::agents::{
    AgentAssertionVerifier, AssertionCheck, AssertionVerification, VerifiedAssertion,
};
use ianua_domain::domains::agents::identity::token_attack::AssertionFault;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AgentId, KeyId, TokenId};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::crypto::jws::{Compact, JwsError, PublicKey};
use crate::crypto::tokens::claims::{Audiences, TimeFault, Times};

/// The longest an assertion may be valid for, from `iat` to `exp`.
const MAX_LIFETIME_SECONDS: i64 = 300;

/// The claims an assertion proves its agent with.
#[derive(Debug, Deserialize)]
struct AssertionClaims {
    iss: Uuid,
    sub: Uuid,
    aud: Audiences,
    jti: String,
    #[serde(flatten)]
    times: Times,
}

/// When `seconds` since the epoch is, for a claim that must be a time.
fn instant(seconds: Option<i64>) -> Result<OffsetDateTime, AssertionFault> {
    seconds
        .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok())
        .ok_or(AssertionFault::Malformed)
}

/// The check of an agent's assertion against its enrolled key.
#[derive(Debug, Clone, Copy, Default)]
pub struct Pkcs8AgentAssertionVerifier;

#[async_trait]
impl AgentAssertionVerifier for Pkcs8AgentAssertionVerifier {
    fn key_id(&self, assertion: &str) -> Result<KeyId, DomainError> {
        let token = Compact::parse(assertion).map_err(|_| {
            DomainError::invalid(message!(
                "infra-the-assertion-is-no-jwt",
                "the assertion is no JWT"
            ))
        })?;
        let kid = token.header().kid.as_deref().ok_or_else(|| {
            DomainError::invalid(message!(
                "infra-the-assertion-names-no-key",
                "the assertion names no key"
            ))
        })?;
        KeyId::new(kid).map_err(Into::into)
    }

    async fn verify(
        &self,
        assertion: &str,
        against: &AssertionVerification<'_>,
    ) -> Result<AssertionCheck, DomainError> {
        let key = PublicKey::from_pem(against.algorithm, against.public_key.as_str())
            .map_err(DomainError::infra)?;
        Ok(match checked(assertion, against, &key) {
            Ok(verified) => AssertionCheck::Verified(verified),
            Err(fault) => AssertionCheck::Refused(fault),
        })
    }
}

/// The assertion, once it checks against `key` as `against` asks, or why
/// it does not.
fn checked(
    assertion: &str,
    against: &AssertionVerification<'_>,
    key: &PublicKey,
) -> Result<VerifiedAssertion, AssertionFault> {
    let token = Compact::parse(assertion).map_err(|_| AssertionFault::Malformed)?;
    let claims: AssertionClaims = token
        .verified_untyped(key)
        .map_err(|error| signature_fault(&error))?;
    let agent = against.expected_issuer.as_uuid();
    if &claims.iss != agent || &claims.sub != agent {
        return Err(AssertionFault::WrongAgent);
    }
    if !claims.aud.names(against.expected_audience.as_str()) {
        return Err(AssertionFault::WrongAudience);
    }
    if let Some(fault) = claims.times.fault_at(clock::now()) {
        return Err(time_fault(fault));
    }
    let issued_at = instant(claims.times.iat)?;
    let expires_at = instant(claims.times.exp)?;
    ensure_short_lived(issued_at, expires_at)?;
    Ok(VerifiedAssertion {
        agent_id: AgentId::from_uuid(claims.sub),
        jti: TokenId::new(claims.jti).map_err(|_| AssertionFault::Malformed)?,
        issued_at,
        expires_at: claims
            .times
            .accepted_until()
            .map_err(|_| AssertionFault::Malformed)?,
    })
}

/// Refuses assertions that remain usable beyond the exchange window.
fn ensure_short_lived(
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> Result<(), AssertionFault> {
    let lifetime = expires_at
        .unix_timestamp()
        .saturating_sub(issued_at.unix_timestamp());
    if lifetime > MAX_LIFETIME_SECONDS {
        return Err(AssertionFault::TooLongLived);
    }
    Ok(())
}

/// The fault of an assertion whose signature check failed as `error`
/// says. A header naming another algorithm than the key's is a signature
/// that is not the key's; claims that do not read under a good signature
/// are the agent's own slip.
fn signature_fault(error: &JwsError) -> AssertionFault {
    match error {
        JwsError::BadClaims => AssertionFault::Malformed,
        JwsError::WrongAlgorithm
        | JwsError::BadSignature
        | JwsError::Malformed
        | JwsError::WrongType
        | JwsError::Key(_) => AssertionFault::BadSignature,
    }
}

/// The fault of an assertion whose times do not hold, as `fault` says.
fn time_fault(fault: TimeFault) -> AssertionFault {
    match fault {
        TimeFault::NoExpiry => AssertionFault::Malformed,
        TimeFault::Expired => AssertionFault::Expired,
        TimeFault::NotYetValid | TimeFault::IssuedAhead => AssertionFault::NotYetValid,
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
    use ianua_domain::types::{Audience, PublicKeyPem};
    use serde_json::{Value, json};

    use super::*;
    use crate::crypto::jws::PrivateKey;
    use crate::crypto::jws::keys_for_tests::pair;

    struct Agent {
        id: AgentId,
        signer: PrivateKey,
        public: PublicKeyPem,
    }

    fn agent() -> Agent {
        let (private, public) = pair(SigningAlgorithm::Es256);
        Agent {
            id: AgentId::new(),
            signer: PrivateKey::from_pem(SigningAlgorithm::Es256, &private).unwrap(),
            public: PublicKeyPem::new(public).unwrap(),
        }
    }

    fn signed(agent: &Agent, claims: &Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","kid":"cred-1"}"#);
        let input = format!("{header}.{}", URL_SAFE_NO_PAD.encode(claims.to_string()));
        let signature = agent.signer.sign(input.as_bytes()).unwrap();
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    fn claims(agent: &Agent, lifetime: i64) -> Value {
        let now = clock::now().unix_timestamp();
        json!({"iss": agent.id, "sub": agent.id, "aud": "ianua", "jti": "j-1", "iat": now, "exp": now + lifetime})
    }

    async fn check(agent: &Agent, assertion: &str) -> AssertionCheck {
        let audience = Audience::new("ianua").unwrap();
        Pkcs8AgentAssertionVerifier
            .verify(
                assertion,
                &AssertionVerification {
                    public_key: &agent.public,
                    algorithm: SigningAlgorithm::Es256,
                    expected_issuer: &agent.id,
                    expected_audience: &audience,
                },
            )
            .await
            .unwrap()
    }

    async fn verify(agent: &Agent, assertion: &str) -> Result<VerifiedAssertion, AssertionFault> {
        match check(agent, assertion).await {
            AssertionCheck::Verified(verified) => Ok(verified),
            AssertionCheck::Refused(fault) => Err(fault),
        }
    }

    /// An assertion the agent signed names its key, and proves the agent.
    #[tokio::test]
    async fn an_assertion_proves_its_agent() {
        let agent = agent();
        let assertion = signed(&agent, &claims(&agent, 60));

        let kid = Pkcs8AgentAssertionVerifier.key_id(&assertion).unwrap();
        let proved = verify(&agent, &assertion).await.unwrap();

        assert_eq!(kid.as_str(), "cred-1");
        assert_eq!(proved.agent_id, agent.id);
    }

    /// An agent assertion's verified expiry includes the allowed clock skew
    /// so callers can track its entire acceptance window.
    #[tokio::test]
    async fn an_assertion_lasts_until_its_expiry_and_the_skew() {
        let agent = agent();
        let claims = claims(&agent, 60);
        let exp = claims["exp"].as_i64().unwrap();

        let proved = verify(&agent, &signed(&agent, &claims)).await.unwrap();

        assert_eq!(
            proved.expires_at.unix_timestamp(),
            exp + crate::crypto::tokens::claims::ALLOWED_SKEW
        );
    }

    /// Excessive lifetime, another agent and a foreign signature produce distinct
    /// refusal reasons for agent assertions.
    #[tokio::test]
    async fn a_long_lived_foreign_or_forged_assertion_is_refused_for_what_it_is() {
        let agent = agent();
        let other = self::agent();
        let long = signed(&agent, &claims(&agent, 3600));
        let foreign = signed(&agent, &claims(&other, 60));
        let forged = signed(&other, &claims(&agent, 60));

        let refusals = [
            (long, AssertionFault::TooLongLived),
            (foreign, AssertionFault::WrongAgent),
            (forged, AssertionFault::BadSignature),
        ];

        for (assertion, fault) in refusals {
            assert_eq!(verify(&agent, &assertion).await.err(), Some(fault));
        }
    }

    /// An assertion that ran out on the way, one for another endpoint, or
    /// one that is no JWT is refused as the agent's own slip, never as a
    /// forgery.
    #[tokio::test]
    async fn an_agents_own_slips_are_told_apart() {
        let agent = agent();
        let now = clock::now().unix_timestamp();
        let expired = signed(
            &agent,
            &json!({"iss": agent.id, "sub": agent.id, "aud": "ianua", "jti": "j-1", "iat": now - 600, "exp": now - 400}),
        );
        let elsewhere = signed(
            &agent,
            &json!({"iss": agent.id, "sub": agent.id, "aud": "elsewhere", "jti": "j-1", "iat": now, "exp": now + 60}),
        );

        let refusals = [
            (expired, AssertionFault::Expired),
            (elsewhere, AssertionFault::WrongAudience),
            ("not-a-jwt".to_owned(), AssertionFault::Malformed),
        ];

        for (assertion, fault) in refusals {
            assert_eq!(verify(&agent, &assertion).await.err(), Some(fault));
        }
    }
}
