//! Enrolling a key an agent made for itself.
//!
//! The platform never generates an agent's key pair. The agent keeps the
//! private half and offers only the public one, so the private key never
//! crosses the network and nothing the platform stores or returns could sign
//! as the agent. Every way a credential comes into being goes through here:
//! at creation, by a person, by rotation and by attestation. Who may vouch
//! for the key, and whether the agent takes a key of that kind, is the
//! domain's call.

use ianua_domain::domains::agents::identity::agent::AgentIdentity;
use ianua_domain::domains::agents::identity::credential::{
    AgentCredential, CredentialLifetimes, KeySource, MintAgentCredentialParams,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{KeyId, Setting};
use time::OffsetDateTime;

use crate::error::AppError;
use crate::ports::agents::EnrolledKey;
use crate::ports::crypto::PublicKeyDecoder;

/// What a new credential binds the enrolled key to.
pub(in crate::use_cases::agents) struct Enrolment<'a> {
    /// The agent the key will sign in.
    pub(in crate::use_cases::agents) agent: &'a AgentIdentity<ResolvedTenant>,
    /// Who vouches for the key: a person, or a verified attestation.
    pub(in crate::use_cases::agents) source: KeySource<'a>,
    /// The public half the agent offered.
    pub(in crate::use_cases::agents) key: &'a EnrolledKey,
    /// When the credential expires, or `Unset` for the default lifetime.
    pub(in crate::use_cases::agents) expires_at: Setting<OffsetDateTime>,
    /// How long credentials live.
    pub(in crate::use_cases::agents) lifetimes: CredentialLifetimes,
}

/// A credential for the enrolled key, under a fresh server-chosen key id.
///
/// # Errors
///
/// - `AppError::Domain` with a validation error when the key is not a
///   public key of its algorithm, so a key that could never verify an
///   assertion is refused at enrolment instead of failing every sign-in
///   after it, or the expiry asked for is not in the future.
/// - `AppError::Forbidden` when the person vouching for the key may not
///   enrol one for the agent, the agent proves itself by attesting and so
///   takes no key enrolled by hand, or its policy does not trust the
///   attestation.
pub(in crate::use_cases::agents) fn enrol(
    decoder: &dyn PublicKeyDecoder,
    enrolment: &Enrolment<'_>,
) -> Result<AgentCredential<ResolvedTenant>, AppError> {
    let kid = KeyId::new(uuid::Uuid::now_v7().simple().to_string())
        .map_err(|e| AppError::from_domain(e.into()))?;
    let key = enrolment.key;
    decoder
        .decode(&key.public_key, &kid, key.algorithm)
        .map_err(|_| {
            AppError::from_domain(DomainError::invalid(message!(
                "agents-public-key-is-not-a-public",
                "public_key is not a public key of the named algorithm"
            )))
        })?;
    AgentCredential::mint(
        MintAgentCredentialParams {
            agent: enrolment.agent,
            source: enrolment.source,
            kid,
            algorithm: key.algorithm,
            public_key: key.public_key.clone(),
            expires_at: enrolment.expires_at,
        },
        enrolment.lifetimes,
    )
    .map_err(AppError::from_domain)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::identity::agent::AgentIdentity;
    use ianua_domain::domains::agents::identity::control::AgentControl;
    use ianua_domain::domains::authorization::authority::TenantAuthority;
    use ianua_domain::types::{AgentId, PublicKeyPem};

    use super::*;
    use crate::test_support::agents::{FakeKeyDecoder, agent_row, caller_person, enrolled_key};
    use crate::test_support::test_ctx;

    fn owners_authority() -> TenantAuthority {
        TenantAuthority::assumed(caller_person(), test_ctx().tenant_id(), &[], &[])
    }

    fn callers_agent() -> AgentIdentity<ResolvedTenant> {
        AgentIdentity::reconstitute(agent_row(AgentId::new(), caller_person())).unwrap()
    }

    fn enrol_key(key: &EnrolledKey) -> Result<AgentCredential<ResolvedTenant>, AppError> {
        let authority = owners_authority();
        let agent = callers_agent();
        enrol(
            &FakeKeyDecoder,
            &Enrolment {
                agent: &agent,
                source: KeySource::Enrolled(AgentControl::new(&authority)),
                key,
                expires_at: Setting::Unset,
                lifetimes: CredentialLifetimes::default(),
            },
        )
    }

    /// Ann enrols the public key her agent made. It is kept as offered, and
    /// the credential is active.
    #[test]
    fn a_public_key_is_enrolled_as_offered() {
        let credential = enrol_key(&enrolled_key()).unwrap();

        assert_eq!(credential.public_key().as_str(), FakeKeyDecoder::VALID);
        assert!(credential.is_active());
    }

    /// Ann hands in something shaped like a key that no parser accepts. It
    /// is refused rather than stored as a key nothing could verify against.
    #[test]
    fn something_that_is_not_a_public_key_is_refused() {
        let key = EnrolledKey {
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
            )
            .unwrap(),
            ..enrolled_key()
        };

        let result = enrol_key(&key);

        assert!(matches!(
            result,
            Err(AppError::Domain(DomainError::Validation(_)))
        ));
    }
}
