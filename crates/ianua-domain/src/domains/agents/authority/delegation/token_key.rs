//! The key a task token minted for a delegation is bound to.

use time::OffsetDateTime;

use crate::domains::agents::identity::credential::AgentCredential;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::types::AgentCredentialId;

/// What a task token minted for a delegation is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKey {
    /// Nothing: whoever holds the token may present it.
    Bearer,
    /// The key of the credential the agent signed in with to mint the
    /// token. That key proved possession when the token was asked for, so
    /// the token is bound to it and to no other key the agent holds.
    SignedInWith(AgentCredentialId),
    /// The agent's one active key. A person granted the delegation, or an
    /// agent passed it on, so no key of the receiving agent proved anything
    /// when the token was made. The token is bound to the only key the agent
    /// may sign new assertions with, and to none when it holds several:
    /// guessing among them could bind the token to a key someone else holds.
    AgentsActiveKey,
}

impl TokenKey {
    /// The credential among `held`, the agent's own, whose key the token is
    /// bound to at `now`. `None` for a bearer token.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Conflict`] when the key that signed the agent in is
    ///   not among `held`, or is revoked or expired.
    /// - [`DomainError::Conflict`] when the agent holds no active key, or
    ///   more than one, for a token bound to its one active key.
    pub fn bound_credential<T: TenantScope>(
        self,
        held: &[AgentCredential<T>],
        now: OffsetDateTime,
    ) -> Result<Option<&AgentCredential<T>>, DomainError> {
        match self {
            Self::Bearer => Ok(None),
            Self::SignedInWith(id) => signed_in_with(&id, held, now).map(Some),
            Self::AgentsActiveKey => only_active(held, now).map(Some),
        }
    }
}

/// The credential `id` names among `held`, while it binds tokens at `now`.
fn signed_in_with<'a, T: TenantScope>(
    id: &AgentCredentialId,
    held: &'a [AgentCredential<T>],
    now: OffsetDateTime,
) -> Result<&'a AgentCredential<T>, DomainError> {
    held.iter()
        .find(|credential| credential.id() == id && credential.binds_tokens_at(now))
        .ok_or_else(|| {
            DomainError::conflict(message!(
                "agents-the-key-that-signed-the-agent",
                "the key that signed the agent in is revoked or expired; no token is bound to it"
            ))
        })
}

/// The one credential among `held` that is active and binds tokens at
/// `now`.
fn only_active<T: TenantScope>(
    held: &[AgentCredential<T>],
    now: OffsetDateTime,
) -> Result<&AgentCredential<T>, DomainError> {
    let mut active = held
        .iter()
        .filter(|credential| credential.is_active() && credential.binds_tokens_at(now));
    let (Some(only), None) = (active.next(), active.next()) else {
        return Err(DomainError::conflict(message!(
            "agents-a-bound-token-needs-the-agent",
            "a bound token needs the agent to hold exactly one active key; with several, the \
             agent asks for its own token with the key it means"
        )));
    };
    Ok(only)
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::domains::agents::identity::credential::{AgentCredentialRow, CredentialOrigin};
    use crate::domains::crypto::key_status::{KeyState, PriorRotation};
    use crate::domains::crypto::signing_key::SigningAlgorithm;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::clock;
    use crate::types::{AgentId, KeyId, PublicKeyPem};

    fn key(agent: AgentId, kid: &str, state: KeyState) -> AgentCredential<ResolvedTenant> {
        let now = clock::now();
        AgentCredential::reconstitute(AgentCredentialRow {
            id: AgentCredentialId::new(),
            agent_id: agent,
            kid: KeyId::new(kid).unwrap(),
            algorithm: SigningAlgorithm::EdDsa,
            public_key: PublicKeyPem::new(
                "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----",
            )
            .unwrap(),
            state,
            created_at: now - Duration::hours(1),
            expires_at: now + Duration::minutes(30),
            origin: CredentialOrigin::Enrolled,
            updated_at: now - Duration::hours(1),
        })
        .unwrap()
    }

    fn revoked() -> KeyState {
        KeyState::Revoked {
            before: PriorRotation::NotRotated,
        }
    }

    /// With two active credentials, a token naming the credential used
    /// for sign-in binds to that credential's key.
    #[test]
    fn a_token_the_agent_minted_binds_the_key_that_signed_it_in() {
        let agent = AgentId::new();
        let held = [
            key(agent, "k2", KeyState::Active),
            key(agent, "k3", KeyState::Active),
        ];

        let bound = TokenKey::SignedInWith(*held[1].id())
            .bound_credential(&held, clock::now())
            .unwrap();

        assert_eq!(bound.map(AgentCredential::kid), Some(held[1].kid()));
    }

    /// A revoked or unknown sign-in credential cannot supply a token
    /// binding, even when another active credential is available.
    #[test]
    fn a_revoked_or_unknown_signing_key_binds_nothing() {
        let agent = AgentId::new();
        let held = [
            key(agent, "k2", KeyState::Active),
            key(agent, "k3", revoked()),
        ];

        let revoked_key =
            TokenKey::SignedInWith(*held[1].id()).bound_credential(&held, clock::now());
        let unknown =
            TokenKey::SignedInWith(AgentCredentialId::new()).bound_credential(&held, clock::now());

        assert!(matches!(revoked_key, Err(DomainError::Conflict(_))));
        assert!(matches!(unknown, Err(DomainError::Conflict(_))));
    }

    /// A key rotated after it signed the agent in still binds the token
    /// during its grace.
    #[test]
    fn a_signing_key_rotated_since_still_binds() {
        let agent = AgentId::new();
        let rotated = KeyState::Rotated {
            at: clock::now() - Duration::minutes(1),
        };
        let held = [key(agent, "k3", rotated)];

        let bound = TokenKey::SignedInWith(*held[0].id()).bound_credential(&held, clock::now());

        assert!(matches!(bound, Ok(Some(_))));
    }

    /// A delegation a person granted binds the agent's one active key. With
    /// none, or with two to choose from, nothing is guessed.
    #[test]
    fn a_granted_token_binds_the_one_active_key_or_nothing() {
        let agent = AgentId::new();
        let one = [
            key(agent, "k2", KeyState::Active),
            key(agent, "k1", revoked()),
        ];
        let two = [
            key(agent, "k2", KeyState::Active),
            key(agent, "k3", KeyState::Active),
        ];

        let bound = TokenKey::AgentsActiveKey.bound_credential(&one, clock::now());
        let none = TokenKey::AgentsActiveKey.bound_credential(&one[1..], clock::now());
        let ambiguous = TokenKey::AgentsActiveKey.bound_credential(&two, clock::now());

        assert_eq!(bound.unwrap().map(AgentCredential::kid), Some(one[0].kid()));
        assert!(matches!(none, Err(DomainError::Conflict(_))));
        assert!(matches!(ambiguous, Err(DomainError::Conflict(_))));
    }

    /// A bearer token is bound to no key, whatever the agent holds.
    #[test]
    fn a_bearer_token_binds_no_key() {
        let held = [key(AgentId::new(), "k2", KeyState::Active)];

        let bound = TokenKey::Bearer.bound_credential(&held, clock::now());

        assert!(matches!(bound, Ok(None)));
    }
}
