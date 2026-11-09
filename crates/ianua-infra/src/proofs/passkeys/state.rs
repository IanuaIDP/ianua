//! The state a passkey ceremony keeps between its challenge and its
//! answer, sealed so only a state this server made, for this kind of
//! ceremony, is ever checked against.
//!
//! The state is what an answer is verified against, so whoever could hand
//! one in could pick what their own answer is checked by. It is kept by
//! the server, never sent out, and sealed as well: an HMAC-SHA256 under a
//! key derived for this use alone, over the ceremony's kind and the state.
//! A state written by anything else, a state of another kind, or one
//! changed by a single byte is refused before it is read.

use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::crypto::keys::{KEY_BYTES, Purpose, PurposeKey, RootSecret, hmac_sha256};

/// Which ceremony a state belongs to. A state opens only as its own kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CeremonyKind {
    /// Registering a new passkey.
    Registration,
    /// Signing in with one of an account's passkeys.
    Authentication,
    /// Signing in with whatever passkey the authenticator offers.
    Discoverable,
    /// A decoy for an address with no passkey, which nothing opens.
    Decoy,
}

impl CeremonyKind {
    /// The fixed word the seal covers for this kind.
    fn label(self) -> &'static [u8] {
        match self {
            Self::Registration => b"registration",
            Self::Authentication => b"authentication",
            Self::Discoverable => b"discoverable",
            Self::Decoy => b"decoy",
        }
    }
}

/// Seals and opens ceremony states under the key derived for them.
#[derive(Debug, Clone)]
pub(crate) struct CeremonySeal {
    key: PurposeKey,
}

impl CeremonySeal {
    /// A seal under the key `root` derives for passkey ceremonies.
    pub(crate) fn new(root: &RootSecret) -> Self {
        Self {
            key: root.derive(Purpose::PasskeyCeremonies),
        }
    }

    /// `state` as JSON, its seal in front.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the state cannot be
    /// written as JSON.
    pub(crate) fn seal(
        &self,
        kind: CeremonyKind,
        state: &impl Serialize,
    ) -> Result<Vec<u8>, DomainError> {
        let body = serde_json::to_vec(state).map_err(DomainError::infra)?;
        let mut sealed = self.tag(kind, &body).to_vec();
        sealed.extend_from_slice(&body);
        Ok(sealed)
    }

    /// The state `sealed` holds, when this server sealed it as `kind`.
    ///
    /// # Errors
    ///
    /// - `DomainError::Unauthorized` when the seal does not hold: another
    ///   server's state, another kind's, or one changed since.
    /// - `DomainError::Infrastructure` when a sealed state does not read as
    ///   the state it should be.
    pub(crate) fn open<T: DeserializeOwned>(
        &self,
        kind: CeremonyKind,
        sealed: &[u8],
    ) -> Result<T, DomainError> {
        let Some((tag, body)) = sealed.split_at_checked(KEY_BYTES) else {
            return Err(not_ours());
        };
        if !same_bytes(tag, &self.tag(kind, body)) {
            return Err(not_ours());
        }
        serde_json::from_slice(body).map_err(DomainError::infra)
    }

    /// The seal over `kind` and `body`.
    fn tag(&self, kind: CeremonyKind, body: &[u8]) -> [u8; KEY_BYTES] {
        hmac_sha256(self.key.bytes(), &[kind.label(), &[0], body])
    }
}

/// Whether two byte strings are the same, compared in time that does not
/// depend on where they first differ.
fn same_bytes(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |differs, (a, b)| differs | (a ^ b))
            == 0
}

/// The refusal of a state this server did not seal as asked.
fn not_ours() -> DomainError {
    DomainError::unauthorized(message!(
        "infra-the-ceremony-state-is-not-one",
        "the ceremony state is not one this server issued"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::tests::test_root;

    /// A state sealed as one kind opens as the same state.
    #[test]
    fn a_sealed_state_opens_as_itself() {
        let seal = CeremonySeal::new(&test_root());

        let sealed = seal
            .seal(CeremonyKind::Registration, &vec![1, 2, 3])
            .unwrap();
        let opened: Vec<u8> = seal.open(CeremonyKind::Registration, &sealed).unwrap();

        assert_eq!(opened, vec![1, 2, 3]);
    }

    /// Registration state cannot be opened as authentication state.
    #[test]
    fn a_state_of_another_kind_is_refused() {
        let seal = CeremonySeal::new(&test_root());
        let sealed = seal.seal(CeremonyKind::Registration, &1).unwrap();

        let opened = seal.open::<u8>(CeremonyKind::Authentication, &sealed);

        assert!(matches!(opened, Err(DomainError::Unauthorized(_))));
    }

    /// Changing one byte of sealed ceremony state makes opening it unauthorized.
    #[test]
    fn a_changed_state_is_refused() {
        let seal = CeremonySeal::new(&test_root());
        let mut sealed = seal.seal(CeremonyKind::Authentication, &"abc").unwrap();
        if let Some(last) = sealed.last_mut() {
            *last ^= 1;
        }

        let opened = seal.open::<String>(CeremonyKind::Authentication, &sealed);

        assert!(matches!(opened, Err(DomainError::Unauthorized(_))));
    }

    /// State sealed under another root key and input too short to contain a seal both fail to open.
    #[test]
    fn a_state_from_elsewhere_is_refused() {
        let other = RootSecret::parse(&"cd".repeat(KEY_BYTES)).unwrap();
        let foreign = CeremonySeal::new(&other)
            .seal(CeremonyKind::Authentication, &1)
            .unwrap();
        let seal = CeremonySeal::new(&test_root());

        assert!(
            seal.open::<u8>(CeremonyKind::Authentication, &foreign)
                .is_err()
        );
        assert!(
            seal.open::<u8>(CeremonyKind::Authentication, b"short")
                .is_err()
        );
    }
}
