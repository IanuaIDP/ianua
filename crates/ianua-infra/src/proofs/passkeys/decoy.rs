//! The decoy challenge for an address with no passkey, made to read as an
//! account's real one.
//!
//! A real sign-in challenge lists the credential ids of the account's
//! passkeys. One that listed nothing, or a fresh random id each time,
//! would tell whoever asks which addresses have accounts. So the decoy
//! lists one id worked out from the address under a key only the server
//! holds: the same address gets the same id every time, as a real account
//! does, and without the key nobody can tell it from a real one. Its
//! length is worked out the same way, from the lengths real passkeys' ids
//! take.
//!
//! It names no ways the credential can be reached. A real one does not
//! either: registration asks for no attestation, so `webauthn-rs` keeps no
//! transports for the passkey and lists none for it. A decoy that named
//! some would be told from every real challenge at a glance.

use ianua_domain::types::Email;
use webauthn_rs::prelude::RequestChallengeResponse;
use webauthn_rs_proto::AllowCredentials;

use crate::crypto::keys::{Purpose, PurposeKey, RootSecret, hmac_sha256};

/// The lengths real passkeys' credential ids come in.
const ID_LENGTHS: [usize; 3] = [16, 32, 64];

/// Works out the credential a decoy challenge lists for an address.
#[derive(Debug, Clone)]
pub(crate) struct DecoyCredentials {
    key: PurposeKey,
}

impl DecoyCredentials {
    /// Decoys under the key `root` derives for them.
    pub(crate) fn new(root: &RootSecret) -> Self {
        Self {
            key: root.derive(Purpose::DecoyPasskeys),
        }
    }

    /// The credential a decoy for `address` lists, the same every time.
    pub(crate) fn listed_for(&self, address: &Email) -> AllowCredentials {
        let shape = self.mac(b"shape", address);
        let pick = usize::from(shape.first().copied().unwrap_or(0));
        let length = ID_LENGTHS
            .get(pick.checked_rem(ID_LENGTHS.len()).unwrap_or(0))
            .copied()
            .unwrap_or(32);
        let id: Vec<u8> = self
            .mac(b"credential", address)
            .into_iter()
            .chain(self.mac(b"credential-more", address))
            .take(length)
            .collect();
        AllowCredentials {
            type_: "public-key".to_owned(),
            id: id.into(),
            transports: None,
        }
    }

    /// The MAC of `address` for one part of its decoy.
    fn mac(&self, part: &[u8], address: &Email) -> [u8; 32] {
        hmac_sha256(self.key.bytes(), &[part, &[0], address.as_str().as_bytes()])
    }
}

/// `options`, a fresh challenge, rewritten as a sign-in challenge for one
/// account would be: listing `listed`, asking no extension, mediated by
/// nothing.
pub(crate) fn naming_one(
    mut options: RequestChallengeResponse,
    listed: AllowCredentials,
) -> RequestChallengeResponse {
    options.public_key.allow_credentials = vec![listed];
    options.public_key.extensions = None;
    options.public_key.hints = None;
    options.mediation = None;
    options
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::tests::test_root;

    fn address(text: &str) -> Email {
        Email::new(text).unwrap()
    }

    /// One address is listed with the same credential every time, as an
    /// account with a passkey is.
    #[test]
    fn an_address_gets_the_same_credential_every_time() {
        let decoys = DecoyCredentials::new(&test_root());

        let first = decoys.listed_for(&address("ann@example.com"));
        let again = decoys.listed_for(&address("ann@example.com"));

        assert_eq!(first.id, again.id);
    }

    /// Two addresses get two credentials, so a decoy cannot be told by an
    /// id every decoy shares.
    #[test]
    fn two_addresses_get_two_credentials() {
        let decoys = DecoyCredentials::new(&test_root());

        let ann = decoys.listed_for(&address("ann@example.com"));
        let bob = decoys.listed_for(&address("bob@example.com"));

        assert_ne!(ann.id, bob.id);
    }

    /// Changing the server root key changes the decoy credential ID for the same address.
    #[test]
    fn the_credential_depends_on_the_server_key() {
        let other = RootSecret::parse(&"cd".repeat(32)).unwrap();

        let ours = DecoyCredentials::new(&test_root()).listed_for(&address("ann@example.com"));
        let theirs = DecoyCredentials::new(&other).listed_for(&address("ann@example.com"));

        assert_ne!(ours.id, theirs.id);
    }

    /// Every decoy id has a length real passkey ids have.
    #[test]
    fn a_decoy_id_has_a_real_length() {
        let decoys = DecoyCredentials::new(&test_root());

        for name in ["ann", "bob", "cy", "dee", "eve", "fay"] {
            let listed = decoys.listed_for(&address(&format!("{name}@example.com")));
            assert!(ID_LENGTHS.contains(&listed.id.len()), "{}", listed.id.len());
        }
    }
}
