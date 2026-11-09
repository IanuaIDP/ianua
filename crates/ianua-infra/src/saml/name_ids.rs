//! The `NameID` values a SAML app is sent that need a secret or chance:
//! the pairwise id, the same for one person at one app every time and
//! unlinkable across apps, and the transient one, fresh at every sign-in.
//!
//! The pairwise id is an HMAC-SHA256 of the app's id and the account's id
//! under a key derived from the root secret for this use alone, so it needs
//! no table: every node computes the same id, and nobody without the key
//! can tell that two apps' ids name one person.

use std::fmt;

use ianua_app::ports::federation::SamlNameIds;
use ianua_domain::domains::federation::saml::name_id::SamlNameIdValue;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{SamlServiceProviderId, UserId};

use crate::crypto::keys::{Purpose, PurposeKey, RootSecret, hmac_sha256};
use crate::saml::xml::keys::random_bytes;

/// Makes pairwise ids under a key of their own, and transient ids from the
/// operating system's secure generator.
pub struct HmacSamlNameIds {
    key: PurposeKey,
}

impl fmt::Debug for HmacSamlNameIds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HmacSamlNameIds(<key redacted>)")
    }
}

impl HmacSamlNameIds {
    /// Ids made under the key `root` derives for pairwise ids.
    #[must_use]
    pub fn new(root: &RootSecret) -> Self {
        Self {
            key: root.derive(Purpose::SamlPairwiseIds),
        }
    }
}

impl SamlNameIds for HmacSamlNameIds {
    fn pairwise(
        &self,
        provider: &SamlServiceProviderId,
        account: &UserId,
    ) -> Result<SamlNameIdValue, DomainError> {
        let mac = hmac_sha256(
            self.key.bytes(),
            &[provider.as_uuid().as_bytes(), account.as_uuid().as_bytes()],
        );
        written(&mac)
    }

    fn transient(&self) -> Result<SamlNameIdValue, DomainError> {
        written(&random_bytes::<20>()?)
    }
}

/// `bytes` as a `NameID`: `_` and lowercase base32, letters and digits
/// that every app stores as they are.
fn written(bytes: &[u8]) -> Result<SamlNameIdValue, DomainError> {
    SamlNameIdValue::new(format!("_{}", data_encoding::BASE32_DNSSEC.encode(bytes)))
        .map_err(DomainError::infra)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(secret: &str) -> HmacSamlNameIds {
        HmacSamlNameIds::new(&RootSecret::parse(&secret.repeat(32)).unwrap())
    }

    /// One person at one app is named the same every time, so the app
    /// finds them again.
    #[test]
    fn a_pairwise_id_is_stable() {
        let names = ids("ab");
        let app = SamlServiceProviderId::new();
        let ann = UserId::new();

        assert_eq!(
            names.pairwise(&app, &ann).unwrap(),
            names.pairwise(&app, &ann).unwrap()
        );
    }

    /// The same person receives distinct persistent IDs in two applications.
    #[test]
    fn two_apps_get_unlinkable_ids() {
        let names = ids("ab");
        let ann = UserId::new();

        let crm = names.pairwise(&SamlServiceProviderId::new(), &ann).unwrap();
        let wiki = names.pairwise(&SamlServiceProviderId::new(), &ann).unwrap();

        assert_ne!(crm, wiki);
    }

    /// Changing the root secret changes the persistent ID for the same person and app.
    #[test]
    fn another_secret_gives_another_id() {
        let app = SamlServiceProviderId::new();
        let ann = UserId::new();

        assert_ne!(
            ids("ab").pairwise(&app, &ann).unwrap(),
            ids("cd").pairwise(&app, &ann).unwrap()
        );
    }

    /// A transient id is fresh every time, and never a pairwise one.
    #[test]
    fn a_transient_id_is_fresh() {
        let names = ids("ab");

        let first = names.transient().unwrap();
        let second = names.transient().unwrap();

        assert_ne!(first, second);
        assert!(first.as_str().starts_with('_'));
    }

    /// Debug output contains only the redacted marker, not the ID derivation key.
    #[test]
    fn the_key_never_prints() {
        assert_eq!(
            format!("{:?}", ids("ab")),
            "HmacSamlNameIds(<key redacted>)"
        );
    }
}
