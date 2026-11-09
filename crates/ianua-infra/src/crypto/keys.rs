//! The secret every key of the platform is derived from, and the keys
//! derived from it, one for each use.
//!
//! The deployment configures one 32-byte root secret for the digests,
//! apart from the keys secrets are sealed under. Each use gets its own key
//! from it through HKDF-SHA256 under a fixed label, so a key that
//! hashes API keys never also hashes recovery codes: a digest leaked from
//! one table matches nothing in another, and the root never touches data
//! itself. Every process derives the same keys from the same root, so the
//! API and the gateway compute the same digests.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The length of the root secret and of every key derived from it.
pub(crate) const KEY_BYTES: usize = 32;

/// The block size of SHA-256, which an HMAC key is padded to.
const BLOCK_BYTES: usize = 64;

/// The HMAC-SHA256 of `parts`, written one after another, under `key`: the
/// one keyed primitive the key derivation and every digest are built on.
///
/// HMAC pads a key shorter than its 64-byte block with zeros (RFC 2104),
/// so a 32-byte key and that key padded to the block are the same key.
/// Padding it here lets the MAC take a key of fixed size, which cannot be
/// the wrong length, so nothing about it can fail.
pub(crate) fn hmac_sha256(key: &[u8; KEY_BYTES], parts: &[&[u8]]) -> [u8; KEY_BYTES] {
    let mut block = [0_u8; BLOCK_BYTES];
    for (padded, byte) in block.iter_mut().zip(key) {
        *padded = *byte;
    }
    let mut mac = <Hmac<Sha256> as KeyInit>::new(&block.into());
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// The root secret could not be read from the deployment's configuration.
#[derive(Debug, thiserror::Error)]
pub enum RootSecretError {
    /// The value is neither 64 hex characters nor base64 of 32 bytes.
    #[error("the root secret must be 32 bytes, written as 64 hex characters or as base64")]
    Unreadable,
}

/// The secret the platform's keys are derived from. It never prints.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootSecret([u8; KEY_BYTES]);

impl fmt::Debug for RootSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RootSecret(<redacted>)")
    }
}

impl RootSecret {
    /// The root secret `value` writes, as 64 hex characters or as base64 of
    /// 32 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`RootSecretError::Unreadable`] when it is neither, or
    /// decodes to another length. A short secret is refused, never padded.
    pub fn parse(value: &str) -> Result<Self, RootSecretError> {
        decoded_key(value)
            .map(Self)
            .ok_or(RootSecretError::Unreadable)
    }

    /// The key for `purpose`, the same every time and in every process:
    /// HKDF-SHA256 (RFC 5869) with no salt, its one output block, which is
    /// the extract step's HMAC and then the expand step's.
    #[must_use]
    pub(crate) fn derive(&self, purpose: Purpose) -> PurposeKey {
        let pseudo_random = hmac_sha256(&[0_u8; KEY_BYTES], &[&self.0]);
        PurposeKey(hmac_sha256(&pseudo_random, &[purpose.label(), &[1]]))
    }
}

/// The 32 bytes `value` writes as hex or as base64, or `None` when it is
/// neither or holds another length. A short key is never padded.
pub(crate) fn decoded_key(value: &str) -> Option<[u8; KEY_BYTES]> {
    data_encoding::HEXLOWER_PERMISSIVE
        .decode(value.as_bytes())
        .ok()
        .or_else(|| STANDARD.decode(value).ok())
        .or_else(|| URL_SAFE_NO_PAD.decode(value).ok())
        .and_then(|decoded| decoded.try_into().ok())
}

/// A key derived for one use. It never prints.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct PurposeKey([u8; KEY_BYTES]);

impl fmt::Debug for PurposeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PurposeKey(<redacted>)")
    }
}

impl PurposeKey {
    /// The key's bytes, for the primitive that uses it.
    pub(crate) fn bytes(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }
}

/// Each use a key is derived for. Its label is fixed: changing one changes
/// the key, and every digest made under the old key stops matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// API keys of tenants, organizations and operators.
    ApiKeys,
    /// The API keys consumers present at the gateway.
    ConsumerKeys,
    /// OAuth client secrets.
    ClientSecrets,
    /// OAuth authorization codes and device codes.
    AuthorizationCodes,
    /// Digests credentials exchanged to renew OAuth access.
    RefreshTokens,
    /// MFA recovery codes.
    RecoveryCodes,
    /// One-time codes sent by mail or text.
    SentCodes,
    /// SCIM bearer tokens.
    ScimTokens,
    /// The secrets that start a workflow from its webhook.
    WorkflowTriggers,
    /// The states and one-time codes that tie an account connection's
    /// sign-in at a service together.
    AccountConnections,
    /// The codes a private network connector enrolls with.
    ConnectorCodes,
    /// The secrets LDAP service accounts bind with.
    ServiceAccounts,
    /// The keys signal receivers present.
    ReceiverKeys,
    /// The seals on app sign-in requests between the gateway and the API.
    RequestSeals,
    /// The seals on the gateway's questions about agent approvals to the
    /// API.
    ApprovalRequestSeals,
    /// The seals on the newest link of each tenant's audit chain.
    AuditChainHeads,
    /// The seals on the anchor a purge leaves where it cut a tenant's
    /// audit chain.
    AuditChainAnchors,
    /// The seals on the sweep's verdict on a tenant's audit chain.
    AuditChainVerdicts,
    /// The seals the control plane puts on the live updates it broadcasts
    /// to dashboards.
    RealtimeSeals,
    /// The seals the data plane puts on the live updates it broadcasts to
    /// dashboards.
    DataPlaneRealtimeSeals,
    /// The seals on the receipts the message bus hands out with each
    /// delivery.
    DeliveryReceipts,
    /// The seals the control plane puts on the events it publishes.
    EventSeals,
    /// The seals the data plane puts on the events it publishes.
    DataPlaneEventSeals,
    /// The seals on the links an export file is downloaded through.
    FileLinks,
    /// The seals on the state a passkey ceremony keeps between its
    /// challenge and its answer.
    PasskeyCeremonies,
    /// The credential ids a decoy passkey challenge lists for an address
    /// with no passkey.
    DecoyPasskeys,
    /// The pairwise NameIDs SAML apps are sent.
    SamlPairwiseIds,
    /// The seals on the puzzles a sign-in under pressure is set.
    SignInPuzzles,
    /// The seals on the threat verdicts the gateway's instances share.
    FleetVerdicts,
    /// The digests the gateway puts in place of the fields a tenant's
    /// classification rules redact by hashing.
    RedactedValues,
}

impl Purpose {
    /// The HKDF label the key for this use is derived under.
    /// This exhaustive mapping keeps every purpose tied to its stable derivation label.
    #[allow(clippy::too_many_lines)]
    fn label(self) -> &'static [u8] {
        match self {
            Self::ApiKeys => b"ianua.digest.api-keys.v1",
            Self::ConsumerKeys => b"ianua.digest.consumer-keys.v1",
            Self::ClientSecrets => b"ianua.digest.client-secrets.v1",
            Self::AuthorizationCodes => b"ianua.digest.authorization-codes.v1",
            Self::RefreshTokens => b"ianua.digest.refresh-tokens.v1",
            Self::RecoveryCodes => b"ianua.digest.recovery-codes.v1",
            Self::SentCodes => b"ianua.digest.sent-codes.v1",
            Self::ScimTokens => b"ianua.digest.scim-tokens.v1",
            Self::WorkflowTriggers => b"ianua.digest.workflow-triggers.v1",
            Self::AccountConnections => b"ianua.digest.account-connections.v1",
            Self::ConnectorCodes => b"ianua.digest.connector-codes.v1",
            Self::ServiceAccounts => b"ianua.digest.service-accounts.v1",
            Self::ReceiverKeys => b"ianua.digest.receiver-keys.v1",
            Self::RequestSeals => b"ianua.seal.app-sign-in-requests.v1",
            Self::ApprovalRequestSeals => b"ianua.seal.approval-requests.v1",
            Self::AuditChainHeads => b"ianua.seal.audit-chain-heads.v1",
            Self::AuditChainAnchors => b"ianua.seal.audit-chain-anchors.v1",
            Self::AuditChainVerdicts => b"ianua.seal.audit-chain-verdicts.v1",
            Self::RealtimeSeals => b"ianua.seal.realtime.control-plane.v1",
            Self::DataPlaneRealtimeSeals => b"ianua.seal.realtime.data-plane.v1",
            Self::DeliveryReceipts => b"ianua.seal.delivery-receipts.v1",
            Self::EventSeals => b"ianua.seal.events.control-plane.v1",
            Self::DataPlaneEventSeals => b"ianua.seal.events.data-plane.v1",
            Self::PasskeyCeremonies => b"ianua.seal.passkey-ceremonies.v1",
            Self::DecoyPasskeys => b"ianua.digest.decoy-passkeys.v1",
            Self::FileLinks => b"ianua.seal.file-links.v1",
            Self::SamlPairwiseIds => b"ianua.digest.saml-pairwise-ids.v1",
            Self::SignInPuzzles => b"ianua.seal.sign-in-puzzles.v1",
            Self::FleetVerdicts => b"ianua.seal.fleet-verdicts.v1",
            Self::RedactedValues => b"ianua.digest.redacted-values.v1",
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use hmac::Mac;

    use super::*;

    /// The MAC under a 32-byte key is the HMAC-SHA256 the `hmac` crate
    /// computes from the same key unpadded.
    #[test]
    fn the_padded_key_is_the_same_key() {
        let key = [7_u8; KEY_BYTES];
        let mut expected = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).unwrap();
        expected.update(b"ian");
        expected.update(b"ua");

        let ours = hmac_sha256(&key, &[b"ian", b"ua"]);

        assert_eq!(ours.as_slice(), expected.finalize().into_bytes().as_slice());
    }

    /// A root secret for tests, the same in every one.
    pub(crate) fn test_root() -> RootSecret {
        RootSecret::parse(&"ab".repeat(KEY_BYTES)).unwrap()
    }

    /// One secret written as hex and as base64 reads as the same root, so
    /// two processes configured either way derive the same keys.
    #[test]
    fn hex_and_base64_of_one_secret_agree() {
        let raw = [0x5a_u8; KEY_BYTES];
        let hex = data_encoding::HEXLOWER.encode(&raw);
        let base64 = STANDARD.encode(raw);

        let from_hex = RootSecret::parse(&hex).unwrap();
        let from_base64 = RootSecret::parse(&base64).unwrap();

        assert_eq!(
            from_hex.derive(Purpose::ApiKeys).bytes(),
            from_base64.derive(Purpose::ApiKeys).bytes()
        );
    }

    /// Incorrect secret lengths and invalid encodings fail validation without padding or truncation.
    #[test]
    fn a_secret_of_the_wrong_length_is_refused() {
        for value in [
            "ab".repeat(16),
            "ab".repeat(64),
            "not a key at all!!".to_owned(),
            String::new(),
        ] {
            assert!(RootSecret::parse(&value).is_err(), "{value:?} was read");
        }
    }

    /// The key derived for a use is the one HKDF-SHA256 expands from the
    /// root under its label, as the `hkdf` crate computes it.
    #[test]
    fn a_key_is_the_hkdf_of_the_root() {
        let root = test_root();
        let mut expected = [0_u8; KEY_BYTES];
        hkdf::Hkdf::<sha2::Sha256>::new(None, &root.0)
            .expand(Purpose::ApiKeys.label(), &mut expected)
            .unwrap();

        assert_eq!(root.derive(Purpose::ApiKeys).bytes(), &expected);
    }

    /// Every key purpose checked for a distinct derivation label.
    const EVERY_PURPOSE: &[Purpose] = &[
        Purpose::ApiKeys,
        Purpose::ConsumerKeys,
        Purpose::ClientSecrets,
        Purpose::AuthorizationCodes,
        Purpose::RefreshTokens,
        Purpose::RecoveryCodes,
        Purpose::SentCodes,
        Purpose::ScimTokens,
        Purpose::WorkflowTriggers,
        Purpose::AccountConnections,
        Purpose::ConnectorCodes,
        Purpose::ServiceAccounts,
        Purpose::ReceiverKeys,
        Purpose::RequestSeals,
        Purpose::ApprovalRequestSeals,
        Purpose::AuditChainHeads,
        Purpose::AuditChainAnchors,
        Purpose::AuditChainVerdicts,
        Purpose::RealtimeSeals,
        Purpose::DataPlaneRealtimeSeals,
        Purpose::DeliveryReceipts,
        Purpose::EventSeals,
        Purpose::DataPlaneEventSeals,
        Purpose::FileLinks,
        Purpose::PasskeyCeremonies,
        Purpose::DecoyPasskeys,
        Purpose::SamlPairwiseIds,
        Purpose::SignInPuzzles,
        Purpose::FleetVerdicts,
        Purpose::RedactedValues,
    ];

    /// Every declared key purpose has a distinct derivation label.
    #[test]
    fn every_purpose_has_a_label_of_its_own() {
        let labels: std::collections::HashSet<&[u8]> = EVERY_PURPOSE
            .iter()
            .map(|purpose| purpose.label())
            .collect();

        assert_eq!(labels.len(), EVERY_PURPOSE.len());
    }

    /// Each use gets a key of its own, and the same use the same key every
    /// time.
    #[test]
    fn each_purpose_derives_its_own_key() {
        let root = test_root();

        let api_keys = root.derive(Purpose::ApiKeys);
        let recovery = root.derive(Purpose::RecoveryCodes);

        assert_ne!(api_keys.bytes(), recovery.bytes());
        assert_eq!(api_keys.bytes(), root.derive(Purpose::ApiKeys).bytes());
    }

    /// Root and derived keys expose only their redacted debug representations.
    #[test]
    fn no_key_prints() {
        let root = test_root();

        assert_eq!(format!("{root:?}"), "RootSecret(<redacted>)");
        assert_eq!(
            format!("{:?}", root.derive(Purpose::ApiKeys)),
            "PurposeKey(<redacted>)"
        );
    }
}
