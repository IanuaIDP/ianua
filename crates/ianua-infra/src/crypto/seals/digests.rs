//! The keyed digest every stored token is kept as: an HMAC-SHA256 of the
//! token under the key of its use, written as URL-safe base64. The seal on
//! the app sign-in requests the gateway hands the API is one too.
//!
//! A digest is the same for the same token every time, so a presented
//! token is found by its digest; and keyed, so a copied table cannot be
//! searched offline for tokens, not even short codes. Two digests compare
//! in constant time through [`TokenHash`]'s own equality. The digest the
//! gateway puts in place of a redacted field is keyed the same way.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_app::ports::authentication::RequestSeal;
use ianua_app::ports::data_classification::RedactionDigest;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Nonce, TenantId, TokenHash};

use crate::crypto::keys::{Purpose, PurposeKey, RootSecret, hmac_sha256};

/// The digest of the tokens of one use, under that use's key.
#[derive(Debug, Clone)]
pub(crate) struct KeyedDigest {
    key: PurposeKey,
}

impl KeyedDigest {
    /// The digest of `purpose`'s tokens, under the key `root` derives for
    /// it.
    pub(crate) fn of(root: &RootSecret, purpose: Purpose) -> Self {
        Self {
            key: root.derive(purpose),
        }
    }

    /// The digest of `token`.
    pub(crate) fn digest(&self, token: &Secret) -> TokenHash {
        self.digest_text(token.expose())
    }

    /// The digest of `text`, a token the caller holds as plain text.
    pub(crate) fn digest_text(&self, text: &str) -> TokenHash {
        let mac = hmac_sha256(self.key.bytes(), &[text.as_bytes()]);
        TokenHash::from_stored(URL_SAFE_NO_PAD.encode(mac))
    }

    /// Whether `presented` is the token `stored` is the digest of.
    pub(crate) fn matches(&self, presented: &Secret, stored: &TokenHash) -> bool {
        &self.digest(presented) == stored
    }
}

/// The seal on a request the gateway relays to the API: the HMAC-SHA256 of
/// its body under a key the two derive from the same root for that one
/// channel. The app sign-in channel and the approvals channel each have
/// their own, so a request sealed for one never opens on the other.
#[derive(Debug, Clone)]
pub struct HmacRequestSeal {
    key: PurposeKey,
}

impl HmacRequestSeal {
    /// A seal under the key `root` derives for app sign-in requests.
    #[must_use]
    pub fn new(root: &RootSecret) -> Self {
        Self {
            key: root.derive(Purpose::RequestSeals),
        }
    }

    /// A seal under the key `root` derives for the gateway's questions
    /// about agent approvals, never the sign-in key.
    #[must_use]
    pub fn approvals(root: &RootSecret) -> Self {
        Self {
            key: root.derive(Purpose::ApprovalRequestSeals),
        }
    }
}

/// What begins every answer's sealed bytes. A question is JSON and begins
/// with `{`, so no answer's seal holds as a question's, nor the reverse.
const ANSWER_LABEL: &[u8] = b"answer\n";

impl RequestSeal for HmacRequestSeal {
    fn seal(&self, body: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(hmac_sha256(self.key.bytes(), &[body]))
    }

    fn verifies(&self, body: &[u8], seal: &str) -> bool {
        TokenHash::from_stored(self.seal(body)) == TokenHash::from_stored(seal.to_owned())
    }

    fn seal_answer(&self, nonce: &Nonce, body: &[u8]) -> String {
        let parts: [&[u8]; 4] = [ANSWER_LABEL, nonce.as_str().as_bytes(), b"\n", body];
        URL_SAFE_NO_PAD.encode(hmac_sha256(self.key.bytes(), &parts))
    }

    fn verifies_answer(&self, nonce: &Nonce, body: &[u8], seal: &str) -> bool {
        TokenHash::from_stored(self.seal_answer(nonce, body))
            == TokenHash::from_stored(seal.to_owned())
    }
}

/// The seals that keep a tenant's audit chain whole: on its newest link,
/// on the anchor a purge leaves where it cut the chain, and on the sweep's
/// verdict. Each is an HMAC-SHA256 of the tenant and what it vouches for,
/// under a key of its own the database never holds, so a seal of one kind
/// never holds as another's.
#[derive(Debug, Clone)]
pub struct AuditChainSeals {
    head: PurposeKey,
    anchor: PurposeKey,
    verdict: PurposeKey,
}

/// The position and digest of one link covered by an audit seal.
#[derive(Clone, Copy)]
pub(crate) struct ChainLink<'a> {
    pub(crate) seq: i64,
    pub(crate) hash: &'a [u8],
}

impl AuditChainSeals {
    /// The seals under the keys `root` derives for audit chain heads,
    /// anchors and verdicts.
    #[must_use]
    pub fn new(root: &RootSecret) -> Self {
        Self {
            head: root.derive(Purpose::AuditChainHeads),
            anchor: root.derive(Purpose::AuditChainAnchors),
            verdict: root.derive(Purpose::AuditChainVerdicts),
        }
    }

    /// The seal on `tenant`'s chain ending at `seq` with `hash`.
    pub(crate) fn head_seal(&self, tenant: &uuid::Uuid, seq: i64, hash: &[u8]) -> [u8; 32] {
        linked(&self.head, tenant, seq, hash)
    }

    /// Whether `seal` covers the end `link` of `tenant`'s chain, compared in constant time.
    pub(crate) fn head_holds(&self, tenant: &uuid::Uuid, link: ChainLink<'_>, seal: &[u8]) -> bool {
        same_seal(&self.head_seal(tenant, link.seq, link.hash), seal)
    }

    /// The seal on `tenant`'s anchor, the link at `seq` with `hash` a purge
    /// left as the chain's start.
    pub(crate) fn anchor_seal(&self, tenant: &uuid::Uuid, seq: i64, hash: &[u8]) -> [u8; 32] {
        linked(&self.anchor, tenant, seq, hash)
    }

    /// Whether `seal` covers the anchor `link` of `tenant`'s chain, compared in constant time.
    pub(crate) fn anchor_holds(
        &self,
        tenant: &uuid::Uuid,
        link: ChainLink<'_>,
        seal: &[u8],
    ) -> bool {
        same_seal(&self.anchor_seal(tenant, link.seq, link.hash), seal)
    }

    /// The seal on `tenant`'s verdict, whose columns written out are
    /// `over`.
    pub(crate) fn verdict_seal(&self, tenant: &uuid::Uuid, over: &[u8]) -> [u8; 32] {
        hmac_sha256(self.verdict.bytes(), &[tenant.as_bytes(), over])
    }

    /// Whether `seal` is the seal on `tenant`'s verdict whose columns
    /// written out are `over`, compared in constant time.
    pub(crate) fn verdict_holds(&self, tenant: &uuid::Uuid, over: &[u8], seal: &[u8]) -> bool {
        same_seal(&self.verdict_seal(tenant, over), seal)
    }
}

/// The HMAC-SHA256 under `key` of `tenant`'s link at `seq` with `hash`.
fn linked(key: &PurposeKey, tenant: &uuid::Uuid, seq: i64, hash: &[u8]) -> [u8; 32] {
    hmac_sha256(key.bytes(), &[tenant.as_bytes(), &seq.to_be_bytes(), hash])
}

/// Whether `presented` is the seal `expected`, compared in constant time.
fn same_seal(expected: &[u8; 32], presented: &[u8]) -> bool {
    TokenHash::from_stored(URL_SAFE_NO_PAD.encode(expected))
        == TokenHash::from_stored(URL_SAFE_NO_PAD.encode(presented))
}

/// The seal on a delivery receipt: an HMAC-SHA256 of the tenant, the
/// consumer and what the receipt says, under a key nothing else uses, so a
/// receipt cannot be forged, altered, or settled through another consumer.
#[derive(Debug, Clone)]
pub struct ReceiptSeal {
    key: PurposeKey,
}

/// A receipt's encoded body and the seal presented beside it.
#[derive(Clone, Copy)]
pub(crate) struct SignedReceipt<'a> {
    pub(crate) body: &'a str,
    pub(crate) seal: &'a str,
}

impl ReceiptSeal {
    /// A seal under the key `root` derives for delivery receipts.
    #[must_use]
    pub fn new(root: &RootSecret) -> Self {
        Self {
            key: root.derive(Purpose::DeliveryReceipts),
        }
    }

    /// The seal on `body`, handed to `consumer` of `tenant`, as URL-safe
    /// base64.
    pub(crate) fn seal(&self, tenant: &uuid::Uuid, consumer: &str, body: &str) -> String {
        URL_SAFE_NO_PAD.encode(hmac_sha256(
            self.key.bytes(),
            &[
                tenant.as_bytes(),
                consumer.as_bytes(),
                b"\0",
                body.as_bytes(),
            ],
        ))
    }

    /// Whether `receipt` was sealed for `consumer` of `tenant`, compared in constant time.
    pub(crate) fn holds(
        &self,
        tenant: &uuid::Uuid,
        consumer: &str,
        receipt: SignedReceipt<'_>,
    ) -> bool {
        TokenHash::from_stored(self.seal(tenant, consumer, receipt.body))
            == TokenHash::from_stored(receipt.seal.to_owned())
    }
}

/// The digest the gateway puts in place of a field redacted by hashing:
/// an HMAC-SHA256 of the tenant and the value, under a key derived for
/// that alone.
///
/// Without the key nobody can try every social security number against a
/// digest; and with the tenant in it, one value digests apart in two
/// tenants. The tenant's id is a fixed sixteen bytes, so it never runs into
/// the value.
#[derive(Debug, Clone)]
pub struct HmacRedactionDigest {
    key: PurposeKey,
}

impl HmacRedactionDigest {
    /// A digest under the key `root` derives for redacted values. The
    /// gateway's root, so every instance digests a value alike.
    #[must_use]
    pub fn new(root: &RootSecret) -> Self {
        Self {
            key: root.derive(Purpose::RedactedValues),
        }
    }
}

impl RedactionDigest for HmacRedactionDigest {
    fn digest(&self, tenant_id: &TenantId, value: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(hmac_sha256(
            self.key.bytes(),
            &[tenant_id.as_uuid().as_bytes(), value],
        ))
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::crypto::keys::tests::test_root;

    /// A chain link whose position and hash can be varied independently.
    fn link(seq: i64, hash: &[u8]) -> ChainLink<'_> {
        ChainLink { seq, hash }
    }

    /// One social security number in one tenant digests the same every
    /// time, so an upstream's records still match on it.
    #[test]
    fn a_redacted_value_digests_alike_in_one_tenant() {
        let digest = HmacRedactionDigest::new(&test_root());
        let acme = TenantId::new();

        let first = digest.digest(&acme, b"\"078-05-1120\"");
        let again = digest.digest(&acme, b"\"078-05-1120\"");

        assert_eq!(first, again);
    }

    /// Redacting a value produces a keyed digest different from its plain SHA-256 hash.
    #[test]
    fn a_redacted_value_is_not_its_plain_hash() {
        let digest = HmacRedactionDigest::new(&test_root());
        let value = b"\"078-05-1120\"";

        let keyed = digest.digest(&TenantId::new(), value);

        assert_ne!(keyed, URL_SAFE_NO_PAD.encode(Sha256::digest(value)));
    }

    /// The same redacted value has different digests in Acme and Globex.
    #[test]
    fn one_value_digests_apart_in_two_tenants() {
        let digest = HmacRedactionDigest::new(&test_root());
        let value = b"\"078-05-1120\"";

        let acme = digest.digest(&TenantId::new(), value);
        let globex = digest.digest(&TenantId::new(), value);

        assert_ne!(acme, globex);
    }

    fn secret(text: &str) -> Secret {
        Secret::new(text.to_owned())
    }

    /// The same token gives the same digest every time, so a presented
    /// token is found by it, and the digest says nothing of the token.
    #[test]
    fn a_token_has_one_digest_that_hides_it() {
        let digest = KeyedDigest::of(&test_root(), Purpose::ApiKeys);

        let first = digest.digest(&secret("ik_live_acme_x_y"));
        let again = digest.digest(&secret("ik_live_acme_x_y"));

        assert_eq!(first, again);
        assert!(!first.as_str().contains("acme"));
    }

    /// The same token text yields distinct digests for each credential purpose.
    #[test]
    fn the_same_token_digests_apart_for_each_use() {
        let root = test_root();

        let as_key = KeyedDigest::of(&root, Purpose::ApiKeys).digest(&secret("12345678"));
        let as_code = KeyedDigest::of(&root, Purpose::RecoveryCodes).digest(&secret("12345678"));

        assert_ne!(as_key, as_code);
    }

    /// A request's seal checks against its own body, and not against a body
    /// changed on the way.
    #[test]
    fn a_request_seal_checks_only_its_own_body() {
        let seal = HmacRequestSeal::new(&test_root());

        let sealed = seal.seal(br#"{"action":"log_in"}"#);

        assert!(seal.verifies(br#"{"action":"log_in"}"#, &sealed));
        assert!(!seal.verifies(br#"{"action":"log_out"}"#, &sealed));
    }

    /// Approval and app-sign-in request seals fail across channels;
    /// an approval seal still verifies on its own channel.
    #[test]
    fn a_request_seal_holds_on_its_own_channel_only() {
        let body = br#"{"ask":"spend"}"#;

        let for_sign_in = HmacRequestSeal::new(&test_root()).seal(body);
        let for_approvals = HmacRequestSeal::approvals(&test_root()).seal(body);

        assert!(!HmacRequestSeal::approvals(&test_root()).verifies(body, &for_sign_in));
        assert!(!HmacRequestSeal::new(&test_root()).verifies(body, &for_approvals));
        assert!(HmacRequestSeal::approvals(&test_root()).verifies(body, &for_approvals));
    }

    fn nonce(text: &str) -> Nonce {
        Nonce::new(format!("{text}-nonce-of-length")).unwrap()
    }

    /// The API's answer to the question that carried a nonce holds for
    /// that nonce and that body.
    #[test]
    fn an_answer_seal_holds_for_its_question_and_body() {
        let seal = HmacRequestSeal::approvals(&test_root());
        let body = br#"{"result":"spent"}"#;

        let sealed = seal.seal_answer(&nonce("first"), body);

        assert!(seal.verifies_answer(&nonce("first"), body, &sealed));
        assert!(!seal.verifies_answer(&nonce("first"), br#"{"result":"refused"}"#, &sealed));
    }

    /// An answer seal fails verification when paired with another question's nonce.
    #[test]
    fn an_answer_seal_never_holds_for_another_question() {
        let seal = HmacRequestSeal::approvals(&test_root());
        let body = br#"{"result":"spent"}"#;

        let sealed = seal.seal_answer(&nonce("first"), body);

        assert!(!seal.verifies_answer(&nonce("second"), body, &sealed));
    }

    /// Request and answer seals cannot substitute for each other,
    /// and answer seals do not verify on another channel.
    #[test]
    fn an_answer_seal_is_apart_from_questions_and_other_channels() {
        let approvals = HmacRequestSeal::approvals(&test_root());
        let sign_in = HmacRequestSeal::new(&test_root());
        let body = br#"{"result":"spent"}"#;

        let as_question = approvals.seal(body);
        let as_answer = approvals.seal_answer(&nonce("first"), body);

        assert!(!approvals.verifies_answer(&nonce("first"), body, &as_question));
        assert!(!approvals.verifies(body, &as_answer));
        assert!(!sign_in.verifies_answer(&nonce("first"), body, &as_answer));
    }

    /// A chain head's seal holds for its own tenant, place and hash, and
    /// not when any of them is changed.
    #[test]
    fn a_chain_head_seal_holds_only_for_its_link() {
        let seals = AuditChainSeals::new(&test_root());
        let tenant = uuid::Uuid::now_v7();
        let sealed = seals.head_seal(&tenant, 7, &[1; 32]);

        assert!(seals.head_holds(&tenant, link(7, &[1; 32]), &sealed));
        assert!(!seals.head_holds(&tenant, link(6, &[1; 32]), &sealed));
        assert!(!seals.head_holds(&tenant, link(7, &[2; 32]), &sealed));
        assert!(!seals.head_holds(&uuid::Uuid::now_v7(), link(7, &[1; 32]), &sealed));
    }

    /// Head, anchor and verdict seals are distinct. An anchor seal verifies
    /// for its own tenant but fails for another tenant.
    #[test]
    fn a_seal_of_one_kind_never_holds_as_another() {
        let seals = AuditChainSeals::new(&test_root());
        let tenant = uuid::Uuid::now_v7();
        let hash = [7_u8; 32];

        let head = seals.head_seal(&tenant, 3, &hash);
        let anchor = seals.anchor_seal(&tenant, 3, &hash);

        let link = ChainLink {
            seq: 3,
            hash: &hash,
        };
        assert!(seals.anchor_holds(&tenant, link, &anchor));
        assert!(!seals.anchor_holds(&tenant, link, &head));
        assert!(!seals.head_holds(&tenant, link, &anchor));
        assert!(!seals.anchor_holds(&uuid::Uuid::now_v7(), link, &anchor));
        assert!(!seals.verdict_holds(&tenant, &hash, &anchor));
    }

    /// A receipt's seal holds for the consumer it was handed to, and not
    /// for another consumer, another tenant or an altered receipt, nor
    /// when the consumer's name and the receipt are cut apart elsewhere.
    #[test]
    fn a_receipt_seal_holds_only_for_its_consumer() {
        let seal = ReceiptSeal::new(&test_root());
        let tenant = uuid::Uuid::now_v7();
        let sealed = seal.seal(&tenant, "sub-1", "body");

        let receipt = |body| SignedReceipt {
            body,
            seal: &sealed,
        };
        assert!(seal.holds(&tenant, "sub-1", receipt("body")));
        assert!(!seal.holds(&tenant, "sub-2", receipt("body")));
        assert!(!seal.holds(&tenant, "sub-1", receipt("bodz")));
        assert!(!seal.holds(&tenant, "sub-1b", receipt("ody")));
        assert!(!seal.holds(&uuid::Uuid::now_v7(), "sub-1", receipt("body")));
    }

    /// A presented token matches its own digest and no other.
    #[test]
    fn a_token_matches_only_its_own_digest() {
        let digest = KeyedDigest::of(&test_root(), Purpose::ScimTokens);
        let stored = digest.digest(&secret("scim_right"));

        assert!(digest.matches(&secret("scim_right"), &stored));
        assert!(!digest.matches(&secret("scim_wrong"), &stored));
    }
}
