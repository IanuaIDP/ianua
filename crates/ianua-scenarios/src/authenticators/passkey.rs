//! A software passkey: one P-256 key pair, answering a registration with a
//! `none` attestation and a sign-in with an ES256 signature, as a browser
//! hands a platform authenticator's answers on.
//!
//! The platform hands a ceremony's options to the browser as base64url
//! JSON, `{"publicKey": {...}}`, the way `webauthn-rs` writes them. The
//! passkey reads the challenge and the relying party's id from there,
//! writes the client data a browser would for the page it runs on, and
//! signs what WebAuthn signs: the authenticator data followed by the
//! SHA-256 of the client data. Its answer goes back base64url-encoded, the
//! JSON `navigator.credentials` would return.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use rand::RngCore as _;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use url::Url;

use super::cbor;

/// The user was present: touched the key.
const PRESENT: u8 = 0x01;

/// The user was verified: a PIN or a biometric.
const VERIFIED: u8 = 0x04;

/// Attested credential data follows.
const ATTESTED: u8 = 0x40;

/// The COSE key type of an elliptic-curve key.
const COSE_EC2: i64 = 2;

/// The COSE algorithm ES256.
const COSE_ES256: i64 = -7;

/// The COSE curve P-256.
const COSE_P256: i64 = 1;

/// The bytes of a credential id this passkey makes.
const CREDENTIAL_ID_BYTES: usize = 32;

/// What a passkey answers, as the API takes it: the credential the
/// browser returned, as base64url JSON, and the credential's id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyAnswer {
    /// The browser's answer, JSON written base64url.
    pub response: String,
    /// The credential that answered, base64url.
    pub credential_id: String,
}

/// A software authenticator holding one P-256 key, on the page at one
/// origin. `Debug` shows no key.
#[derive(Clone)]
pub struct SoftPasskey {
    key: SigningKey,
    credential_id: Vec<u8>,
    origin: String,
    sign_count: u32,
}

impl std::fmt::Debug for SoftPasskey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftPasskey")
            .field("credential_id", &self.credential_id())
            .field("origin", &self.origin)
            .field("sign_count", &self.sign_count)
            .finish_non_exhaustive()
    }
}

impl SoftPasskey {
    /// A new passkey, a fresh key pair and credential id, used on pages at
    /// `page`'s origin.
    #[must_use]
    pub fn new(page: &Url) -> Self {
        let mut credential_id = vec![0_u8; CREDENTIAL_ID_BYTES];
        rand::thread_rng().fill_bytes(&mut credential_id);
        Self {
            key: SigningKey::random(&mut rand::rngs::OsRng),
            credential_id,
            origin: page.origin().ascii_serialization(),
            sign_count: 0,
        }
    }

    /// The same key, used on a page at `page`'s origin instead, as when a
    /// phishing page relays the ceremony to it.
    #[must_use]
    pub fn on_page(&self, page: &Url) -> Self {
        Self {
            origin: page.origin().ascii_serialization(),
            ..self.clone()
        }
    }

    /// The credential's id, base64url.
    #[must_use]
    pub fn credential_id(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.credential_id)
    }

    /// The count its last signature carried.
    #[must_use]
    pub fn sign_count(&self) -> u32 {
        self.sign_count
    }

    /// Its answer to the registration whose options are `challenge`: a new
    /// credential with a `none` attestation, the person present and
    /// verified.
    ///
    /// # Panics
    ///
    /// When `challenge` does not read as WebAuthn creation options.
    #[must_use]
    pub fn register(&self, challenge: &str) -> PasskeyAnswer {
        let options = options_in(challenge);
        let relying_party = text_at(&options, "/publicKey/rp/id");
        let client_data = self.client_data("webauthn.create", &options);
        let auth_data = [
            Sha256::digest(relying_party.as_bytes()).to_vec(),
            vec![PRESENT | VERIFIED | ATTESTED],
            self.sign_count.to_be_bytes().to_vec(),
            vec![0; 16],
            (self.credential_id.len() as u16).to_be_bytes().to_vec(),
            self.credential_id.clone(),
            self.cose_key(),
        ]
        .concat();
        let attestation = cbor::map(&[
            (cbor::text("fmt"), cbor::text("none")),
            (cbor::text("attStmt"), cbor::map(&[])),
            (cbor::text("authData"), cbor::bytes(&auth_data)),
        ]);
        self.answer(&json!({
            "id": self.credential_id(),
            "rawId": self.credential_id(),
            "type": "public-key",
            "response": {
                "attestationObject": URL_SAFE_NO_PAD.encode(&attestation),
                "clientDataJSON": URL_SAFE_NO_PAD.encode(&client_data),
                "transports": ["internal"],
            },
            "extensions": {},
        }))
    }

    /// Its signed answer to the sign-in whose options are `challenge`, its
    /// count one higher than the last.
    ///
    /// # Panics
    ///
    /// When `challenge` does not read as WebAuthn request options.
    #[must_use]
    pub fn sign_in(&mut self, challenge: &str) -> PasskeyAnswer {
        self.sign_count += 1;
        self.assertion(challenge, self.sign_count)
    }

    /// A signed answer to `challenge` carrying the count of its last
    /// signature again, as a copy of the key would after the original
    /// signed: the count did not go up.
    ///
    /// # Panics
    ///
    /// When `challenge` does not read as WebAuthn request options.
    #[must_use]
    pub fn sign_in_repeating_count(&self, challenge: &str) -> PasskeyAnswer {
        self.assertion(challenge, self.sign_count)
    }

    /// An assertion over `challenge` at `count`.
    fn assertion(&self, challenge: &str, count: u32) -> PasskeyAnswer {
        let options = options_in(challenge);
        let relying_party = text_at(&options, "/publicKey/rpId");
        let client_data = self.client_data("webauthn.get", &options);
        let auth_data = [
            Sha256::digest(relying_party.as_bytes()).to_vec(),
            vec![PRESENT | VERIFIED],
            count.to_be_bytes().to_vec(),
        ]
        .concat();
        let signed = [auth_data.clone(), Sha256::digest(&client_data).to_vec()].concat();
        let signature: Signature = self.key.sign(&signed);
        self.answer(&json!({
            "id": self.credential_id(),
            "rawId": self.credential_id(),
            "type": "public-key",
            "response": {
                "authenticatorData": URL_SAFE_NO_PAD.encode(&auth_data),
                "clientDataJSON": URL_SAFE_NO_PAD.encode(&client_data),
                "signature": URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
                "userHandle": null,
            },
            "extensions": {},
        }))
    }

    /// The client data a browser writes for a ceremony of `kind` on this
    /// passkey's page.
    fn client_data(&self, kind: &str, options: &Value) -> Vec<u8> {
        let written = json!({
            "type": kind,
            "challenge": text_at(options, "/publicKey/challenge"),
            "origin": self.origin,
            "crossOrigin": false,
        });
        written.to_string().into_bytes()
    }

    /// The public key as COSE writes an ES256 key: kty, alg, crv, x, y.
    fn cose_key(&self) -> Vec<u8> {
        let point = self.key.verifying_key().to_encoded_point(false);
        let (Some(x), Some(y)) = (point.x(), point.y()) else {
            unreachable!("an uncompressed P-256 point has both coordinates");
        };
        cbor::map(&[
            (cbor::integer(1), cbor::integer(COSE_EC2)),
            (cbor::integer(3), cbor::integer(COSE_ES256)),
            (cbor::integer(-1), cbor::integer(COSE_P256)),
            (cbor::integer(-2), cbor::bytes(x)),
            (cbor::integer(-3), cbor::bytes(y)),
        ])
    }

    /// `credential` as the API takes it.
    fn answer(&self, credential: &Value) -> PasskeyAnswer {
        PasskeyAnswer {
            response: URL_SAFE_NO_PAD.encode(credential.to_string()),
            credential_id: self.credential_id(),
        }
    }
}

/// The options `challenge` carries, base64url JSON.
///
/// # Panics
///
/// When it is not base64url JSON.
fn options_in(challenge: &str) -> Value {
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(challenge.trim_end_matches('=')) else {
        panic!("the ceremony's challenge is not base64url");
    };
    let Ok(options) = serde_json::from_slice(&bytes) else {
        panic!("the ceremony's challenge is not JSON");
    };
    options
}

/// The text at `pointer` in `options`.
///
/// # Panics
///
/// When there is none, naming the pointer.
fn text_at<'a>(options: &'a Value, pointer: &str) -> &'a str {
    let Some(text) = options.pointer(pointer).and_then(Value::as_str) else {
        panic!("the ceremony's options have no {pointer}");
    };
    text
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier as _;

    use super::*;

    fn page() -> Url {
        Url::parse("https://app.s1.test/sign-in").unwrap()
    }

    fn encoded(options: &Value) -> String {
        URL_SAFE_NO_PAD.encode(options.to_string())
    }

    fn creation() -> String {
        encoded(&json!({ "publicKey": {
            "rp": { "id": "s1.test", "name": "Scenarios" },
            "user": { "id": "AQID", "name": "ann@s1.test", "displayName": "Ann" },
            "challenge": "c2lnbi1tZS11cA",
        }}))
    }

    fn request() -> String {
        encoded(&json!({ "publicKey": { "rpId": "s1.test", "challenge": "bG9nLW1lLWlu" }}))
    }

    fn decoded(answer: &PasskeyAnswer) -> Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&answer.response).unwrap()).unwrap()
    }

    fn field(answer: &Value, name: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD
            .decode(answer["response"][name].as_str().unwrap())
            .unwrap()
    }

    /// The client data names the challenge, the ceremony and the page's
    /// origin, as a browser writes it.
    #[test]
    fn the_client_data_names_the_challenge_and_the_origin() {
        let passkey = SoftPasskey::new(&page());

        let answer = decoded(&passkey.register(&creation()));
        let client: Value = serde_json::from_slice(&field(&answer, "clientDataJSON")).unwrap();

        assert_eq!(client["type"], "webauthn.create");
        assert_eq!(client["challenge"], "c2lnbi1tZS11cA");
        assert_eq!(client["origin"], "https://app.s1.test");
    }

    /// The authenticator data starts with the relying party's hash and the
    /// flags of a person present and verified, with a credential attested.
    #[test]
    fn the_registration_is_bound_to_the_relying_party() {
        let passkey = SoftPasskey::new(&page());

        let answer = decoded(&passkey.register(&creation()));
        let attestation = field(&answer, "attestationObject");

        let hash = Sha256::digest(b"s1.test");
        let at = attestation
            .windows(hash.len())
            .position(|window| window == hash.as_slice())
            .expect("the attestation holds the relying party's hash");
        assert_eq!(attestation[at + 32], PRESENT | VERIFIED | ATTESTED);
    }

    /// The signature verifies over the authenticator data and the client
    /// data's hash with the passkey's public key, and the count goes up.
    #[test]
    fn a_sign_in_is_signed_with_the_key_and_counts_up() {
        let mut passkey = SoftPasskey::new(&page());
        let public: VerifyingKey = *passkey.key.verifying_key();

        let first = decoded(&passkey.sign_in(&request()));
        let second = decoded(&passkey.sign_in(&request()));

        let auth_data = field(&second, "authenticatorData");
        let client_data = field(&second, "clientDataJSON");
        let signature = Signature::from_der(&field(&second, "signature")).unwrap();
        let signed = [auth_data.clone(), Sha256::digest(&client_data).to_vec()].concat();
        assert!(public.verify(&signed, &signature).is_ok());
        assert_eq!(auth_data[33..37], 2_u32.to_be_bytes());
        assert_eq!(
            field(&first, "authenticatorData")[33..37],
            1_u32.to_be_bytes()
        );
    }

    /// A repeated count is the count of the last signature.
    #[test]
    fn a_repeated_count_is_the_last_one() {
        let mut passkey = SoftPasskey::new(&page());
        let _ = passkey.sign_in(&request());

        let repeated = decoded(&passkey.sign_in_repeating_count(&request()));

        assert_eq!(
            field(&repeated, "authenticatorData")[33..37],
            1_u32.to_be_bytes()
        );
    }

    /// The same key on another page writes that page's origin.
    #[test]
    fn the_same_key_on_another_page_writes_its_origin() {
        let passkey = SoftPasskey::new(&page());
        let phished = passkey.on_page(&Url::parse("https://app.s1.example").unwrap());

        let answer = decoded(&phished.register(&creation()));
        let client: Value = serde_json::from_slice(&field(&answer, "clientDataJSON")).unwrap();

        assert_eq!(client["origin"], "https://app.s1.example");
        assert_eq!(phished.credential_id(), passkey.credential_id());
    }
}
