//! Passkeys through WebAuthn: the ceremonies that register a passkey and
//! sign in with one, checked by `webauthn-rs`.
//!
//! A started ceremony comes back in two halves kept apart: the options the
//! browser needs, and the state its answer is checked against, which never
//! leaves the server and is sealed ([`state`]) so only a state this server
//! made, for that kind of ceremony, is ever used. The key a passkey stores
//! is the `webauthn-rs` credential as JSON, opaque to everyone but this
//! adapter.
//!
//! Everything is refused that does not verify: an answer that does not
//! read, comes from another origin, signs another challenge, was made
//! without the person verified on the authenticator, or comes from another
//! passkey than the one it is checked against. Nothing here calls out.

mod decoy;
mod state;

use std::fmt;

use async_trait::async_trait;
use ianua_app::ports::authentication::{
    PasskeyAuthenticationResult, PasskeyRegistrationResult, PasskeyVerifier, StartedCeremony,
};
use ianua_domain::domains::authentication::credentials::passkey::{
    AuthenticatorType, KeyAttestation,
};
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, PasskeyCredentialId, UserId};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use url::Url;
use webauthn_rs::prelude::{
    AuthenticationResult, DiscoverableAuthentication, DiscoverableKey, Passkey,
    PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    Uuid, Webauthn, WebauthnBuilder,
};
use webauthn_rs_proto::AuthenticatorTransport;

use crate::crypto::keys::RootSecret;
use crate::proofs::passkeys::decoy::{DecoyCredentials, naming_one};
use crate::proofs::passkeys::state::{CeremonyKind, CeremonySeal};

/// Whether pages on subdomains of the relying party's origins may run its
/// ceremonies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubdomainOrigins {
    /// Only the origins named.
    Refused,
    /// The origins named and every subdomain of them, as for a deployment
    /// where each tenant signs in on its own subdomain.
    Accepted,
}

/// The relying party passkeys are made for, from the deployment's
/// configuration.
#[derive(Debug, Clone)]
pub struct PasskeySettings {
    /// The relying party's id, the domain every passkey is bound to, such
    /// as `example.com`. It can never change: a passkey made for one id
    /// signs in nowhere else.
    pub relying_party_id: String,
    /// The name an authenticator shows the person.
    pub relying_party_name: String,
    /// The origin the sign-in pages are served from.
    pub origin: Url,
    /// Further origins the pages may be served from, such as the
    /// organization dashboard's.
    pub other_origins: Vec<Url>,
    /// Whether subdomains of those origins may run ceremonies too.
    pub subdomains: SubdomainOrigins,
}

/// The [`PasskeyVerifier`] over `webauthn-rs`.
pub struct WebauthnPasskeyVerifier {
    webauthn: Webauthn,
    seal: CeremonySeal,
    decoys: DecoyCredentials,
}

impl fmt::Debug for WebauthnPasskeyVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebauthnPasskeyVerifier")
            .field("origins", &self.webauthn.get_allowed_origins())
            .finish_non_exhaustive()
    }
}

impl WebauthnPasskeyVerifier {
    /// A verifier for the relying party `settings` names, sealing
    /// ceremony states and working out decoys under keys `root` derives.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the relying party's id
    /// does not fit its origins.
    pub fn new(settings: &PasskeySettings, root: &RootSecret) -> Result<Self, DomainError> {
        let webauthn = settings
            .other_origins
            .iter()
            .fold(
                WebauthnBuilder::new(&settings.relying_party_id, &settings.origin)
                    .map_err(DomainError::infra)?,
                WebauthnBuilder::append_allowed_origin,
            )
            .rp_name(&settings.relying_party_name)
            .allow_subdomains(matches!(settings.subdomains, SubdomainOrigins::Accepted))
            .build()
            .map_err(DomainError::infra)?;
        Ok(Self {
            webauthn,
            seal: CeremonySeal::new(root),
            decoys: DecoyCredentials::new(root),
        })
    }

    /// The browser's half of a ceremony and its sealed state.
    fn started(
        &self,
        options: &impl Serialize,
        kind: CeremonyKind,
        state: &impl Serialize,
    ) -> Result<StartedCeremony, DomainError> {
        Ok(StartedCeremony {
            client_payload: serde_json::to_vec(options).map_err(DomainError::infra)?,
            server_state: self.seal.seal(kind, state)?,
        })
    }
}

#[async_trait]
impl PasskeyVerifier for WebauthnPasskeyVerifier {
    async fn start_registration(
        &self,
        user_id: &UserId,
        user_name: &Email,
    ) -> Result<StartedCeremony, DomainError> {
        let user = Uuid::from_bytes(*user_id.as_uuid().as_bytes());
        let name = user_name.as_str();
        let (options, state) = self
            .webauthn
            .start_passkey_registration(user, name, name, None)
            .map_err(DomainError::infra)?;
        self.started(&options, CeremonyKind::Registration, &state)
    }

    async fn start_authentication(
        &self,
        stored_credentials: &[Vec<u8>],
    ) -> Result<StartedCeremony, DomainError> {
        if stored_credentials.is_empty() {
            return Err(DomainError::invalid(message!(
                "infra-there-is-no-passkey-to-sign",
                "there is no passkey to sign in with"
            )));
        }
        let passkeys = stored_credentials
            .iter()
            .map(Vec::as_slice)
            .map(stored_passkey)
            .collect::<Result<Vec<_>, _>>()?;
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(DomainError::infra)?;
        self.started(&options, CeremonyKind::Authentication, &state)
    }

    async fn start_decoy_authentication(
        &self,
        address: &Email,
    ) -> Result<StartedCeremony, DomainError> {
        let (fresh, _) = self
            .webauthn
            .start_discoverable_authentication()
            .map_err(DomainError::infra)?;
        let options = naming_one(fresh, self.decoys.listed_for(address));
        self.started(&options, CeremonyKind::Decoy, &())
    }

    async fn verify_registration(
        &self,
        server_state: &[u8],
        response: &[u8],
    ) -> Result<PasskeyRegistrationResult, DomainError> {
        let state: PasskeyRegistration =
            self.seal.open(CeremonyKind::Registration, server_state)?;
        let answer: RegisterPublicKeyCredential = answer_in(response)?;
        let passkey = self
            .webauthn
            .finish_passkey_registration(&answer, &state)
            .map_err(|_| does_not_verify())?;
        registered(&passkey, answer.response.transports.as_deref())
    }

    async fn verify_authentication(
        &self,
        server_state: &[u8],
        response: &[u8],
        public_key: &[u8],
        _sign_count: u32,
    ) -> Result<PasskeyAuthenticationResult, DomainError> {
        let state: PasskeyAuthentication =
            self.seal.open(CeremonyKind::Authentication, server_state)?;
        let answer: PublicKeyCredential = answer_in(response)?;
        let passkey = stored_passkey(public_key)?;
        let result = self
            .webauthn
            .finish_passkey_authentication(&answer, &state)
            .map_err(|_| does_not_verify())?;
        signed_in(&passkey, &result)
    }

    async fn start_discoverable_authentication(&self) -> Result<StartedCeremony, DomainError> {
        let (options, state) = self
            .webauthn
            .start_discoverable_authentication()
            .map_err(DomainError::infra)?;
        self.started(&options, CeremonyKind::Discoverable, &state)
    }

    async fn verify_discoverable_authentication(
        &self,
        server_state: &[u8],
        response: &[u8],
        public_key: &[u8],
        _sign_count: u32,
    ) -> Result<PasskeyAuthenticationResult, DomainError> {
        let state: DiscoverableAuthentication =
            self.seal.open(CeremonyKind::Discoverable, server_state)?;
        let answer: PublicKeyCredential = answer_in(response)?;
        let passkey = stored_passkey(public_key)?;
        let result = self
            .webauthn
            .finish_discoverable_authentication(&answer, state, &[DiscoverableKey::from(&passkey)])
            .map_err(|_| does_not_verify())?;
        signed_in(&passkey, &result)
    }
}

/// The passkey a stored key holds, as [`registered`] wrote it.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the stored key is not one:
/// only this adapter writes them, so the fault is the store's.
fn stored_passkey(stored: &[u8]) -> Result<Passkey, DomainError> {
    serde_json::from_slice(stored).map_err(|_| {
        DomainError::corrupt_row(
            "passkey",
            "the stored key does not read as a WebAuthn credential",
        )
    })
}

/// The authenticator's answer, as WebAuthn writes it.
///
/// # Errors
///
/// Returns `DomainError::Validation` when it does not read as one.
fn answer_in<T: DeserializeOwned>(response: &[u8]) -> Result<T, DomainError> {
    serde_json::from_slice(response).map_err(|_| {
        DomainError::invalid(message!(
            "infra-the-authenticator-s-answer-does-not",
            "the authenticator's answer does not read as WebAuthn"
        ))
    })
}

/// The refusal of an answer that does not verify. It says nothing of why,
/// so a forger learns nothing from it.
fn does_not_verify() -> DomainError {
    DomainError::unauthorized(message!(
        "authentication-the-passkey-s-answer-does-not",
        "the passkey's answer does not verify"
    ))
}

/// What a verified registration added: the passkey to keep, its id, the
/// count it starts from and where the browser said it lives.
///
/// A passkey registration asks for no attestation, so none was checked
/// and the key counts as [`KeyAttestation::Unattested`]: it may be a copy
/// synced to another device.
fn registered(
    passkey: &Passkey,
    transports: Option<&[AuthenticatorTransport]>,
) -> Result<PasskeyRegistrationResult, DomainError> {
    let public_key = serde_json::to_vec(passkey).map_err(DomainError::infra)?;
    let sign_count = serde_json::from_slice::<CountedPasskey>(&public_key)
        .map_err(DomainError::infra)?
        .cred
        .counter;
    Ok(PasskeyRegistrationResult {
        credential_id: PasskeyCredentialId::new(passkey.cred_id().to_vec())?,
        public_key,
        sign_count,
        authenticator_type: authenticator_type(transports),
        attestation: KeyAttestation::Unattested,
    })
}

/// The count a stored passkey holds, read from the JSON `webauthn-rs`
/// writes it as, which keeps the counter its authenticator started at.
#[derive(Deserialize)]
struct CountedPasskey {
    cred: CountedCredential,
}

/// The one field of a stored credential [`CountedPasskey`] reads.
#[derive(Deserialize)]
struct CountedCredential {
    counter: u32,
}

/// Where the browser said a new passkey lives. A key reached inside the
/// device is the device's own; anything else, or nothing said, roams.
fn authenticator_type(transports: Option<&[AuthenticatorTransport]>) -> AuthenticatorType {
    let inside = transports
        .unwrap_or_default()
        .iter()
        .any(|transport| matches!(transport, AuthenticatorTransport::Internal));
    if inside {
        return AuthenticatorType::Platform;
    }
    AuthenticatorType::CrossPlatform
}

/// What a verified sign-in proved, once it is sure it came from `passkey`
/// with the person verified on the authenticator. The new count is the
/// authenticator's; whether it went up is the domain's to judge.
///
/// # Errors
///
/// Returns `DomainError::Unauthorized` when the authenticator did not
/// verify the person, or another passkey answered.
fn signed_in(
    passkey: &Passkey,
    result: &AuthenticationResult,
) -> Result<PasskeyAuthenticationResult, DomainError> {
    if !result.user_verified() {
        return Err(DomainError::unauthorized(message!(
            "infra-the-authenticator-did-not-verify-its",
            "the authenticator did not verify its user; set a PIN or use a biometric"
        )));
    }
    if result.cred_id().as_slice() != passkey.cred_id().as_slice() {
        return Err(does_not_verify());
    }
    Ok(PasskeyAuthenticationResult {
        credential_id: PasskeyCredentialId::new(result.cred_id().to_vec())?,
        new_sign_count: result.counter(),
    })
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{Signature, SigningKey};
    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::crypto::keys::tests::test_root;

    const ORIGIN: &str = "https://login.example.com";
    const RELYING_PARTY: &str = "login.example.com";
    const PRESENT: u8 = 0x01;
    const VERIFIED: u8 = 0x04;
    const ATTESTED: u8 = 0x40;

    fn settings() -> PasskeySettings {
        PasskeySettings {
            relying_party_id: RELYING_PARTY.to_owned(),
            relying_party_name: "Example".to_owned(),
            origin: Url::parse(ORIGIN).unwrap(),
            other_origins: Vec::new(),
            subdomains: SubdomainOrigins::Refused,
        }
    }

    fn verifier() -> WebauthnPasskeyVerifier {
        WebauthnPasskeyVerifier::new(&settings(), &test_root()).unwrap()
    }

    fn address(text: &str) -> Email {
        Email::new(text).unwrap()
    }

    fn encoded(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// The challenge a started ceremony's options carry, as written there.
    fn challenge_of(started: &StartedCeremony) -> String {
        let options: Value = serde_json::from_slice(&started.client_payload).unwrap();
        options["publicKey"]["challenge"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// The options a started ceremony hands the browser, as JSON.
    fn options_of(started: &StartedCeremony) -> Value {
        serde_json::from_slice(&started.client_payload).unwrap()
    }

    /// The head of a CBOR item of `major` type and `length`.
    fn cbor_head(major: u8, length: usize) -> Vec<u8> {
        if length < 24 {
            return vec![(major << 5) | length as u8];
        }
        if length < 256 {
            return vec![(major << 5) | 24, length as u8];
        }
        let mut head = vec![(major << 5) | 25];
        head.extend((length as u16).to_be_bytes());
        head
    }

    fn cbor_bytes(bytes: &[u8]) -> Vec<u8> {
        [cbor_head(2, bytes.len()), bytes.to_vec()].concat()
    }

    fn cbor_text(text: &str) -> Vec<u8> {
        [cbor_head(3, text.len()), text.as_bytes().to_vec()].concat()
    }

    /// A software authenticator holding one P-256 key, answering as a
    /// browser would hand its answers on.
    struct Authenticator {
        key: SigningKey,
        credential_id: Vec<u8>,
        origin: &'static str,
        flags: u8,
    }

    impl Authenticator {
        fn new() -> Self {
            Self::on(ORIGIN)
        }

        /// One answering from the page at `origin`.
        fn on(origin: &'static str) -> Self {
            Self {
                key: SigningKey::random(&mut rand::rngs::OsRng),
                credential_id: rand::random::<[u8; 16]>().to_vec(),
                origin,
                flags: PRESENT | VERIFIED,
            }
        }

        /// The same key, answering without verifying its user.
        fn without_verifying(self) -> Self {
            Self {
                flags: PRESENT,
                ..self
            }
        }

        fn client_data(&self, kind: &str, started: &StartedCeremony) -> Vec<u8> {
            serde_json::to_vec(&json!({
                "type": kind,
                "challenge": challenge_of(started),
                "origin": self.origin,
                "crossOrigin": false,
            }))
            .unwrap()
        }

        fn cose_key(&self) -> Vec<u8> {
            let point = self.key.verifying_key().to_encoded_point(false);
            [
                vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21],
                cbor_bytes(point.x().unwrap()),
                vec![0x22],
                cbor_bytes(point.y().unwrap()),
            ]
            .concat()
        }

        /// Its answer to a registration challenge, attesting nothing.
        fn register(&self, started: &StartedCeremony) -> Vec<u8> {
            let client_data = self.client_data("webauthn.create", started);
            let auth_data = self.registration_data();
            let attestation = [
                vec![0xa3],
                cbor_text("fmt"),
                cbor_text("none"),
                cbor_text("attStmt"),
                vec![0xa0],
                cbor_text("authData"),
                cbor_bytes(&auth_data),
            ]
            .concat();
            serde_json::to_vec(&json!({
                "id": encoded(&self.credential_id),
                "rawId": encoded(&self.credential_id),
                "type": "public-key",
                "response": {
                    "attestationObject": encoded(&attestation),
                    "clientDataJSON": encoded(&client_data),
                    "transports": ["internal"],
                },
                "extensions": {},
            }))
            .unwrap()
        }

        /// Encodes the attested credential with its relying-party hash and initial counter.
        fn registration_data(&self) -> Vec<u8> {
            [
                Sha256::digest(RELYING_PARTY.as_bytes()).to_vec(),
                vec![self.flags | ATTESTED],
                0_u32.to_be_bytes().to_vec(),
                vec![0; 16],
                (self.credential_id.len() as u16).to_be_bytes().to_vec(),
                self.credential_id.clone(),
                self.cose_key(),
            ]
            .concat()
        }

        /// Its signed answer to a sign-in challenge, at `counter`.
        fn assert(&self, started: &StartedCeremony, counter: u32) -> Vec<u8> {
            let client_data = self.client_data("webauthn.get", started);
            let auth_data = [
                Sha256::digest(RELYING_PARTY.as_bytes()).to_vec(),
                vec![self.flags],
                counter.to_be_bytes().to_vec(),
            ]
            .concat();
            let signed = [auth_data.clone(), Sha256::digest(&client_data).to_vec()].concat();
            let signature: Signature = self.key.sign(&signed);
            serde_json::to_vec(&json!({
                "id": encoded(&self.credential_id),
                "rawId": encoded(&self.credential_id),
                "type": "public-key",
                "response": {
                    "authenticatorData": encoded(&auth_data),
                    "clientDataJSON": encoded(&client_data),
                    "signature": encoded(signature.to_der().as_bytes()),
                    "userHandle": null,
                },
                "extensions": {},
            }))
            .unwrap()
        }
    }

    /// `authenticator`'s passkey, registered with `verifier` for Ann.
    async fn registered(
        verifier: &WebauthnPasskeyVerifier,
        authenticator: &Authenticator,
    ) -> PasskeyRegistrationResult {
        let started = verifier
            .start_registration(&UserId::new(), &address("ann@example.com"))
            .await
            .unwrap();
        verifier
            .verify_registration(&started.server_state, &authenticator.register(&started))
            .await
            .unwrap()
    }

    /// A passkey made on the device registers with its credential id, the
    /// counter it started at, the place the browser said it lives, and no
    /// attestation claimed.
    #[tokio::test]
    async fn a_new_passkey_registers() {
        let verifier = verifier();
        let authenticator = Authenticator::new();

        let added = registered(&verifier, &authenticator).await;

        assert_eq!(
            added.credential_id.as_bytes(),
            authenticator.credential_id.as_slice()
        );
        assert_eq!(added.sign_count, 0);
        assert_eq!(added.authenticator_type, AuthenticatorType::Platform);
        assert_eq!(added.attestation, KeyAttestation::Unattested);
    }

    /// A registered passkey signs in against a challenge naming it, and
    /// the count it reports comes back.
    #[tokio::test]
    async fn a_registered_passkey_signs_in() {
        let verifier = verifier();
        let authenticator = Authenticator::new();
        let added = registered(&verifier, &authenticator).await;
        let started = verifier
            .start_authentication(std::slice::from_ref(&added.public_key))
            .await
            .unwrap();

        let signed = verifier
            .verify_authentication(
                &started.server_state,
                &authenticator.assert(&started, 7),
                &added.public_key,
                0,
            )
            .await
            .unwrap();

        assert_eq!(signed.credential_id, added.credential_id);
        assert_eq!(signed.new_sign_count, 7);
    }

    /// A passkey signs in on a challenge naming no one, checked against
    /// the key it names.
    #[tokio::test]
    async fn a_passkey_signs_in_without_a_name_given() {
        let verifier = verifier();
        let authenticator = Authenticator::new();
        let added = registered(&verifier, &authenticator).await;
        let started = verifier.start_discoverable_authentication().await.unwrap();

        let signed = verifier
            .verify_discoverable_authentication(
                &started.server_state,
                &authenticator.assert(&started, 1),
                &added.public_key,
                0,
            )
            .await;

        assert_eq!(signed.unwrap().credential_id, added.credential_id);
    }

    /// A registration response naming another origin fails verification as unauthorized.
    #[tokio::test]
    async fn an_answer_from_another_origin_is_refused() {
        let verifier = verifier();
        let started = verifier
            .start_registration(&UserId::new(), &address("ann@example.com"))
            .await
            .unwrap();
        let phished = Authenticator::on("https://login.example.net").register(&started);

        let result = verifier
            .verify_registration(&started.server_state, &phished)
            .await;

        assert!(matches!(result, Err(DomainError::Unauthorized(_))));
    }

    /// Authentication fails when the authenticator has not verified the user.
    #[tokio::test]
    async fn a_sign_in_without_the_person_verified_is_refused() {
        let verifier = verifier();
        let authenticator = Authenticator::new();
        let added = registered(&verifier, &authenticator).await;
        let started = verifier
            .start_authentication(std::slice::from_ref(&added.public_key))
            .await
            .unwrap();
        let lazy = authenticator.without_verifying();

        let result = verifier
            .verify_authentication(
                &started.server_state,
                &lazy.assert(&started, 1),
                &added.public_key,
                0,
            )
            .await;

        assert!(result.is_err());
    }

    /// Mallory's passkey response cannot authenticate against Ann's stored credential.
    #[tokio::test]
    async fn an_answer_from_another_passkey_is_refused() {
        let verifier = verifier();
        let ann = Authenticator::new();
        let mallory = Authenticator::new();
        let ann_key = registered(&verifier, &ann).await;
        let mallory_key = registered(&verifier, &mallory).await;
        let started = verifier
            .start_authentication(&[ann_key.public_key.clone(), mallory_key.public_key])
            .await
            .unwrap();

        let result = verifier
            .verify_authentication(
                &started.server_state,
                &mallory.assert(&started, 1),
                &ann_key.public_key,
                0,
            )
            .await;

        assert!(matches!(result, Err(DomainError::Unauthorized(_))));
    }

    /// Ceremony state sealed by another server root makes the response unauthorized.
    #[tokio::test]
    async fn a_state_from_another_server_is_refused() {
        let other_root = RootSecret::parse(&"cd".repeat(32)).unwrap();
        let other = WebauthnPasskeyVerifier::new(&settings(), &other_root).unwrap();
        let started = other
            .start_registration(&UserId::new(), &address("ann@example.com"))
            .await
            .unwrap();
        let answer = Authenticator::new().register(&started);

        let result = verifier()
            .verify_registration(&started.server_state, &answer)
            .await;

        assert!(matches!(result, Err(DomainError::Unauthorized(_))));
    }

    /// Registration state cannot be used to verify an authentication response.
    #[tokio::test]
    async fn a_state_of_another_ceremony_is_refused() {
        let verifier = verifier();
        let authenticator = Authenticator::new();
        let added = registered(&verifier, &authenticator).await;
        let registering = verifier
            .start_registration(&UserId::new(), &address("ann@example.com"))
            .await
            .unwrap();

        let result = verifier
            .verify_authentication(
                &registering.server_state,
                &authenticator.assert(&registering, 1),
                &added.public_key,
                0,
            )
            .await;

        assert!(matches!(result, Err(DomainError::Unauthorized(_))));
    }

    /// An empty WebAuthn response produces a validation error.
    #[tokio::test]
    async fn an_unreadable_answer_is_refused() {
        let verifier = verifier();
        let started = verifier
            .start_registration(&UserId::new(), &address("ann@example.com"))
            .await
            .unwrap();

        let result = verifier
            .verify_registration(&started.server_state, b"{}")
            .await;

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// An unreadable stored WebAuthn credential produces an infrastructure error instead of being skipped.
    #[tokio::test]
    async fn a_stored_key_that_does_not_read_is_a_store_fault() {
        let result = verifier()
            .start_authentication(&[b"not a key".to_vec()])
            .await;

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// Starting authentication with an empty credential list fails.
    #[tokio::test]
    async fn a_challenge_over_no_passkey_is_refused() {
        let result = verifier().start_authentication(&[]).await;

        assert!(result.is_err());
    }

    /// A decoy reads as a real one-passkey challenge: the same fields, one
    /// credential listed, no mediation, and the same credential for the
    /// same address every time.
    #[tokio::test]
    async fn a_decoy_reads_as_a_real_challenge() {
        let verifier = verifier();
        let added = registered(&verifier, &Authenticator::new()).await;
        let real = options_of(
            &verifier
                .start_authentication(&[added.public_key])
                .await
                .unwrap(),
        );
        let ann = address("ann@example.com");

        let first = options_of(&verifier.start_decoy_authentication(&ann).await.unwrap());
        let again = options_of(&verifier.start_decoy_authentication(&ann).await.unwrap());

        assert_eq!(option_fields(&first), option_fields(&real));
        assert_eq!(first.get("mediation"), real.get("mediation"));
        assert_eq!(
            first["publicKey"]["allowCredentials"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            first["publicKey"]["allowCredentials"],
            again["publicKey"]["allowCredentials"]
        );
        assert_ne!(
            first["publicKey"]["challenge"],
            again["publicKey"]["challenge"]
        );
    }

    /// Lists challenge option names in a stable order for real and decoy comparisons.
    fn option_fields(options: &Value) -> Vec<String> {
        let mut keys: Vec<String> = options["publicKey"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        keys.sort();
        keys
    }

    /// Decoy and real challenge credentials expose the same field names.
    #[tokio::test]
    async fn a_decoy_credential_names_what_a_real_one_names() {
        let verifier = verifier();
        let added = registered(&verifier, &Authenticator::new()).await;
        let real = options_of(
            &verifier
                .start_authentication(&[added.public_key])
                .await
                .unwrap(),
        );
        let decoy = options_of(
            &verifier
                .start_decoy_authentication(&address("bob@example.com"))
                .await
                .unwrap(),
        );

        let named = |options: &Value| {
            let mut keys: Vec<String> = options["publicKey"]["allowCredentials"][0]
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect();
            keys.sort();
            keys
        };
        assert_eq!(named(&decoy), named(&real));
    }

    /// A signed response to a decoy challenge fails authentication as unauthorized.
    #[tokio::test]
    async fn no_answer_to_a_decoy_verifies() {
        let verifier = verifier();
        let authenticator = Authenticator::new();
        let added = registered(&verifier, &authenticator).await;
        let decoy = verifier
            .start_decoy_authentication(&address("bob@example.com"))
            .await
            .unwrap();

        let result = verifier
            .verify_authentication(
                &decoy.server_state,
                &authenticator.assert(&decoy, 1),
                &added.public_key,
                0,
            )
            .await;

        assert!(matches!(result, Err(DomainError::Unauthorized(_))));
    }
}
