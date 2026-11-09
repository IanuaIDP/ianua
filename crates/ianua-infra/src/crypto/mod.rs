//! Cryptography: what the platform keeps secret and how it proves things.
//!
//! Two root secrets are configured, the one shared with the gateway and
//! the control plane's own; every key is derived from one of them for one
//! use ([`keys`]). Secrets kept at rest are sealed with AES-256-GCM under keys
//! that rotate, each bound to where it is kept ([`sealing`]); events and
//! live updates on the bus carry their publisher's seal; tokens handed out
//! once are kept only as keyed digests ([`issued`]); passwords are hashed
//! with Argon2id ([`passwords`]). Requests to AWS and to S3-compatible stores are signed
//! by one signer ([`sigv4`]). Nothing here holds a connection or calls out.

pub(crate) mod certificates;
mod hashes;
mod issued;
pub(crate) mod jws;
pub mod keys;
mod passwords;
mod random;
pub mod sealing;
mod seals;
pub mod sigv4;
mod tokens;
mod totp;

pub use certificates::{
    ConnectorCaError, ConnectorIdentity, ConnectorPki, ConnectorPkiValidity, InternalLeaf,
    InternalListener, InternalPki, KeyedCertificate, LdapCaError, LinkClient, LinkPki,
    LinkValidity, NoConnectorAuthority, NoLdapCertificateAuthority, RcgenConnectorAuthority,
    RcgenLdapCertificateAuthority, X509CertPemValidator, X509CertificateParser, connector_identity,
    issue_connector_pki, issue_internal_pki, issue_link_pki,
};
pub use hashes::{Sha2AtHashCalculator, Sha256PayloadHasher, Sha256PkceVerifier};
pub use issued::{
    HmacApiKeyGenerator, HmacClientSecretGenerator, HmacClientSecretVerifier, HmacCodeHasher,
    HmacConnectionSecrets, HmacConnectorCodeGenerator, HmacConsumerKeyDigests,
    HmacConsumerKeyGenerator, HmacReceiverKeys, HmacRecoveryCodeGenerator,
    HmacRefreshTokenGenerator, HmacScimTokenGenerator, HmacSentCodeGenerator,
    HmacServiceAccountSecrets, HmacTokenResolver, HmacWorkflowTriggerSecretGenerator,
    OsAttestationNonceGenerator, OsDestinationSecretGenerator, OsExternalIdGenerator,
    OsPushSecretGenerator, OsWebhookSecretGenerator,
};
pub use jws::{Pkcs8KeyGenerator, Pkcs8PublicKeyDecoder};
pub use keys::{RootSecret, RootSecretError};
pub use passwords::{
    Argon2PasswordHashFormat, Argon2PasswordHasher, Argon2Settings, PasswordHashError,
};
pub(crate) use random::{OsRandomSource, random_bytes};
pub use random::{OsSecureRandom, OsSecureTokenGenerator};
pub use sealing::{AesGcmSecretEncryptor, SealingError, SealingKey};
pub(crate) use seals::broadcasts::Vouched;
pub use seals::broadcasts::{BroadcastCheck, BroadcastSeal};
pub use seals::digests::{AuditChainSeals, HmacRedactionDigest, HmacRequestSeal, ReceiptSeal};
pub(crate) use seals::digests::{ChainLink, SignedReceipt};
pub(crate) use seals::events::raised_by_the_data_plane;
pub use seals::events::{EventCheck, EventSeal, SEAL_HEADER};
pub use seals::fleet::FleetVerdictSeal;
pub use tokens::{
    AssertionKeyMessageSigner, JwkClientAssertionVerifier, JwkConsumerTokenVerifier,
    JwkDpopProofVerifier, Pkcs8AccessTokenJwtVerifier, Pkcs8AgentAssertionVerifier,
    Pkcs8AppSessionTokens, Pkcs8AssertionSigner, Pkcs8AssertionVerifier, Pkcs8IdTokenHintVerifier,
    Pkcs8JwtSigner, Pkcs8MessageProvenanceSigner, Pkcs8MessageProvenanceVerifier,
    Pkcs8PresentedTokens, Pkcs8RunPasses, Pkcs8TaskTokenIssuer, Pkcs8TaskTokenVerifier,
    PublishedKeys,
};
pub(crate) use tokens::{Audiences, Times};
pub use totp::TotpMfaVerifier;
