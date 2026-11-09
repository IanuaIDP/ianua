//! SAML, both ways: as a connection's service provider, checking the
//! answers its identity provider sends and writing the requests and
//! metadata it sends, and as a tenant's identity provider, signing and
//! sealing assertions for its apps and reading what those apps send.
//!
//! Every message is read from its parsed tree, by namespace and name, and
//! its signature checked over the very element read, so a signed element
//! cannot be wrapped, moved or copied beside a forged one. Algorithms come
//! from a fixed list and keys from the certificates registered for the
//! sender, never from the message. Anything in doubt is refused.
//!
//! The adapters lead with what they rest on, as the crypto ones do: XML
//! Signature (`Dsig`), the screened client, the HTTP-Redirect binding, RSA,
//! HMAC, XML Encryption and X.509.

mod certificates;
mod conditions;
mod encryption;
mod messages;
mod metadata;
mod name_ids;
mod outgoing;
mod redirect;
mod signer;
mod validator;
mod xml;

pub use certificates::{RsaSamlEncryptionKeys, X509SigningCertificateIssuer};
pub use encryption::XmlEncAssertionEncrypter;
pub use messages::DsigSamlMessageReader;
pub use metadata::ScreenedSamlMetadataReader;
pub use name_ids::HmacSamlNameIds;
pub use outgoing::RedirectSamlServiceProviderMessages;
pub use signer::EnvelopedXmlSigner;
pub use validator::DsigSamlValidator;
