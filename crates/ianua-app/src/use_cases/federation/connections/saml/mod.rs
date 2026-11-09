//! SAML specifics: certificates, encrypted assertions, metadata, and the
//! sweep that reads a followed metadata address again.

pub(crate) mod accept_readable_assertions;
pub(crate) mod refresh_metadata;
pub(crate) mod require_encrypted_assertions;
pub(crate) mod roll_over_certificate;
pub(crate) mod sp_metadata;

pub use accept_readable_assertions::{
    AcceptReadableAssertionsPorts, AcceptReadableAssertionsUseCase,
};
pub use refresh_metadata::{RefreshMetadataPorts, RefreshMetadataUseCase};
pub use require_encrypted_assertions::{
    RequireEncryptedAssertionsPorts, RequireEncryptedAssertionsRequest,
    RequireEncryptedAssertionsUseCase, SpKeySource,
};
pub use roll_over_certificate::{RollOverCertificatePorts, RollOverCertificateUseCase};
pub use sp_metadata::{SpMetadataPorts, SpMetadataRequest, SpMetadataUseCase};
