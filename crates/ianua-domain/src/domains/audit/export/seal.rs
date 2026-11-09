//! What lets an auditor trust a tenant's export file after it has left the
//! platform.
//!
//! Ann hands Acme's exported log to an outside auditor. The worker took the
//! SHA-256 of the file as it wrote it, and signed a statement naming that
//! digest, the export and how many records it holds with Acme's signing
//! key. The auditor checks the signature against the keys Acme publishes
//! and the digest against the file. A record removed or changed on the
//! way breaks the digest; a statement made up for another file breaks the
//! signature.
//!
//! Only a tenant publishes signing keys, so only a tenant's exports are
//! sealed. An organization's or the platform's export carries its digest
//! alone.

use time::OffsetDateTime;

use crate::domains::audit::export::filter::AuditExportFormat;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::{Charset, Rule, TextValue, ValidationError, Validator, text_value};
use crate::types::{AuditExportId, TenantId};

/// The longest seal kept, in bytes: a compact JWS over a short statement,
/// with room for the largest signature a tenant key makes.
const LONGEST_SEAL: usize = 4096;

/// The SHA-256 of an export's file, taken while it was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileDigest([u8; 32]);

impl FileDigest {
    /// The digest from the 32 bytes a SHA-256 gives.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when `bytes` is not 32 long: a
    ///   stored digest that is not a SHA-256 is corrupt.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DomainError> {
        <[u8; 32]>::try_from(bytes).map(Self).map_err(|_| {
            DomainError::corrupt_row("audit log export", "a file digest that is not a SHA-256")
        })
    }

    /// The 32 bytes, as storage keeps them.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The digest in lower-case hex, as the signed statement and the export's
    /// details show it.
    #[must_use]
    pub fn hex(&self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

text_value! {
    /// The compact JWS the worker signed over an export's
    /// [`SealStatement`] with the tenant's signing key.
    pub struct ExportSeal;
}

impl TextValue for ExportSeal {
    const FIELD: &'static str = "seal";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .max_bytes(LONGEST_SEAL)
            .charset(
                Charset::LOWERCASE
                    | Charset::UPPERCASE
                    | Charset::DIGIT
                    | Charset::HYPHEN
                    | Charset::UNDERSCORE
                    | Charset::DOT,
            )
            .rule(&ThreeParts)
    }
}

/// A header, a payload and a signature, none of them empty.
struct ThreeParts;

impl Rule for ThreeParts {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let parts: Vec<&str> = value.split('.').collect();
        if parts.len() == 3 && parts.iter().all(|part| !part.is_empty()) {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "invalid_seal".to_owned(),
            message: message!(
                "audit-a-seal-is-a-compact-jws",
                format!("{field} must be a compact JWS: a header, a payload and a signature")
            ),
        })
    }
}

/// What a seal says about one tenant export, for the worker to sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealStatement {
    /// The export the file is of, its `jti`.
    pub export_id: AuditExportId,
    /// The tenant whose log it is.
    pub tenant_id: TenantId,
    /// How the file is written.
    pub format: AuditExportFormat,
    /// The newest moment the file covers.
    pub covers_until: OffsetDateTime,
    /// How many records it holds.
    pub rows: u64,
    /// The file's SHA-256.
    pub digest: FileDigest,
}

/// The file the worker wrote: how many records it holds, its digest, and
/// for a tenant's log the seal over them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenFile {
    /// How many records it holds.
    pub rows: u64,
    /// Its SHA-256.
    pub digest: FileDigest,
    /// The seal over its statement; only a tenant's export has one.
    pub seal: Option<ExportSeal>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A digest shows as 64 lower-case hex digits, the way `sha256sum`
    /// prints it, so an auditor compares them by eye.
    #[test]
    fn a_digest_shows_as_lower_case_hex() {
        let digest = FileDigest::from_bytes(&[0xAB; 32]).unwrap();

        assert_eq!(digest.hex(), "ab".repeat(32));
    }

    /// A stored digest of 31 bytes is no SHA-256 and is refused as corrupt.
    #[test]
    fn a_digest_of_the_wrong_length_is_refused() {
        let refused = FileDigest::from_bytes(&[0; 31]);

        assert!(matches!(refused, Err(DomainError::Infrastructure(_))));
    }

    /// A compact JWS is kept; text of two parts, or with an empty
    /// signature, is no seal.
    #[test]
    fn a_seal_is_a_compact_jws() {
        assert!(ExportSeal::new("eyJh.eyJi.c2ln").is_ok());
        assert!(ExportSeal::new("eyJh.eyJi").is_err());
        assert!(ExportSeal::new("eyJh.eyJi.").is_err());
        assert!(ExportSeal::new("eyJh.ey Ji.c2ln").is_err());
    }
}
