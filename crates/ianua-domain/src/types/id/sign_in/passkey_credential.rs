//! The id an authenticator gave a passkey.

use std::fmt;

use crate::shared::validation::ValidationError;
use crate::shared::validation::numeric::validate_count;

/// The longest credential id WebAuthn allows, in bytes.
const MAX_CREDENTIAL_ID_BYTES: usize = 1023;

/// The id an authenticator gave a passkey credential.
///
/// It is raw bytes, and the authenticator names the credential by it on
/// every sign-in. It is written out as lower-case hex.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PasskeyCredentialId(Vec<u8>);

impl PasskeyCredentialId {
    /// The id `bytes`, as the authenticator returned it.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] when it is empty.
    /// - [`ValidationError`] when it is longer than WebAuthn allows.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ValidationError> {
        validate_count("credential_id", bytes.len(), 1..=MAX_CREDENTIAL_ID_BYTES)?;
        Ok(Self(bytes))
    }

    /// The raw bytes, for comparing with what an authenticator presents.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for PasskeyCredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl fmt::Debug for PasskeyCredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PasskeyCredentialId({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bytes `0x0a 0xff` print as `0aff` and read back as the same
    /// bytes.
    #[test]
    fn a_credential_id_is_written_as_lower_case_hex() {
        let id = PasskeyCredentialId::new(vec![0x0a, 0xff]).unwrap();

        assert_eq!(id.to_string(), "0aff");
        assert_eq!(id.as_bytes(), [0x0a, 0xff]);
    }

    /// An empty id and one of 1024 bytes, one past the WebAuthn limit, are
    /// both refused.
    #[test]
    fn an_empty_or_oversized_id_is_refused() {
        assert!(PasskeyCredentialId::new(Vec::new()).is_err());
        assert!(PasskeyCredentialId::new(vec![0; MAX_CREDENTIAL_ID_BYTES + 1]).is_err());
    }
}
