use crate::shared::validation::{TextValue, Validator, text_value};

/// The largest PEM text accepted, which fits any key in use.
const MAX_PEM_BYTES: usize = 16_384;

text_value! {
    /// A public key, PEM-encoded as `SubjectPublicKeyInfo`. It verifies
    /// signatures the matching private key made.
    pub struct PublicKeyPem;
}

impl TextValue for PublicKeyPem {
    const FIELD: &'static str = "public_key";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.pem("PUBLIC KEY", MAX_PEM_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A body wrapped in `BEGIN PUBLIC KEY` and `END PUBLIC KEY` lines is
    /// accepted.
    #[test]
    fn a_well_formed_public_key_pem_is_accepted() {
        assert!(
            PublicKeyPem::new("-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n")
                .is_ok()
        );
    }

    /// An empty value and bare base64 are refused. So is a private key
    /// pasted by mistake, so it is never stored as a public one.
    #[test]
    fn a_malformed_public_key_pem_is_refused() {
        for value in [
            "",
            "MFkw",
            "-----BEGIN PRIVATE KEY-----\nMFkw\n-----END PRIVATE KEY-----",
        ] {
            assert!(PublicKeyPem::new(value).is_err(), "{value:?} was accepted");
        }
    }
}
