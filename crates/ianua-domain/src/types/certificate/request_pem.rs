use crate::shared::validation::{TextValue, Validator, text_value};

/// The largest PEM text accepted, which fits a request for any key in use.
const MAX_PEM_BYTES: usize = 16_384;

text_value! {
    /// A certificate signing request, PEM-encoded as PKCS #10. It names a
    /// public key and is signed by the matching private key, so whoever
    /// sends one shows they hold that key.
    pub struct CertificateRequestPem;
}

impl TextValue for CertificateRequestPem {
    const FIELD: &'static str = "csr";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.pem("CERTIFICATE REQUEST", MAX_PEM_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A body wrapped in `BEGIN CERTIFICATE REQUEST` lines is accepted.
    #[test]
    fn a_well_formed_request_is_accepted() {
        assert!(
            CertificateRequestPem::new(
                "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n"
            )
            .is_ok()
        );
    }

    /// An empty value, bare base64 and a private key pasted by mistake are
    /// refused.
    #[test]
    fn a_malformed_request_is_refused() {
        for value in [
            "",
            "MIIB",
            "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----",
        ] {
            assert!(
                CertificateRequestPem::new(value).is_err(),
                "{value:?} was accepted"
            );
        }
    }
}
