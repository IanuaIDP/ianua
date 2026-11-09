use crate::shared::validation::{TextValue, Validator, text_value};

/// The largest PEM text accepted: a long chain fits, a document does not.
const MAX_PEM_BYTES: usize = 65_536;

text_value! {
    /// One or more PEM-encoded X.509 certificates, such as a CA to trust, an
    /// identity provider's signing certificate or a served chain.
    ///
    /// A certificate is public, so it shows in debug output. The adapter
    /// that uses it parses the contents.
    pub struct CertificatePem;
}

impl TextValue for CertificatePem {
    const FIELD: &'static str = "certificate";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.pem("CERTIFICATE", MAX_PEM_BYTES)
    }
}

impl CertificatePem {
    /// The base64 body of the first certificate, without its `BEGIN` and
    /// `END` lines or line breaks. SAML metadata and an `x5c` chain carry
    /// this form.
    #[must_use]
    pub fn base64_body(&self) -> String {
        self.0
            .lines()
            .skip_while(|line| !line.starts_with("-----BEGIN CERTIFICATE-----"))
            .skip(1)
            .take_while(|line| !line.starts_with("-----END CERTIFICATE-----"))
            .map(str::trim)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A body wrapped in `BEGIN CERTIFICATE` and `END CERTIFICATE` lines is
    /// accepted.
    #[test]
    fn a_well_formed_certificate_pem_is_accepted() {
        assert!(
            CertificatePem::new("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
                .is_ok()
        );
    }

    /// An empty value, bare base64 with no armour lines, and a public key
    /// pasted where a certificate belongs are all refused.
    #[test]
    fn a_malformed_certificate_pem_is_refused() {
        for value in [
            "",
            "MIIB",
            "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----",
        ] {
            assert!(
                CertificatePem::new(value).is_err(),
                "{value:?} was accepted"
            );
        }
    }

    /// A certificate reads back byte for byte as it was given, trailing
    /// newline included.
    #[test]
    fn a_certificate_is_kept_as_written() {
        let pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

        assert_eq!(CertificatePem::new(pem).unwrap().as_str(), pem);
    }

    /// A certificate printed with `{:?}` shows its `BEGIN CERTIFICATE` text.
    /// It is public, so it stays readable in logs.
    #[test]
    fn a_certificate_shows_itself_in_debug_output() {
        let certificate =
            CertificatePem::new("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----")
                .unwrap();

        assert!(format!("{certificate:?}").contains("BEGIN CERTIFICATE"));
    }

    /// A certificate whose body spans the lines `MIIB` and `xTCC` gives
    /// `MIIBxTCC`, the form SAML metadata carries.
    #[test]
    fn the_body_is_the_base64_between_the_armour_lines() {
        let certificate = CertificatePem::new(
            "-----BEGIN CERTIFICATE-----\nMIIB\nxTCC\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        assert_eq!(certificate.base64_body(), "MIIBxTCC");
    }
}
