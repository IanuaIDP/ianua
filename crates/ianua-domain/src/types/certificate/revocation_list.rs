use crate::shared::validation::{TextValue, Validator, text_value};

/// The largest PEM text accepted for one revocation list. A list naming
/// tens of thousands of revoked certificates fits; a dump does not.
const MAX_PEM_BYTES: usize = 1_048_576;

text_value! {
    /// One or more PEM-encoded X.509 certificate revocation lists (CRLs),
    /// signed by an authority a tenant trusts, naming the certificates it
    /// revoked.
    ///
    /// A revocation list is public, so it shows in debug output. The
    /// adapter that uses it parses the contents and checks its signature.
    pub struct RevocationListPem;
}

impl TextValue for RevocationListPem {
    const FIELD: &'static str = "revocation_list";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.pem("X509 CRL", MAX_PEM_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A body wrapped in `BEGIN X509 CRL` and `END X509 CRL` lines is
    /// accepted, and reads back as written.
    #[test]
    fn a_well_formed_revocation_list_pem_is_accepted() {
        let pem = "-----BEGIN X509 CRL-----\nMIIB\n-----END X509 CRL-----\n";

        assert_eq!(RevocationListPem::new(pem).unwrap().as_str(), pem);
    }

    /// A certificate pasted where a revocation list belongs, bare base64
    /// and an empty value are refused.
    #[test]
    fn anything_but_a_revocation_list_is_refused() {
        for value in [
            "",
            "MIIB",
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
        ] {
            assert!(
                RevocationListPem::new(value).is_err(),
                "{value:?} was accepted"
            );
        }
    }
}
