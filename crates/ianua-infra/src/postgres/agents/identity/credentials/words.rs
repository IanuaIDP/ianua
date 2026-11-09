//! The words an agent credential's choices are stored as. Its algorithm
//! and status are stored with the words of the crypto context's keys.

use ianua_domain::domains::agents::identity::attestation::AttestationMethod;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    AttestationMethod as "attestation method" {
        Spiffe => "spiffe",
        AwsIam => "aws_iam",
        GcpInstanceIdentity => "gcp_instance_identity",
        Tpm => "tpm",
        KubernetesServiceAccount => "kubernetes_service_account",
        GithubActions => "github_actions",
        OidcToken => "oidc_token",
        AzureManagedIdentity => "azure_managed_identity",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every attestation method reads back from the word it is written as.
    #[test]
    fn every_method_reads_back_from_its_word() {
        for method in [
            AttestationMethod::Spiffe,
            AttestationMethod::AwsIam,
            AttestationMethod::GcpInstanceIdentity,
            AttestationMethod::Tpm,
            AttestationMethod::KubernetesServiceAccount,
            AttestationMethod::GithubActions,
            AttestationMethod::OidcToken,
            AttestationMethod::AzureManagedIdentity,
        ] {
            assert_eq!(AttestationMethod::from_word(method.word()), Some(method));
        }
    }
}
