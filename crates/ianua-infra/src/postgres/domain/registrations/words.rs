//! The words a registered domain's choices are stored as.

use ianua_domain::domains::tenant::custom_domains::registered_domain::DomainConnection;
use ianua_domain::domains::tenant::custom_domains::verification_status::{
    TlsStatus, VerificationStatus,
};

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    DomainConnection as "domain connection" {
        SelfManaged => "self_managed",
        Delegated => "delegated",
    }
}

stored_words! {
    VerificationStatus as "verification status" {
        Pending => "pending",
        Verified => "verified",
        Failed => "failed",
    }
}

stored_words! {
    TlsStatus as "certificate status" {
        NotRequired => "not_required",
        Provisioning => "provisioning",
        Active => "active",
        Expired => "expired",
        NoCertificate => "no_certificate",
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{SortKey, SortKeys};
    use ianua_app::ports::domain::DomainSortField;
    use ianua_domain::domains::tenant::custom_domains::registered_domain::{
        DomainProof, RegisteredDomain, RegisteredDomainRow,
    };
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::postgres::foundation::stored::StoredWord;
    use crate::test_support::rows::at;
    use crate::test_support::rows::domain::registered_domain_row;

    /// A list sorted by verification seeks past the cursor's word in the
    /// column, so the word a status is stored as must be the word it sorts
    /// by.
    #[test]
    fn every_verification_status_is_stored_as_the_word_it_sorts_by() {
        for (status, proof) in [
            (VerificationStatus::Pending, DomainProof::Unproved),
            (
                VerificationStatus::Verified,
                DomainProof::Verified { at: at(1) },
            ),
            (
                VerificationStatus::Failed,
                DomainProof::Lost {
                    verified_at: at(1),
                    failed_at: at(2),
                },
            ),
        ] {
            let domain: RegisteredDomain<ResolvedTenant> =
                RegisteredDomain::reconstitute(RegisteredDomainRow {
                    proof,
                    ..registered_domain_row("login.acme.example")
                })
                .unwrap();

            assert_eq!(
                domain.sort_key(DomainSortField::VerificationStatus),
                SortKey::Text(status.word().to_owned())
            );
            assert_eq!(VerificationStatus::from_word(status.word()), Some(status));
        }
    }
}
