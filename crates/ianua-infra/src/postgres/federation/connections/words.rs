//! The words a connection's choices are stored as. An organization's own
//! identity provider and a tenant's SAML apps keep the same choices, in the
//! same words.

use ianua_domain::domains::federation::connection::{AssuranceTrust, EmailTrust, JitProvisioning};
use ianua_domain::domains::federation::connection_status::ConnectionStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    EmailTrust as "email trust" {
        Unverified => "unverified",
        Authoritative => "authoritative",
    }
}

stored_words! {
    AssuranceTrust as "assurance trust" {
        Untrusted => "untrusted",
        Trusted => "trusted",
    }
}

stored_words! {
    ConnectionStatus as "connection status" {
        Active => "active",
        Disabled => "disabled",
    }
}

stored_words! {
    JitProvisioning as "account provisioning" {
        Enabled => "enabled",
        Disabled => "disabled",
    }
}

/// What a group mapping rule gives, as its row tells it: a role or a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrantKind {
    /// Assigns the mapped permission set to the signing-in principal.
    Role,
    /// A place in a group.
    Group,
}

stored_words! {
    GrantKind as "mapped grant" {
        Role => "role",
        Group => "group",
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::listing::{SortKey, SortKeys};
    use ianua_app::ports::federation::ConnectionSortField;
    use ianua_domain::domains::federation::connection::{ConnectionRow, FederatedIdpConnection};
    use ianua_domain::isolation::scope::ResolvedTenant;

    use super::*;
    use crate::postgres::foundation::stored::StoredWord;
    use crate::test_support::rows::federation::{connection_row, oidc_config};

    /// A list sorted by status seeks past the cursor's word in the column,
    /// so the word a status is stored as must be the word it sorts by.
    #[test]
    fn every_status_is_stored_as_the_word_it_sorts_by() {
        for status in [ConnectionStatus::Active, ConnectionStatus::Disabled] {
            let connection: FederatedIdpConnection<ResolvedTenant> =
                FederatedIdpConnection::reconstitute(ConnectionRow {
                    status,
                    ..connection_row("Okta", oidc_config())
                })
                .unwrap();

            assert_eq!(
                connection.sort_key(ConnectionSortField::Status),
                SortKey::Text(status.word().to_owned())
            );
            assert_eq!(ConnectionStatus::from_word(status.word()), Some(status));
        }
    }
}
