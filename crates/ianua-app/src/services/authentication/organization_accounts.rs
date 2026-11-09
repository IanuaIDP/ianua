//! Resolving the organizations of accounts discovered by address in one read.

use std::collections::HashMap;

use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::types::OrganizationId;

use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrganizationStore;

/// The organizations of `members`, keyed so each caller keeps the account
/// order it discovered. Missing organizations remain absent; the caller keeps
/// enforcing the sign-in method and proof rules for each account.
///
/// # Errors
///
/// Returns `AppError::Internal` when the organizations cannot be read.
pub(crate) async fn organizations_of(
    store: &dyn OrganizationStore,
    members: &[OrgUser],
) -> Result<HashMap<OrganizationId, Organization>, AppError> {
    if members.is_empty() {
        return Ok(HashMap::new());
    }
    let ids: Vec<_> = members
        .iter()
        .map(|member| *member.organization_id())
        .collect();
    let organizations = store.find_by_ids(&ids).await.or_internal()?;
    Ok(organizations
        .into_iter()
        .map(|organization| (*organization.id(), organization))
        .collect())
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::organization::members::membership::OrgRole;

    use super::*;
    use crate::test_support::block_on;
    use crate::test_support::organization::{org_store_with, test_org, test_org_user};

    /// An address with no accounts needs no organization lookup and reveals
    /// no organization through its discovery result.
    #[test]
    fn no_accounts_need_no_organization_read() {
        let organizations = org_store_with([test_org(OrganizationId::new(), "unrelated")]);

        let found = block_on(organizations_of(organizations.as_ref(), &[])).unwrap();

        assert!(found.is_empty());
        assert_eq!(organizations.id_reads(), 0);
    }

    /// Only the accounts' existing organizations are loaded; a gone
    /// organization stays missing and an unrelated organization stays private.
    #[test]
    fn discovered_accounts_load_only_their_existing_organizations() {
        let acme = test_org(OrganizationId::new(), "acme");
        let acme_id = *acme.id();
        let gone = OrganizationId::new();
        let organizations = org_store_with([test_org(OrganizationId::new(), "unrelated"), acme]);
        let members = [
            test_org_user(gone, "ann@example.test", OrgRole::Member),
            test_org_user(acme_id, "ann@example.test", OrgRole::Member),
        ];

        let found = block_on(organizations_of(organizations.as_ref(), &members)).unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[&acme_id].slug().as_str(), "acme");
        assert!(!found.contains_key(&gone));
        assert_eq!(organizations.id_reads(), 1);
    }
}
