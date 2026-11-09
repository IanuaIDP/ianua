//! What the org-plane emails call the organization they are about.

use ianua_domain::domains::organization::members::org_user::OrgUser;

use crate::ports::organization::OrganizationStore;

/// The name of `member`'s organization, or an empty string when it cannot
/// be read. The templates fall back on their own, and a name is never worth
/// failing a mail over.
pub(in crate::use_cases::organization) async fn organization_name(
    store: &dyn OrganizationStore,
    member: &OrgUser,
) -> String {
    store
        .find_by_id(member.organization_id())
        .await
        .ok()
        .flatten()
        .map(|organization| organization.name().as_str().to_owned())
        .unwrap_or_default()
}
