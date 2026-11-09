//! The part of the directory a DN names, as the use cases take it, and the
//! addresses and names its entries carry.

use ianua_app::use_cases::directory::principal::DirectoryBase;
use ianua_domain::types::{Email, Label, TenantSlug};

use crate::dit::dn::{self, TenantPath};

/// The organization and tenant `path` spells, when both are slugs.
pub(super) fn base_of(path: &TenantPath) -> Option<DirectoryBase> {
    Some(DirectoryBase {
        organization: TenantSlug::try_from(path.org_slug.clone()).ok()?,
        tenant: TenantSlug::try_from(path.tenant_slug.clone()).ok()?,
    })
}

/// The organization and tenant the DN `name` lies in.
pub(super) fn base_named(name: &str) -> Option<DirectoryBase> {
    base_of(&dn::tenant_of(name)?)
}

/// The tenant `base` names, as DNs spell it.
pub(super) fn path_of(base: &DirectoryBase) -> TenantPath {
    TenantPath {
        org_slug: base.organization.as_str().to_owned(),
        tenant_slug: base.tenant.as_str().to_owned(),
    }
}

/// The address a user entry's DN, or a `uid=` RDN, names by its `uid`.
pub(super) fn user_address(name: &str) -> Option<Email> {
    match dn::leading_rdn(name)? {
        (attribute, address) if attribute == "uid" => Email::new(address).ok(),
        _ => None,
    }
}

/// The group name a group entry's DN, or a `cn=` RDN, names by its `cn`,
/// as written.
pub(super) fn group_name(name: &str) -> Option<Label> {
    let (attribute, _) = dn::leading_rdn(name)?;
    if attribute != "cn" {
        return None;
    }
    Label::new("group_name", dn::leading_rdn_value_exact(name)?).ok()
}
