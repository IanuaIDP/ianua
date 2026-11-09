//! The user or group a write's DN names, found in the tenant the person
//! bound to. Only the id is taken: whether the write may touch it is the
//! write's use case's to decide.

use ianua_app::error::AppError;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Email, GroupId, UserId};
use ldap3_proto::proto::LdapResultCode;

use crate::ops::{Refused, naming};
use crate::ports::LdapPorts;
use crate::session::PersonBind;

/// The user the entry `name` names by its `uid`.
pub(super) async fn user(
    ports: &LdapPorts,
    person: &PersonBind,
    name: &str,
) -> Result<UserId, Refused> {
    let address = naming::user_address(name)
        .ok_or_else(|| Refused::answer(LdapResultCode::InvalidDNSyntax, "not a user's DN"))?;
    user_at(ports, person, &address).await
}

/// The user signing in with `address`.
pub(super) async fn user_at(
    ports: &LdapPorts,
    person: &PersonBind,
    address: &Email,
) -> Result<UserId, Refused> {
    let found = ports
        .targets
        .users
        .find_by_email(person.principal.tenant(), address)
        .await
        .map_err(lookup_failed)?;
    found
        .map(|user| *user.id())
        .ok_or_else(|| Refused::answer(LdapResultCode::NoSuchObject, ""))
}

/// The group the entry `name` names by its `cn`.
pub(super) async fn group(
    ports: &LdapPorts,
    person: &PersonBind,
    name: &str,
) -> Result<GroupId, Refused> {
    let group_name = naming::group_name(name)
        .ok_or_else(|| Refused::answer(LdapResultCode::InvalidDNSyntax, "not a group's DN"))?;
    let found = ports
        .targets
        .groups
        .find_by_name(person.principal.tenant(), &group_name)
        .await
        .map_err(lookup_failed)?;
    found
        .map(|group| *group.id())
        .ok_or_else(|| Refused::answer(LdapResultCode::NoSuchObject, ""))
}

/// A store that could not be asked, which is a fault, never an absence.
fn lookup_failed(error: DomainError) -> Refused {
    Refused::UseCase(AppError::from_domain(error))
}
