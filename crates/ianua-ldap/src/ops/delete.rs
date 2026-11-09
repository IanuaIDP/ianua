//! Delete: a user or group entry removed by the person the connection is
//! bound as. The tree's own nodes (the tenant, `ou=users`, `ou=groups`)
//! are no child of either container, so they are refused as anything else
//! outside them is.

use ianua_app::use_case::Command as _;
use ldap3_proto::proto::{LdapMsg, LdapResultCode};

use crate::dit::dn;
use crate::ops::responses::delete_response;
use crate::ops::{Refused, person_auditor, settled, targets, writer, written_in};
use crate::ports::LdapPorts;
use crate::session::Session;

/// Answers a delete of `target`.
pub(super) async fn handle(
    ports: &LdapPorts,
    session: &mut Session,
    msgid: i32,
    target: &str,
) -> LdapMsg {
    let deleted = delete_entry(ports, session, target).await;
    let (code, message) = settled(session, deleted);
    delete_response(msgid, code, message)
}

/// Removes the entry `target` names, as the person bound.
async fn delete_entry(ports: &LdapPorts, session: &Session, target: &str) -> Result<(), Refused> {
    let person = writer(session)?;
    let tenant = written_in(person, target)?;
    let auditor = person_auditor(ports, &person.principal);
    if dn::is_child_of(target, &tenant.users()) {
        let user_id = targets::user(ports, person, target).await?;
        ports
            .users
            .remove
            .execute(&person.principal, &auditor, user_id)
            .await?;
        return Ok(());
    }
    if dn::is_child_of(target, &tenant.groups()) {
        let group_id = targets::group(ports, person, target).await?;
        ports
            .groups
            .remove
            .execute(&person.principal, &auditor, group_id)
            .await?;
        return Ok(());
    }
    Err(Refused::answer(
        LdapResultCode::UnwillingToPerform,
        "only user and group entries may be deleted",
    ))
}
