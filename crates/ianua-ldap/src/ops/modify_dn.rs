//! ModifyDN: a user's address (their `uid`) or a group's name (its `cn`)
//! changed by the person the connection is bound as.
//!
//! An entry stays in its container and its tenant: a new superior, when
//! given, must be the container it is in. `deleteoldrdn` is not read: the
//! old name is always replaced, there is no keeping both.

use ianua_app::use_case::Command as _;
use ianua_app::use_cases::authorization::groups::RenameRequest;
use ianua_app::use_cases::directory::users::DirectoryEmailChange;
use ldap3_proto::proto::{LdapModifyDNRequest, LdapMsg, LdapResultCode};

use crate::dit::dn;
use crate::ops::responses::modify_dn_response;
use crate::ops::{Refused, naming, person_auditor, settled, targets, writer, written_in};
use crate::ports::LdapPorts;
use crate::session::{PersonBind, Session};

/// Answers a modify DN.
pub(super) async fn handle(
    ports: &LdapPorts,
    session: &mut Session,
    msgid: i32,
    req: LdapModifyDNRequest,
) -> LdapMsg {
    let renamed = rename_entry(ports, session, &req).await;
    let (code, message) = settled(session, renamed);
    modify_dn_response(msgid, code, message)
}

/// Renames the entry `req` names, as the person bound.
async fn rename_entry(
    ports: &LdapPorts,
    session: &Session,
    req: &LdapModifyDNRequest,
) -> Result<(), Refused> {
    let person = writer(session)?;
    let tenant = written_in(person, &req.dn)?;
    let users = tenant.users();
    if dn::is_child_of(&req.dn, &users) {
        ensure_stays_in(req, &users)?;
        return change_email(ports, person, req).await;
    }
    let groups = tenant.groups();
    if dn::is_child_of(&req.dn, &groups) {
        ensure_stays_in(req, &groups)?;
        return rename_group(ports, person, req).await;
    }
    Err(Refused::answer(
        LdapResultCode::UnwillingToPerform,
        "only user and group entries may be renamed",
    ))
}

/// Refuses moving the entry out of `container`.
fn ensure_stays_in(req: &LdapModifyDNRequest, container: &str) -> Result<(), Refused> {
    let stays = req
        .new_superior
        .as_deref()
        .is_none_or(|superior| dn::normalize(superior) == dn::normalize(container));
    if stays {
        return Ok(());
    }
    Err(Refused::answer(
        LdapResultCode::UnwillingToPerform,
        "an entry stays in its container and its tenant",
    ))
}

/// Gives the user the DN names the address `uid=<new address>` names.
async fn change_email(
    ports: &LdapPorts,
    person: &PersonBind,
    req: &LdapModifyDNRequest,
) -> Result<(), Refused> {
    let user_id = targets::user(ports, person, &req.dn).await?;
    let new_email = naming::user_address(&req.newrdn).ok_or_else(|| {
        Refused::answer(
            LdapResultCode::InvalidAttributeSyntax,
            "the new RDN of a user is uid=<new address>",
        )
    })?;
    let change = DirectoryEmailChange { user_id, new_email };
    let auditor = person_auditor(ports, &person.principal);
    ports
        .users
        .change_email
        .execute(&person.principal, &auditor, change)
        .await?;
    Ok(())
}

/// Gives the group the DN names the name `cn=<new name>` names.
async fn rename_group(
    ports: &LdapPorts,
    person: &PersonBind,
    req: &LdapModifyDNRequest,
) -> Result<(), Refused> {
    let group_id = targets::group(ports, person, &req.dn).await?;
    let new_name = naming::group_name(&req.newrdn).ok_or_else(|| {
        Refused::answer(
            LdapResultCode::InvalidAttributeSyntax,
            "the new RDN of a group is cn=<new name>",
        )
    })?;
    let request = RenameRequest { group_id, new_name };
    let auditor = person_auditor(ports, &person.principal);
    ports
        .groups
        .rename
        .execute(&person.principal, &auditor, request)
        .await?;
    Ok(())
}
