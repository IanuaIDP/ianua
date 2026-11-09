//! Password-Modify (RFC 3062), the only way `userPassword` ever changes; a
//! plain Modify of it is refused.
//!
//! A person changes their own password by giving the current one, or
//! resets another user's, as the change-password use case decides. Naming
//! no user, or naming themselves, is their own.

use ianua_app::use_case::Command as _;
use ianua_app::use_cases::directory::users::DirectoryPasswordChange;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::Email;
use ldap3_proto::proto::{LdapMsg, LdapPasswordModifyRequest, LdapResultCode};

use crate::dit::dn;
use crate::ops::responses::password_modify_response;
use crate::ops::{Refused, naming, person_auditor, refused_with, targets, writer, written_in};
use crate::ports::LdapPorts;
use crate::session::{PersonBind, Session};

/// Answers a Password-Modify, handing back the password made up when a
/// reset was given none.
pub(super) async fn handle(
    ports: &LdapPorts,
    session: &mut Session,
    msgid: i32,
    req: LdapPasswordModifyRequest,
) -> LdapMsg {
    match changed(ports, session, req).await {
        Ok(made_up) => password_modify_response(
            msgid,
            LdapResultCode::Success,
            String::new(),
            made_up.map(|password| password.expose().to_owned()),
        ),
        Err(refused) => {
            let (code, message) = refused_with(session, refused);
            password_modify_response(msgid, code, message, None)
        }
    }
}

/// Changes the password `req` asks for, as the person bound.
async fn changed(
    ports: &LdapPorts,
    session: &Session,
    req: LdapPasswordModifyRequest,
) -> Result<Option<Secret>, Refused> {
    let person = writer(session)?;
    let passwords = Passwords {
        old: req.old_password,
        new: req.new_password,
    };
    let change = match req.user_identity {
        None => own(passwords)?,
        Some(named) => named_change(ports, person, &named, passwords).await?,
    };
    let auditor = person_auditor(ports, &person.principal);
    let made_up = ports
        .users
        .change_password
        .execute(&person.principal, &auditor, change)
        .await?;
    Ok(made_up)
}

/// The passwords a Password-Modify carries. It holds them, so it has no
/// `Debug`.
struct Passwords {
    old: Option<String>,
    new: Option<String>,
}

/// The change for the user `named`: the person's own when it is them, a
/// reset of another user's otherwise.
async fn named_change(
    ports: &LdapPorts,
    person: &PersonBind,
    named: &str,
    passwords: Passwords,
) -> Result<DirectoryPasswordChange, Refused> {
    let address = named_address(person, named)?;
    let user_id = targets::user_at(ports, person, &address).await?;
    if &user_id == person.principal.user_id() {
        return own(passwords);
    }
    Ok(DirectoryPasswordChange::ForOtherUser {
        user_id,
        new_password: passwords.new,
    })
}

/// The person's own change: the current password proves them again, and
/// the new one is theirs to give.
fn own(passwords: Passwords) -> Result<DirectoryPasswordChange, Refused> {
    let old_password = passwords.old.ok_or_else(|| {
        Refused::answer(
            LdapResultCode::InsufficentAccessRights,
            "changing your own password takes the current one",
        )
    })?;
    let new_password = passwords.new.ok_or_else(|| {
        Refused::answer(
            LdapResultCode::UnwillingToPerform,
            "changing your own password takes the new one",
        )
    })?;
    Ok(DirectoryPasswordChange::Own {
        old_password: Secret::new(old_password),
        new_password: Secret::new(new_password),
    })
}

/// The address a Password-Modify's user identity names: a user's DN in the
/// tenant `person` bound to, or the address itself, either bare or as an
/// authorization identity (`dn:` or `u:`).
fn named_address(person: &PersonBind, named: &str) -> Result<Email, Refused> {
    let named = named
        .strip_prefix("dn:")
        .or_else(|| named.strip_prefix("u:"))
        .unwrap_or(named);
    let no_user = || {
        Refused::answer(
            LdapResultCode::InvalidAttributeSyntax,
            "the user identity names no user",
        )
    };
    if dn::tenant_of(named).is_none() {
        return Email::new(named).map_err(|_| no_user());
    }
    let tenant = written_in(person, named)?;
    if !dn::is_child_of(named, &tenant.users()) {
        return Err(no_user());
    }
    naming::user_address(named).ok_or_else(no_user)
}
