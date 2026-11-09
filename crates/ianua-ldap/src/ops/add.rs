//! Add: a user under `ou=users` or a group under `ou=groups`, made by the
//! person the connection is bound as. Nothing else may be added.
//!
//! The entry's DN names it: a user's `uid` is their address, a group's `cn`
//! its name. An attribute saying otherwise is refused, not followed.

use ianua_app::use_case::Command as _;
use ianua_app::use_cases::directory::users::NewDirectory;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::DisplayName;
use ldap3_proto::proto::{LdapAddRequest, LdapMsg, LdapResultCode};

use crate::dit::dn;
use crate::ops::responses::add_response;
use crate::ops::{Refused, attrs, naming, person_auditor, settled, writer, written_in};
use crate::ports::LdapPorts;
use crate::session::{PersonBind, Session};

/// Answers an add.
pub(super) async fn handle(
    ports: &LdapPorts,
    session: &mut Session,
    msgid: i32,
    req: LdapAddRequest,
) -> LdapMsg {
    let added = add_entry(ports, session, &req).await;
    let (code, message) = settled(session, added);
    add_response(msgid, code, message)
}

/// Adds the entry `req` describes, as the person bound.
async fn add_entry(
    ports: &LdapPorts,
    session: &Session,
    req: &LdapAddRequest,
) -> Result<(), Refused> {
    let person = writer(session)?;
    let tenant = written_in(person, &req.dn)?;
    if dn::is_child_of(&req.dn, &tenant.users()) {
        return add_user(ports, person, req).await;
    }
    if dn::is_child_of(&req.dn, &tenant.groups()) {
        return add_group(ports, person, req).await;
    }
    Err(Refused::answer(
        LdapResultCode::UnwillingToPerform,
        "entries may only be added under ou=users or ou=groups",
    ))
}

/// Adds the user `req` describes. `Add` has no secure way to hand a
/// made-up password back, so the entry brings its first one.
async fn add_user(
    ports: &LdapPorts,
    person: &PersonBind,
    req: &LdapAddRequest,
) -> Result<(), Refused> {
    let user = new_user(req)?;
    let auditor = person_auditor(ports, &person.principal);
    ports
        .users
        .add
        .execute(&person.principal, &auditor, user)
        .await?;
    Ok(())
}

/// Reads the user's attributes without allowing mail to contradict the DN.
fn new_user(req: &LdapAddRequest) -> Result<NewDirectory, Refused> {
    let email = naming::user_address(&req.dn).ok_or_else(|| {
        Refused::answer(
            LdapResultCode::InvalidDNSyntax,
            "a user is named uid=<address>",
        )
    })?;
    let named_alike = attrs::value(&req.attributes, "mail")
        .is_none_or(|mail| mail.eq_ignore_ascii_case(email.as_str()));
    if !named_alike {
        return Err(Refused::answer(
            LdapResultCode::ConstraintViolation,
            "mail must be the address the entry's uid names",
        ));
    }
    let display_name = display_name(req)?;
    let password = attrs::value(&req.attributes, "userPassword").ok_or_else(|| {
        Refused::answer(
            LdapResultCode::ConstraintViolation,
            "userPassword is required",
        )
    })?;
    Ok(NewDirectory {
        email,
        display_name,
        password: Secret::new(password),
    })
}

/// Requires a common name that satisfies the directory's display-name rules.
fn display_name(req: &LdapAddRequest) -> Result<DisplayName, Refused> {
    let cn = attrs::value(&req.attributes, "cn")
        .ok_or_else(|| Refused::answer(LdapResultCode::ConstraintViolation, "cn is required"))?;
    DisplayName::new(cn, &DomainLimits::default().display_name).map_err(|_| {
        Refused::answer(
            LdapResultCode::InvalidAttributeSyntax,
            "cn is not a valid display name",
        )
    })
}

/// Adds the group the DN names, at the top of the tree.
async fn add_group(
    ports: &LdapPorts,
    person: &PersonBind,
    req: &LdapAddRequest,
) -> Result<(), Refused> {
    let name = naming::group_name(&req.dn).ok_or_else(|| {
        Refused::answer(
            LdapResultCode::InvalidDNSyntax,
            "a group is named cn=<name>",
        )
    })?;
    let named_alike = attrs::value(&req.attributes, "cn").is_none_or(|cn| cn == name.as_str());
    if !named_alike {
        return Err(Refused::answer(
            LdapResultCode::ConstraintViolation,
            "cn must be the name the entry's DN names",
        ));
    }
    let auditor = person_auditor(ports, &person.principal);
    ports
        .groups
        .add
        .execute(&person.principal, &auditor, name)
        .await?;
    Ok(())
}
