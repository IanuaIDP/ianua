//! Modify: a user's display name, or who is in a group, changed by the
//! person the connection is bound as.
//!
//! `uid` and `mail` (a user) and `cn` (a group) name their entries, and RFC
//! 4511 leaves changing those to ModifyDN, as does this server. `memberOf`
//! is worked out from the groups' `member`, never written. `userPassword`
//! changes only through Password-Modify, which can prove the caller knows
//! the current one; a plain Modify cannot.

use ianua_app::auditor::RequestAuditor;
use ianua_app::use_case::Command as _;
use ianua_app::use_cases::authorization::groups::{AddMemberRequest, RemoveMemberRequest};
use ianua_app::use_cases::identity::users::RenameRequest;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::types::{DisplayName, Expiry, GroupId, PrincipalRef};
use ldap3_proto::proto::{LdapModify, LdapModifyRequest, LdapModifyType, LdapMsg, LdapResultCode};

use crate::dit::dn::{self, TenantPath};
use crate::ops::responses::modify_response;
use crate::ops::{Refused, person_auditor, settled, targets, writer, written_in};
use crate::ports::LdapPorts;
use crate::session::{PersonBind, Session};

/// Answers a modify.
pub(super) async fn handle(
    ports: &LdapPorts,
    session: &mut Session,
    msgid: i32,
    req: LdapModifyRequest,
) -> LdapMsg {
    let modified = modify_entry(ports, session, &req).await;
    let (code, message) = settled(session, modified);
    modify_response(msgid, code, message)
}

/// Makes the changes `req` lists, in order, as the person bound. The first
/// refused stops the rest.
async fn modify_entry(
    ports: &LdapPorts,
    session: &Session,
    req: &LdapModifyRequest,
) -> Result<(), Refused> {
    let person = writer(session)?;
    let tenant = written_in(person, &req.dn)?;
    if dn::is_child_of(&req.dn, &tenant.users()) {
        return modify_user(ports, person, req).await;
    }
    if dn::is_child_of(&req.dn, &tenant.groups()) {
        return modify_group(ports, person, &tenant, req).await;
    }
    Err(Refused::answer(
        LdapResultCode::UnwillingToPerform,
        "only user and group entries may be modified",
    ))
}

/// Renames the user the DN names, once for each `cn` change.
async fn modify_user(
    ports: &LdapPorts,
    person: &PersonBind,
    req: &LdapModifyRequest,
) -> Result<(), Refused> {
    let user_id = targets::user(ports, person, &req.dn).await?;
    let auditor = person_auditor(ports, &person.principal);
    for change in &req.changes {
        let request = RenameRequest {
            user_id,
            new_name: new_display_name(change)?,
        };
        ports
            .users
            .rename
            .execute(&person.principal, &auditor, request)
            .await?;
    }
    Ok(())
}

/// The display name a user `change` sets: only `cn` may change, and it
/// takes a value.
fn new_display_name(change: &LdapModify) -> Result<DisplayName, Refused> {
    ensure_user_attribute(&change.modification.atype)?;
    let value = first_value(change)
        .ok_or_else(|| Refused::answer(LdapResultCode::ConstraintViolation, "cn takes a value"))?;
    DisplayName::new(value, &DomainLimits::default().display_name).map_err(|_| {
        Refused::answer(
            LdapResultCode::InvalidAttributeSyntax,
            "cn is not a valid display name",
        )
    })
}

/// Refuses a user change to any attribute but `cn`.
fn ensure_user_attribute(attribute: &str) -> Result<(), Refused> {
    match attribute.to_ascii_lowercase().as_str() {
        "cn" => Ok(()),
        "uid" | "mail" => Err(Refused::answer(
            LdapResultCode::NotALlowedOnRDN,
            "uid and mail name the entry; change them with ModifyDN",
        )),
        "memberof" => Err(Refused::answer(
            LdapResultCode::ConstraintViolation,
            "memberOf is worked out; change member on the group",
        )),
        "userpassword" => Err(Refused::answer(
            LdapResultCode::UnwillingToPerform,
            "userPassword changes only through Password-Modify",
        )),
        _ => Err(Refused::answer(
            LdapResultCode::ConstraintViolation,
            "only cn may be modified on a user",
        )),
    }
}

/// Applies each `member` change to the group the DN names.
async fn modify_group(
    ports: &LdapPorts,
    person: &PersonBind,
    tenant: &TenantPath,
    req: &LdapModifyRequest,
) -> Result<(), Refused> {
    let group_id = targets::group(ports, person, &req.dn).await?;
    for change in &req.changes {
        ensure_member_change(change)?;
        for value in &change.modification.vals {
            let member = member_named(ports, person, tenant, value).await?;
            let one = MemberChange {
                group_id,
                operation: &change.operation,
                member,
            };
            change_member(ports, person, one).await?;
        }
    }
    Ok(())
}

/// Refuses a group change other than adding or deleting `member` values.
fn ensure_member_change(change: &LdapModify) -> Result<(), Refused> {
    let attribute = &change.modification.atype;
    if attribute.eq_ignore_ascii_case("cn") {
        return Err(Refused::answer(
            LdapResultCode::NotALlowedOnRDN,
            "cn names the group; rename it with ModifyDN",
        ));
    }
    if !attribute.eq_ignore_ascii_case("member") {
        return Err(Refused::answer(
            LdapResultCode::ConstraintViolation,
            "only member may be modified on a group",
        ));
    }
    if change.operation == LdapModifyType::Replace {
        return Err(Refused::answer(
            LdapResultCode::UnwillingToPerform,
            "member takes add and delete, not replace",
        ));
    }
    Ok(())
}

/// The user a `member` value names, by their entry's DN in `tenant`.
async fn member_named(
    ports: &LdapPorts,
    person: &PersonBind,
    tenant: &TenantPath,
    value: &[u8],
) -> Result<PrincipalRef, Refused> {
    let not_a_user = || {
        Refused::answer(
            LdapResultCode::InvalidAttributeSyntax,
            "member must be a user of this directory",
        )
    };
    let member_dn = std::str::from_utf8(value).map_err(|_| not_a_user())?;
    if !dn::is_child_of(member_dn, &tenant.users()) {
        return Err(not_a_user());
    }
    let user_id = targets::user(ports, person, member_dn).await?;
    Ok(PrincipalRef::User(user_id))
}

/// One `member` value added to a group or deleted from it.
struct MemberChange<'a> {
    group_id: GroupId,
    operation: &'a LdapModifyType,
    member: PrincipalRef,
}

/// Puts the member into the group or takes them out, as `change` says.
async fn change_member(
    ports: &LdapPorts,
    person: &PersonBind,
    change: MemberChange<'_>,
) -> Result<(), Refused> {
    let auditor = person_auditor(ports, &person.principal);
    match change.operation {
        LdapModifyType::Add => add_member(ports, person, &auditor, change).await?,
        LdapModifyType::Delete => {
            let request = RemoveMemberRequest {
                group_id: change.group_id,
                member: change.member,
            };
            ports
                .groups
                .remove_member
                .execute(&person.principal, &auditor, request)
                .await?;
        }
        LdapModifyType::Replace => {
            return Err(Refused::answer(
                LdapResultCode::UnwillingToPerform,
                "member takes add and delete only",
            ));
        }
    }
    Ok(())
}

/// Adds the resolved member without an expiry through the directory use case.
async fn add_member(
    ports: &LdapPorts,
    person: &PersonBind,
    auditor: &RequestAuditor,
    change: MemberChange<'_>,
) -> Result<(), Refused> {
    let request = AddMemberRequest {
        group_id: change.group_id,
        member: change.member,
        until: Expiry::Never,
    };
    ports
        .groups
        .add_member
        .execute(&person.principal, auditor, request)
        .await?;
    Ok(())
}

/// The first value of `change`, when it is text.
fn first_value(change: &LdapModify) -> Option<String> {
    let value = change.modification.vals.first()?;
    String::from_utf8(value.clone()).ok()
}
