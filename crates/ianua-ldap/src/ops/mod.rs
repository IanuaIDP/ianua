//! One handler per LDAP operation: read the request, ask the use case,
//! encode its answer.
//!
//! `ldap3_proto::simple::ServerOps` decodes the simple bind, search,
//! Who-am-I, compare and unbind. The rest a client may send (a SASL bind,
//! add, modify, delete, modify DN and Password-Modify) is read here from
//! the lower-level `LdapOp`. Anything else is not served and closes the
//! connection.

mod add;
mod attrs;
mod bind;
mod compare;
mod delete;
mod errors;
mod modify;
mod modify_dn;
mod naming;
mod password_modify;
mod reading;
mod responses;
mod search;
mod targets;
mod whoami;

use std::sync::Arc;

use ianua_app::auditor::RequestAuditor;
use ianua_app::error::AppError;
use ianua_app::use_cases::directory::principal::DirectoryPrincipal;
use ianua_domain::domains::audit::builder::AuditContext;
use ianua_domain::types::Fact;
use ldap3_proto::proto::{
    LdapAddRequest, LdapBindCred, LdapBindRequest, LdapModifyDNRequest, LdapModifyRequest, LdapMsg,
    LdapOp, LdapPasswordModifyRequest, LdapResultCode, OID_PASSWORD_MODIFY,
};
use ldap3_proto::simple::{DisconnectionNotice, ServerOps};

use crate::dit::dn::TenantPath;
use crate::ip_throttle::IpBindThrottle;
use crate::ports::LdapPorts;
use crate::session::{Bound, PersonBind, Session};

/// What a message is answered with, and what the connection does next.
pub(crate) struct Reply {
    /// The answers to send, in order.
    pub(crate) answers: Vec<LdapMsg>,
    /// What follows them.
    pub(crate) then: Then,
}

/// What a connection does once its answers are sent.
pub(crate) enum Then {
    /// Reads the next message.
    Read,
    /// Ends the connection after any final reply has been sent.
    Close,
}

impl Reply {
    /// `answers`, then the next message.
    fn answer(answers: Vec<LdapMsg>) -> Self {
        Self {
            answers,
            then: Then::Read,
        }
    }

    /// `notice`, if any, then close.
    fn hang_up(notice: Option<LdapMsg>) -> Self {
        Self {
            answers: notice.into_iter().collect(),
            then: Then::Close,
        }
    }
}

/// The operations `ServerOps` does not decode.
enum RawOp {
    /// A SASL bind. Binding takes a password over a client certificate or a
    /// service account's secret, both simple binds, so none is served.
    SaslBind {
        msgid: i32,
    },
    Add {
        msgid: i32,
        req: LdapAddRequest,
    },
    Modify {
        msgid: i32,
        req: LdapModifyRequest,
    },
    Delete {
        msgid: i32,
        dn: String,
    },
    ModifyDn {
        msgid: i32,
        req: LdapModifyDNRequest,
    },
    PasswordModify {
        msgid: i32,
        req: LdapPasswordModifyRequest,
    },
}

/// A message as the handlers read it.
enum Operation {
    Known(ServerOps),
    Raw(RawOp),
    Unsupported,
}

/// The reply to `message` on `session`.
pub(crate) async fn reply(
    ports: &LdapPorts,
    throttle: &IpBindThrottle,
    session: &mut Session,
    message: LdapMsg,
) -> Reply {
    match decode(message) {
        Operation::Known(ServerOps::Unbind(_)) => Reply::hang_up(None),
        Operation::Known(op) => Reply::answer(known(ports, throttle, session, op).await),
        Operation::Raw(op) => Reply::answer(vec![raw(ports, session, op).await]),
        Operation::Unsupported => Reply::hang_up(Some(DisconnectionNotice::gen_response(
            LdapResultCode::UnwillingToPerform,
            "operation not supported by this directory",
        ))),
    }
}

/// The notice a connection sending what cannot be read is closed with.
pub(crate) fn malformed() -> LdapMsg {
    DisconnectionNotice::gen_response(LdapResultCode::ProtocolError, "malformed message")
}

/// `message` sorted by the decoder that reads it, taken apart without a
/// copy, so a password it carries is held once.
fn decode(message: LdapMsg) -> Operation {
    let LdapMsg { msgid, op, ctrl } = message;
    match op {
        LdapOp::BindRequest(LdapBindRequest {
            cred: LdapBindCred::SASL(_),
            ..
        }) => Operation::Raw(RawOp::SaslBind { msgid }),
        LdapOp::AddRequest(req) => Operation::Raw(RawOp::Add { msgid, req }),
        LdapOp::ModifyRequest(req) => Operation::Raw(RawOp::Modify { msgid, req }),
        LdapOp::DelRequest(dn) => Operation::Raw(RawOp::Delete { msgid, dn }),
        LdapOp::ModifyDNRequest(req) => Operation::Raw(RawOp::ModifyDn { msgid, req }),
        LdapOp::ExtendedRequest(ext) if ext.name == OID_PASSWORD_MODIFY => {
            LdapPasswordModifyRequest::try_from(&ext).map_or(Operation::Unsupported, |req| {
                Operation::Raw(RawOp::PasswordModify { msgid, req })
            })
        }
        op => ServerOps::try_from(LdapMsg { msgid, op, ctrl })
            .map_or(Operation::Unsupported, Operation::Known),
    }
}

/// The answers to an operation `ServerOps` decoded.
async fn known(
    ports: &LdapPorts,
    throttle: &IpBindThrottle,
    session: &mut Session,
    op: ServerOps,
) -> Vec<LdapMsg> {
    match op {
        ServerOps::SimpleBind(req) => vec![bind::handle(ports, throttle, session, req).await],
        ServerOps::Search(req) => search::handle(ports, session, req).await,
        ServerOps::Compare(req) => vec![compare::handle(ports, session, req).await],
        ServerOps::Whoami(req) => vec![whoami::handle(session, &req)],
        ServerOps::Unbind(_) => Vec::new(),
    }
}

/// The answer to an operation only [`RawOp`] reads.
async fn raw(ports: &LdapPorts, session: &mut Session, op: RawOp) -> LdapMsg {
    match op {
        RawOp::SaslBind { msgid } => bind::refuse_sasl(session, msgid),
        RawOp::Add { msgid, req } => add::handle(ports, session, msgid, req).await,
        RawOp::Modify { msgid, req } => modify::handle(ports, session, msgid, req).await,
        RawOp::Delete { msgid, dn } => delete::handle(ports, session, msgid, &dn).await,
        RawOp::ModifyDn { msgid, req } => modify_dn::handle(ports, session, msgid, req).await,
        RawOp::PasswordModify { msgid, req } => {
            password_modify::handle(ports, session, msgid, req).await
        }
    }
}

/// Why a write was not done: an answer the handler gave itself, or the use
/// case's refusal.
enum Refused {
    /// The request named nothing the use cases could be asked about.
    Answer(LdapResultCode, String),
    /// The use case refused it.
    UseCase(AppError),
}

impl Refused {
    /// The answer `code`, saying `message`.
    fn answer(code: LdapResultCode, message: &str) -> Self {
        Self::Answer(code, message.to_owned())
    }
}

impl From<AppError> for Refused {
    fn from(refused: AppError) -> Self {
        Self::UseCase(refused)
    }
}

/// The result code and message a write's `outcome` answers with.
fn settled(session: &mut Session, outcome: Result<(), Refused>) -> (LdapResultCode, String) {
    match outcome {
        Ok(()) => (LdapResultCode::Success, String::new()),
        Err(refused) => refused_with(session, refused),
    }
}

/// The result code and message `refused` answers with.
fn refused_with(session: &mut Session, refused: Refused) -> (LdapResultCode, String) {
    match refused {
        Refused::Answer(code, message) => (code, message),
        Refused::UseCase(refused) => errors::refusal(session, refused),
    }
}

/// The person the connection is bound as, for a write; a write is a
/// person's, so a service account's bind or none makes none.
fn writer(session: &Session) -> Result<&PersonBind, Refused> {
    match &session.bound {
        Bound::Person(person) => Ok(person.as_ref()),
        Bound::Service(_) => Err(Refused::answer(
            LdapResultCode::InsufficentAccessRights,
            "a service account does not write",
        )),
        Bound::Nobody => Err(Refused::answer(
            LdapResultCode::InsufficentAccessRights,
            "bind first",
        )),
    }
}

/// The tenant `target` lies in, when it is the one `person` bound to: a
/// write reaches no other, so a DN elsewhere names no entry.
fn written_in(person: &PersonBind, target: &str) -> Result<TenantPath, Refused> {
    let bound_to = person.principal.base();
    match naming::base_named(target) {
        Some(base) if &base == bound_to => Ok(naming::path_of(&base)),
        _ => Err(Refused::answer(LdapResultCode::NoSuchObject, "")),
    }
}

/// The auditor of a request on `principal`'s bind.
fn person_auditor(ports: &LdapPorts, principal: &DirectoryPrincipal) -> RequestAuditor {
    RequestAuditor::new(Arc::clone(&ports.events), principal.audit_context())
}

/// The auditor of a request no person is bound for: a bind, or a service
/// account's search, whose use case names the tenant itself.
fn connection_auditor(ports: &LdapPorts, session: &Session) -> RequestAuditor {
    let context = AuditContext::system().with_request(session.ip.clone(), Fact::Unknown);
    RequestAuditor::new(Arc::clone(&ports.events), context)
}
