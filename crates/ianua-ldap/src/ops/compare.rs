//! Compare: whether one attribute of one entry holds a value.
//!
//! It reads through the same use case as a search aimed at the entry, and
//! discloses less: the entry's contents never leave the server.

use ldap3_proto::proto::{LdapMsg, LdapResultCode};
use ldap3_proto::simple::CompareRequest;

use crate::dit::{dn, entries};
use crate::ops::reading;
use crate::ports::LdapPorts;
use crate::session::Session;

/// Answers a compare.
pub(super) async fn handle(
    ports: &LdapPorts,
    session: &mut Session,
    req: CompareRequest,
) -> LdapMsg {
    let (tenant, listing) = match reading::listing(ports, session, &req.entry).await {
        Ok(read) => read,
        Err((code, message)) => return req.gen_error(code, message),
    };
    let all = entries::build_entries(&tenant, &listing);
    let wanted = dn::normalize(&req.entry);
    let Some(entry) = all.iter().find(|e| dn::normalize(&e.dn) == wanted) else {
        return req.gen_error(LdapResultCode::NoSuchObject, String::new());
    };
    let holds = entry
        .values(&req.atype)
        .is_some_and(|vals| vals.iter().any(|v| v.eq_ignore_ascii_case(&req.val)));
    if holds {
        return req.gen_compare_true();
    }
    req.gen_compare_false()
}
