//! Who am I: the DN the connection is bound as, if any.

use ldap3_proto::proto::LdapMsg;
use ldap3_proto::simple::WhoamiRequest;

use crate::session::Session;

/// Answers a Who-am-I with `dn:` and the bound DN, or nothing when bound
/// as nobody.
pub(super) fn handle(session: &Session, req: &WhoamiRequest) -> LdapMsg {
    let authzid = session
        .bound_dn()
        .map(|dn| format!("dn:{dn}"))
        .unwrap_or_default();
    req.gen_success(&authzid)
}
