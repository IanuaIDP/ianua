//! Search: the users and groups who the connection is bound as may read.

use ldap3_proto::proto::{LdapMsg, LdapResultCode, LdapSearchScope};
use ldap3_proto::simple::SearchRequest;

use crate::dit::entries::{self, Entry};
use crate::dit::filter;
use crate::ops::reading;
use crate::ports::LdapPorts;
use crate::server::SIZE_LIMIT;
use crate::session::Session;

/// Answers a search.
///
/// The root DSE is the only entry visible without a bind. Anything else is
/// read through the use case of who the connection is bound as, which
/// decides whether it may read where the search is aimed; the entries
/// returned are those in the search's scope that its filter matches.
pub(super) async fn handle(
    ports: &LdapPorts,
    session: &mut Session,
    req: SearchRequest,
) -> Vec<LdapMsg> {
    if req.base.is_empty() && matches!(req.scope, LdapSearchScope::Base) {
        return root_dse(&req);
    }
    let (tenant, listing) = match reading::listing(ports, session, &req.base).await {
        Ok(read) => read,
        Err((code, message)) => return vec![req.gen_error(code, message)],
    };
    let all = entries::build_entries(&tenant, &listing);
    let selected: Vec<&Entry> = all
        .iter()
        .filter(|e| e.in_scope(&req.base, &req.scope))
        .filter(|e| filter::matches(&req.filter, e))
        .collect();
    found(&req, &selected)
}

/// The root DSE, when the search's filter matches it.
fn root_dse(req: &SearchRequest) -> Vec<LdapMsg> {
    let dse = entries::root_dse();
    let matched =
        filter::matches(&req.filter, &dse).then(|| req.gen_result_entry(dse.to_result(&req.attrs)));
    matched.into_iter().chain([req.gen_success()]).collect()
}

/// The answers for `selected`, cut at the size limit.
fn found(req: &SearchRequest, selected: &[&Entry]) -> Vec<LdapMsg> {
    let mut out: Vec<LdapMsg> = selected
        .iter()
        .take(SIZE_LIMIT)
        .map(|e| req.gen_result_entry(e.to_result(&req.attrs)))
        .collect();
    if selected.len() > SIZE_LIMIT {
        out.push(req.gen_error(LdapResultCode::SizeLimitExceeded, String::new()));
        return out;
    }
    out.push(req.gen_success());
    out
}
