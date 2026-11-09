//! Reading the directory, for a search or a compare: the use case of who
//! the connection is bound as decides whether it may read where it aims.

use ianua_app::use_case::Command as _;
use ianua_app::use_cases::directory::DirectoryListing;
use ianua_app::use_cases::directory::principal::DirectoryBase;
use ianua_app::use_cases::directory::service_accounts::ServiceSearchRequest;
use ianua_domain::domains::authentication::directory_service::scope::BaseDn;
use ldap3_proto::proto::LdapResultCode;

use crate::dit::dn::{self, TenantPath};
use crate::ops::{connection_auditor, errors, naming, person_auditor};
use crate::ports::LdapPorts;
use crate::session::{Bound, Session};

/// The tenant the DN `aimed_at` lies in and its listing, when who the
/// connection is bound as may read there; otherwise the refusal to answer.
pub(super) async fn listing(
    ports: &LdapPorts,
    session: &mut Session,
    aimed_at: &str,
) -> Result<(TenantPath, DirectoryListing), (LdapResultCode, String)> {
    let Some(base) = naming::base_named(aimed_at) else {
        return Err((LdapResultCode::NoSuchObject, String::new()));
    };
    let read = match &session.bound {
        Bound::Nobody => {
            return Err((
                LdapResultCode::InsufficentAccessRights,
                "bind first".to_owned(),
            ));
        }
        Bound::Person(person) => {
            let auditor = person_auditor(ports, &person.principal);
            ports
                .search
                .execute(&person.principal, &auditor, base.clone())
                .await
        }
        Bound::Service(service) => {
            let request = service_request(&base, aimed_at)?;
            let auditor = connection_auditor(ports, session);
            ports
                .service_search
                .execute(&service.principal, &auditor, request)
                .await
        }
    };
    read.map(|listing| (naming::path_of(&base), listing))
        .map_err(|refused| errors::refusal(session, refused))
}

/// A service account's read under `aimed_at` in `base`. A DN its scope
/// could not be compared against is no entry it may read.
fn service_request(
    base: &DirectoryBase,
    aimed_at: &str,
) -> Result<ServiceSearchRequest, (LdapResultCode, String)> {
    let search_base = BaseDn::new(dn::normalize(aimed_at))
        .map_err(|_| (LdapResultCode::NoSuchObject, String::new()))?;
    Ok(ServiceSearchRequest {
        base: base.clone(),
        search_base,
    })
}
