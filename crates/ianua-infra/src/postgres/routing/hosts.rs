//! The domains a route, or the server names a stream route, answers on, as
//! a `text[]` column: the names, or `NULL` for every one.

use ianua_domain::domains::routing::matching::host::RouteHosts;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::DomainName;

use crate::postgres::foundation::stored::Stored;

/// The column `hosts` is written to: its names, or `None` for every one.
pub(crate) fn hosts_column(hosts: &RouteHosts) -> Option<Vec<String>> {
    match hosts {
        RouteHosts::Any => None,
        RouteHosts::Only(names) => Some(
            names
                .as_slice()
                .iter()
                .map(|name| name.as_str().to_owned())
                .collect(),
        ),
    }
}

/// The hosts a stored column of `entity` holds.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a stored name is not a domain
/// name, or the stored list is empty.
pub(crate) fn hosts_from(
    entity: Stored,
    stored: Option<Vec<String>>,
) -> Result<RouteHosts, DomainError> {
    let names = stored
        .map(|hosts| {
            hosts
                .into_iter()
                .map(|host| entity.value("host", DomainName::new(host)))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    RouteHosts::from_stored(names)
}
