//! Reading a row by what it holds before its tenant is known, such as a
//! presented token's digest: in the platform database for every tenant
//! living there and in each database of a tenant living apart, all at
//! once, each read held to a few seconds.
//!
//! A row the platform database still holds for a tenant that moved apart
//! is left out, and a tenant's own database answers only for that tenant.
//! A read that failed fails the search unless another database found what
//! was looked for.

use std::future::Future;
use std::time::Duration;

use futures_util::future::join_all;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;

/// How long one read of a search may take before it counts as failed.
pub(crate) const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// What `read` finds in the platform database and in every tenant's own
/// in `databases`, all at once, keeping the rows each database may answer
/// for, as `tenant_of` names their tenant.
///
/// # Errors
///
/// Returns the first failure when nothing was found and a read failed.
pub(crate) async fn everywhere<T, F, R>(
    databases: &Databases,
    read: F,
    tenant_of: impl Fn(&T) -> TenantId,
) -> Result<Vec<T>, DomainError>
where
    F: Fn(RowScope) -> R,
    R: Future<Output = Result<Vec<T>, DomainError>>,
{
    let scopes = std::iter::once(RowScope::Platform).chain(
        databases
            .with_own_database()
            .into_iter()
            .map(RowScope::Tenant),
    );
    let answers = join_all(scopes.map(|scope| {
        let reading = bounded(read(scope));
        async move { (scope, reading.await) }
    }))
    .await;
    let mut found = Vec::new();
    let mut failed = None;
    for (scope, answer) in answers {
        match answer {
            Ok(rows) => found.extend(
                rows.into_iter()
                    .filter(|row| belongs(databases, scope, &tenant_of(row))),
            ),
            Err(error) => failed = failed.or(Some(error)),
        }
    }
    let Some(error) = failed.filter(|_| found.is_empty()) else {
        return Ok(found);
    };
    Err(error)
}

/// `reading`, failed when it takes longer than [`READ_TIMEOUT`].
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when it runs out of time, and the
/// read's own failure otherwise.
pub(crate) async fn bounded<T>(
    reading: impl Future<Output = Result<T, DomainError>>,
) -> Result<T, DomainError> {
    tokio::time::timeout(READ_TIMEOUT, reading)
        .await
        .map_err(DomainError::infra)?
}

/// Whether a row of `tenant` read under `scope` is one to trust: from the
/// platform database only while the tenant lives there, from a tenant's
/// own database only its own.
fn belongs(databases: &Databases, scope: RowScope, tenant: &TenantId) -> bool {
    match scope {
        RowScope::Platform => !databases.lives_apart(tenant),
        RowScope::Tenant(own) => own == *tenant,
        RowScope::Unscoped => false,
    }
}
