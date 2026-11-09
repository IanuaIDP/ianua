//! What a proven caller holds now, read from the tenant's records, never
//! from what a token claims. Read once here; the access decision takes it
//! from the proof rather than reading it again.

use ianua_domain::domains::authorization::held::Held;
use ianua_domain::domains::proxy::request::context::CallerClaims;
use ianua_domain::types::PrincipalRef;

use crate::ports::authorization::AccessRecordStore;
use crate::services::authorization::held::held;
use crate::tenancy::ScopedTenant;
use crate::use_cases::proxy::credentials::outcome::Refusal;

/// What `principal` holds in `tenant` now: from its roles and groups,
/// widened by the ladders, and for a person their live break-glass access.
/// A principal the records do not name holds nothing, which is no refusal.
///
/// # Errors
///
/// - [`Refusal::Unavailable`] when the records cannot be read, or name a
///   role or group that is not there: a gateway that cannot find out what
///   a caller holds does not assume it.
pub(crate) async fn held_by(
    records: &dyn AccessRecordStore,
    tenant: &ScopedTenant,
    principal: PrincipalRef,
) -> Result<Held, Refusal> {
    held(records, tenant, principal)
        .await
        .map_err(Refusal::unavailable)
}

/// What `held` gives, written out as an upstream reads it: the permissions
/// by name, and the roles by name and id.
pub(crate) fn claims_of(held: &Held) -> CallerClaims {
    CallerClaims {
        permissions: held.holdings().names(),
        role_names: held.role_names().to_vec(),
        role_ids: held.roles().to_vec(),
        ..CallerClaims::default()
    }
}
