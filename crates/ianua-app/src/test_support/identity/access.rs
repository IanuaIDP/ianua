//! Tenant records in which one user holds a role, for tests about acting on
//! an account that holds more than the person acting.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::types::{PrincipalRef, UserId};

use crate::ports::authorization::AccessRecords;
use crate::test_support::authorization::{FakeAccessRecordStore, stored_assignment, stored_role};
use crate::test_support::identity::held::seeded_tenant;

/// The seeded tenant's records, in which `user_id` holds a role granting
/// `system` and nobody holds anything else.
#[must_use]
pub fn access_where_holds(
    user_id: UserId,
    system: &[SystemPermission],
) -> Arc<FakeAccessRecordStore> {
    let role = stored_role("held", system.to_vec(), Vec::new());
    let assignment = stored_assignment(PrincipalRef::User(user_id), *role.id());
    Arc::new(FakeAccessRecordStore::holding(
        seeded_tenant(),
        AccessRecords {
            roles: vec![role],
            assignments: vec![assignment],
            groups: Vec::new(),
            memberships: Vec::new(),
            catalogue: Vec::new(),
            break_glass: Vec::new(),
        },
    ))
}
