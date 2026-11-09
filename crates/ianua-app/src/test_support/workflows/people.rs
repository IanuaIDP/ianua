//! The people a workflow acts for, as the tenant's records hold them in
//! tests: active accounts, each holding one role.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::SystemPermission;
use ianua_domain::types::{Human, HumanAccount};

use crate::ports::authorization::AccessRecords;
use crate::services::account_now::{AccountsNow, AccountsNowPorts};
use crate::test_support::agents::FakeRelationshipResolver;
use crate::test_support::authorization::{FakeAccessRecordStore, stored_assignment, stored_role};
use crate::test_support::identity::FakeUserStore;
use crate::test_support::{Fake, test_ctx};

/// The tenant's records where each person in `people` has an active
/// account and holds one role granting what is listed beside them. Each
/// holds use of every resource asked about.
///
/// # Panics
///
/// Panics if a person is an organization member, whom these records do not
/// hold.
#[must_use]
pub fn accounts_now_of(people: &[(&Human, &[SystemPermission])]) -> AccountsNow {
    let users = FakeUserStore::empty();
    let mut records = AccessRecords::default();
    for (person, held) in people {
        let HumanAccount::User(user) = person.account() else {
            panic!("a test names tenant users only");
        };
        users.add_active_user(user, person.person().as_str());
        let role = stored_role("workflow rights", held.to_vec(), Vec::new());
        records
            .assignments
            .push(stored_assignment(person.principal(), *role.id()));
        records.roles.push(role);
    }
    AccountsNow::new(AccountsNowPorts {
        access_records: Arc::new(FakeAccessRecordStore::holding(
            test_ctx().tenant_id(),
            records,
        )),
        users: Arc::new(users),
        relationships: Arc::new(FakeRelationshipResolver::HoldsEverything),
        ..AccountsNowPorts::fakes()
    })
}

impl Fake for Arc<AccountsNow> {
    fn fake() -> Self {
        Arc::new(AccountsNow::new(AccountsNowPorts::fakes()))
    }
}
