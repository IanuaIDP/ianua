//! A tenant's access policy and the records of access granted: the stores
//! of `ports/authorization/policies.rs`.

mod access_records;
mod versions;

pub use access_records::PgAccessRecordStore;
pub use versions::PgPolicyStore;
