//! What a tenant living in a database of its own needs of the foundation:
//! its schema made and dropped, its audit trail handed in and back, its
//! rows removed from a database once it is deleted, and reading a row in
//! every tenant's database before its tenant is known.

pub(crate) mod everywhere;
pub(crate) mod purge;
pub(crate) mod schemas;
pub(crate) mod trail;
