//! Accounts that applications such as Jira, GitLab and SSSD bind to the
//! tenant's LDAP directory as, instead of a person's password: what each
//! may do and where, who may hand that out, and each bind.

pub mod account;
pub mod bind;
pub mod control;
pub mod scope;
