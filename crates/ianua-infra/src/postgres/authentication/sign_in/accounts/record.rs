//! The account a password sign-in names, as its rows hold it: read back
//! into the port's candidate through each value's own constructor.
//!
//! The account's status is read with the words users are stored with, and
//! whether a second factor is held is the domain's call over what was
//! found.

use ianua_domain::domains::authentication::credentials::password_rules::PasswordDue;
use ianua_domain::domains::authentication::mfa::owed::{CodeFactorHolding, HeldFactors};
use ianua_domain::domains::authentication::operations::password_login::LoginCandidate;
use ianua_domain::domains::identity::account::address::AddressStanding;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{PasswordHash, UserId};
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;
use crate::postgres::identity::users::record::RouteVouches;

const CANDIDATE: Stored = Stored("sign-in account");

/// An account as a sign-in reads it. The store's checked query fills it.
pub(super) struct CandidateRecord {
    pub(super) id: Uuid,
    pub(super) status: String,
    pub(super) email_verified: bool,
    pub(super) route_vouches: bool,
    pub(super) password_hash: String,
    pub(super) code_factor: bool,
    pub(super) passkeys: i64,
}

impl CandidateRecord {
    /// The candidate the record holds, its password taken as current: the
    /// sign-in works out whether it must change.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the status is unknown or
    /// the count of passkeys does not fit.
    pub(super) fn into_candidate(self) -> Result<LoginCandidate, DomainError> {
        let passkeys = usize::try_from(self.passkeys).map_err(DomainError::infra)?;
        let email_standing = if self.email_verified {
            AddressStanding::Verified
        } else {
            AddressStanding::Unverified
        };
        let code_factor = if self.code_factor {
            CodeFactorHolding::Active
        } else {
            CodeFactorHolding::None
        };
        Ok(LoginCandidate {
            user_id: UserId::from_uuid(self.id),
            password_hash: PasswordHash::from_stored(self.password_hash),
            status: CANDIDATE.choice(&self.status)?,
            email_standing,
            enrolment: HeldFactors::new(code_factor, passkeys).enrolment(),
            vouching: RouteVouches(self.route_vouches).into(),
            password_due: PasswordDue::Current,
        })
    }
}
