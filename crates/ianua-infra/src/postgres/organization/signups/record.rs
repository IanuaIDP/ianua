//! A sign-up as its row holds it: read back into the aggregate, and written
//! out from it.

use ianua_domain::domains::organization::signup::{PendingSignup, PendingSignupRow, SignupDetails};
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DisplayName, Email, Label, Locale, PasswordHash, Timezone, TokenHash};
use time::OffsetDateTime;

use crate::postgres::foundation::stored::Stored;

const SIGNUP: Stored = Stored("pending sign-up");

/// A sign-up as it is read. The store's checked queries fill it.
pub(super) struct SignupRecord {
    pub(super) token_hash: String,
    pub(super) email: String,
    pub(super) company_name: String,
    pub(super) tenant_name: String,
    pub(super) admin_display_name: String,
    pub(super) password_hash: String,
    pub(super) timezone: String,
    pub(super) locale: String,
    pub(super) requested_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
}

impl SignupRecord {
    /// The sign-up the record holds, rebuilt through the domain's checks,
    /// the founder's name checked against `limits`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, or the link's times break the sign-up's rules.
    pub(super) fn into_signup(self, limits: &DomainLimits) -> Result<PendingSignup, DomainError> {
        PendingSignup::reconstitute(PendingSignupRow {
            email: SIGNUP.value("email", Email::new(self.email))?,
            details: SignupDetails {
                company_name: SIGNUP.value(
                    "company name",
                    Label::new("company_name", self.company_name),
                )?,
                tenant_name: SIGNUP
                    .value("tenant name", Label::new("tenant_name", self.tenant_name))?,
                admin_display_name: SIGNUP.value(
                    "founder's name",
                    DisplayName::new(self.admin_display_name, &limits.display_name),
                )?,
                password_hash: PasswordHash::from_stored(self.password_hash),
                timezone: SIGNUP.value("timezone", Timezone::new(self.timezone))?,
                locale: SIGNUP.value("locale", Locale::new(self.locale))?,
            },
            token_hash: TokenHash::from_stored(self.token_hash),
            requested_at: self.requested_at,
            expires_at: self.expires_at,
        })
    }
}

/// A sign-up's columns, as they are written.
pub(super) struct SignupColumns<'a> {
    pub(super) token_hash: &'a str,
    pub(super) email: &'a str,
    pub(super) company_name: &'a str,
    pub(super) tenant_name: &'a str,
    pub(super) admin_display_name: &'a str,
    pub(super) password_hash: &'a str,
    pub(super) timezone: &'a str,
    pub(super) locale: &'a str,
    pub(super) requested_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
}

impl<'a> SignupColumns<'a> {
    /// The columns the sign-up stored as `row` is written to, `row` being
    /// what [`PendingSignup::to_row`] gives.
    pub(super) fn of(row: &'a PendingSignupRow) -> Self {
        Self {
            token_hash: row.token_hash.as_str(),
            email: row.email.as_str(),
            company_name: row.details.company_name.as_str(),
            tenant_name: row.details.tenant_name.as_str(),
            admin_display_name: row.details.admin_display_name.as_str(),
            password_hash: row.details.password_hash.as_str(),
            timezone: row.details.timezone.as_str(),
            locale: row.details.locale.as_str(),
            requested_at: row.requested_at,
            expires_at: row.expires_at,
        }
    }
}
