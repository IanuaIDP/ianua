//! An organization member as their row holds them: read back into the
//! aggregate, and written out from it.

use ianua_domain::domains::identity::account::vouching::Vouching;
use ianua_domain::domains::organization::members::org_user::{OrgPassword, OrgUser, OrgUserRow};
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    CredentialChange, DisplayName, Email, Joining, Locale, OrgUserId, OrganizationId, PasswordHash,
    Preference, Timezone,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};
use crate::postgres::identity::users::record::RouteVouches;

const ORG_USER: Stored = Stored("organization member");

/// A member as it is read. The checked queries of every store reading
/// members fill it.
pub(crate) struct OrgUserRecord {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) email: String,
    pub(crate) display_name: String,
    pub(crate) password_hash: Option<String>,
    pub(crate) status: String,
    pub(crate) role: String,
    pub(crate) email_standing: String,
    pub(crate) locale: Option<String>,
    pub(crate) timezone: Option<String>,
    pub(crate) joined_at: Option<OffsetDateTime>,
    pub(crate) credentials_changed_at: Option<OffsetDateTime>,
    pub(crate) route_vouches: bool,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) updated_at: OffsetDateTime,
}

impl OrgUserRecord {
    /// The member the record holds, rebuilt through the domain's checks,
    /// the name checked against `limits`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the member
    /// keeps.
    pub(crate) fn into_org_user(self, limits: &DomainLimits) -> Result<OrgUser, DomainError> {
        let locale = self
            .locale
            .map(|locale| ORG_USER.value("locale", Locale::new(locale)))
            .transpose()?;
        let timezone = self
            .timezone
            .map(|timezone| ORG_USER.value("timezone", Timezone::new(timezone)))
            .transpose()?;
        OrgUser::reconstitute(OrgUserRow {
            id: OrgUserId::from_uuid(self.id),
            organization_id: OrganizationId::from_uuid(self.organization_id),
            email: ORG_USER.value("email", Email::new(self.email))?,
            display_name: ORG_USER.value(
                "display name",
                DisplayName::new(self.display_name, &limits.display_name),
            )?,
            password_hash: OrgPassword::from_stored(
                self.password_hash.map(PasswordHash::from_stored),
            ),
            status: ORG_USER.choice(&self.status)?,
            role: ORG_USER.choice(&self.role)?,
            email_standing: ORG_USER.choice(&self.email_standing)?,
            locale: Preference::from_stored(locale),
            timezone: Preference::from_stored(timezone),
            created_at: self.created_at,
            updated_at: self.updated_at,
            joining: Joining::from_stored(self.joined_at),
            credentials_changed_at: CredentialChange::from_stored(self.credentials_changed_at),
            vouching: RouteVouches(self.route_vouches).into(),
        })
    }
}

/// A member's columns, as they are written.
pub(super) struct OrgUserColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) organization_id: &'a Uuid,
    pub(super) email: &'a str,
    pub(super) display_name: &'a str,
    pub(super) password_hash: Option<&'a str>,
    pub(super) status: &'static str,
    pub(super) role: &'static str,
    pub(super) email_standing: &'static str,
    pub(super) locale: Option<&'a str>,
    pub(super) timezone: Option<&'a str>,
    pub(super) joined_at: Option<OffsetDateTime>,
    pub(super) credentials_changed_at: Option<OffsetDateTime>,
    pub(super) route_vouches: bool,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> OrgUserColumns<'a> {
    /// The columns `member` is written to.
    pub(super) fn of(member: &'a OrgUser) -> Self {
        Self {
            id: member.id().as_uuid(),
            organization_id: member.organization_id().as_uuid(),
            email: member.email().as_str(),
            display_name: member.display_name().as_str(),
            password_hash: member.password_hash().hash().map(PasswordHash::as_str),
            status: member.status().word(),
            role: member.role().word(),
            email_standing: member.address().standing().word(),
            locale: member.locale().value().map(Locale::as_str),
            timezone: member.timezone().value().map(Timezone::as_str),
            joined_at: member.joined_at(),
            credentials_changed_at: member.credentials_changed_at().changed_at(),
            route_vouches: member.vouching() == Vouching::Fresh,
            created_at: member.created_at(),
            updated_at: member.updated_at(),
        }
    }
}
