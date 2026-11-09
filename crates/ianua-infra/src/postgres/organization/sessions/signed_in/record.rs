//! A member's session as its row holds it: read back into the aggregate,
//! and written out from it.

use ianua_domain::domains::authentication::sessions::mfa_factor::{FactorProved, MfaFactor};
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
use ianua_domain::domains::organization::access::session::{
    OrgSession, OrgSessionRow, SessionPlace,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    CredentialChange, Fact, IpAddress, OrgUserId, OrganizationId, SessionId, TenantId, TokenHash,
    UserAgent,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const SESSION: Stored = Stored("organization session");

/// A session as it is read. The store's checked queries fill it.
pub(super) struct SessionRecord {
    pub(super) id: Uuid,
    pub(super) organization_id: Uuid,
    pub(super) org_user_id: Uuid,
    pub(super) working_tenant: Option<Uuid>,
    pub(super) refresh_token_hash: String,
    pub(super) auth_method: String,
    pub(super) factor: Option<String>,
    pub(super) owed: String,
    pub(super) ip_address: Option<String>,
    pub(super) user_agent: Option<String>,
    pub(super) status: String,
    pub(super) kept_through: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
    pub(super) last_active_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
}

impl SessionRecord {
    /// The session the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the session
    /// keeps.
    pub(super) fn into_session(self) -> Result<OrgSession, DomainError> {
        let factor = self
            .factor
            .as_deref()
            .map(|word| SESSION.choice(word))
            .transpose()?;
        let ip_address = read_ip_address(self.ip_address)?;
        let user_agent = read_user_agent(self.user_agent)?;
        OrgSession::reconstitute(OrgSessionRow {
            id: SessionId::from_uuid(self.id),
            org_user_id: OrgUserId::from_uuid(self.org_user_id),
            organization_id: OrganizationId::from_uuid(self.organization_id),
            place: place_from(self.working_tenant),
            refresh_token_hash: TokenHash::from_stored(self.refresh_token_hash),
            progress: SignInProgressRow {
                method: SESSION.choice(&self.auth_method)?,
                factor: FactorProved::from_stored(factor),
                owed: SESSION.choice(&self.owed)?,
            },
            ip_address: Fact::from_option(ip_address),
            user_agent: Fact::from_option(user_agent),
            status: SESSION.choice(&self.status)?,
            created_at: self.created_at,
            last_active_at: self.last_active_at,
            expires_at: self.expires_at,
            kept_through: CredentialChange::from_stored(self.kept_through),
        })
    }
}

/// A session's columns, as they are written.
pub(super) struct SessionColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) organization_id: &'a Uuid,
    pub(super) org_user_id: &'a Uuid,
    pub(super) working_tenant: Option<Uuid>,
    pub(super) refresh_token_hash: &'a str,
    pub(super) auth_method: &'static str,
    pub(super) factor: Option<&'static str>,
    pub(super) owed: &'static str,
    pub(super) ip_address: Option<String>,
    pub(super) user_agent: Option<String>,
    pub(super) status: &'static str,
    pub(super) kept_through: Option<OffsetDateTime>,
    pub(super) created_at: OffsetDateTime,
    pub(super) last_active_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
}

impl<'a> SessionColumns<'a> {
    /// The columns `session` is written to.
    pub(super) fn of(session: &'a OrgSession) -> Self {
        let progress = session.progress();
        Self {
            id: session.id().as_uuid(),
            organization_id: session.organization_id().as_uuid(),
            org_user_id: session.org_user_id().as_uuid(),
            working_tenant: working_tenant_of(session.place()),
            refresh_token_hash: session.refresh_token_hash().as_str(),
            auth_method: progress.method().word(),
            factor: progress.factor().stored().map(MfaFactor::word),
            owed: progress.owed().word(),
            ip_address: session
                .ip_address()
                .known()
                .map(|ip| ip.as_str().to_owned()),
            user_agent: session
                .user_agent()
                .known()
                .map(|agent| agent.as_str().to_owned()),
            status: session.status().word(),
            kept_through: session.kept_through().changed_at(),
            created_at: session.created_at(),
            last_active_at: session.last_active_at(),
            expires_at: session.expires_at(),
        }
    }
}

/// Reads a stored address without turning an unobserved client into a known one.
fn read_ip_address(value: Option<String>) -> Result<Option<IpAddress>, DomainError> {
    value
        .map(|ip| SESSION.value("ip address", IpAddress::new(ip)))
        .transpose()
}

/// Validates a stored user agent while preserving an unobserved client.
fn read_user_agent(value: Option<String>) -> Result<Option<UserAgent>, DomainError> {
    value
        .map(|agent| SESSION.value("user agent", UserAgent::new(agent)))
        .transpose()
}

/// The tenant a session works in, as its column holds it: `None` for one
/// that works on the organization alone.
fn working_tenant_of(place: SessionPlace) -> Option<Uuid> {
    match place {
        SessionPlace::Tenant(tenant) => Some(*tenant.as_uuid()),
        SessionPlace::Organization => None,
    }
}

fn place_from(working_tenant: Option<Uuid>) -> SessionPlace {
    working_tenant.map_or(SessionPlace::Organization, |tenant| {
        SessionPlace::Tenant(TenantId::from_uuid(tenant))
    })
}
