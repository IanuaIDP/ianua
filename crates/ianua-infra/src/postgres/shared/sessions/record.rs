//! A tenant session as its row holds it: read back into the aggregate, and
//! written out from it.
//!
//! The words of a session's choices are the ones the organization's
//! sessions are stored with, so both planes read the same words.

use ianua_domain::domains::authentication::risk_engine::assessment::IpGeolocation;
use ianua_domain::domains::authentication::sessions::channel::SessionChannel;
use ianua_domain::domains::authentication::sessions::last_use::{CallerNetwork, LastUse};
use ianua_domain::domains::authentication::sessions::mfa_factor::{FactorProved, MfaFactor};
use ianua_domain::domains::authentication::sessions::session::{
    Session, SessionOrigin, SessionRow,
};
use ianua_domain::domains::authentication::sessions::sign_in_progress::SignInProgressRow;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{
    CountryCode, CredentialChange, Fact, IpAddress, ServiceId, SessionId, TokenHash,
    TrustedDeviceId, UserAgent, UserId,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const SESSION: Stored = Stored("session");

/// A session as it is read. The store's checked queries fill it.
pub(super) struct SessionRecord {
    pub(super) id: Uuid,
    pub(super) user_id: Uuid,
    pub(super) refresh_token_hash: String,
    pub(super) parent_id: Option<Uuid>,
    pub(super) ip_address: Option<String>,
    pub(super) user_agent: Option<String>,
    pub(super) auth_method: String,
    pub(super) factor: Option<String>,
    pub(super) owed: String,
    pub(super) status: String,
    pub(super) app_service_id: Option<Uuid>,
    pub(super) signed_in_at: OffsetDateTime,
    pub(super) created_at: OffsetDateTime,
    pub(super) last_active_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) kept_through: Option<OffsetDateTime>,
    pub(super) signed_in_from: Option<Uuid>,
    pub(super) last_used_network: Option<String>,
    pub(super) last_used_latitude: Option<f64>,
    pub(super) last_used_longitude: Option<f64>,
    pub(super) last_used_country: Option<String>,
    pub(super) last_used_at: Option<OffsetDateTime>,
}

impl SessionRecord {
    /// The session the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the session
    /// keeps.
    pub(super) fn into_session(self) -> Result<Session<ResolvedTenant>, DomainError> {
        let factor = stored_factor(self.factor.as_deref())?;
        let last_use = self.stored_last_use()?;
        let ip_address = stored_ip_address(self.ip_address)?;
        let user_agent = stored_user_agent(self.user_agent)?;
        Session::reconstitute(SessionRow {
            id: SessionId::from_uuid(self.id),
            user_id: UserId::from_uuid(self.user_id),
            refresh_token_hash: TokenHash::from_stored(self.refresh_token_hash),
            parent_id: SessionOrigin::from_stored(self.parent_id.map(SessionId::from_uuid)),
            ip_address: Fact::from_option(ip_address),
            user_agent: Fact::from_option(user_agent),
            signed_in_from: Fact::from_option(self.signed_in_from.map(TrustedDeviceId::from_uuid)),
            progress: SignInProgressRow {
                method: SESSION.choice(&self.auth_method)?,
                factor: FactorProved::from_stored(factor),
                owed: SESSION.choice(&self.owed)?,
            },
            status: SESSION.choice(&self.status)?,
            channel: channel_from(self.app_service_id),
            signed_in_at: self.signed_in_at,
            created_at: self.created_at,
            last_active_at: self.last_active_at,
            expires_at: self.expires_at,
            kept_through: CredentialChange::from_stored(self.kept_through),
            last_use,
        })
    }

    /// Where the session was last used, as its row keeps it. The schema
    /// keeps all five columns set or none, so a partial row cannot be read.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules.
    fn stored_last_use(&self) -> Result<Fact<LastUse>, DomainError> {
        let (Some(network), Some(latitude), Some(longitude), Some(country), Some(at)) = (
            self.last_used_network.as_ref(),
            self.last_used_latitude,
            self.last_used_longitude,
            self.last_used_country.as_deref(),
            self.last_used_at,
        ) else {
            return Ok(Fact::Unknown);
        };
        let country = SESSION.value("last used country", CountryCode::new(country))?;
        let place = IpGeolocation::new(latitude, longitude, country, None).map_err(|_| {
            DomainError::corrupt_row("session", "a last used place that is no place")
        })?;
        Ok(Fact::Known(LastUse::new(
            SESSION.value("last used network", CallerNetwork::new(network.clone()))?,
            place,
            at,
        )))
    }
}

/// A session's columns, as they are written.
pub(super) struct SessionColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) user_id: &'a Uuid,
    pub(super) refresh_token_hash: &'a str,
    pub(super) parent_id: Option<Uuid>,
    pub(super) ip_address: Option<String>,
    pub(super) user_agent: Option<String>,
    pub(super) auth_method: &'static str,
    pub(super) factor: Option<&'static str>,
    pub(super) owed: &'static str,
    pub(super) status: &'static str,
    pub(super) app_service_id: Option<Uuid>,
    pub(super) signed_in_at: OffsetDateTime,
    pub(super) created_at: OffsetDateTime,
    pub(super) last_active_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) kept_through: Option<OffsetDateTime>,
    pub(super) signed_in_from: Option<Uuid>,
    pub(super) last_used_network: Option<String>,
    pub(super) last_used_latitude: Option<f64>,
    pub(super) last_used_longitude: Option<f64>,
    pub(super) last_used_country: Option<String>,
    pub(super) last_used_at: Option<OffsetDateTime>,
}

impl<'a> SessionColumns<'a> {
    /// The columns `session` is written to.
    pub(super) fn of(session: &'a Session<ResolvedTenant>) -> Self {
        let progress = session.progress();
        let held_use = session.last_use();
        let last_use = held_use.known();
        Self {
            id: session.id().as_uuid(),
            user_id: session.user_id().as_uuid(),
            refresh_token_hash: session.refresh_token_hash().as_str(),
            parent_id: session.parent_id().parent().map(|parent| *parent.as_uuid()),
            ip_address: ip_address_column(session.ip_address()),
            user_agent: user_agent_column(session.user_agent()),
            auth_method: progress.method().word(),
            factor: progress.factor().stored().map(MfaFactor::word),
            owed: progress.owed().word(),
            status: session.status().word(),
            app_service_id: service_column(session.channel()),
            signed_in_at: session.signed_in_at(),
            created_at: session.created_at(),
            last_active_at: session.last_active_at(),
            expires_at: session.expires_at(),
            kept_through: session.kept_through().changed_at(),
            signed_in_from: device_column(session.signed_in_from()),
            last_used_network: last_use.map(|last| last.network().as_str().to_owned()),
            last_used_latitude: last_use.map(|last| last.place().latitude()),
            last_used_longitude: last_use.map(|last| last.place().longitude()),
            last_used_country: last_use.map(|last| last.place().country_code().to_string()),
            last_used_at: last_use.map(|last| last.at()),
        }
    }
}

/// Decodes an optional proved factor before other session fields are validated.
fn stored_factor(word: Option<&str>) -> Result<Option<MfaFactor>, DomainError> {
    word.map(|word| SESSION.choice(word)).transpose()
}

/// The address the session was opened from, checked, when the row has one.
fn stored_ip_address(address: Option<String>) -> Result<Option<IpAddress>, DomainError> {
    address
        .map(|ip| SESSION.value("ip address", IpAddress::new(ip)))
        .transpose()
}

/// The browser the session was opened in, checked, when the row has one.
fn stored_user_agent(agent: Option<String>) -> Result<Option<UserAgent>, DomainError> {
    agent
        .map(|agent| SESSION.value("user agent", UserAgent::new(agent)))
        .transpose()
}

/// Stores the address when it is known; a session with none leaves it empty.
fn ip_address_column(address: Fact<&IpAddress>) -> Option<String> {
    address.known().map(|ip| ip.as_str().to_owned())
}

/// Stores the browser when it is known; a session with none leaves it empty.
fn user_agent_column(agent: Fact<&UserAgent>) -> Option<String> {
    agent.known().map(|agent| agent.as_str().to_owned())
}

/// Stores the trusted device when one vouched for the sign-in.
fn device_column(device: Fact<TrustedDeviceId>) -> Option<Uuid> {
    device.known().map(|device| *device.as_uuid())
}

/// Stores only an app channel's service; dashboard sessions leave it empty.
fn service_column(channel: SessionChannel) -> Option<Uuid> {
    channel.app_service().map(|service| *service.as_uuid())
}

/// Where a session was opened, as its column holds it: the dashboard when
/// the column is empty.
fn channel_from(app_service_id: Option<Uuid>) -> SessionChannel {
    app_service_id.map_or(SessionChannel::Dashboard, |service| {
        SessionChannel::App(ServiceId::from_uuid(service))
    })
}
