//! An account's channel as its row holds it: read back into the aggregate,
//! and written out from it.

use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::domains::workflows::triggers::channel::{
    AccountChannel, AccountChannelRow, ChannelCursor, ChannelSetup, ChannelStatus, HistoryPlace,
};
use ianua_domain::domains::workflows::triggers::subscription::{Lapse, Registration};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{AccountChannelId, IntegrationAccountId, SealedSecret, TenantId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _, stored_words};
use crate::postgres::workflows::triggers::subscriptions::registration_from;

const CHANNEL: Stored = Stored("account channel");

stored_words! {
    ChannelSetup as "channel setup" {
        Registered => "registered",
        PastedKey => "pasted_key",
        TokenFromService => "token_from_service",
    }
}

stored_words! {
    ChannelStatus as "channel status" {
        Registering => "registering",
        AwaitingKey => "awaiting_key",
        AwaitingToken => "awaiting_token",
        AwaitingConfirmation => "awaiting_confirmation",
        Live => "live",
        Lapsed => "lapsed",
    }
}

/// A channel as it is read. The store's checked queries fill it.
pub(super) struct ChannelRecord {
    pub(super) id: Uuid,
    pub(super) account_id: Uuid,
    pub(super) integration: String,
    pub(super) secret_sealed: String,
    pub(super) setup: String,
    pub(super) status: String,
    pub(super) remote: Option<String>,
    pub(super) lapses_at: Option<OffsetDateTime>,
    pub(super) history_cursor: Option<String>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl ChannelRecord {
    /// The channel the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the channel
    /// keeps.
    pub(super) fn into_channel(self) -> Result<AccountChannel<ResolvedTenant>, DomainError> {
        let history = self
            .history_cursor
            .map(|written| CHANNEL.value("cursor", ChannelCursor::new(written)))
            .transpose()?
            .map_or(HistoryPlace::Unknown, HistoryPlace::At);
        AccountChannel::reconstitute(AccountChannelRow {
            id: AccountChannelId::from_uuid(self.id),
            account: IntegrationAccountId::from_uuid(self.account_id),
            integration: CHANNEL.value("integration", IntegrationKey::new(self.integration))?,
            secret: CHANNEL.value("secret", SealedSecret::new(self.secret_sealed))?,
            setup: CHANNEL.choice(&self.setup)?,
            status: CHANNEL.choice(&self.status)?,
            registration: registration_from(self.remote, self.lapses_at)?,
            history,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// A channel's columns, as they are written.
pub(super) struct ChannelColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) account_id: Uuid,
    pub(super) integration: &'a str,
    pub(super) secret_sealed: &'a str,
    pub(super) setup: &'static str,
    pub(super) status: &'static str,
    pub(super) remote: Option<&'a str>,
    pub(super) lapses_at: Option<OffsetDateTime>,
    pub(super) history_cursor: Option<&'a str>,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> ChannelColumns<'a> {
    /// The columns `channel` is written to. Its secret is written in the
    /// sealed form it already holds.
    pub(super) fn of(channel: &'a AccountChannel<ResolvedTenant>) -> Self {
        let (remote, lapses_at) = match channel.registration() {
            Registration::NotTaken => (None, None),
            Registration::Taken { remote, lapses } => (
                Some(remote.as_str()),
                match lapses {
                    Lapse::Never => None,
                    Lapse::At(at) => Some(*at),
                },
            ),
        };
        Self {
            id: channel.id().as_uuid(),
            account_id: *channel.account().as_uuid(),
            integration: channel.integration().as_str(),
            secret_sealed: channel.secret().as_str(),
            setup: channel.setup().word(),
            status: channel.status().word(),
            remote,
            lapses_at,
            history_cursor: channel.history().cursor().map(ChannelCursor::as_str),
            created_at: channel.created_at(),
            updated_at: channel.updated_at(),
        }
    }
}

/// Where a channel found across tenants is kept, as its row holds it.
pub(super) struct ChannelHit {
    pub(super) tenant_id: Uuid,
    pub(super) id: Uuid,
}

impl ChannelHit {
    /// The tenant it is kept in.
    pub(super) fn tenant(&self) -> TenantId {
        TenantId::from_uuid(self.tenant_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::foundation::stored::StoredWord;

    /// Every setup and status reads back from the word it is written as.
    #[test]
    fn every_word_reads_back() {
        for setup in [
            ChannelSetup::Registered,
            ChannelSetup::PastedKey,
            ChannelSetup::TokenFromService,
        ] {
            assert_eq!(ChannelSetup::from_word(setup.word()), Some(setup));
        }
        for status in [
            ChannelStatus::Registering,
            ChannelStatus::AwaitingKey,
            ChannelStatus::AwaitingToken,
            ChannelStatus::AwaitingConfirmation,
            ChannelStatus::Live,
            ChannelStatus::Lapsed,
        ] {
            assert_eq!(ChannelStatus::from_word(status.word()), Some(status));
        }
    }
}
