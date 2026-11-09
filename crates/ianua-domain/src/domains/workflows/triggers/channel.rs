//! An account's channel: the one address a service sends every event of an
//! account to, for a service that takes one address per account rather than
//! one per workflow.
//!
//! Telegram's bot has one webhook. A Gmail mailbox has one watch. Notion,
//! HubSpot and Salesforce are set up by a person in the service's own
//! settings, once for the account. Every workflow waiting on such an
//! account shares the channel, and the channel holds what proves a delivery
//! came from the service.
//!
//! How it becomes ready depends on the service. One the platform registers
//! itself goes live when the service takes the call. One set up by hand
//! waits for its owner to paste in a key. One whose service sends a token
//! waits for the token, shows it to the owner, and goes live only when the
//! owner confirms they pasted it back. No delivery is read until it is
//! live, so nobody who learns the address starts anything while it waits.

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::workflows::account::IntegrationAccount;
use crate::domains::workflows::control::WorkflowControl;
use crate::domains::workflows::events::{
    AccountChannelClosed, AccountChannelLapsed, AccountChannelReady, AccountChannelTokenShown,
    ChannelRef,
};
use crate::domains::workflows::integration::IntegrationKey;
use crate::domains::workflows::triggers::subscription::{
    Lapse, LapseReason, Registration, RemoteRegistration,
};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::shared::model::transition::{InvalidTransition, checked};
use crate::shared::validation::{TextValue, Validator, text_value};
use crate::types::{AccountChannelId, IntegrationAccountId, SealedSecret};

text_value! {
    /// Where a service's history was last read up to for a channel, in the
    /// service's own words, such as a Gmail history id.
    pub struct ChannelCursor;
}

impl TextValue for ChannelCursor {
    const FIELD: &'static str = "cursor";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.length(1..=512).no_control_chars()
    }
}

/// How far a service's history has been read for a channel. A service that
/// announces events through its history, as Gmail does, moves it along; one
/// that sends each event whole leaves it [`HistoryPlace::Unknown`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryPlace {
    /// No place is known: the service keeps no history, or named none.
    Unknown,
    /// Read up to this place, which the next read starts from.
    At(ChannelCursor),
}

impl HistoryPlace {
    /// The place, in the form storage and the service's own calls take it.
    #[must_use]
    pub fn cursor(&self) -> Option<&ChannelCursor> {
        match self {
            Self::Unknown => None,
            Self::At(cursor) => Some(cursor),
        }
    }
}

text_value! {
    redacted
    /// A service's key as a person pastes it, such as HubSpot's app secret
    /// or a shared secret set in a Salesforce callout. A key this short, or
    /// an empty one, would let anyone sign what they like, so it is refused.
    pub struct ChannelKey;
}

impl TextValue for ChannelKey {
    const FIELD: &'static str = "key";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.length(16..=4096).no_control_chars()
    }
}

/// How a channel gets from opened to ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelSetup {
    /// The platform registers it at the service with a call, as Telegram's
    /// `setWebhook` and Gmail's `users.watch` do.
    Registered,
    /// A person sets the address in the service's settings and pastes the
    /// service's key here, as HubSpot's app secret and a shared secret in a
    /// Salesforce callout are.
    PastedKey,
    /// The service sends a one-time token to the address, and a person
    /// pastes it back at the service, as Notion asks.
    TokenFromService,
}

/// Where a channel is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelStatus {
    /// It is being registered at the service.
    Registering,
    /// It waits for its owner to paste in the service's key.
    AwaitingKey,
    /// It waits for the service to send its token.
    AwaitingToken,
    /// It holds the token, and waits for its owner to confirm they pasted
    /// it back at the service.
    AwaitingConfirmation,
    /// It takes the service's events.
    Live,
    /// It lapsed; the service's events start nothing until it is
    /// registered again.
    Lapsed,
}

impl ChannelStatus {
    /// Moves to `to`. One registered goes live or lapses, and a lapsed one
    /// may go live again. A key goes live; a token waits to be confirmed,
    /// and a newer token replaces one not yet confirmed.
    ///
    /// # Errors
    ///
    /// - [`InvalidTransition`] for any other move.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
        checked(self, to, |from, to| {
            matches!(
                (from, to),
                (Self::Registering | Self::Live, Self::Live | Self::Lapsed)
                    | (Self::Lapsed | Self::AwaitingKey, Self::Live)
                    | (
                        Self::AwaitingToken | Self::AwaitingConfirmation,
                        Self::AwaitingConfirmation
                    )
                    | (Self::AwaitingConfirmation, Self::Live)
            )
        })
    }
}

/// What a new channel is opened with.
pub struct OpenChannel {
    /// Its id, which its address names.
    pub id: AccountChannelId,
    /// The account whose events it takes.
    pub account: IntegrationAccountId,
    /// The integration whose service sends them.
    pub integration: IntegrationKey,
    /// What proves a delivery, sealed; the platform's own until a service's
    /// key or token replaces it.
    pub secret: SealedSecret,
    /// How it gets to ready.
    pub setup: ChannelSetup,
}

/// A channel as stored.
pub struct AccountChannelRow {
    /// Its id, which its address names.
    pub id: AccountChannelId,
    /// The account whose events it takes.
    pub account: IntegrationAccountId,
    /// The integration whose service sends them.
    pub integration: IntegrationKey,
    /// What proves a delivery, sealed.
    pub secret: SealedSecret,
    /// How it gets to ready.
    pub setup: ChannelSetup,
    /// Where it is.
    pub status: ChannelStatus,
    /// The service's side of it.
    pub registration: Registration,
    /// How far the service's history was read, so the next read starts there.
    pub history: HistoryPlace,
    /// When it was opened.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

/// An account's one address for a service's events.
#[derive(Debug)]
pub struct AccountChannel<T: TenantScope> {
    id: AccountChannelId,
    account: IntegrationAccountId,
    integration: IntegrationKey,
    secret: SealedSecret,
    setup: ChannelSetup,
    status: ChannelStatus,
    registration: Registration,
    history: HistoryPlace,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> AccountChannel<T> {
    /// Opens a channel, waiting for whatever `opening.setup` needs.
    ///
    /// # Errors
    ///
    /// None today; every value is already checked. It answers as every
    /// constructor of an aggregate does.
    pub fn open(opening: OpenChannel) -> Result<Self, DomainError> {
        let now = crate::shared::clock::now();
        Ok(Self {
            id: opening.id,
            account: opening.account,
            integration: opening.integration,
            secret: opening.secret,
            setup: opening.setup,
            status: first_status(opening.setup),
            registration: Registration::NotTaken,
            history: HistoryPlace::Unknown,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Rebuilds a channel from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says it changed before
    ///   it was opened, is a registered one live with no name from the
    ///   service, or is waiting in a way its setup never does.
    pub fn reconstitute(row: AccountChannelRow) -> Result<Self, DomainError> {
        RowCheck::of("account channel")
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was opened",
            )
            .holds(
                !registered_without_a_name(&row),
                "registered and live with no name from the service",
            )
            .holds(
                waits_as_its_setup_does(row.setup, row.status),
                "waiting in a way its setup never does",
            )
            .finish()?;
        Ok(Self {
            id: row.id,
            account: row.account,
            integration: row.integration,
            secret: row.secret,
            setup: row.setup,
            status: row.status,
            registration: row.registration,
            history: row.history,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The service took or renewed the registration, naming it `remote`,
    /// lapsing as `lapses` says. A `place` the service named becomes where
    /// its history is read from; [`HistoryPlace::Unknown`] keeps the place
    /// already held, so a renewal reads no mail twice. Raises
    /// `workflows.channel_ready` when it was not already live.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it is not one the platform
    ///   registers.
    pub fn register(
        &mut self,
        remote: RemoteRegistration,
        lapses: Lapse,
        place: HistoryPlace,
    ) -> Result<(), DomainError> {
        self.ensure_platform_registers(ChannelStatus::Live)?;
        let was_live = self.status == ChannelStatus::Live;
        self.status = self.status.try_transition(ChannelStatus::Live)?;
        self.registration = Registration::Taken { remote, lapses };
        if matches!(place, HistoryPlace::At(_)) {
            self.history = place;
        }
        self.touch();
        if !was_live {
            self.raise_ready();
        }
        Ok(())
    }

    /// Takes `key`, pasted by the account's owner, and goes live. A key
    /// pasted again replaces the last one. Raises `workflows.channel_ready`
    /// each time, so the trail shows every change of key.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is not the owner of `account`.
    /// - [`DomainError::Conflict`] when this service's channel takes no key.
    pub fn paste_key(
        &mut self,
        key: SealedSecret,
        account: &IntegrationAccount<T>,
        by: &WorkflowControl<'_>,
    ) -> Result<(), DomainError> {
        account.ensure_sets_up_events(by)?;
        if self.setup != ChannelSetup::PastedKey {
            return Err(DomainError::conflict(message!(
                "workflows-this-service-s-channel-takes-no-key",
                "this service's channel takes no pasted key"
            )));
        }
        self.status = self.status.try_transition(ChannelStatus::Live)?;
        self.secret = key;
        self.touch();
        self.raise_ready();
        Ok(())
    }

    /// Keeps `token`, which the service sent the address, until its owner
    /// has pasted it back. A newer token replaces one not yet confirmed, as
    /// a person who starts the setup again at the service gets a new one.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when it is not waiting for one.
    pub fn receive_token(&mut self, token: SealedSecret) -> Result<(), DomainError> {
        self.status = self
            .status
            .try_transition(ChannelStatus::AwaitingConfirmation)?;
        self.secret = token;
        self.touch();
        Ok(())
    }

    /// The token waiting for `by`, the account's owner, to paste back at
    /// the service. Raises `workflows.channel_token_shown`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is not the owner of `account`.
    /// - [`DomainError::Conflict`] when no token is waiting.
    pub fn show_token(
        &mut self,
        account: &IntegrationAccount<T>,
        by: &WorkflowControl<'_>,
    ) -> Result<SealedSecret, DomainError> {
        account.ensure_sets_up_events(by)?;
        if self.status != ChannelStatus::AwaitingConfirmation {
            return Err(DomainError::conflict(message!(
                "workflows-no-token-is-waiting-on-the-channel",
                "no token from the service is waiting on the channel"
            )));
        }
        let shown_at = crate::shared::clock::now();
        self.raised.raise(AccountChannelTokenShown {
            channel: self.channel_ref(),
            occurred_at: shown_at,
        });
        Ok(self.secret.clone())
    }

    /// The owner pasted the token back at the service, so its events can be
    /// taken. Raises `workflows.channel_ready`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is not the owner of `account`.
    /// - [`DomainError::InvalidTransition`] when no token is waiting.
    pub fn confirm(
        &mut self,
        account: &IntegrationAccount<T>,
        by: &WorkflowControl<'_>,
    ) -> Result<(), DomainError> {
        account.ensure_sets_up_events(by)?;
        if self.status != ChannelStatus::AwaitingConfirmation {
            return Err(InvalidTransition {
                from: self.status,
                to: ChannelStatus::Live,
            }
            .into());
        }
        self.status = self.status.try_transition(ChannelStatus::Live)?;
        self.touch();
        self.raise_ready();
        Ok(())
    }

    /// It lapsed, or could not be registered or renewed, for `reason`.
    /// Raises `workflows.channel_lapsed`, which colleagues hear of.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when the platform does not
    ///   register it, or it is not live or being registered.
    pub fn lapse(&mut self, reason: LapseReason) -> Result<(), DomainError> {
        self.ensure_platform_registers(ChannelStatus::Lapsed)?;
        self.status = self.status.try_transition(ChannelStatus::Lapsed)?;
        self.touch();
        self.raised.raise(AccountChannelLapsed {
            channel: self.channel_ref(),
            reason,
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// Notes that the service's history was read up to `cursor`.
    pub fn note_cursor(&mut self, cursor: ChannelCursor) {
        self.history = HistoryPlace::At(cursor);
        self.touch();
    }

    /// Notes that another workflow began waiting on it, so a sweep looking
    /// for an idle channel leaves it alone while that publish finishes.
    pub fn note_workflow_added(&mut self) {
        self.touch();
    }

    /// Raises `workflows.channel_closed`, as the channel is taken off the
    /// service and forgotten.
    pub fn close(&mut self) {
        self.touch();
        self.raised.raise(AccountChannelClosed {
            channel: self.channel_ref(),
            occurred_at: self.updated_at,
        });
    }

    /// Whether the platform has yet to register it at the service: one it
    /// registers, not yet taken or lapsed.
    #[must_use]
    pub fn needs_registering(&self) -> bool {
        self.setup == ChannelSetup::Registered
            && matches!(
                self.status,
                ChannelStatus::Registering | ChannelStatus::Lapsed
            )
    }

    /// Whether it takes the service's events now.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.status == ChannelStatus::Live
    }

    /// Refuses a move to `to` for a channel set up by hand or by a token.
    /// Only a channel the platform registers has a registration to lapse,
    /// and a row saying otherwise is refused when it is read back.
    fn ensure_platform_registers(&self, to: ChannelStatus) -> Result<(), DomainError> {
        if self.setup == ChannelSetup::Registered {
            return Ok(());
        }
        Err(InvalidTransition {
            from: self.status,
            to,
        }
        .into())
    }

    /// Records a change without moving the stored timestamp backwards.
    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now().max(self.updated_at);
    }

    fn raise_ready(&mut self) {
        self.raised.raise(AccountChannelReady {
            channel: self.channel_ref(),
            occurred_at: self.updated_at,
        });
    }

    fn channel_ref(&self) -> ChannelRef {
        ChannelRef {
            channel_id: self.id,
            account_id: self.account,
            integration: self.integration.clone(),
        }
    }

    /// The account whose events it takes.
    #[must_use]
    pub fn account(&self) -> IntegrationAccountId {
        self.account
    }

    /// The integration whose service sends them.
    #[must_use]
    pub fn integration(&self) -> &IntegrationKey {
        &self.integration
    }

    /// What proves a delivery, sealed.
    #[must_use]
    pub fn secret(&self) -> &SealedSecret {
        &self.secret
    }

    /// How it gets to ready.
    #[must_use]
    pub fn setup(&self) -> ChannelSetup {
        self.setup
    }

    /// Where it is.
    #[must_use]
    pub fn status(&self) -> ChannelStatus {
        self.status
    }

    /// The service's side of it.
    #[must_use]
    pub fn registration(&self) -> &Registration {
        &self.registration
    }

    /// How far the service's history was read, so the next read starts there.
    #[must_use]
    pub fn history(&self) -> &HistoryPlace {
        &self.history
    }
}

/// The status a channel set up as `setup` starts in.
fn first_status(setup: ChannelSetup) -> ChannelStatus {
    match setup {
        ChannelSetup::Registered => ChannelStatus::Registering,
        ChannelSetup::PastedKey => ChannelStatus::AwaitingKey,
        ChannelSetup::TokenFromService => ChannelStatus::AwaitingToken,
    }
}

/// Whether `row` is registered by the platform, live, and unnamed.
fn registered_without_a_name(row: &AccountChannelRow) -> bool {
    row.setup == ChannelSetup::Registered
        && row.status == ChannelStatus::Live
        && row.registration == Registration::NotTaken
}

/// Whether a channel set up as `setup` can stand at `status`.
fn waits_as_its_setup_does(setup: ChannelSetup, status: ChannelStatus) -> bool {
    match status {
        ChannelStatus::Registering | ChannelStatus::Lapsed => setup == ChannelSetup::Registered,
        ChannelStatus::AwaitingKey => setup == ChannelSetup::PastedKey,
        ChannelStatus::AwaitingToken | ChannelStatus::AwaitingConfirmation => {
            setup == ChannelSetup::TokenFromService
        }
        ChannelStatus::Live => true,
    }
}

impl<T: TenantScope> Raises for AccountChannel<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for AccountChannel<T> {
    type Id = AccountChannelId;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::workflows::account::{
        AccountSharing, ConnectAccountParams, OperationScope,
    };
    use crate::domains::workflows::execution::tests::fixtures::managing;
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::raised_names;
    use crate::types::{Human, HumanAccount, Label, PersonKey, UserId};

    const READY: &str = "workflows.channel_ready";

    fn person(address: &str) -> Human {
        Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new(address).unwrap(),
        )
    }

    fn sealed(words: &str) -> SealedSecret {
        SealedSecret::new(format!("v1.{words}")).unwrap()
    }

    fn remote() -> RemoteRegistration {
        RemoteRegistration::new("bot-webhook").unwrap()
    }

    fn accounts_of(owner: &Human) -> IntegrationAccount<ResolvedTenant> {
        IntegrationAccount::connect(
            ConnectAccountParams {
                id: IntegrationAccountId::new(),
                integration: IntegrationKey::new("notion").unwrap(),
                name: Label::new("name", "Team notes").unwrap(),
                credential: sealed("AAECAwQF"),
                sharing: AccountSharing::Tenant,
                scope: OperationScope::All,
            },
            &managing(owner),
        )
        .unwrap()
    }

    fn opened(setup: ChannelSetup) -> AccountChannel<ResolvedTenant> {
        AccountChannel::open(OpenChannel {
            id: AccountChannelId::new(),
            account: IntegrationAccountId::new(),
            integration: IntegrationKey::new("notion").unwrap(),
            secret: sealed("BBECAwQF"),
            setup,
        })
        .unwrap()
    }

    fn row_of(setup: ChannelSetup, status: ChannelStatus) -> AccountChannelRow {
        let now = crate::shared::clock::now();
        AccountChannelRow {
            id: AccountChannelId::new(),
            account: IntegrationAccountId::new(),
            integration: IntegrationKey::new("notion").unwrap(),
            secret: sealed("BBECAwQF"),
            setup,
            status,
            registration: Registration::NotTaken,
            history: HistoryPlace::Unknown,
            created_at: now,
            updated_at: now,
        }
    }

    fn live_registered() -> AccountChannel<ResolvedTenant> {
        let mut channel = opened(ChannelSetup::Registered);
        channel
            .register(remote(), Lapse::Never, HistoryPlace::Unknown)
            .unwrap();
        raised_names(&mut channel);
        channel
    }

    fn lapse_reason() -> LapseReason {
        LapseReason::new("the watch expired").unwrap()
    }

    /// Ann's Telegram bot takes the webhook. The channel goes live, and
    /// renewing it later records nothing new.
    #[test]
    fn a_registered_channel_goes_live_once_the_service_takes_it() {
        let mut channel = opened(ChannelSetup::Registered);

        channel
            .register(remote(), Lapse::Never, HistoryPlace::Unknown)
            .unwrap();
        let first = raised_names(&mut channel);
        channel
            .register(remote(), Lapse::Never, HistoryPlace::Unknown)
            .unwrap();

        assert!(channel.is_live());
        assert_eq!(first, [READY]);
        assert!(raised_names(&mut channel).is_empty());
    }

    /// A renewal the service answers with no cursor keeps the place the
    /// channel had read up to, so no mail is read twice or lost.
    #[test]
    fn a_renewal_with_no_cursor_keeps_the_one_it_has() {
        let mut channel = opened(ChannelSetup::Registered);
        let first = HistoryPlace::At(ChannelCursor::new("1200").unwrap());
        channel
            .register(remote(), Lapse::Never, first.clone())
            .unwrap();

        channel
            .register(remote(), Lapse::Never, HistoryPlace::Unknown)
            .unwrap();

        assert_eq!(channel.history(), &first);
    }

    /// A service naming a new place on renewal moves the channel there.
    #[test]
    fn a_renewal_naming_a_cursor_moves_to_it() {
        let mut channel = live_registered();
        let later = HistoryPlace::At(ChannelCursor::new("1300").unwrap());

        channel
            .register(remote(), Lapse::Never, later.clone())
            .unwrap();

        assert_eq!(channel.history(), &later);
    }

    /// Stops: a channel Ann set up by hand with HubSpot's key is told the
    /// service registered it. It has no registration at the service, so it
    /// is refused and stays as it was.
    #[test]
    fn a_channel_set_up_by_hand_takes_no_registration() {
        let ann = person("ann@corp.test");
        let account = accounts_of(&ann);
        let mut channel = opened(ChannelSetup::PastedKey);
        channel
            .paste_key(sealed("KEYONE"), &account, &managing(&ann))
            .unwrap();
        raised_names(&mut channel);

        let refused = channel.register(remote(), Lapse::Never, HistoryPlace::Unknown);

        assert!(matches!(refused, Err(DomainError::InvalidTransition(_))));
        assert_eq!(channel.registration(), &Registration::NotTaken);
        assert!(raised_names(&mut channel).is_empty());
    }

    /// A channel set up by hand has nothing that can lapse. Letting it
    /// lapse would store a row that is refused when it is read back.
    #[test]
    fn a_channel_set_up_by_hand_does_not_lapse() {
        let ann = person("ann@corp.test");
        let account = accounts_of(&ann);
        let mut channel = opened(ChannelSetup::PastedKey);
        channel
            .paste_key(sealed("KEYONE"), &account, &managing(&ann))
            .unwrap();
        raised_names(&mut channel);

        let refused = channel.lapse(lapse_reason());

        assert!(matches!(refused, Err(DomainError::InvalidTransition(_))));
        assert!(channel.is_live());
        assert!(raised_names(&mut channel).is_empty());
    }

    /// A channel that already lapsed does not lapse again, so colleagues
    /// hear of it once.
    #[test]
    fn a_lapsed_channel_does_not_lapse_again() {
        let mut channel = live_registered();
        channel.lapse(lapse_reason()).unwrap();
        raised_names(&mut channel);

        let refused = channel.lapse(lapse_reason());

        assert!(matches!(refused, Err(DomainError::InvalidTransition(_))));
        assert!(raised_names(&mut channel).is_empty());
    }

    /// Reading further into the history moves the place held.
    #[test]
    fn a_read_of_the_history_moves_the_place() {
        let mut channel = live_registered();
        let cursor = ChannelCursor::new("1300").unwrap();

        channel.note_cursor(cursor.clone());

        assert_eq!(channel.history(), &HistoryPlace::At(cursor));
    }

    /// Ann pastes HubSpot's app secret. The channel goes live and holds
    /// it, and pasting a new one later is recorded too.
    #[test]
    fn a_pasted_key_makes_the_channel_live_and_each_change_is_recorded() {
        let ann = person("ann@corp.test");
        let account = accounts_of(&ann);
        let mut channel = opened(ChannelSetup::PastedKey);

        channel
            .paste_key(sealed("KEYONE"), &account, &managing(&ann))
            .unwrap();
        channel
            .paste_key(sealed("KEYTWO"), &account, &managing(&ann))
            .unwrap();

        assert!(channel.is_live());
        assert_eq!(channel.secret(), &sealed("KEYTWO"));
        assert_eq!(raised_names(&mut channel), [READY, READY]);
    }

    /// Stops: Sam may manage workflows but does not own Ann's account. He
    /// pastes in a key he knows, to forge the events that start her
    /// workflows. It is refused and the channel keeps waiting.
    #[test]
    fn only_the_owner_pastes_a_key() {
        let ann = person("ann@corp.test");
        let sam = person("sam@corp.test");
        let account = accounts_of(&ann);
        let mut channel = opened(ChannelSetup::PastedKey);

        let refused = channel.paste_key(sealed("KEYSAM"), &account, &managing(&sam));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(!channel.is_live());
        assert!(raised_names(&mut channel).is_empty());
    }

    /// A channel that takes a token has no use for a pasted key.
    #[test]
    fn a_token_channel_takes_no_pasted_key() {
        let ann = person("ann@corp.test");
        let account = accounts_of(&ann);
        let mut channel = opened(ChannelSetup::TokenFromService);

        let refused = channel.paste_key(sealed("KEYONE"), &account, &managing(&ann));

        assert!(matches!(refused, Err(DomainError::Conflict(_))));
        assert!(raised_names(&mut channel).is_empty());
    }

    /// Stops: Sam reads the token waiting on Ann's channel. It would let
    /// him prove deliveries as the service, so it is refused and nothing
    /// is recorded as shown.
    #[test]
    fn only_the_owner_is_shown_the_token() {
        let ann = person("ann@corp.test");
        let sam = person("sam@corp.test");
        let account = accounts_of(&ann);
        let mut channel = opened(ChannelSetup::TokenFromService);
        channel.receive_token(sealed("TOKENONE")).unwrap();

        let refused = channel.show_token(&account, &managing(&sam));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(raised_names(&mut channel).is_empty());
    }

    /// Stops: Sam says the token was pasted back at Notion on Ann's
    /// channel. Only its owner can say so, and it keeps waiting.
    #[test]
    fn only_the_owner_confirms_a_token() {
        let ann = person("ann@corp.test");
        let sam = person("sam@corp.test");
        let account = accounts_of(&ann);
        let mut channel = opened(ChannelSetup::TokenFromService);
        channel.receive_token(sealed("TOKENONE")).unwrap();

        let refused = channel.confirm(&account, &managing(&sam));

        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
        assert!(!channel.is_live());
        assert!(raised_names(&mut channel).is_empty());
    }

    /// Ann cannot confirm before Notion has sent anything. The channel
    /// stays waiting, and a delivery still reads nothing.
    #[test]
    fn a_channel_with_no_token_waiting_cannot_be_confirmed() {
        let ann = person("ann@corp.test");
        let account = accounts_of(&ann);
        let mut channel = opened(ChannelSetup::TokenFromService);

        let refused = channel.confirm(&account, &managing(&ann));

        assert!(matches!(refused, Err(DomainError::InvalidTransition(_))));
        assert!(!channel.is_live());
        assert!(raised_names(&mut channel).is_empty());
    }

    /// Notion sends its token. The channel still reads nothing until Ann
    /// says she pasted it back.
    #[test]
    fn a_token_waits_for_the_owner_to_confirm_it() {
        let ann = person("ann@corp.test");
        let account = accounts_of(&ann);
        let mut channel = opened(ChannelSetup::TokenFromService);

        channel.receive_token(sealed("TOKENONE")).unwrap();
        let before = channel.is_live();
        channel.confirm(&account, &managing(&ann)).unwrap();

        assert!(!before);
        assert!(channel.is_live());
        assert_eq!(raised_names(&mut channel), [READY]);
    }

    /// Ann starts Notion's setup again and gets a new token, which replaces
    /// the one she never confirmed.
    #[test]
    fn a_newer_token_replaces_one_not_confirmed() {
        let mut channel = opened(ChannelSetup::TokenFromService);

        channel.receive_token(sealed("TOKENONE")).unwrap();
        channel.receive_token(sealed("TOKENTWO")).unwrap();

        assert_eq!(channel.secret(), &sealed("TOKENTWO"));
    }

    /// Stops: Mallory learns the address of Ann's live channel and posts a
    /// token of her own. It would replace what proves every delivery, so
    /// it is refused.
    #[test]
    fn a_live_channel_takes_no_new_token() {
        let ann = person("ann@corp.test");
        let account = accounts_of(&ann);
        let mut channel = opened(ChannelSetup::TokenFromService);
        channel.receive_token(sealed("TOKENONE")).unwrap();
        channel.confirm(&account, &managing(&ann)).unwrap();

        let refused = channel.receive_token(sealed("MALLORY"));

        assert!(matches!(refused, Err(DomainError::InvalidTransition(_))));
        assert_eq!(channel.secret(), &sealed("TOKENONE"));
    }

    /// Ann reads the token to paste it at Notion. Her reading it is on the
    /// record; a token nobody sent yet cannot be shown.
    #[test]
    fn showing_a_token_is_recorded_and_needs_one_waiting() {
        let ann = person("ann@corp.test");
        let account = accounts_of(&ann);
        let mut channel = opened(ChannelSetup::TokenFromService);
        let too_soon = channel.show_token(&account, &managing(&ann));
        channel.receive_token(sealed("TOKENONE")).unwrap();

        let shown = channel.show_token(&account, &managing(&ann)).unwrap();

        assert!(matches!(too_soon, Err(DomainError::Conflict(_))));
        assert_eq!(shown, sealed("TOKENONE"));
        assert_eq!(
            raised_names(&mut channel),
            ["workflows.channel_token_shown"]
        );
    }

    /// A lapsed channel is the only way a registered one needs the service
    /// asked again, and colleagues hear of the lapse.
    #[test]
    fn a_lapsed_channel_needs_registering_and_is_heard_of() {
        let mut channel = live_registered();

        channel.lapse(lapse_reason()).unwrap();

        assert!(channel.needs_registering());
        assert_eq!(raised_names(&mut channel), ["workflows.channel_lapsed"]);
    }

    /// A key too short to be secret is refused, an empty one above all,
    /// since anyone can sign with it.
    #[test]
    fn a_short_key_is_refused() {
        assert!(ChannelKey::new("").is_err());
        assert!(ChannelKey::new("too short").is_err());
        assert!(ChannelKey::new("a key that is long enough").is_ok());
    }

    /// A channel set up by hand never needs the platform to call anyone.
    #[test]
    fn a_channel_set_up_by_hand_is_never_registered() {
        assert!(!opened(ChannelSetup::PastedKey).needs_registering());
        assert!(!opened(ChannelSetup::TokenFromService).needs_registering());
    }

    /// A row claiming a registered channel is live with nothing from the
    /// service, or waiting in a way its setup never does, is refused.
    #[test]
    fn a_broken_row_is_refused() {
        let unnamed = row_of(ChannelSetup::Registered, ChannelStatus::Live);
        let mismatched = row_of(ChannelSetup::PastedKey, ChannelStatus::AwaitingToken);

        assert!(refused_as_corrupt(
            &AccountChannel::<ResolvedTenant>::reconstitute(unnamed)
        ));
        assert!(refused_as_corrupt(
            &AccountChannel::<ResolvedTenant>::reconstitute(mismatched)
        ));
    }

    /// A row saying a channel changed before it was opened is refused.
    #[test]
    fn a_row_changed_before_it_was_opened_is_refused() {
        let good = row_of(ChannelSetup::Registered, ChannelStatus::Registering);
        let backwards = AccountChannelRow {
            updated_at: good.created_at - time::Duration::SECOND,
            ..good
        };

        assert!(refused_as_corrupt(
            &AccountChannel::<ResolvedTenant>::reconstitute(backwards)
        ));
    }

    /// A stored place in the service's history reads back as held, and a
    /// row with none reads back as no place known.
    #[test]
    fn a_stored_place_reads_back() {
        let cursor = ChannelCursor::new("1200").unwrap();
        let at = AccountChannelRow {
            history: HistoryPlace::At(cursor.clone()),
            ..row_of(ChannelSetup::Registered, ChannelStatus::Registering)
        };
        let unknown = row_of(ChannelSetup::Registered, ChannelStatus::Registering);

        let reads_at = AccountChannel::<ResolvedTenant>::reconstitute(at).unwrap();
        let reads_unknown = AccountChannel::<ResolvedTenant>::reconstitute(unknown).unwrap();

        assert_eq!(reads_at.history().cursor(), Some(&cursor));
        assert_eq!(reads_unknown.history(), &HistoryPlace::Unknown);
    }
}
