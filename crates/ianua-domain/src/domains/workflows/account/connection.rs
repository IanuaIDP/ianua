//! An account connection a person began by signing in at the integration's
//! service, rather than pasting a credential.
//!
//! Ann asks to connect GitHub. A pending connection keeps what she asked
//! for, the digest of the random `state` her browser carries to GitHub and
//! back, and her PKCE verifier, sealed. GitHub sends her browser back with
//! a code, which the platform swaps at once for a credential, kept sealed
//! here; the browser gets only a one-time code of the platform's own, kept
//! here as a digest. Ann's dashboard then finishes the connection with
//! that code, and only Ann may.
//!
//! The last step is the one that matters. Mallory begins a connection in
//! her tenant and sends Bob the link. Bob signs in at GitHub, and his
//! browser comes back with the code. Without this check his GitHub token
//! would land in Mallory's tenant; here, Bob's dashboard finishes as Bob,
//! the connection is spent and refused, and nobody keeps the token.
//!
//! A connection lives ten minutes and is used once.

use std::marker::PhantomData;

use time::{Duration, OffsetDateTime};

use crate::domains::authorization::permission::WorkflowAction;
use crate::domains::workflows::account::{AccountSharing, OperationScope};
use crate::domains::workflows::control::WorkflowControl;
use crate::domains::workflows::events::{
    AccountConnectionRefused, AccountConnectionStarted, ConnectionRef,
};
use crate::domains::workflows::integration::IntegrationKey;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::shared::validation::{Charset, TextValue, Validator, text_value};
use crate::types::{Human, Label, PendingConnectionId, SealedSecret, TokenHash};

/// How long a person has from asking to connect to finishing.
pub(crate) const CONNECTION_LIFETIME: Duration = Duration::minutes(10);

text_value! {
    /// The space at the service an account works in, for a service whose
    /// sign-in reaches several, such as the Azure DevOps organization
    /// `contoso`. The person names it when they connect.
    pub struct ServicePlace;
}

impl TextValue for ServicePlace {
    const FIELD: &'static str = "place";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.length(1..=128).charset(
            Charset::LOWERCASE
                | Charset::UPPERCASE
                | Charset::DIGIT
                | Charset::HYPHEN
                | Charset::UNDERSCORE
                | Charset::DOT,
        )
    }
}

/// The account a person asks to connect.
pub struct ConnectionRequest {
    /// The catalogue entry that defines the account's authentication and operations.
    pub integration: IntegrationKey,
    /// Its name for people.
    pub name: Label,
    /// Who may use it.
    pub sharing: AccountSharing,
    /// Which operations it may be used for.
    pub scope: OperationScope,
    /// The space at the service it works in, for an integration whose
    /// sign-in asks for one.
    pub place: Option<ServicePlace>,
}

/// The values a connection starts with.
pub struct StartConnectionParams {
    /// The connection's id, chosen first so its verifier can be sealed for
    /// it.
    pub id: PendingConnectionId,
    /// The account asked for.
    pub request: ConnectionRequest,
    /// The digest of the `state` the browser carries to the service.
    pub state: TokenHash,
    /// The PKCE verifier, sealed.
    pub verifier: SealedSecret,
}

/// How far a connection got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionStage {
    /// Waiting for the service to send the browser back.
    AwaitingService,
    /// The service's code was swapped for a credential, waiting for the
    /// person to finish with the platform's one-time code.
    Answered {
        /// The credential the service issued, sealed.
        credential: SealedSecret,
        /// The digest of the platform's one-time code.
        code: TokenHash,
    },
    /// Finished or refused; it connects nothing more.
    Spent,
}

/// What finishing a connection came to.
#[derive(Debug)]
pub enum Finished {
    /// The person who began it finished it: the account to connect, its
    /// credential still sealed for the connection.
    Connect(FinishedConnection),
    /// Someone else tried. The connection is spent and the refusal is
    /// recorded; nothing is connected.
    Refused,
}

/// An account to connect, as the connection hands it over.
#[derive(Debug)]
pub struct FinishedConnection {
    /// The catalogue entry whose authentication produced this connectable account.
    pub integration: IntegrationKey,
    /// Its name for people.
    pub name: Label,
    /// Who may use it.
    pub sharing: AccountSharing,
    /// Which operations it may be used for.
    pub scope: OperationScope,
    /// The credential, sealed for the connection.
    pub credential: SealedSecret,
}

/// A connection as stored.
pub struct PendingConnectionRow {
    /// The persisted identity tying an authorization callback to the pending account setup.
    pub id: PendingConnectionId,
    /// The integration it connects.
    pub integration: IntegrationKey,
    /// The account's name.
    pub name: Label,
    /// Who may use the account.
    pub sharing: AccountSharing,
    /// Which operations the account may be used for.
    pub scope: OperationScope,
    /// The space at the service the account works in, when asked for.
    pub place: Option<ServicePlace>,
    /// The person who began it.
    pub started_by: Human,
    /// The digest of the browser's `state`.
    pub state: TokenHash,
    /// The PKCE verifier, sealed.
    pub verifier: SealedSecret,
    /// How far it got.
    pub stage: ConnectionStage,
    /// When it stops being finishable.
    pub expires_at: OffsetDateTime,
    /// When it began.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

/// An account connection waiting for the service's answer.
#[derive(Debug)]
pub struct PendingConnection<T: TenantScope> {
    id: PendingConnectionId,
    integration: IntegrationKey,
    name: Label,
    sharing: AccountSharing,
    scope: OperationScope,
    place: Option<ServicePlace>,
    started_by: Human,
    state: TokenHash,
    verifier: SealedSecret,
    stage: ConnectionStage,
    expires_at: OffsetDateTime,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> PendingConnection<T> {
    /// Begins a connection for `by`. Raises
    /// `workflows.account_connection_started`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not connect accounts.
    pub fn start(
        params: StartConnectionParams,
        by: &WorkflowControl<'_>,
    ) -> Result<Self, DomainError> {
        by.ensure_may(WorkflowAction::ConnectAccounts)?;
        let now = crate::shared::clock::now();
        let mut connection = Self {
            id: params.id,
            integration: params.request.integration,
            name: params.request.name,
            sharing: params.request.sharing,
            scope: params.request.scope,
            place: params.request.place,
            started_by: by.by().clone(),
            state: params.state,
            verifier: params.verifier,
            stage: ConnectionStage::AwaitingService,
            expires_at: now.saturating_add(CONNECTION_LIFETIME),
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        connection.raised.raise(AccountConnectionStarted {
            connection: connection.connection_ref(),
            occurred_at: now,
        });
        Ok(connection)
    }

    /// Rebuilds a connection from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row changed before it
    ///   began, or expires before it began.
    pub fn reconstitute(row: PendingConnectionRow) -> Result<Self, DomainError> {
        RowCheck::of("pending connection")
            .in_order(row.created_at, row.updated_at, "changed before it began")
            .in_order(row.created_at, row.expires_at, "expires before it began")
            .finish()?;
        Ok(Self {
            id: row.id,
            integration: row.integration,
            name: row.name,
            sharing: row.sharing,
            scope: row.scope,
            place: row.place,
            started_by: row.started_by,
            state: row.state,
            verifier: row.verifier,
            stage: row.stage,
            expires_at: row.expires_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// The service sent the browser back with `state`, and its code was
    /// swapped for `credential`; the browser is handed the one-time code
    /// whose digest is `code`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `state` is not this connection's.
    /// - [`DomainError::Conflict`] when it expired, or the service already
    ///   answered.
    pub fn answer(
        &mut self,
        state: &TokenHash,
        credential: SealedSecret,
        code: TokenHash,
    ) -> Result<(), DomainError> {
        if *state != self.state {
            return Err(DomainError::forbidden(message!(
                "workflows-the-connection-state-is-wrong",
                "the sign-in's state is not this connection's"
            )));
        }
        self.ensure_live()?;
        if self.stage != ConnectionStage::AwaitingService {
            return Err(DomainError::conflict(message!(
                "workflows-the-service-already-answered",
                "the service already answered this connection"
            )));
        }
        self.stage = ConnectionStage::Answered { credential, code };
        self.touch();
        Ok(())
    }

    /// `by` finishes the connection with the one-time code whose digest is
    /// `code`. It is spent either way. Only the person who began it gets
    /// the account to connect; anyone else is refused, recorded as
    /// `workflows.account_connection_refused`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `code` is not the one handed out.
    /// - [`DomainError::Conflict`] when it expired, the service has not
    ///   answered, or it was already finished.
    pub fn finish(
        &mut self,
        code: &TokenHash,
        by: &WorkflowControl<'_>,
    ) -> Result<Finished, DomainError> {
        let credential = self.answered_with(code)?;
        self.ensure_live()?;
        self.stage = ConnectionStage::Spent;
        self.touch();
        if !by.by().is_same_account_as(&self.started_by) {
            self.raised.raise(AccountConnectionRefused {
                connection: self.connection_ref(),
                tried_by: by.by().principal(),
                occurred_at: self.updated_at,
            });
            return Ok(Finished::Refused);
        }
        Ok(Finished::Connect(FinishedConnection {
            integration: self.integration.clone(),
            name: self.name.clone(),
            sharing: self.sharing,
            scope: self.scope.clone(),
            credential,
        }))
    }

    /// Whether it can no longer be finished at `now`.
    #[must_use]
    pub fn expired_at(&self, now: OffsetDateTime) -> bool {
        now >= self.expires_at
    }

    /// The credential the service issued, once the one-time code whose
    /// digest is `code` is the one handed out.
    fn answered_with(&self, code: &TokenHash) -> Result<SealedSecret, DomainError> {
        let ConnectionStage::Answered {
            credential,
            code: handed_out,
        } = &self.stage
        else {
            return Err(DomainError::conflict(message!(
                "workflows-the-connection-is-not-answered",
                "the service has not answered this connection, or it was finished"
            )));
        };
        if code != handed_out {
            return Err(DomainError::forbidden(message!(
                "workflows-the-connection-code-is-wrong",
                "the code is not this connection's"
            )));
        }
        Ok(credential.clone())
    }

    fn ensure_live(&self) -> Result<(), DomainError> {
        if self.expired_at(crate::shared::clock::now()) {
            return Err(DomainError::conflict(message!(
                "workflows-the-connection-expired",
                "the connection expired; it is begun again"
            )));
        }
        Ok(())
    }

    /// Records a change without moving the stored timestamp backwards.
    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now().max(self.updated_at);
    }

    fn connection_ref(&self) -> ConnectionRef {
        ConnectionRef {
            connection_id: self.id,
            integration: self.integration.clone(),
            by: self.started_by.principal(),
        }
    }

    /// The integration it connects.
    #[must_use]
    pub fn integration(&self) -> &IntegrationKey {
        &self.integration
    }

    /// The account's name.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// Who may use the account.
    #[must_use]
    pub fn sharing(&self) -> AccountSharing {
        self.sharing
    }

    /// Which operations the account may be used for.
    #[must_use]
    pub fn scope(&self) -> &OperationScope {
        &self.scope
    }

    /// The space at the service the account works in, when asked for.
    #[must_use]
    pub fn place(&self) -> Option<&ServicePlace> {
        self.place.as_ref()
    }

    /// The person who began it.
    #[must_use]
    pub fn started_by(&self) -> &Human {
        &self.started_by
    }

    /// The digest of the browser's `state`.
    #[must_use]
    pub fn state(&self) -> &TokenHash {
        &self.state
    }

    /// The PKCE verifier, sealed.
    #[must_use]
    pub fn verifier(&self) -> &SealedSecret {
        &self.verifier
    }

    /// How far it got.
    #[must_use]
    pub fn stage(&self) -> &ConnectionStage {
        &self.stage
    }

    /// When it stops being finishable.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}

impl<T: TenantScope> Raises for PendingConnection<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for PendingConnection<T> {
    type Id = PendingConnectionId;

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
    use crate::domains::workflows::execution::tests::fixtures::{
        ann, bob, cid, holding_only, managing,
    };
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::events::raised;
    use crate::types::event_type::{EventType, WorkflowsEvent};

    fn digest(value: &str) -> TokenHash {
        TokenHash::from_stored(value.to_owned())
    }

    fn sealed(value: &str) -> SealedSecret {
        SealedSecret::new(value).unwrap()
    }

    /// Ann asks to connect the team's GitHub, shared with the tenant.
    fn begun() -> PendingConnection<ResolvedTenant> {
        PendingConnection::start(
            StartConnectionParams {
                id: PendingConnectionId::new(),
                request: ConnectionRequest {
                    integration: IntegrationKey::new("github").unwrap(),
                    name: Label::new("name", "Team GitHub").unwrap(),
                    sharing: AccountSharing::Tenant,
                    scope: OperationScope::All,
                    place: None,
                },
                state: digest("state digest"),
                verifier: sealed("v1.VERIFIER"),
            },
            &managing(&ann()),
        )
        .unwrap()
    }

    /// GitHub sent Ann's browser back, and its code was swapped.
    fn answered() -> PendingConnection<ResolvedTenant> {
        let mut connection = begun();
        connection
            .answer(
                &digest("state digest"),
                sealed("v1.TOKEN"),
                digest("code digest"),
            )
            .unwrap();
        connection
    }

    fn kinds(connection: &mut PendingConnection<ResolvedTenant>) -> Vec<EventType> {
        raised(connection)
            .iter()
            .map(DomainEvent::event_type)
            .collect()
    }

    /// Ann begins, GitHub answers, and Ann finishes with the code her
    /// browser was handed: she gets the account she asked for, with the
    /// credential GitHub issued, and the connection is spent.
    #[test]
    fn the_person_who_began_it_finishes_it() {
        let mut connection = answered();

        let finished = connection
            .finish(&digest("code digest"), &managing(&ann()))
            .unwrap();

        let Finished::Connect(account) = finished else {
            panic!("Ann's own connection was refused");
        };
        assert_eq!(account.name.as_str(), "Team GitHub");
        assert_eq!(account.credential, sealed("v1.TOKEN"));
        assert_eq!(connection.stage(), &ConnectionStage::Spent);
        assert_eq!(
            kinds(&mut connection),
            [EventType::Workflows(
                WorkflowsEvent::AccountConnectionStarted
            )]
        );
    }

    /// Finishing another person's connection is refused, spends the connection
    /// and raises a refusal event. Its initiator cannot finish it afterward.
    #[test]
    fn someone_else_finishing_it_is_refused_and_spends_it() {
        let mut connection = answered();
        kinds(&mut connection);

        let finished = connection
            .finish(&digest("code digest"), &managing(&bob()))
            .unwrap();

        assert!(matches!(finished, Finished::Refused));
        assert_eq!(connection.stage(), &ConnectionStage::Spent);
        assert_eq!(
            kinds(&mut connection),
            [EventType::Workflows(
                WorkflowsEvent::AccountConnectionRefused
            )]
        );
        assert!(
            connection
                .finish(&digest("code digest"), &managing(&ann()))
                .is_err()
        );
    }

    /// A different account sharing the initiator's address cannot finish the
    /// connection.
    #[test]
    fn an_account_sharing_the_address_is_not_the_person_who_began_it() {
        let mut connection = answered();
        let twin = crate::types::Human::new(
            crate::types::HumanAccount::User(crate::types::UserId::new()),
            crate::types::PersonKey::new("ann@corp.test").unwrap(),
        );

        let finished = connection
            .finish(&digest("code digest"), &managing(&twin))
            .unwrap();

        assert!(matches!(finished, Finished::Refused));
    }

    /// A connection rejects an answer with mismatched state, a repeated answer,
    /// completion before the service answers and completion with the wrong code.
    #[test]
    fn a_wrong_state_a_second_answer_or_a_wrong_code_is_refused() {
        let mut fresh = begun();
        let mut twice = answered();
        let mut early = begun();
        let mut wrong_code = answered();

        assert!(matches!(
            fresh.answer(&digest("other state"), sealed("v1.TOKEN"), digest("c")),
            Err(DomainError::Forbidden(_))
        ));
        assert!(matches!(
            twice.answer(&digest("state digest"), sealed("v1.TOKEN"), digest("c")),
            Err(DomainError::Conflict(_))
        ));
        assert!(matches!(
            early.finish(&digest("code digest"), &managing(&ann())),
            Err(DomainError::Conflict(_))
        ));
        assert!(matches!(
            wrong_code.finish(&digest("guessed"), &managing(&ann())),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// Workflow viewing rights do not authorize starting an account connection.
    #[test]
    fn a_person_who_may_not_connect_accounts_begins_nothing() {
        let viewer = cid();

        let begun = PendingConnection::<ResolvedTenant>::start(
            StartConnectionParams {
                id: PendingConnectionId::new(),
                request: ConnectionRequest {
                    integration: IntegrationKey::new("github").unwrap(),
                    name: Label::new("name", "Cid's GitHub").unwrap(),
                    sharing: AccountSharing::OwnerOnly,
                    scope: OperationScope::All,
                    place: None,
                },
                state: digest("state"),
                verifier: sealed("v1.VERIFIER"),
            },
            &holding_only(&viewer, WorkflowAction::View),
        );

        assert!(matches!(begun, Err(DomainError::Forbidden(_))));
    }

    /// A connection begun now is finishable for ten minutes and no longer.
    #[test]
    fn a_connection_lives_ten_minutes() {
        let connection = begun();
        let began = connection.created_at;

        assert!(!connection.expired_at(began + Duration::minutes(9)));
        assert!(connection.expired_at(began + CONNECTION_LIFETIME));
    }

    /// Bob names the Azure DevOps organization `contoso` as he connects, and
    /// the connection keeps it for the account it makes.
    #[test]
    fn the_place_named_is_kept() {
        let begun = PendingConnection::<ResolvedTenant>::start(
            StartConnectionParams {
                id: PendingConnectionId::new(),
                request: ConnectionRequest {
                    integration: IntegrationKey::new("azure-devops").unwrap(),
                    name: Label::new("name", "Contoso boards").unwrap(),
                    sharing: AccountSharing::OwnerOnly,
                    scope: OperationScope::All,
                    place: Some(ServicePlace::new("contoso").unwrap()),
                },
                state: digest("state"),
                verifier: sealed("v1.VERIFIER"),
            },
            &managing(&bob()),
        )
        .unwrap();

        assert_eq!(begun.place().map(ServicePlace::as_str), Some("contoso"));
    }

    /// A service place rejects a path containing slashes and an empty name.
    #[test]
    fn a_place_with_a_path_in_it_is_refused() {
        assert!(ServicePlace::new("contoso/../admin").is_err());
        assert!(ServicePlace::new("").is_err());
    }
}
