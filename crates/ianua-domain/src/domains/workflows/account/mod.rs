//! An account a tenant connected to an integration.
//!
//! It holds the credential a workflow's action steps act through. It also
//! says who owns it, who may use it and for which operations.
//!
//! An action step names an account. It acts through it only with an
//! [`AccountUse`], and only the account grants one. It does so when it is
//! active, the person the execution acts for may use it, and the operation
//! is one it allows. Nothing reaches an integration's credential any other
//! way. An account may also be connected by signing in at its service
//! ([`connection`]).

use std::marker::PhantomData;

use time::OffsetDateTime;

use crate::domains::authorization::permission::WorkflowAction;
use crate::domains::workflows::control::WorkflowControl;
use crate::domains::workflows::events::{
    AccountRef, IntegrationAccountChanged, IntegrationAccountConnected,
    IntegrationAccountCredentialRenewed, IntegrationAccountDisabled, IntegrationAccountEnabled,
};
use crate::domains::workflows::execution::ActingAuthority;
use crate::domains::workflows::integration::{IntegrationKey, OperationKey};
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::shared::model::aggregate::Aggregate;
use crate::shared::model::row_check::RowCheck;
use crate::shared::model::transition::{InvalidTransition, checked};
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::types::{EventLabel, Human, IntegrationAccountId, Label, SealedSecret};

pub mod connection;
mod lending;

/// The most operations an account may be limited to by name.
pub(crate) const MAX_SCOPED_OPERATIONS: usize = 64;

/// Whether an account may be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStatus {
    /// It may be used.
    Active,
    /// It may not be used until it is enabled again.
    Disabled,
}

impl AccountStatus {
    /// Moves to `to` when it is a change. An active account is disabled, a
    /// disabled one enabled.
    ///
    /// # Errors
    ///
    /// - [`InvalidTransition`] for a move to the status it is in.
    pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
        checked(self, to, |from, to| from != to)
    }
}

/// Who may have workflows act through an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountSharing {
    /// Only workflows run for the person who connected it.
    OwnerOnly,
    /// Workflows run for anyone in the tenant.
    Tenant,
}

/// Which operations an account may be used for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationScope {
    /// Every operation its integration offers.
    All,
    /// Restricts use to the explicitly named catalogue operations.
    Only(ScopedOperations),
}

/// The operations an account is limited to. At least one, each named once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedOperations(Vec<OperationKey>);

impl ScopedOperations {
    /// A limit to `operations`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it names none, or more than
    ///   `MAX_SCOPED_OPERATIONS`.
    /// - [`DomainError::Validation`] when it names one twice.
    pub fn new(operations: Vec<OperationKey>) -> Result<Self, DomainError> {
        validate_count(
            "scoped_operations",
            operations.len(),
            1..=MAX_SCOPED_OPERATIONS,
        )?;
        if first_repeat(&operations).is_some() {
            return Err(DomainError::invalid(message!(
                "workflows-an-operation-is-named-twice",
                "an operation is named twice"
            )));
        }
        Ok(Self(operations))
    }

    /// The nonempty, distinct operation keys this account is permitted to perform.
    #[must_use]
    pub fn operations(&self) -> &[OperationKey] {
        &self.0
    }
}

impl OperationScope {
    fn allows(&self, operation: &OperationKey) -> bool {
        match self {
            Self::All => true,
            Self::Only(scoped) => scoped.0.contains(operation),
        }
    }
}

/// Permission to act through one account for one operation, for one person.
///
/// Only [`IntegrationAccount::grant_use`] gives one. So an action step can
/// only reach a credential the account's own rules let it reach.
#[derive(Debug, PartialEq, Eq)]
pub struct AccountUse<T: TenantScope> {
    account_id: IntegrationAccountId,
    integration: IntegrationKey,
    operation: OperationKey,
    granted_to: Human,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> AccountUse<T> {
    /// The person whose workflow runs it is for.
    #[must_use]
    pub fn granted_to(&self) -> &Human {
        &self.granted_to
    }

    /// The account it permits acting through.
    #[must_use]
    pub fn account_id(&self) -> IntegrationAccountId {
        self.account_id
    }

    /// The integration that account belongs to.
    #[must_use]
    pub fn integration(&self) -> &IntegrationKey {
        &self.integration
    }

    /// The catalogue operation authorized by this account-use proof.
    #[must_use]
    pub fn operation(&self) -> &OperationKey {
        &self.operation
    }
}

/// The values an account is connected with.
pub struct ConnectAccountParams {
    /// The id it is kept under, chosen before it is connected so its
    /// credential can be sealed for it.
    pub id: IntegrationAccountId,
    /// The catalogue entry that defines how this credential may be used.
    pub integration: IntegrationKey,
    /// Its name for people.
    pub name: Label,
    /// The credential, sealed.
    pub credential: SealedSecret,
    /// Who may use it.
    pub sharing: AccountSharing,
    /// Which operations it may be used for.
    pub scope: OperationScope,
}

/// An account as stored.
pub struct IntegrationAccountRow {
    /// The persisted identity used to bind and unseal this account's credential.
    pub id: IntegrationAccountId,
    /// The catalogue entry that defines how the stored credential may be used.
    pub integration: IntegrationKey,
    /// Its name for people.
    pub name: Label,
    /// The credential, sealed.
    pub credential: SealedSecret,
    /// The person who owns it.
    pub owner: Human,
    /// Who may use it.
    pub sharing: AccountSharing,
    /// Which operations it may be used for.
    pub scope: OperationScope,
    /// Whether it may be used.
    pub status: AccountStatus,
    /// When it was connected.
    pub created_at: OffsetDateTime,
    /// When it last changed.
    pub updated_at: OffsetDateTime,
}

/// An account a tenant connected to an integration.
#[derive(Debug, Clone)]
pub struct IntegrationAccount<T: TenantScope> {
    id: IntegrationAccountId,
    integration: IntegrationKey,
    name: Label,
    credential: SealedSecret,
    owner: Human,
    sharing: AccountSharing,
    scope: OperationScope,
    status: AccountStatus,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> IntegrationAccount<T> {
    /// Connects an account, active, owned by the person connecting it.
    /// Raises `workflows.account_connected`.
    ///
    /// The owner is always whoever connects it. Sam could otherwise connect
    /// his own credential in Ann's name, so her workflows act through it and
    /// he reads what they send.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` may not connect accounts.
    pub fn connect(
        params: ConnectAccountParams,
        by: &WorkflowControl<'_>,
    ) -> Result<Self, DomainError> {
        by.ensure_may(WorkflowAction::ConnectAccounts)?;
        let now = crate::shared::clock::now();
        let mut account = Self {
            id: params.id,
            integration: params.integration,
            name: params.name,
            credential: params.credential,
            owner: by.by().clone(),
            sharing: params.sharing,
            scope: params.scope,
            status: AccountStatus::Active,
            created_at: now,
            updated_at: now,
            raised: Raised::default(),
            _scope: PhantomData,
        };
        account.raised.raise(IntegrationAccountConnected {
            account: account.account_ref(),
            occurred_at: now,
        });
        Ok(account)
    }

    /// Rebuilds an account from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row says it changed before
    ///   it was connected.
    pub fn reconstitute(row: IntegrationAccountRow) -> Result<Self, DomainError> {
        Self::ensure_consistent(&row)?;
        Ok(Self {
            id: row.id,
            integration: row.integration,
            name: row.name,
            credential: row.credential,
            owner: row.owner,
            sharing: row.sharing,
            scope: row.scope,
            status: row.status,
            created_at: row.created_at,
            updated_at: row.updated_at,
            raised: Raised::default(),
            _scope: PhantomData,
        })
    }

    /// Refuses a stored row that breaks a rule this keeps.
    fn ensure_consistent(row: &IntegrationAccountRow) -> Result<(), DomainError> {
        RowCheck::of("integration account")
            .in_order(
                row.created_at,
                row.updated_at,
                "changed before it was connected",
            )
            .finish()
    }

    /// Permission for a workflow run for `acting_for` to act through this
    /// account with `operation`.
    ///
    /// `owner` is what the account's owner holds right now. A credential is
    /// lent only while its owner may still lend it. Ann shares her account
    /// with the tenant and then leaves. From then on her account acts for
    /// nobody.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when the account is disabled.
    /// - [`DomainError::Forbidden`] when its owner may no longer lend
    ///   accounts.
    /// - [`DomainError::Forbidden`] when it is kept to its owner and
    ///   `acting_for` is someone else.
    /// - [`DomainError::Forbidden`] when it is not allowed `operation`.
    pub fn grant_use(
        &self,
        acting_for: &ActingAuthority,
        operation: &OperationKey,
        owner: &ActingAuthority,
    ) -> Result<AccountUse<T>, DomainError> {
        self.ensure_lent_to(acting_for, owner)?;
        if !self.scope.allows(operation) {
            return Err(DomainError::forbidden(message!(
                "workflows-this-account-may-not-be-used",
                format!("this account may not be used for {operation}")
            )));
        }
        Ok(AccountUse {
            account_id: self.id,
            integration: self.integration.clone(),
            operation: operation.clone(),
            granted_to: acting_for.person().clone(),
            _scope: PhantomData,
        })
    }

    /// Refuses registering a workflow published by `acting_for` at the
    /// service through this account, for events of `integration`, unless
    /// the account is for that integration and is lent to them as it would
    /// be for one of their workflow's steps.
    ///
    /// The registration acts through the account for as long as the version
    /// is in service, so Sam may not register his workflow through Ann's
    /// account she kept to herself.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when it is another integration's
    ///   account, is disabled, its owner may no longer lend it, or it is
    ///   kept to its owner and `acting_for` is someone else.
    pub fn ensure_lends_events(
        &self,
        acting_for: &ActingAuthority,
        integration: &IntegrationKey,
        owner: &ActingAuthority,
    ) -> Result<(), DomainError> {
        if &self.integration != integration {
            return Err(DomainError::forbidden(message!(
                "workflows-the-account-is-for-another-integration",
                format!("the account is for {}, not {integration}", self.integration)
            )));
        }
        self.ensure_lent_to(acting_for, owner)
    }

    /// Stops the account being used.
    ///
    /// Its owner may do it, and so may anyone allowed to connect accounts.
    /// So a leaked credential is switched off without waiting for its owner.
    /// Raises `workflows.account_disabled`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is neither its owner nor
    ///   allowed to connect accounts.
    /// - [`DomainError::InvalidTransition`] when it is already disabled.
    pub fn disable(&mut self, by: &WorkflowControl<'_>) -> Result<(), DomainError> {
        self.ensure_owner_or_manager(by)?;
        self.status = self.status.try_transition(AccountStatus::Disabled)?;
        self.touch();
        self.raised.raise(IntegrationAccountDisabled {
            account: self.account_ref(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// `by`, its owner, lets the account be used again.
    ///
    /// Switching it back on widens what it lets workflows do, so only its
    /// owner may, while they may still connect accounts. A manager who
    /// disabled a leaked credential cannot switch it back on for them.
    /// Raises `workflows.account_enabled`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is not its owner, or may no
    ///   longer connect accounts.
    /// - [`DomainError::InvalidTransition`] when it is already active.
    pub fn enable(&mut self, by: &WorkflowControl<'_>) -> Result<(), DomainError> {
        self.ensure_owner(by)?;
        self.status = self.status.try_transition(AccountStatus::Active)?;
        self.touch();
        self.raised.raise(IntegrationAccountEnabled {
            account: self.account_ref(),
            occurred_at: self.updated_at,
        });
        Ok(())
    }

    /// `by`, its owner, replaces the credential, as when it is rotated.
    /// Raises `workflows.account_changed`, which never names the credential.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is not its owner, or may no
    ///   longer connect accounts.
    pub fn replace_credential(
        &mut self,
        by: &WorkflowControl<'_>,
        credential: SealedSecret,
    ) -> Result<(), DomainError> {
        self.ensure_owner(by)?;
        self.credential = credential;
        self.record_change();
        Ok(())
    }

    /// Keeps `renewed` in place of the credential, as the service renewed
    /// it while a step acted through the account, the way Jira hands out a
    /// new refresh token with each access token and the old one stops
    /// working. Raises `workflows.account_credential_renewed`, which never
    /// names the credential and notifies nobody.
    ///
    /// No person acts here: the service, not the owner, chose the new
    /// credential, for the very grant the owner connected.
    pub fn renew_credential(&mut self, renewed: SealedSecret) {
        self.credential = renewed;
        self.updated_at = crate::shared::clock::now().max(self.updated_at);
        self.raised.raise(IntegrationAccountCredentialRenewed {
            account: self.account_ref(),
            occurred_at: self.updated_at,
        });
    }

    /// `by`, its owner, lets workflows run for anyone in the tenant act
    /// through it. Raises `workflows.account_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is not its owner, or may no
    ///   longer connect accounts. Only the person whose credential it is may
    ///   hand it to others, even past someone allowed to manage accounts.
    pub fn share_with_tenant(&mut self, by: &WorkflowControl<'_>) -> Result<(), DomainError> {
        self.ensure_owner(by)?;
        self.sharing = AccountSharing::Tenant;
        self.record_change();
        Ok(())
    }

    /// Keeps the account to its owner's workflows again. Its owner, or
    /// anyone allowed to connect accounts, may narrow it, as they may
    /// disable it. Raises `workflows.account_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is neither its owner nor
    ///   allowed to connect accounts.
    pub fn keep_to_owner(&mut self, by: &WorkflowControl<'_>) -> Result<(), DomainError> {
        self.ensure_owner_or_manager(by)?;
        self.sharing = AccountSharing::OwnerOnly;
        self.record_change();
        Ok(())
    }

    /// `by`, its owner, changes which operations it may be used for. Raises
    /// `workflows.account_changed`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is not its owner, or may no
    ///   longer connect accounts.
    pub fn limit_to(
        &mut self,
        by: &WorkflowControl<'_>,
        scope: OperationScope,
    ) -> Result<(), DomainError> {
        self.ensure_owner(by)?;
        self.scope = scope;
        self.record_change();
        Ok(())
    }

    /// Renames it. Its owner may, and so may anyone allowed to connect
    /// accounts, as they may disable it. A name changes nothing it lets
    /// others do. Raises `workflows.account_changed`, naming the account by
    /// its new name.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is neither its owner nor
    ///   allowed to connect accounts.
    pub fn rename(&mut self, by: &WorkflowControl<'_>, name: Label) -> Result<(), DomainError> {
        self.ensure_owner_or_manager(by)?;
        self.name = name;
        self.record_change();
        Ok(())
    }

    /// Marks a change to its sharing, scope, name or credential and raises
    /// `workflows.account_changed`.
    fn record_change(&mut self) {
        self.touch();
        self.raised.raise(IntegrationAccountChanged {
            account: self.account_ref(),
            occurred_at: self.updated_at,
        });
    }

    /// This account as the audit trail names it, with its name as it is now.
    fn account_ref(&self) -> AccountRef {
        AccountRef {
            account_id: self.id,
            integration: self.integration.clone(),
            label: EventLabel::of(self.name.as_str()),
        }
    }

    /// Refuses anyone but the owner, matched by the exact account that
    /// connected it, while they may still connect accounts. Another account
    /// with the same address is not them.
    fn ensure_owner(&self, by: &WorkflowControl<'_>) -> Result<(), DomainError> {
        if !self.owner.is_same_account_as(by.by()) {
            return Err(DomainError::forbidden(message!(
                "workflows-only-the-account-s-owner-may",
                "only the account's owner may change what it lets others do"
            )));
        }
        by.ensure_may(WorkflowAction::ConnectAccounts)
    }

    /// Refuses anyone but the owner or someone allowed to connect accounts:
    /// the only people with any say over the account. A change only its
    /// owner makes is refused to the others again when it is made.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is neither the owner nor may
    ///   connect accounts.
    pub fn ensure_owner_or_manager(&self, by: &WorkflowControl<'_>) -> Result<(), DomainError> {
        if self.owner.is_same_account_as(by.by()) {
            return Ok(());
        }
        by.ensure_may(WorkflowAction::ConnectAccounts)
    }

    /// Refuses anyone but the owner setting up, or being shown a secret of,
    /// the address this account's service events arrive at: the key or
    /// token there proves every event the account's workflows start on.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `by` is not the owner, or may no
    ///   longer connect accounts.
    pub fn ensure_sets_up_events(&self, by: &WorkflowControl<'_>) -> Result<(), DomainError> {
        self.ensure_owner(by)
    }

    fn touch(&mut self) {
        self.updated_at = crate::shared::clock::now();
    }

    /// The stable identity referenced by workflow steps and credential sealing.
    #[must_use]
    pub fn id(&self) -> &IntegrationAccountId {
        &self.id
    }

    /// The catalogue entry that defines the available operations for this account.
    #[must_use]
    pub fn integration(&self) -> &IntegrationKey {
        &self.integration
    }

    /// The display label people use when choosing a connected credential.
    #[must_use]
    pub fn name(&self) -> &Label {
        &self.name
    }

    /// The credential, sealed.
    #[must_use]
    pub fn credential(&self) -> &SealedSecret {
        &self.credential
    }

    /// The person who owns it.
    #[must_use]
    pub fn owner(&self) -> &Human {
        &self.owner
    }

    /// Who may use it.
    #[must_use]
    pub fn sharing(&self) -> AccountSharing {
        self.sharing
    }

    /// Which operations it may be used for.
    #[must_use]
    pub fn scope(&self) -> &OperationScope {
        &self.scope
    }

    /// Whether it may be used.
    #[must_use]
    pub fn status(&self) -> AccountStatus {
        self.status
    }
}

impl<T: TenantScope> Raises for IntegrationAccount<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

impl<T: TenantScope> Aggregate for IntegrationAccount<T> {
    type Id = IntegrationAccountId;

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
    use crate::domains::agents::authority::capability::CapabilitySet;
    use crate::domains::authorization::permission::{SystemPermission, WorkflowAction};
    use crate::domains::workflows::design::workflow::{AccountUnusable, UsedAccount};
    use crate::domains::workflows::execution::tests::fixtures::{managing, viewing};
    use crate::isolation::scope::ResolvedTenant;
    use crate::shared::model::row_check::refused_as_corrupt;
    use crate::test_support::events::{raised, raised_names};
    use crate::types::{HumanAccount, PersonKey, UserId};

    fn person(address: &str) -> Human {
        Human::new(
            HumanAccount::User(UserId::new()),
            PersonKey::new(address).unwrap(),
        )
    }

    /// A connected account belongs to the person connecting it. A workflow
    /// viewer cannot connect an account.
    #[test]
    fn an_account_belongs_to_whoever_connects_it() {
        let sam = person("sam@corp.test");
        let connected = account(&sam, AccountSharing::Tenant, OperationScope::All);
        let viewer = person("vic@corp.test");
        let refused = IntegrationAccount::<ResolvedTenant>::connect(
            ConnectAccountParams {
                id: IntegrationAccountId::new(),
                integration: IntegrationKey::new("google-sheets").unwrap(),
                name: Label::new("name", "Sheets").unwrap(),
                credential: SealedSecret::new("v1.AAECAwQF").unwrap(),
                sharing: AccountSharing::Tenant,
                scope: OperationScope::All,
            },
            &crate::domains::workflows::execution::tests::fixtures::viewing(&viewer),
        );

        assert!(connected.owner().is_same_account_as(&sam));
        assert!(matches!(refused, Err(DomainError::Forbidden(_))));
    }

    /// A workflow viewer cannot disable another person's account or narrow
    /// its sharing. The account remains shared with the tenant and active.
    #[test]
    fn only_the_owner_or_a_manager_disables_or_narrows_an_account() {
        let ann = person("ann@corp.test");
        let mut shared = account(&ann, AccountSharing::Tenant, OperationScope::All);
        let sam = person("sam@corp.test");
        let viewing = crate::domains::workflows::execution::tests::fixtures::viewing(&sam);

        assert!(matches!(
            shared.disable(&viewing),
            Err(DomainError::Forbidden(_))
        ));
        assert!(matches!(
            shared.keep_to_owner(&viewing),
            Err(DomainError::Forbidden(_))
        ));
        assert_eq!(shared.status(), AccountStatus::Active);
        assert_eq!(shared.sharing(), AccountSharing::Tenant);
    }

    /// Jira hands out a new refresh token as Ann's workflow calls it. The
    /// account keeps the new one, and the renewal is recorded without
    /// telling anyone.
    #[test]
    fn a_renewed_credential_is_kept_and_recorded_quietly() {
        let ann = person("ann@corp.test");
        let mut kept = account(&ann, AccountSharing::Tenant, OperationScope::All);
        raised(&mut kept);

        kept.renew_credential(SealedSecret::new("v1.RENEWED").unwrap());

        assert_eq!(kept.credential(), &SealedSecret::new("v1.RENEWED").unwrap());
        assert_eq!(
            raised_names(&mut kept),
            ["workflows.account_credential_renewed"]
        );
        assert!(
            !crate::types::event_type::WorkflowsEvent::AccountCredentialRenewed.is_notifiable()
        );
    }

    fn operation(name: &str) -> OperationKey {
        OperationKey::new(name).unwrap()
    }

    fn account(
        owner: &Human,
        sharing: AccountSharing,
        scope: OperationScope,
    ) -> IntegrationAccount<ResolvedTenant> {
        IntegrationAccount::connect(
            ConnectAccountParams {
                id: IntegrationAccountId::new(),
                integration: IntegrationKey::new("google-sheets").unwrap(),
                name: Label::new("name", "Finance sheets").unwrap(),
                credential: SealedSecret::new("v1.AAECAwQF").unwrap(),
                sharing,
                scope,
            },
            &managing(owner),
        )
        .unwrap()
    }

    /// What an owner still in good standing holds. They may lend the
    /// accounts they connected.
    fn lending(owner: &Human) -> ActingAuthority {
        ActingAuthority::assumed(
            owner.clone(),
            CapabilitySet::new(
                vec![SystemPermission::Workflows(WorkflowAction::ConnectAccounts)],
                Vec::new(),
            ),
        )
    }

    fn use_of(
        account: &IntegrationAccount<ResolvedTenant>,
        by: &Human,
        name: &str,
    ) -> Result<AccountUse<ResolvedTenant>, DomainError> {
        account.grant_use(&lending(by), &operation(name), &lending(account.owner()))
    }

    /// Event registrations may use the publisher's own account or a shared
    /// account. Another person's private account and an account belonging to
    /// another integration are refused.
    #[test]
    fn an_account_lends_event_registrations_as_it_lends_steps() {
        let ann = person("ann@corp.test");
        let bob = person("bob@corp.test");
        let sheets = IntegrationKey::new("google-sheets").unwrap();
        let kept = account(&ann, AccountSharing::OwnerOnly, OperationScope::All);
        let shared = account(&ann, AccountSharing::Tenant, OperationScope::All);
        let owner = lending(&ann);

        assert!(
            kept.ensure_lends_events(&lending(&ann), &sheets, &owner)
                .is_ok()
        );
        assert!(
            shared
                .ensure_lends_events(&lending(&bob), &sheets, &owner)
                .is_ok()
        );
        assert!(matches!(
            kept.ensure_lends_events(&lending(&bob), &sheets, &owner),
            Err(DomainError::Forbidden(_))
        ));
        assert!(matches!(
            shared.ensure_lends_events(
                &lending(&bob),
                &IntegrationKey::new("github").unwrap(),
                &owner
            ),
            Err(DomainError::Forbidden(_))
        ));
    }

    /// Ann keeps her sheets account to herself. Her own workflow gets a use
    /// of it for "append row", naming her account, its integration and Ann.
    #[test]
    fn the_owner_may_use_an_account_kept_to_them() {
        let owner = person("ann@corp.test");
        let account = account(&owner, AccountSharing::OwnerOnly, OperationScope::All);

        let granted = use_of(&account, &owner, "append-row").unwrap();

        assert_eq!(granted.account_id(), *account.id());
        assert_eq!(granted.integration().as_str(), "google-sheets");
        assert_eq!(granted.granted_to(), &owner);
    }

    /// Another person's workflow cannot use a private account but may use an
    /// account shared with the tenant.
    #[test]
    fn another_person_may_not_use_an_account_kept_to_its_owner() {
        let account = account(
            &person("ann@corp.test"),
            AccountSharing::OwnerOnly,
            OperationScope::All,
        );
        let shared = account_shared();

        assert!(use_of(&account, &person("bob@corp.test"), "append-row").is_err());
        assert!(use_of(&shared, &person("bob@corp.test"), "append-row").is_ok());
    }

    /// A different account sharing the owner's address cannot use or share
    /// the private credential. The owner can still use it.
    #[test]
    fn an_account_sharing_the_owners_address_gains_nothing() {
        let owner = person("ann@corp.test");
        let mut kept = account(&owner, AccountSharing::OwnerOnly, OperationScope::All);
        let lookalike = person("ann@corp.test");

        let used = use_of(&kept, &lookalike, "append-row");
        let shared = kept.share_with_tenant(&managing(&lookalike));

        assert!(matches!(used, Err(DomainError::Forbidden(_))));
        assert!(matches!(shared, Err(DomainError::Forbidden(_))));
        assert!(use_of(&kept, &owner, "append-row").is_ok());
    }

    /// A shared account refuses use by another person's workflow when its
    /// owner no longer has permission to lend accounts.
    #[test]
    fn an_account_whose_owner_may_no_longer_lend_it_acts_for_nobody() {
        let shared = account_shared();
        let left = ActingAuthority::assumed(shared.owner().clone(), CapabilitySet::empty());

        let for_bob = shared.grant_use(
            &lending(&person("bob@corp.test")),
            &operation("append-row"),
            &left,
        );

        assert!(matches!(for_bob, Err(DomainError::Forbidden(_))));
    }

    fn account_shared() -> IntegrationAccount<ResolvedTenant> {
        account(
            &person("ann@corp.test"),
            AccountSharing::Tenant,
            OperationScope::All,
        )
    }

    /// Ann limits her account to "read rows". "Read rows" is granted and
    /// "delete sheet" is refused. Once the account is disabled, "read rows"
    /// is refused too.
    #[test]
    fn a_disabled_account_or_an_operation_outside_its_scope_is_refused() {
        let owner = person("ann@corp.test");
        let scope =
            OperationScope::Only(ScopedOperations::new(vec![operation("read-rows")]).unwrap());
        let mut scoped = account(&owner, AccountSharing::OwnerOnly, scope);

        assert!(use_of(&scoped, &owner, "read-rows").is_ok());
        assert!(use_of(&scoped, &owner, "delete-sheet").is_err());

        scoped
            .disable(&managing(&person("admin@corp.test")))
            .unwrap();
        assert!(use_of(&scoped, &owner, "read-rows").is_err());
    }

    /// A manager cannot share another person's account, set its operation
    /// scope, replace its credential or enable it. The account remains disabled
    /// and private to its owner.
    #[test]
    fn only_the_owner_widens_rotates_or_re_enables_an_account() {
        let owner = person("ann@corp.test");
        let colleague = person("bob@corp.test");
        let bob = managing(&colleague);
        let mut kept = account(&owner, AccountSharing::OwnerOnly, OperationScope::All);
        kept.disable(&managing(&person("admin@corp.test"))).unwrap();
        let forbidden =
            |result: Result<(), DomainError>| matches!(result, Err(DomainError::Forbidden(_)));

        assert!(forbidden(kept.share_with_tenant(&bob)));
        assert!(forbidden(kept.limit_to(&bob, OperationScope::All)));
        assert!(forbidden(kept.replace_credential(
            &bob,
            SealedSecret::new("v1.BBECAwQF").unwrap()
        )));
        assert!(forbidden(kept.enable(&bob)));
        assert_eq!(kept.sharing(), AccountSharing::OwnerOnly);
        assert_eq!(kept.status(), AccountStatus::Disabled);
    }

    /// An owner with only workflow viewing rights cannot share or enable the
    /// account. Its sharing remains private to the owner.
    #[test]
    fn an_owner_who_may_no_longer_connect_accounts_widens_nothing() {
        let owner = person("ann@corp.test");
        let mut kept = account(&owner, AccountSharing::OwnerOnly, OperationScope::All);
        kept.disable(&managing(&person("admin@corp.test"))).unwrap();
        let ann = crate::domains::workflows::execution::tests::fixtures::viewing(&owner);

        let shared = kept.share_with_tenant(&ann);
        let enabled = kept.enable(&ann);

        assert!(matches!(shared, Err(DomainError::Forbidden(_))));
        assert!(matches!(enabled, Err(DomainError::Forbidden(_))));
        assert_eq!(kept.sharing(), AccountSharing::OwnerOnly);
    }

    /// A workflow viewer cannot rename another person's account. An account
    /// manager can rename it, and the new name is retained.
    #[test]
    fn only_the_owner_or_a_manager_renames_an_account() {
        let mut shared = account_shared();
        let sam = person("sam@corp.test");
        let viewing = crate::domains::workflows::execution::tests::fixtures::viewing(&sam);

        let by_sam = shared.rename(&viewing, Label::new("name", "Payroll (approved)").unwrap());

        assert!(matches!(by_sam, Err(DomainError::Forbidden(_))));
        shared
            .rename(
                &managing(&person("admin@corp.test")),
                Label::new("name", "Sheets").unwrap(),
            )
            .unwrap();
        assert_eq!(shared.name().as_str(), "Sheets");
    }

    /// Ann switches her disabled account back on and shares it with the
    /// tenant. Both are allowed, so it ends active and shared.
    #[test]
    fn the_owner_shares_and_re_enables_their_account() {
        let owner = person("ann@corp.test");
        let mut kept = account(&owner, AccountSharing::OwnerOnly, OperationScope::All);
        kept.disable(&managing(&person("admin@corp.test"))).unwrap();

        kept.enable(&managing(&owner)).unwrap();
        kept.share_with_tenant(&managing(&owner)).unwrap();

        assert_eq!(kept.status(), AccountStatus::Active);
        assert_eq!(kept.sharing(), AccountSharing::Tenant);
    }

    /// An account Ann shared is kept to her again and disabled, with no
    /// owner named. Both only take access away, so they need no owner.
    #[test]
    fn anyone_managing_accounts_may_narrow_or_disable_one() {
        let mut shared = account_shared();

        shared
            .keep_to_owner(&managing(&person("admin@corp.test")))
            .unwrap();
        shared
            .disable(&managing(&person("admin@corp.test")))
            .unwrap();

        assert_eq!(shared.sharing(), AccountSharing::OwnerOnly);
        assert_eq!(shared.status(), AccountStatus::Disabled);
    }

    /// A limit to no operations is refused. So is a limit naming "a" twice.
    #[test]
    fn a_scope_naming_no_operation_or_one_twice_is_refused() {
        assert!(ScopedOperations::new(Vec::new()).is_err());
        assert!(ScopedOperations::new(vec![operation("a"), operation("a")]).is_err());
    }

    /// A stored row says the account changed one second before it was
    /// connected. It is refused as corrupt.
    #[test]
    fn a_stored_account_changed_before_it_was_connected_is_refused() {
        let account = account_shared();
        let row = IntegrationAccountRow {
            id: account.id,
            integration: account.integration.clone(),
            name: account.name.clone(),
            credential: account.credential.clone(),
            owner: account.owner.clone(),
            sharing: account.sharing,
            scope: account.scope.clone(),
            status: account.status,
            created_at: account.created_at,
            updated_at: account.created_at - time::Duration::SECOND,
        };

        assert!(refused_as_corrupt(
            &IntegrationAccount::<ResolvedTenant>::reconstitute(row)
        ));
    }

    /// Ann's sheets account, with its connection already taken out.
    fn fresh_account(owner: &Human) -> IntegrationAccount<ResolvedTenant> {
        let mut connected = account(owner, AccountSharing::OwnerOnly, OperationScope::All);
        raised_names(&mut connected);
        connected
    }

    /// Ann connects her sheets account. The connection is raised, naming
    /// the account and its integration.
    #[test]
    fn connecting_raises_workflows_account_connected() {
        let mut connected = account(
            &person("ann@corp.test"),
            AccountSharing::OwnerOnly,
            OperationScope::All,
        );

        let events = raised(&mut connected);

        assert_eq!(
            events[0].event_type().to_string(),
            "workflows.account_connected"
        );
        assert_eq!(
            events[0].payload().get("integration"),
            Some("google-sheets")
        );
    }

    /// Ann disables her account, then enables it again. Each is raised, in
    /// order.
    #[test]
    fn disabling_and_enabling_raise_workflows_account_disabled_and_enabled() {
        let ann = person("ann@corp.test");
        let mut kept = fresh_account(&ann);

        kept.disable(&managing(&ann)).unwrap();
        kept.enable(&managing(&ann)).unwrap();

        assert_eq!(
            raised_names(&mut kept),
            ["workflows.account_disabled", "workflows.account_enabled"]
        );
    }

    /// Ann rotates the credential, shares the account, keeps it to herself
    /// again, limits it to "append row" and renames it. Each is raised as a
    /// change to the account.
    #[test]
    fn every_other_change_raises_workflows_account_changed() {
        let ann = person("ann@corp.test");
        let by = managing(&ann);
        let mut kept = fresh_account(&ann);
        let only_append = ScopedOperations::new(vec![operation("append-row")]).unwrap();

        kept.replace_credential(&by, SealedSecret::new("v1.BQQDAgEA").unwrap())
            .unwrap();
        kept.share_with_tenant(&by).unwrap();
        kept.keep_to_owner(&by).unwrap();
        kept.limit_to(&by, OperationScope::Only(only_append))
            .unwrap();
        kept.rename(&by, Label::new("name", "Payroll sheets").unwrap())
            .unwrap();

        assert_eq!(raised_names(&mut kept), ["workflows.account_changed"; 5]);
    }

    /// A workflow viewer's attempts to disable or share another person's
    /// account are refused without raising events.
    #[test]
    fn a_refused_change_raises_nothing() {
        let mut kept = fresh_account(&person("ann@corp.test"));
        let sam = person("sam@corp.test");
        let viewing = viewing(&sam);

        let disabled = kept.disable(&viewing);
        let shared = kept.share_with_tenant(&viewing);

        assert!(disabled.is_err());
        assert!(shared.is_err());
        assert!(raised_names(&mut kept).is_empty());
    }

    /// Ann's account is read back from storage. Loading it is no change, so
    /// it has raised nothing.
    #[test]
    fn an_account_read_back_from_storage_has_raised_nothing() {
        let account = fresh_account(&person("ann@corp.test"));
        let row = IntegrationAccountRow {
            id: account.id,
            integration: account.integration.clone(),
            name: account.name.clone(),
            credential: account.credential.clone(),
            owner: account.owner.clone(),
            sharing: account.sharing,
            scope: account.scope.clone(),
            status: account.status,
            created_at: account.created_at,
            updated_at: account.updated_at,
        };

        let mut stored = IntegrationAccount::<ResolvedTenant>::reconstitute(row).unwrap();

        assert!(raised_names(&mut stored).is_empty());
    }

    /// The "append" step of a sheets workflow, through `account`.
    fn appending(account: &IntegrationAccount<ResolvedTenant>) -> UsedAccount {
        UsedAccount {
            account: *account.id(),
            integration: IntegrationKey::new("google-sheets").unwrap(),
            at: crate::domains::workflows::design::workflow::AccountUse::Trigger,
            operation: Some(operation("append-row")),
        }
    }

    /// Ann's shared account still serves Bob's version; once she leaves,
    /// switches it off, or keeps it to herself, the answer says why it no
    /// longer does, exactly as a run would be refused.
    #[test]
    fn why_an_account_no_longer_serves_a_version_is_named() {
        let bob = person("bob@corp.test");
        let mut shared = account_shared();
        let owner = lending(shared.owner());
        let left = ActingAuthority::assumed(shared.owner().clone(), CapabilitySet::empty());
        let usable = shared.unusable_for(&lending(&bob), &appending(&shared), &owner);
        let after_leaving = shared.unusable_for(&lending(&bob), &appending(&shared), &left);

        shared
            .keep_to_owner(&managing(&shared.owner().clone()))
            .unwrap();
        let kept = shared.unusable_for(&lending(&bob), &appending(&shared), &owner);
        shared.disable(&managing(&shared.owner().clone())).unwrap();
        let disabled = shared.unusable_for(&lending(&bob), &appending(&shared), &owner);

        assert_eq!(usable, None);
        assert_eq!(after_leaving, Some(AccountUnusable::OwnerCannotLend));
        assert_eq!(kept, Some(AccountUnusable::NotLent));
        assert_eq!(disabled, Some(AccountUnusable::Disabled));
    }
}
