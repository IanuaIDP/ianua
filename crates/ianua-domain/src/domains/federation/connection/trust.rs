//! How far a connection's provider is believed: the factors it reports,
//! and the addresses it vouches for.

use crate::domains::authentication::sessions::mfa_factor::FactorProved;
use crate::domains::authentication::sessions::sign_in_progress::ProviderSignIn;
use crate::domains::federation::account_privilege::AccountPrivilege;
use crate::domains::federation::connection::{AssuranceTrust, EmailTrust, FederatedIdpConnection};
use crate::domains::federation::control::FederationControl;
use crate::domains::federation::vouched_identity::VouchedIdentity;
use crate::isolation::scope::TenantScope;
use crate::shared::errors::DomainError;

impl<T: TenantScope> FederatedIdpConnection<T> {
    /// Changes trust in provider-reported factors; enabling trust needs federation rights.
    /// Privileged accounts still need their own factor; see [`Self::vouched_sign_in`].
    /// Raises `federation.connection_updated` once per save across setting changes.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] if the actor lacks the right required by the setting.
    pub fn change_assurance_trust(
        &mut self,
        trust: AssuranceTrust,
        control: &FederationControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(trust.needs())?;
        self.assurance_trust = trust;
        self.settings_changed();
        Ok(())
    }

    /// Whether the provider's report of factors is taken on its word.
    #[must_use]
    pub fn assurance_trust(&self) -> AssuranceTrust {
        self.assurance_trust
    }

    /// Records the provider's factor only for an identity from this trusted connection.
    /// An untrusted or different connection contributes no factor. Privileged accounts
    /// never accept provider factors, even from trusted connections. `account` must reflect
    /// all roles granted at sign-in before its privilege is checked.
    #[must_use]
    pub fn vouched_sign_in(
        &self,
        identity: &VouchedIdentity,
        account: AccountPrivilege,
    ) -> ProviderSignIn {
        ProviderSignIn::new(
            self.protocol().into(),
            self.proven_factor(identity, account),
        )
    }

    fn proven_factor(&self, identity: &VouchedIdentity, account: AccountPrivilege) -> FactorProved {
        if !self.vouched(identity) {
            return FactorProved::NoneYet;
        }
        if account == AccountPrivilege::Privileged {
            return FactorProved::NoneYet;
        }
        self.assurance_trust.proves(identity.factor())
    }

    /// Whether `identity` came through this connection.
    #[must_use]
    pub fn vouched(&self, identity: &VouchedIdentity) -> bool {
        *identity.connection_id() == self.id
    }

    /// Changes trust in provider addresses; enabling trust needs federation rights.
    /// Only tenant-owned domains can be vouched for, and address matching cannot link
    /// privileged accounts; see [`admission`](crate::domains::federation::admission::admission).
    /// Raises `federation.connection_updated` once per save across setting changes.
    ///
    /// # Errors
    /// [`DomainError::Forbidden`] if the actor lacks the right required by the setting.
    pub fn change_email_trust(
        &mut self,
        trust: EmailTrust,
        control: &FederationControl<'_>,
    ) -> Result<(), DomainError> {
        control.ensure_may(trust.needs())?;
        self.email_trust = trust;
        self.settings_changed();
        Ok(())
    }

    /// Whether the provider's addresses are taken on its word.
    #[must_use]
    pub fn email_trust(&self) -> EmailTrust {
        self.email_trust
    }
}
