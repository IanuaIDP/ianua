//! A person sent to an identity provider to sign in, as the audit trail
//! records it.
//!
//! Nobody is known yet and nothing is stored but the pending sign-in, so a
//! [`SingleSignOnStart`] stands for the start: it raises the record naming
//! the provider, and is dropped once the record is taken.

use std::marker::PhantomData;

use crate::domains::authentication::events::login::SingleSignOnStarted;
use crate::domains::federation::connection::FederatedIdpConnection;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::types::EventLabel;

/// A sign-in sent to a connection's provider, with its record.
#[derive(Debug)]
pub struct SingleSignOnStart<T: TenantScope> {
    raised: Raised<T>,
    _scope: PhantomData<T>,
}

impl<T: TenantScope> SingleSignOnStart<T> {
    /// A sign-in was sent to `connection`'s provider. Raises
    /// `authentication.single_sign_on_started`, naming the provider.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Forbidden`] when `connection` is switched off. No
    ///   sign-in starts through it.
    pub fn through(connection: &FederatedIdpConnection<T>) -> Result<Self, DomainError> {
        if !connection.is_active() {
            return Err(DomainError::forbidden(message!(
                "authentication-connection-is-disabled",
                "connection is disabled"
            )));
        }
        let mut start = Self {
            raised: Raised::default(),
            _scope: PhantomData,
        };
        start.raised.raise(SingleSignOnStarted {
            connection: EventLabel::of(connection.provider_name().as_str()),
            occurred_at: crate::shared::clock::now(),
        });
        Ok(start)
    }
}

impl<T: TenantScope> Raises for SingleSignOnStart<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::federation::connection::{EmailTrust, JitProvisioning};
    use crate::domains::federation::fixtures::connection_for;
    use crate::test_support::events::raised;

    /// Ann is sent to Acme's Okta to sign in. The start raises
    /// `authentication.single_sign_on_started`, naming Okta.
    #[test]
    fn a_sign_in_sent_to_a_provider_raises_its_start() {
        let okta = connection_for(
            "acme.com",
            EmailTrust::Authoritative,
            JitProvisioning::Enabled,
        );

        let mut start = SingleSignOnStart::through(&okta).unwrap();

        let events = raised(&mut start);
        assert_eq!(
            events[0].event_type().as_str(),
            "authentication.single_sign_on_started"
        );
        assert_eq!(events[0].payload().get("connection"), Some("Okta"));
    }
}
