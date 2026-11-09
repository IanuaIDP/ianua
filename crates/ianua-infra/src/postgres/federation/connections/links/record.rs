//! A link between a local account and who its owner is at a provider, as
//! its row holds it: read back into the aggregate, and written out from it.

use ianua_domain::domains::federation::link::{FederatedLink, FederatedLinkRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConnectionId, FederatedSubject, UserId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const LINK: Stored = Stored("federated link");

/// A link as it is read. The store's checked queries fill it.
pub(super) struct LinkRecord {
    pub(super) connection_id: Uuid,
    pub(super) subject: String,
    pub(super) user_id: Uuid,
    pub(super) linked_at: OffsetDateTime,
    pub(super) confirmed_at: OffsetDateTime,
}

impl LinkRecord {
    /// The link the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the subject no longer
    /// passes its rules, or the link was confirmed before it was made.
    pub(super) fn into_link(self) -> Result<FederatedLink<ResolvedTenant>, DomainError> {
        FederatedLink::reconstitute(FederatedLinkRow {
            connection_id: ConnectionId::from_uuid(self.connection_id),
            subject: LINK.value("subject", FederatedSubject::new(self.subject))?,
            user_id: UserId::from_uuid(self.user_id),
            linked_at: self.linked_at,
            confirmed_at: self.confirmed_at,
        })
    }
}

/// A link's columns, as they are written.
pub(super) struct LinkColumns<'a> {
    pub(super) connection_id: &'a Uuid,
    pub(super) subject: &'a str,
    pub(super) user_id: &'a Uuid,
    pub(super) linked_at: OffsetDateTime,
    pub(super) confirmed_at: OffsetDateTime,
}

impl<'a> LinkColumns<'a> {
    /// The columns `link` is written to.
    pub(super) fn of(link: &'a FederatedLink<ResolvedTenant>) -> Self {
        Self {
            connection_id: link.connection_id().as_uuid(),
            subject: link.subject().as_str(),
            user_id: link.user_id().as_uuid(),
            linked_at: link.linked_at(),
            confirmed_at: link.confirmed_at(),
        }
    }
}
