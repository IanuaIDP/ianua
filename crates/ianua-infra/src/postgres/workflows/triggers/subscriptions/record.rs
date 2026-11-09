//! A registration at a service as its row holds it: read back into the
//! aggregate, and written out from it.

use ianua_app::ports::workflows::Routing;
use ianua_domain::domains::workflows::triggers::subscription::{
    Lapse, Registration, RemoteRegistration, ServiceSubscription, ServiceSubscriptionRow,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{EventLabel, SealedSecret, ServiceSubscriptionId, TenantId, WorkflowId};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};
use crate::postgres::workflows::triggers::service::StoredTrigger;

const SUBSCRIPTION: Stored = Stored("service subscription");

const TRIGGER: Kept = Kept {
    entity: SUBSCRIPTION.0,
    column: "trigger",
    shape: 1,
};

/// A registration as it is read. The store's checked queries fill it.
pub(super) struct SubscriptionRecord {
    pub(super) id: Uuid,
    pub(super) workflow_id: Uuid,
    pub(super) version: i32,
    pub(super) trigger: Value,
    pub(super) secret_sealed: String,
    pub(super) status: String,
    pub(super) remote: Option<String>,
    pub(super) lapses_at: Option<OffsetDateTime>,
    pub(super) label: String,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl SubscriptionRecord {
    /// The registration the record holds, rebuilt through the domain's
    /// checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the
    /// registration keeps.
    pub(super) fn into_subscription(
        self,
    ) -> Result<ServiceSubscription<ResolvedTenant>, DomainError> {
        ServiceSubscription::reconstitute(ServiceSubscriptionRow {
            id: ServiceSubscriptionId::from_uuid(self.id),
            workflow_id: WorkflowId::from_uuid(self.workflow_id),
            version: u32::try_from(self.version)
                .map_err(|_| DomainError::corrupt_row(SUBSCRIPTION.0, "a negative version"))?,
            trigger: TRIGGER
                .open::<StoredTrigger>(self.trigger)?
                .into_trigger(SUBSCRIPTION)?,
            secret: SUBSCRIPTION.value("secret", SealedSecret::new(self.secret_sealed))?,
            status: SUBSCRIPTION.choice(&self.status)?,
            registration: registration_from(self.remote, self.lapses_at)?,
            label: EventLabel::of(&self.label),
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// The service's side of a registration or a channel, from its columns.
pub(in crate::postgres::workflows::triggers) fn registration_from(
    remote: Option<String>,
    lapses_at: Option<OffsetDateTime>,
) -> Result<Registration, DomainError> {
    match (remote, lapses_at) {
        (None, None) => Ok(Registration::NotTaken),
        (Some(remote), lapses_at) => Ok(Registration::Taken {
            remote: SUBSCRIPTION.value("registration", RemoteRegistration::new(remote))?,
            lapses: lapses_at.map_or(Lapse::Never, Lapse::At),
        }),
        (None, Some(_)) => Err(DomainError::corrupt_row(
            SUBSCRIPTION.0,
            "a lapse with no registration at the service",
        )),
    }
}

/// A registration's columns, as they are written.
pub(super) struct SubscriptionColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) workflow_id: &'a Uuid,
    pub(super) version: i32,
    pub(super) integration: &'a str,
    pub(super) trigger: Value,
    pub(super) secret_sealed: &'a str,
    pub(super) status: &'static str,
    pub(super) remote: Option<&'a str>,
    pub(super) lapses_at: Option<OffsetDateTime>,
    pub(super) label: &'a str,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> SubscriptionColumns<'a> {
    /// The columns `subscription` is written to. Its secret is written in
    /// the sealed form it already holds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when its trigger cannot be
    /// written out, or its version does not fit its column.
    pub(super) fn of(
        subscription: &'a ServiceSubscription<ResolvedTenant>,
    ) -> Result<Self, DomainError> {
        let (remote, lapses_at) = match subscription.registration() {
            Registration::NotTaken => (None, None),
            Registration::Taken { remote, lapses } => (
                Some(remote.as_str()),
                match lapses {
                    Lapse::Never => None,
                    Lapse::At(at) => Some(*at),
                },
            ),
        };
        Ok(Self {
            id: subscription.id().as_uuid(),
            workflow_id: subscription.workflow_id().as_uuid(),
            version: i32::try_from(subscription.version()).map_err(DomainError::infra)?,
            integration: subscription.integration().as_str(),
            trigger: TRIGGER.seal(&StoredTrigger::of(subscription.trigger()))?,
            secret_sealed: subscription.secret().as_str(),
            status: subscription.status().word(),
            remote,
            lapses_at,
            label: subscription.label().as_str(),
            created_at: subscription.created_at(),
            updated_at: subscription.updated_at(),
        })
    }
}

/// The key a registration's events name it by, or none when they reach
/// its own address.
pub(super) fn route_key(routing: &Routing) -> Option<&str> {
    match routing {
        Routing::OwnAddress => None,
        Routing::Keyed(key) => Some(key.as_str()),
    }
}

/// Where a registration found across tenants is kept, as its row holds it.
pub(super) struct SubscriptionHit {
    pub(super) tenant_id: Uuid,
    pub(super) id: Uuid,
}

impl SubscriptionHit {
    /// The tenant it is kept in.
    pub(super) fn tenant(&self) -> TenantId {
        TenantId::from_uuid(self.tenant_id)
    }
}

/// A registration due for renewal, with when it lapses.
pub(super) struct DueHit {
    pub(super) tenant_id: Uuid,
    pub(super) id: Uuid,
    pub(super) lapses_at: OffsetDateTime,
}

impl DueHit {
    /// The tenant it is kept in.
    pub(super) fn tenant(&self) -> TenantId {
        TenantId::from_uuid(self.tenant_id)
    }
}

#[cfg(test)]
mod tests {
    //! The shape the trigger column is stored in today. A row written now
    //! is read for years, so when this fails, raise the column's shape and
    //! add the step that reads the old one.

    use ianua_domain::domains::workflows::integration::IntegrationKey;
    use ianua_domain::domains::workflows::integration::events::ServiceEventKey;
    use ianua_domain::domains::workflows::triggers::ServiceTrigger;
    use ianua_domain::types::IntegrationAccountId;
    use serde_json::json;

    use super::*;

    /// A registration's trigger, on new GitHub issues with no filter, is
    /// written in the shape pinned here, and reads back.
    #[test]
    fn the_trigger_is_stored_in_its_pinned_shape() {
        let trigger = ServiceTrigger::from_stored(
            IntegrationKey::new("github").unwrap(),
            ServiceEventKey::new("issue-opened").unwrap(),
            IntegrationAccountId::from_uuid(Uuid::nil()),
            Vec::new(),
        )
        .unwrap();
        let stored = json!({"v": 1, "value": {
            "integration": "github",
            "event": "issue-opened",
            "account": "00000000-0000-0000-0000-000000000000",
            "filters": []
        }});

        assert_eq!(TRIGGER.seal(&StoredTrigger::of(&trigger)).unwrap(), stored);
        assert_eq!(
            TRIGGER
                .open::<StoredTrigger>(stored)
                .unwrap()
                .into_trigger(SUBSCRIPTION)
                .unwrap(),
            trigger
        );
    }
}
