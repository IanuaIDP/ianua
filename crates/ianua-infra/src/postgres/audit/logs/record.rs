//! An audit log entry as its row holds it, read back with the names the
//! log shows beside it: who acted, and which tenant it happened in.

use std::collections::HashMap;

use ianua_app::listing::{SortKey, SortKeys};
use ianua_app::ports::audit::{AuditLogEntry, AuditLogSortField};
use ianua_domain::domains::audit::builder::ActedThrough;
use ianua_domain::domains::audit::record::AuditTarget;
use ianua_domain::shared::config::DomainLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AuditRecordId, DisplayName, EventType, IpAddress, TenantId, TenantSlug};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::audit::payload::opened;
use crate::postgres::audit::through::KeptThrough;
use crate::postgres::foundation::stored::Stored;

const ENTRY: Stored = Stored("audit record");

const TENANT: Stored = Stored("tenant");

/// An entry as it is read, from a tenant's records or the platform's.
pub(crate) struct EntryRecord {
    pub(crate) id: Uuid,
    pub(crate) tenant_id: Option<Uuid>,
    pub(crate) event_type: String,
    pub(crate) actor: String,
    pub(crate) actor_kind: String,
    pub(crate) actor_id: Option<Uuid>,
    pub(crate) target_id: Option<String>,
    pub(crate) ip_address: Option<String>,
    pub(crate) payload: Value,
    pub(crate) occurred_at: OffsetDateTime,
    pub(crate) user_name: Option<String>,
    pub(crate) user_email: Option<String>,
    pub(crate) acted_through: String,
    pub(crate) through_operator_id: Option<Uuid>,
    pub(crate) through_admin_id: Option<Uuid>,
    pub(crate) as_user_id: Option<Uuid>,
    pub(crate) support_impersonation_id: Option<Uuid>,
    pub(crate) through_execution_id: Option<Uuid>,
}

/// A tenant's name, as the tenants table holds it.
pub(crate) struct TenantNameRecord {
    pub(crate) id: Uuid,
    pub(crate) slug: String,
    pub(crate) display_name: String,
}

/// A person's name and address, as the members table holds them.
pub(crate) struct MemberNameRecord {
    pub(crate) id: Uuid,
    pub(crate) display_name: String,
    pub(crate) email: String,
}

/// An operator's address, as the operators table holds it.
pub(crate) struct OperatorNameRecord {
    pub(crate) id: Uuid,
    pub(crate) email: String,
}

/// The names the entries of one page show, read once for the page.
#[derive(Default)]
pub(crate) struct Names {
    tenants: HashMap<Uuid, (TenantSlug, DisplayName)>,
    people: HashMap<Uuid, String>,
}

impl Names {
    /// The names the records hold, each tenant's checked against `limits`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a tenant's slug or name
    /// no longer passes its rules.
    pub(crate) fn of(
        tenants: Vec<TenantNameRecord>,
        members: Vec<MemberNameRecord>,
        operators: Vec<OperatorNameRecord>,
        limits: &DomainLimits,
    ) -> Result<Self, DomainError> {
        let tenants = tenants
            .into_iter()
            .map(|tenant| {
                let slug = TENANT.value("slug", TenantSlug::new(tenant.slug, &limits.slug))?;
                let name = TENANT.value(
                    "display name",
                    DisplayName::new(tenant.display_name, &limits.display_name),
                )?;
                Ok((tenant.id, (slug, name)))
            })
            .collect::<Result<HashMap<_, _>, DomainError>>()?;
        let people = members
            .into_iter()
            .map(|member| (member.id, person(&member.display_name, &member.email)))
            .chain(
                operators
                    .into_iter()
                    .map(|operator| (operator.id, operator.email)),
            )
            .collect();
        Ok(Self { tenants, people })
    }
}

/// How a person is shown: their name and address.
fn person(name: &str, email: &str) -> String {
    format!("{name} ({email})")
}

impl EntryRecord {
    /// The entry the record holds, with the names `names` gives.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the event type is one
    /// this release does not know, the address no longer reads as one, the
    /// payload does not read, or who the actor acted through does not match
    /// the ids kept.
    pub(crate) fn into_entry(self, names: &Names) -> Result<AuditLogEntry, DomainError> {
        let actor_display = self.actor_display(names);
        let acted_through = self.acted_through()?;
        let event_type = EventType::parse(&self.event_type)
            .ok_or_else(|| DomainError::corrupt_row(ENTRY.0, "an unknown event type"))?;
        let ip_address = self
            .ip_address
            .map(|ip| ENTRY.value("ip address", IpAddress::new(ip)))
            .transpose()?;
        let named_tenant = self.tenant_id.and_then(|tenant| names.tenants.get(&tenant));
        Ok(AuditLogEntry {
            id: AuditRecordId::from_uuid(self.id),
            event_type,
            actor_display,
            tenant_id: self.tenant_id.map(TenantId::from_uuid),
            tenant_slug: named_tenant.map(|(slug, _)| slug.clone()),
            tenant_name: named_tenant.map(|(_, name)| name.clone()),
            target: self
                .target_id
                .map_or(AuditTarget::Untargeted, AuditTarget::Entity),
            ip_address,
            payload: opened(self.payload)?,
            acted_through,
            occurred_at: self.occurred_at,
        })
    }

    /// Whom the actor acted through, from its word and the ids beside it.
    fn acted_through(&self) -> Result<ActedThrough, DomainError> {
        KeptThrough {
            word: &self.acted_through,
            operator: self.through_operator_id,
            admin: self.through_admin_id,
            as_user: self.as_user_id,
            impersonation: self.support_impersonation_id,
            execution: self.through_execution_id,
        }
        .read(ENTRY.0)
    }

    /// Who acted, as the log shows them: a person by name and address, an
    /// operator by address, and anyone else by their label.
    fn actor_display(&self, names: &Names) -> String {
        if let (Some(name), Some(email)) = (&self.user_name, &self.user_email) {
            return person(name, email);
        }
        let known = self.actor_id.and_then(|id| names.people.get(&id));
        match (self.actor_kind.as_str(), known) {
            ("org_user" | "operator", Some(shown)) => shown.clone(),
            ("system", _) => "System".to_owned(),
            ("anonymous", _) => "Anonymous".to_owned(),
            _ => self.actor.clone(),
        }
    }

    /// The tenant the record names and the members and operator who acted,
    /// whose names the page reads.
    pub(crate) fn named(&self) -> (Option<Uuid>, Option<Uuid>, Option<Uuid>) {
        let actor = self.actor_id;
        match self.actor_kind.as_str() {
            "org_user" => (self.tenant_id, actor, None),
            "operator" => (self.tenant_id, None, actor),
            _ => (self.tenant_id, None, None),
        }
    }
}

/// An entry sorts as the entry it becomes, so the page read from rows and
/// the cursor made from its last entry agree.
impl SortKeys<AuditLogSortField> for EntryRecord {
    fn sort_key(&self, field: AuditLogSortField) -> SortKey {
        match field {
            AuditLogSortField::OccurredAt => self.occurred_at.into(),
            AuditLogSortField::EventType => self.event_type.as_str().into(),
        }
    }

    fn tiebreak(&self) -> SortKey {
        self.id.into()
    }
}
