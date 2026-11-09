//! Where use cases send their events in tests, and the labels audit
//! records name entities by.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::audit::builder::AuditContext;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::data::{EventData, FieldValue};
use ianua_domain::shared::events::event::DomainEvent;
use ianua_domain::types::{AuditRecordId, TenantId};

use crate::ports::TenantScoped;
use crate::ports::shared::{EventDispatcher, EventReaction, EventReactions, Noted, ReactionNote};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// In-memory event dispatcher that captures event type strings and payloads.
pub struct FakeEventDispatcher {
    /// Recorded event type strings.
    pub records: Mutex<Vec<String>>,
    /// Recorded payloads, paired with their event type in dispatch order.
    pub payloads: Mutex<Vec<(String, EventData)>>,
    /// The tenant each event was scoped to, paired with its event type.
    pub tenants: Mutex<Vec<(String, Option<TenantId>)>>,
}

impl Default for FakeEventDispatcher {
    fn default() -> Self {
        Self {
            records: Mutex::new(Vec::new()),
            payloads: Mutex::new(Vec::new()),
            tenants: Mutex::new(Vec::new()),
        }
    }
}

impl FakeEventDispatcher {
    /// Creates an empty dispatcher.
    pub fn new() -> Self {
        Self::default()
    }

    /// The payload of the first event dispatched with `event_type`.
    ///
    /// # Panics
    ///
    /// Panics if no event of that type was dispatched, a test asserting on a
    /// payload that never arrived is a failing test, not a `None`.
    #[must_use]
    pub fn payload_of(&self, event_type: &str) -> EventData {
        let payloads = self.payloads.lock().unwrap();
        payloads
            .iter()
            .find(|(kind, _)| kind == event_type)
            .map(|(_, data)| data.clone())
            .unwrap_or_else(|| panic!("no {event_type} event was dispatched"))
    }

    /// The `label` of a reference field in the first `event_type` payload, or
    /// `None` when the field is absent or is not a reference.
    #[must_use]
    pub fn label_of(&self, event_type: &str, key: &str) -> Option<String> {
        reference_label(&self.payload_of(event_type), key).map(str::to_owned)
    }

    /// Every payload dispatched, in order, whatever its event type.
    #[must_use]
    pub fn all_payloads(&self) -> Vec<EventData> {
        let payloads = self.payloads.lock().unwrap();
        payloads.iter().map(|(_, data)| data.clone()).collect()
    }

    /// The tenant the first `event_type` event was scoped to, `None` for an
    /// organization or platform event.
    ///
    /// # Panics
    ///
    /// Panics if no event of that type was dispatched.
    #[must_use]
    pub fn tenant_of(&self, event_type: &str) -> Option<TenantId> {
        self.tenants
            .lock()
            .unwrap()
            .iter()
            .find(|(kind, _)| kind == event_type)
            .map(|(_, tenant)| *tenant)
            .unwrap_or_else(|| panic!("no {event_type} event was dispatched"))
    }
}

#[async_trait]
impl EventDispatcher for FakeEventDispatcher {
    async fn dispatch(
        &self,
        events: &[DomainEvent],
        _ctx: &AuditContext,
    ) -> Result<(), DomainError> {
        let mut records = self.records.lock().unwrap();
        let mut payloads = self.payloads.lock().unwrap();
        let mut tenants = self.tenants.lock().unwrap();
        for event in events {
            let event_type = event.event_type().as_str().to_owned();
            payloads.push((event_type.clone(), event.payload()));
            tenants.push((event_type.clone(), event.tenant_id().copied()));
            records.push(event_type);
        }
        Ok(())
    }
}

/// The `label` of the reference field `key` in `payload`, or `None` when the
/// field is absent or is not a reference.
#[must_use]
pub fn reference_label<'a>(payload: &'a EventData, key: &str) -> Option<&'a str> {
    match payload.value(key)? {
        FieldValue::Reference(reference) => Some(reference.label()),
        _ => None,
    }
}

/// Dispatcher whose audit sink is down: every dispatch fails. For tests that
/// an operation does not take effect without its record.
pub struct FailingEventDispatcher;

#[async_trait]
impl EventDispatcher for FailingEventDispatcher {
    async fn dispatch(
        &self,
        _events: &[DomainEvent],
        _ctx: &AuditContext,
    ) -> Result<(), DomainError> {
        Err(DomainError::infra_msg("the audit sink is down"))
    }
}

impl Fake for Arc<dyn EventDispatcher> {
    fn fake() -> Self {
        Arc::new(FakeEventDispatcher::new())
    }
}

/// The reactions noted, kept in memory by tenant, reaction and record.
#[derive(Default)]
pub struct FakeEventReactions {
    noted: Mutex<HashSet<(TenantId, EventReaction, AuditRecordId)>>,
}

impl FakeEventReactions {
    /// How many reactions were noted.
    #[must_use]
    pub fn count(&self) -> usize {
        self.noted.lock().unwrap().len()
    }
}

impl TenantScoped for FakeEventReactions {}

#[async_trait]
impl EventReactions for FakeEventReactions {
    async fn note(
        &self,
        tenant_id: &ScopedTenant,
        note: &ReactionNote,
    ) -> Result<Noted, DomainError> {
        let mut noted = self
            .noted
            .lock()
            .map_err(|_| DomainError::infra_msg("poisoned"))?;
        if noted.insert((**tenant_id, note.reaction, note.record)) {
            return Ok(Noted::First);
        }
        Ok(Noted::Before)
    }
}

impl Fake for Arc<dyn EventReactions> {
    fn fake() -> Self {
        Arc::new(FakeEventReactions::default())
    }
}
