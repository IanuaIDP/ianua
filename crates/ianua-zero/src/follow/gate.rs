//! Which read is newer than what the tables hold.
//!
//! Reloads of one tenant can overlap: a full reload reads every tenant
//! while a heard change reads one of them again. Each read takes a ticket
//! before it starts, and what it read reaches the tables only when no read
//! that started after it has reached them first, so an older read never
//! overwrites a newer one. The gate also knows which tenants the tables
//! hold, and whose organization each is.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use ianua_domain::types::{OrganizationId, TenantId};

use super::locked;

/// What a ticket's read is applied to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Slot {
    Tenant(TenantId),
    Certificates,
}

/// When a read started, against every other read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Ticket(u64);

/// The tenant and ordering ticket of one store read.
#[derive(Debug, Clone, Copy)]
pub(super) struct TenantRead {
    /// The tenant whose snapshot is being read.
    pub tenant: TenantId,
    /// Ordering assigned before the store read begins.
    pub ticket: Ticket,
}

/// What the tables hold for a slot after a read was applied to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Holding {
    /// A tenant, owned by the organization.
    Tenant(OrganizationId),
    /// The slot contains the currently applied set of served TLS identities.
    Certificates,
    /// Nothing.
    Dropped,
}

/// What the tables were last given for a slot.
#[derive(Debug, Clone, Copy)]
struct Applied {
    ticket: Ticket,
    holding: Holding,
}

/// The tickets handed out, and the newest applied to each slot.
#[derive(Debug, Default)]
pub(super) struct Gate {
    issued: AtomicU64,
    applied: Mutex<HashMap<Slot, Applied>>,
}

impl Gate {
    /// A ticket for a read starting now, newer than every one before it.
    pub(super) fn ticket(&self) -> Ticket {
        Ticket(self.issued.fetch_add(1, Ordering::AcqRel) + 1)
    }

    /// Installs `read` under its organization unless a newer read already applied.
    pub(super) fn install_tenant(
        &self,
        read: TenantRead,
        organization: OrganizationId,
        install: impl FnOnce(),
    ) {
        let held = Applied {
            ticket: read.ticket,
            holding: Holding::Tenant(organization),
        };
        self.apply(Slot::Tenant(read.tenant), held, install);
    }

    /// Runs `withdraw` when nothing newer than `ticket` reached `tenant`,
    /// and holds it no longer.
    pub(super) fn withdraw_tenant(
        &self,
        tenant: TenantId,
        ticket: Ticket,
        withdraw: impl FnOnce(),
    ) {
        let dropped = Applied {
            ticket,
            holding: Holding::Dropped,
        };
        self.apply(Slot::Tenant(tenant), dropped, withdraw);
    }

    /// Runs `install` when nothing newer than `ticket` reached the
    /// certificates.
    pub(super) fn install_certificates(&self, ticket: Ticket, install: impl FnOnce()) {
        let held = Applied {
            ticket,
            holding: Holding::Certificates,
        };
        self.apply(Slot::Certificates, held, install);
    }

    /// Every tenant the tables hold now.
    pub(super) fn held_tenants(&self) -> Vec<TenantId> {
        self.tenants_where(|_| true)
    }

    /// Every tenant of `organization` the tables hold now.
    pub(super) fn held_of(&self, organization: OrganizationId) -> Vec<TenantId> {
        self.tenants_where(|owner| owner == organization)
    }

    fn tenants_where(&self, owned: impl Fn(OrganizationId) -> bool) -> Vec<TenantId> {
        locked(&self.applied)
            .iter()
            .filter_map(|(slot, applied)| match (slot, applied.holding) {
                (Slot::Tenant(tenant), Holding::Tenant(owner)) => owned(owner).then_some(*tenant),
                (Slot::Tenant(_) | Slot::Certificates, _) => None,
            })
            .collect()
    }

    /// Runs `change` under the lock, so two reads of one slot reach the
    /// tables in ticket order.
    fn apply(&self, slot: Slot, next: Applied, change: impl FnOnce()) {
        let mut applied = locked(&self.applied);
        let newer_applied = applied
            .get(&slot)
            .is_some_and(|last| last.ticket > next.ticket);
        if newer_applied {
            return;
        }
        change();
        applied.insert(slot, next);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// After a newer tenant ticket installs, an older ticket's install
    /// callback is never run.
    #[test]
    fn an_older_read_never_overwrites_a_newer_one() {
        let gate = Gate::default();
        let (acme, owner) = (TenantId::new(), OrganizationId::new());
        let older = gate.ticket();
        let newer = gate.ticket();
        let mut reached = Vec::new();

        gate.install_tenant(
            TenantRead {
                tenant: acme,
                ticket: newer,
            },
            owner,
            || reached.push("newer"),
        );
        gate.install_tenant(
            TenantRead {
                tenant: acme,
                ticket: older,
            },
            owner,
            || reached.push("older"),
        );

        assert_eq!(reached, vec!["newer"]);
    }

    #[test]
    fn a_withdrawn_tenant_is_no_longer_held() {
        let gate = Gate::default();
        let acme = TenantId::new();
        gate.install_tenant(
            TenantRead {
                tenant: acme,
                ticket: gate.ticket(),
            },
            OrganizationId::new(),
            || {},
        );

        gate.withdraw_tenant(acme, gate.ticket(), || {});

        assert!(gate.held_tenants().is_empty());
    }

    #[test]
    fn the_tenants_of_one_organization_are_told_apart() {
        let gate = Gate::default();
        let (acme, globex) = (TenantId::new(), TenantId::new());
        let owner = OrganizationId::new();
        gate.install_tenant(
            TenantRead {
                tenant: acme,
                ticket: gate.ticket(),
            },
            owner,
            || {},
        );
        gate.install_tenant(
            TenantRead {
                tenant: globex,
                ticket: gate.ticket(),
            },
            OrganizationId::new(),
            || {},
        );

        assert_eq!(gate.held_of(owner), vec![acme]);
    }
}
