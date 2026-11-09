//! A zone a tenant has delegated to us, and the records we answer from it.
//!
//! Delegation is one `NS` record at the tenant's own provider. It points a
//! single hostname at our nameservers. We then answer for that name and
//! nothing else. The tenant's apex, mail and website stay where they are, and
//! we cannot break any of them.
//!
//! We can then write the records that name needs without asking the tenant.
//! These are the address it points at and the `TXT` record a certificate
//! authority wants for DNS-01. The tenant no longer has to get DNS right.
//!
//! The tenant gets the rest of the zone. Everything under the delegated
//! hostname is theirs to fill, so this models a full DNS zone and not only
//! the two records we write.
//!
//! # The parts
//!
//! - [`RecordName`] is the name a record answers for. It is looser than a
//!   hostname, because `_acme-challenge` and `_dmarc` are not hostnames.
//! - [`RecordKind`] is the type, and [`RecordValue`] the answer. One variant
//!   per type, so the two cannot disagree.
//! - [`RecordSet`] is every answer to one question, which is how DNS actually
//!   resolves and how a resolver caches. It is the unit of change.
//! - [`ZonePolicy`] says which records the tenant may write and which few
//!   we keep. What it allows, a [`RecordSetWrite`] or a
//!   [`RecordSetRemoval`], raises the record of the change.
//!
//! Zones are written by the control plane and read by the nameservers, the
//! same split the HTTP-01 challenge store uses.

mod catalog;
mod change;
mod delegation;
mod kind;
mod name;
mod policy;
mod record_set;
mod resolution;
mod ttl;
mod value;
mod zone;

pub use catalog::{HeldZone, ZoneCatalog, ZoneStanding, served_zones};
pub use change::{RecordSetRemoval, RecordSetWrite, RemovedRecordSet, WriteEffect};
pub use delegation::DelegationLabel;
pub use kind::RecordKind;
pub use name::RecordName;
pub use policy::ZonePolicy;
pub use record_set::RecordSet;
pub use resolution::{Answer, AnswerValue, QueryKind, Resolution, resolve};
pub use ttl::Ttl;
pub use value::{
    CaaHandling, CaaProperty, CaaTag, MailExchange, RecordValue, ServiceTarget, TxtValue,
};
pub use zone::{Authority, Serial, SoaTimers, StartOfAuthority, Zone};
