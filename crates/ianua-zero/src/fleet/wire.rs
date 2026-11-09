//! A verdict as it travels: stamped with the instance that sent it, when
//! and a nonce, sealed, and framed as `<seal>.<stamped verdict>`.

use std::net::IpAddr;
use std::time::Duration;

use ianua_domain::types::TenantId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::seal::VerdictSeal;
use super::verdict::{ThreatVerdict, VerdictLifetime};

/// What stands between a verdict's seal and the verdict in a frame.
const SEAL_END: u8 = b'.';

/// A verdict as one instance sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Stamped {
    /// The instance that sent it.
    pub(super) origin: Uuid,
    /// Spent once: a second verdict with it is a replay.
    pub(super) nonce: Uuid,
    /// When it was sent.
    pub(super) sent_at: OffsetDateTime,
    /// What it says.
    pub(super) verdict: ThreatVerdict,
}

/// Why a received verdict is not applied. Names nothing it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(super) enum Refusal {
    #[error("the verdict carries no seal")]
    Unsealed,
    #[error("the verdict's seal does not hold")]
    SealBroken,
    #[error("the verdict does not read back")]
    Unreadable,
    #[error("the verdict was sent too long ago")]
    Stale,
    #[error("the verdict was sent later than now")]
    Early,
    #[error("the verdict's nonce was already spent")]
    Replayed,
    #[error("too many verdicts arrived of late to tell a replay")]
    LedgerFull,
}

/// `stamped`, sealed with `seal` under `subject` and framed for the bus.
///
/// # Errors
///
/// Returns the encoder's error, which a verdict of these fields never
/// meets.
pub(super) fn sealed(
    seal: &dyn VerdictSeal,
    subject: &str,
    stamped: &Stamped,
) -> Result<Vec<u8>, serde_json::Error> {
    let body = serde_json::to_vec(&Wire::from(stamped))?;
    let mut frame = seal.seal(subject, &body).into_bytes();
    frame.push(SEAL_END);
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// The verdict `frame` carries, when `seal` holds on it under `subject`.
///
/// # Errors
///
/// Returns [`Refusal`] when the frame has no seal, the seal does not hold,
/// or what it carries does not read back.
pub(super) fn opened(
    seal: &dyn VerdictSeal,
    subject: &str,
    frame: &[u8],
) -> Result<Stamped, Refusal> {
    let end = frame
        .iter()
        .position(|byte| *byte == SEAL_END)
        .ok_or(Refusal::Unsealed)?;
    let (sealed_with, rest) = frame.split_at(end);
    let body = rest.get(1..).ok_or(Refusal::Unsealed)?;
    let sealed_with = std::str::from_utf8(sealed_with).map_err(|_| Refusal::Unsealed)?;
    if !seal.holds(subject, body, sealed_with) {
        return Err(Refusal::SealBroken);
    }
    let wire: Wire = serde_json::from_slice(body).map_err(|_| Refusal::Unreadable)?;
    Ok(Stamped::from(wire))
}

#[derive(Serialize, Deserialize)]
struct Wire {
    origin: Uuid,
    nonce: Uuid,
    #[serde(with = "time::serde::timestamp")]
    sent_at: OffsetDateTime,
    verdict: VerdictWire,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum VerdictWire {
    ClientBlocked {
        tenant_id: Uuid,
        client: IpAddr,
        lasts_seconds: u64,
    },
    ClientFlagged {
        client: IpAddr,
        lasts_seconds: u64,
    },
}

impl From<&Stamped> for Wire {
    fn from(stamped: &Stamped) -> Self {
        Self {
            origin: stamped.origin,
            nonce: stamped.nonce,
            sent_at: stamped.sent_at,
            verdict: VerdictWire::from(stamped.verdict),
        }
    }
}

impl From<Wire> for Stamped {
    fn from(wire: Wire) -> Self {
        Self {
            origin: wire.origin,
            nonce: wire.nonce,
            sent_at: wire.sent_at,
            verdict: ThreatVerdict::from(wire.verdict),
        }
    }
}

impl From<ThreatVerdict> for VerdictWire {
    fn from(verdict: ThreatVerdict) -> Self {
        match verdict {
            ThreatVerdict::ClientBlocked {
                tenant,
                client,
                lasts,
            } => Self::ClientBlocked {
                tenant_id: *tenant.as_uuid(),
                client,
                lasts_seconds: lasts.get().as_secs(),
            },
            ThreatVerdict::ClientFlagged { client, lasts } => Self::ClientFlagged {
                client,
                lasts_seconds: lasts.get().as_secs(),
            },
        }
    }
}

/// The lifetime a received verdict asks for is capped as it is read.
impl From<VerdictWire> for ThreatVerdict {
    fn from(wire: VerdictWire) -> Self {
        match wire {
            VerdictWire::ClientBlocked {
                tenant_id,
                client,
                lasts_seconds,
            } => Self::ClientBlocked {
                tenant: TenantId::from_uuid(tenant_id),
                client,
                lasts: VerdictLifetime::capped(Duration::from_secs(lasts_seconds)),
            },
            VerdictWire::ClientFlagged {
                client,
                lasts_seconds,
            } => Self::ClientFlagged {
                client,
                lasts: VerdictLifetime::capped(Duration::from_secs(lasts_seconds)),
            },
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::hash::{DefaultHasher, Hash, Hasher};

    use super::*;
    use crate::config::deployment::FleetName;

    /// The subject the tests' verdicts travel on.
    const ON: &str = "fleet.threats.default";

    /// The fleet the tests' instances belong to.
    pub(in crate::fleet) fn test_fleet() -> FleetName {
        FleetName::new("default").unwrap()
    }

    /// A seal under `key`, standing in for the one derived from the root.
    #[derive(Debug, Clone, Copy)]
    pub(in crate::fleet) struct KeyedSeal(pub(in crate::fleet) u64);

    impl VerdictSeal for KeyedSeal {
        fn seal(&self, subject: &str, verdict: &[u8]) -> String {
            let mut hasher = DefaultHasher::new();
            (self.0, subject, verdict).hash(&mut hasher);
            format!("{:016x}", hasher.finish())
        }

        fn holds(&self, subject: &str, verdict: &[u8], seal: &str) -> bool {
            self.seal(subject, verdict) == seal
        }
    }

    pub(in crate::fleet) fn flagged(client: &str) -> ThreatVerdict {
        ThreatVerdict::ClientFlagged {
            client: client.parse().unwrap(),
            lasts: VerdictLifetime::capped(Duration::from_secs(600)),
        }
    }

    pub(in crate::fleet) fn stamped(verdict: ThreatVerdict) -> Stamped {
        Stamped {
            origin: Uuid::now_v7(),
            nonce: Uuid::now_v7(),
            sent_at: OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
            verdict,
        }
    }

    #[test]
    fn a_sealed_verdict_opens_as_it_was_sent() {
        let sent = stamped(ThreatVerdict::ClientBlocked {
            tenant: TenantId::new(),
            client: "1.2.3.4".parse().unwrap(),
            lasts: VerdictLifetime::capped(Duration::from_secs(3600)),
        });

        let frame = sealed(&KeyedSeal(7), ON, &sent).unwrap();

        assert_eq!(opened(&KeyedSeal(7), ON, &frame), Ok(sent));
    }

    /// Opening a verdict with a different sealing key reports a broken seal.
    #[test]
    fn a_verdict_sealed_with_another_key_is_refused() {
        let frame = sealed(&KeyedSeal(7), ON, &stamped(flagged("1.2.3.4"))).unwrap();

        assert_eq!(opened(&KeyedSeal(8), ON, &frame), Err(Refusal::SealBroken));
    }

    /// A staging verdict's seal fails verification on the default fleet's subject.
    #[test]
    fn a_seal_does_not_hold_on_another_subject() {
        let frame = sealed(
            &KeyedSeal(7),
            "fleet.threats.staging",
            &stamped(flagged("1.2.3.4")),
        )
        .unwrap();

        assert_eq!(opened(&KeyedSeal(7), ON, &frame), Err(Refusal::SealBroken));
    }

    /// Replacing a sealed verdict's body with another address invalidates its seal.
    #[test]
    fn a_seal_does_not_carry_over_to_another_verdict() {
        let honest = sealed(&KeyedSeal(7), ON, &stamped(flagged("1.2.3.4"))).unwrap();
        let other = sealed(&KeyedSeal(7), ON, &stamped(flagged("5.6.7.8"))).unwrap();
        let seal_end = honest.iter().position(|byte| *byte == SEAL_END).unwrap();
        let other_end = other.iter().position(|byte| *byte == SEAL_END).unwrap();
        let mut forged = honest[..seal_end].to_vec();
        forged.extend_from_slice(&other[other_end..]);

        assert_eq!(opened(&KeyedSeal(7), ON, &forged), Err(Refusal::SealBroken));
    }

    #[test]
    fn a_verdict_with_no_seal_is_refused() {
        assert_eq!(opened(&KeyedSeal(7), ON, b"{}"), Err(Refusal::Unsealed));
    }

    /// A verdict that asks to last a century, sealed by a member of the
    /// fleet, still lasts a day at most.
    #[test]
    fn a_received_lifetime_is_capped() {
        let wire = VerdictWire::ClientFlagged {
            client: "1.2.3.4".parse().unwrap(),
            lasts_seconds: 100 * 365 * 24 * 60 * 60,
        };

        let verdict = ThreatVerdict::from(wire);

        assert!(matches!(
            verdict,
            ThreatVerdict::ClientFlagged { lasts, .. } if lasts.get() == VerdictLifetime::LONGEST
        ));
    }
}
