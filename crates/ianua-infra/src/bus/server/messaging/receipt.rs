//! A delivery's receipt: the server's acknowledgement subject and what the
//! delivery was, sealed for its tenant and consumer, so a receipt that was
//! forged, altered or made for another consumer is refused.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_app::ports::messaging::DeliveryReceipt;
use ianua_domain::types::TenantId;
use time::OffsetDateTime;

use crate::bus::server::messaging::names::Durable;
use crate::crypto::{ReceiptSeal, SignedReceipt};

/// The version a receipt is written in.
const RECEIPT_VERSION: &str = "r1";

/// `at` in milliseconds since the epoch.
pub(super) fn unix_ms(at: OffsetDateTime) -> i128 {
    at.unix_timestamp_nanos() / 1_000_000
}

/// One delivery, as its receipt names it.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Delivery {
    pub(super) reply: String,
    pub(super) delivered: u32,
    pub(super) sequence: u64,
    pub(super) fetched_at_ms: i128,
}

impl Delivery {
    fn body(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.reply, self.delivered, self.sequence, self.fetched_at_ms
        )
    }

    /// The receipt handed to `durable` of `tenant_id` for this delivery.
    pub(super) fn receipt(
        &self,
        seal: &ReceiptSeal,
        tenant_id: &TenantId,
        durable: &Durable,
    ) -> DeliveryReceipt {
        let body = self.body();
        let sealed = seal.seal(tenant_id.as_uuid(), durable.as_str(), &body);
        DeliveryReceipt::new(format!(
            "{RECEIPT_VERSION}.{}.{sealed}",
            URL_SAFE_NO_PAD.encode(&body)
        ))
    }

    /// The delivery `receipt` names, when its seal holds for `durable` of
    /// `tenant_id`.
    pub(super) fn read(
        seal: &ReceiptSeal,
        tenant_id: &TenantId,
        durable: &Durable,
        receipt: &DeliveryReceipt,
    ) -> Option<Self> {
        let rest = receipt
            .as_str()
            .strip_prefix(RECEIPT_VERSION)?
            .strip_prefix('.')?;
        let (body, sealed) = rest.split_once('.')?;
        let body = String::from_utf8(URL_SAFE_NO_PAD.decode(body).ok()?).ok()?;
        let signed = SignedReceipt {
            body: &body,
            seal: sealed,
        };
        if !seal.holds(tenant_id.as_uuid(), durable.as_str(), signed) {
            return None;
        }
        Self::parsed(&body)
    }

    fn parsed(body: &str) -> Option<Self> {
        let mut fields = body.rsplitn(4, '|');
        let fetched_at_ms = fields.next()?.parse().ok()?;
        let sequence = fields.next()?.parse().ok()?;
        let delivered = fields.next()?.parse().ok()?;
        let reply = fields.next()?.to_owned();
        Some(Self {
            reply,
            delivered,
            sequence,
            fetched_at_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;
    use crate::crypto::keys::tests::test_root;

    fn tenant() -> TenantId {
        TenantId::from_uuid(Uuid::now_v7())
    }

    /// A receipt reads back as the delivery it was written for.
    #[test]
    fn a_receipt_reads_back_whole() {
        let seal = ReceiptSeal::new(&test_root());
        let tenant_id = tenant();
        let durable = Durable::of(&tenant_id, "sub-1");
        let delivery = Delivery {
            reply: "$JS.ACK.ianua-messages.c.1.7.1.17|0".to_owned(),
            delivered: 2,
            sequence: 7,
            fetched_at_ms: 1_700_000_000_000,
        };

        let receipt = delivery.receipt(&seal, &tenant_id, &durable);

        assert_eq!(
            Delivery::read(&seal, &tenant_id, &durable, &receipt),
            Some(delivery)
        );
    }

    /// A receipt cannot be read by another consumer or tenant, or after its seal is altered.
    #[test]
    fn a_receipt_is_refused_anywhere_else() {
        let seal = ReceiptSeal::new(&test_root());
        let tenant_id = tenant();
        let durable = Durable::of(&tenant_id, "sub-1");
        let receipt = Delivery {
            reply: "$JS.ACK.x".to_owned(),
            delivered: 1,
            sequence: 1,
            fetched_at_ms: 0,
        }
        .receipt(&seal, &tenant_id, &durable);
        let other = Durable::of(&tenant_id, "sub-2");
        let elsewhere = tenant();
        let altered = DeliveryReceipt::new(format!("{}x", receipt.as_str()));

        assert_eq!(Delivery::read(&seal, &tenant_id, &other, &receipt), None);
        assert_eq!(
            Delivery::read(
                &seal,
                &elsewhere,
                &Durable::of(&elsewhere, "sub-1"),
                &receipt
            ),
            None
        );
        assert_eq!(Delivery::read(&seal, &tenant_id, &durable, &altered), None);
    }
}
