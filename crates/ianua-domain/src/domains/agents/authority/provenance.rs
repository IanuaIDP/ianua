//! Message provenance: who wrote a message, and on whose authority.
//!
//! Every message one agent sends another carries a [`MessageProvenance`]. It
//! names the sending agent, the delegation it acted under and the principals
//! it acts for. It also holds a hash of the exact payload. An adapter signs
//! the claim with the tenant's key before the message is encrypted. The
//! recipient checks it before acting. So an agent connected to a shared topic
//! cannot pose as another agent.
//!
//! This module only models and checks the claim. Hashing and signing happen
//! in infrastructure. The domain carries the 32-byte digest.

use crate::domains::agents::authority::delegation::Delegation;
use crate::isolation::scope::TenantScope;
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_range;
use crate::shared::validation::{Charset, TextValue, Validator, text_value};
use crate::types::{AgentId, DelegationId, PrincipalRef};

text_value! {
    /// A provenance claim sealed by the tenant's key: the compact signed
    /// token an adapter makes and a recipient hands back to be checked.
    ///
    /// The domain never reads inside it. It only keeps what arrives from
    /// outside to the shape a sealed token can have, so an oversized or
    /// garbled one is refused before any key is used on it.
    ///
    /// Rules:
    /// - 16 to 8192 characters.
    /// - Only ASCII letters, digits, `-`, `_` and `.`, as a compact signed
    ///   token has.
    pub struct SealedProvenance;
}

impl TextValue for SealedProvenance {
    const FIELD: &'static str = "provenance";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(
            16..=8192,
            Charset::UPPERCASE
                | Charset::LOWERCASE
                | Charset::DIGIT
                | Charset::HYPHEN
                | Charset::UNDERSCORE
                | Charset::DOT,
        )
    }
}

/// A SHA-256 digest that ties a provenance claim to one payload.
///
/// The domain carries the digest but never computes it. The adapter that
/// seals the message does the hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PayloadHash([u8; 32]);

impl PayloadHash {
    /// Wraps a raw 32-byte digest.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The digest as 64 lowercase hex characters, the form it travels in.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
            out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
        }
        out
    }

    /// Parses a digest written as 64 lowercase hex characters.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the input is not 64 characters long.
    /// - [`DomainError::Validation`] when a character is not lowercase hex.
    pub fn from_hex(value: &str) -> Result<Self, DomainError> {
        Validator::new("payload_hash", value)
            .length(64..=64)
            .validate_first()?;
        let mut bytes = [0u8; 32];
        let mut nibbles = value.bytes().map(hex_nibble);
        for slot in &mut bytes {
            let (Some(high), Some(low)) = (nibbles.next(), nibbles.next()) else {
                return Err(not_hex());
            };
            *slot = (high? << 4) | low?;
        }
        Ok(Self(bytes))
    }
}

fn hex_nibble(byte: u8) -> Result<u8, DomainError> {
    let lower_hex = matches!(byte, b'0'..=b'9' | b'a'..=b'f');
    char::from(byte)
        .to_digit(16)
        .filter(|_| lower_hex)
        .and_then(|digit| u8::try_from(digit).ok())
        .ok_or_else(not_hex)
}

fn not_hex() -> DomainError {
    DomainError::invalid(message!(
        "agents-payload-hash-contains-a-non-hex",
        "payload hash contains a non-hex character"
    ))
}

/// Who wrote one message, for whom, and under which delegation.
///
/// A claim read from the wire passes the same checks as one built with
/// [`MessageProvenance::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "MessageProvenanceWire"))]
pub struct MessageProvenance {
    sender: AgentId,
    on_behalf_of: Vec<PrincipalRef>,
    delegation_id: DelegationId,
    payload_hash: PayloadHash,
}

/// A claim as it arrives, before [`MessageProvenance::new`] has checked it.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct MessageProvenanceWire {
    sender: AgentId,
    on_behalf_of: Vec<PrincipalRef>,
    delegation_id: DelegationId,
    payload_hash: PayloadHash,
}

#[cfg(feature = "serde")]
impl TryFrom<MessageProvenanceWire> for MessageProvenance {
    type Error = DomainError;

    /// Checks a received claim through [`MessageProvenance::new`]. A chain
    /// longer than a sender may build is refused when read in.
    fn try_from(wire: MessageProvenanceWire) -> Result<Self, Self::Error> {
        Self::new(
            wire.sender,
            wire.on_behalf_of,
            wire.delegation_id,
            wire.payload_hash,
        )
    }
}

impl MessageProvenance {
    /// The most principals a message's chain may hold. It keeps envelopes
    /// small.
    const MAX_CHAIN: usize = 16;

    /// Builds a provenance claim.
    ///
    /// `on_behalf_of` lists the principals the sender acts for, with the root
    /// last. It is empty when the sender acts on its own, under an owner
    /// delegation.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when the chain holds more than
    ///   `MAX_CHAIN` principals.
    pub fn new(
        sender: AgentId,
        on_behalf_of: Vec<PrincipalRef>,
        delegation_id: DelegationId,
        payload_hash: PayloadHash,
    ) -> Result<Self, DomainError> {
        let as_count = |length: usize| u64::try_from(length).unwrap_or(u64::MAX);
        validate_range(
            "on_behalf_of",
            as_count(on_behalf_of.len()),
            0..=as_count(Self::MAX_CHAIN),
        )?;
        Ok(Self {
            sender,
            on_behalf_of,
            delegation_id,
            payload_hash,
        })
    }

    /// The agent that authored the message.
    #[must_use]
    pub fn sender(&self) -> &AgentId {
        &self.sender
    }

    /// The principals the sender acts for, with the root last. It is empty
    /// when the sender acts on its own.
    #[must_use]
    pub fn on_behalf_of(&self) -> &[PrincipalRef] {
        &self.on_behalf_of
    }

    /// The delegation the sender acted under. Its id is also the token's
    /// `jti`.
    #[must_use]
    pub fn delegation_id(&self) -> &DelegationId {
        &self.delegation_id
    }

    /// The digest that ties this claim to its payload.
    #[must_use]
    pub fn payload_hash(&self) -> &PayloadHash {
        &self.payload_hash
    }

    /// Whether this claim agrees with `delegation`, the one it names as
    /// stored.
    ///
    /// The sender is the agent the delegation was given to, and the first
    /// party it acts for is the one who gave it. A delegation an agent made
    /// for itself acts for nobody. The recipient checks this, together with
    /// the signature, before acting. Sam's agent holds a delegation from Sam.
    /// Without this check, it could claim to act for Ann in a message to
    /// Ann's finance agent.
    #[must_use]
    pub fn agrees_with<T: TenantScope>(&self, delegation: &Delegation<T>) -> bool {
        if delegation.id() != &self.delegation_id || delegation.delegate() != &self.sender {
            return false;
        }
        if delegation.is_self_rooted() {
            return self.on_behalf_of.is_empty();
        }
        self.on_behalf_of.first() == Some(delegation.delegator())
    }

    /// Whether this claim was made for the payload with `payload_hash`.
    ///
    /// The recipient checks this before acting, so a payload changed on the
    /// way is caught.
    #[must_use]
    pub fn binds_to(&self, payload_hash: &PayloadHash) -> bool {
        &self.payload_hash == payload_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::UserId;

    fn hash(seed: u8) -> PayloadHash {
        PayloadHash::from_bytes([seed; 32])
    }

    /// A digest of repeated `0xab` bytes is written as 64 hex characters and
    /// parsed back. The parsed hash equals the original.
    #[test]
    fn payload_hash_hex_roundtrips() {
        let original = hash(0xab);
        let hex = original.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(PayloadHash::from_hex(&hex).unwrap(), original);
    }

    /// A three-character string and a string of 64 `z` characters are both
    /// refused. Only a full-length hex digest parses.
    #[test]
    fn from_hex_rejects_bad_input() {
        assert!(PayloadHash::from_hex("abc").is_err());
        assert!(PayloadHash::from_hex(&"z".repeat(64)).is_err());
    }

    /// A sender builds a claim with 17 principals, one more than allowed. It
    /// is refused with a validation error, so envelopes stay small.
    #[test]
    fn new_rejects_overlong_chain() {
        let chain = vec![PrincipalRef::User(UserId::new()); MessageProvenance::MAX_CHAIN + 1];
        let result = MessageProvenance::new(AgentId::new(), chain, DelegationId::new(), hash(1));
        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A self-rooted delegation agrees with a claim naming its agent and
    /// no represented principals. Claims naming a principal or another
    /// sender disagree with it.
    #[test]
    fn a_claim_must_agree_with_the_delegation_it_names() {
        let agent = AgentId::new();
        let own = crate::domains::agents::authority::delegation::Delegation::<
            crate::isolation::scope::ResolvedTenant,
        >::grant_owned(
            agent,
            crate::domains::agents::authority::capability::CapabilitySet::default(),
            crate::domains::agents::authority::capability::DelegationConstraints::new(
                crate::types::Seconds::new(600),
                0,
            )
            .unwrap(),
        );
        let claim =
            |sender, chain| MessageProvenance::new(sender, chain, *own.id(), hash(1)).unwrap();

        assert!(claim(agent, vec![]).agrees_with(&own));
        assert!(!claim(agent, vec![PrincipalRef::User(UserId::new())]).agrees_with(&own));
        assert!(!claim(AgentId::new(), vec![]).agrees_with(&own));
    }

    /// An agent under an owner delegation builds a claim that names no
    /// principals. The claim is valid and its chain reads back empty.
    #[test]
    fn autonomous_sender_has_empty_chain() {
        let provenance =
            MessageProvenance::new(AgentId::new(), vec![], DelegationId::new(), hash(1)).unwrap();
        assert!(provenance.on_behalf_of().is_empty());
    }

    /// A provenance claim binds to its original payload hash and refuses
    /// a different hash.
    #[test]
    fn binds_to_detects_tampering() {
        let provenance =
            MessageProvenance::new(AgentId::new(), vec![], DelegationId::new(), hash(1)).unwrap();
        assert!(provenance.binds_to(&hash(1)));
        assert!(!provenance.binds_to(&hash(2)));
    }

    /// A hash built from bytes with set first and last values hands back
    /// those exact bytes. A tamper check compares them, so a constant answer
    /// would let any payload pass.
    #[test]
    fn a_hash_reports_the_bytes_it_was_built_from() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xab;
        bytes[31] = 0xcd;

        let hash = PayloadHash::from_bytes(bytes);

        assert_eq!(hash.as_bytes(), &bytes);
        assert_ne!(hash.as_bytes(), &[0u8; 32]);
        assert_ne!(hash.as_bytes(), &[1u8; 32]);
    }

    /// A digest using every nibble value, digits and letters, in both halves
    /// of a byte goes to hex and back. The bytes come back unchanged and the
    /// hex starts with `0ff019a5`.
    #[test]
    fn hex_round_trips_through_every_nibble_value() {
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::try_from(index * 8 % 256).unwrap();
        }
        bytes[0] = 0x0f;
        bytes[1] = 0xf0;
        bytes[2] = 0x19;
        bytes[3] = 0xa5;

        let hex = PayloadHash::from_bytes(bytes).to_hex();
        let parsed = PayloadHash::from_hex(&hex).unwrap();

        assert_eq!(parsed.as_bytes(), &bytes);
        assert_eq!(parsed.to_hex(), hex);
        assert_eq!(&hex[0..8], "0ff019a5");
    }

    /// Empty input, 63 characters, a `z` inside the digest and uppercase hex
    /// are all refused. A digest travels as exactly 64 lowercase hex
    /// characters.
    #[test]
    fn hex_that_is_not_a_digest_is_refused() {
        let valid = PayloadHash::from_bytes([0xab; 32]).to_hex();

        assert!(PayloadHash::from_hex(&valid).is_ok());
        assert!(PayloadHash::from_hex("").is_err());
        assert!(PayloadHash::from_hex(&valid[..63]).is_err());
        assert!(
            PayloadHash::from_hex(&format!("{}zz", &valid[..62])).is_err(),
            "a non-hex character is not a digest"
        );
        assert!(
            PayloadHash::from_hex(&valid.to_uppercase()).is_err(),
            "the digest travels lowercase"
        );
    }

    /// A claim built for one sender, one principal and one delegation hands
    /// back each of them. A recipient reads all three to decide whether to
    /// act.
    #[test]
    fn provenance_reports_the_sender_the_chain_and_the_delegation() {
        let sender = AgentId::new();
        let delegation = DelegationId::new();
        let principal = PrincipalRef::User(crate::types::UserId::new());

        let provenance =
            MessageProvenance::new(sender, vec![principal], delegation, hash(1)).unwrap();

        assert_eq!(provenance.sender(), &sender);
        assert_eq!(provenance.on_behalf_of(), [principal]);
        assert_eq!(provenance.delegation_id(), &delegation);
    }

    /// An agent acting for nobody but itself builds a claim with no
    /// principals. The chain reads back empty, which is how a recipient
    /// tells the agent acts on its own.
    #[test]
    fn an_autonomous_sender_carries_an_empty_chain() {
        let provenance =
            MessageProvenance::new(AgentId::new(), vec![], DelegationId::new(), hash(1)).unwrap();

        assert!(provenance.on_behalf_of().is_empty());
    }

    /// Reading a claim from the wire runs the same checks as
    /// `MessageProvenance::new`. A claim the constructor refuses is refused
    /// when read in too.
    #[cfg(feature = "serde")]
    mod serde_goes_through_the_constructor {
        use super::*;

        /// Adding a seventeenth principal to a valid claim's JSON prevents
        /// deserialization, preserving the chain limit on received claims.
        #[cfg(feature = "serde")]
        #[test]
        fn a_received_claim_with_an_overlong_chain_is_refused() {
            let chain = vec![PrincipalRef::User(UserId::new()); MessageProvenance::MAX_CHAIN];
            let at_limit =
                MessageProvenance::new(AgentId::new(), chain, DelegationId::new(), hash(1))
                    .unwrap();
            let mut json = serde_json::to_value(&at_limit).unwrap();
            json["on_behalf_of"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::to_value(PrincipalRef::User(UserId::new())).unwrap());

            assert!(serde_json::from_value::<MessageProvenance>(json).is_err());
        }

        /// A claim with one principal is written to JSON and read back. It
        /// comes back equal to the original.
        #[cfg(feature = "serde")]
        #[test]
        fn a_claim_reads_back_what_it_writes() {
            let provenance = MessageProvenance::new(
                AgentId::new(),
                vec![PrincipalRef::User(UserId::new())],
                DelegationId::new(),
                hash(7),
            )
            .unwrap();

            let json = serde_json::to_string(&provenance).unwrap();

            assert_eq!(
                serde_json::from_str::<MessageProvenance>(&json).unwrap(),
                provenance
            );
        }
    }

    /// A compact token the signer made is taken as it is.
    #[test]
    fn a_compact_signed_token_is_a_sealed_provenance() {
        assert!(SealedProvenance::new("eyJhbGciOiJFZERTQSJ9.eyJzIjoiYSJ9.c2ln-_x").is_ok());
    }

    /// Sealed provenance refuses a token above the length limit, tokens
    /// containing a space or quote, and a token shorter than the minimum.
    #[test]
    fn an_oversized_or_garbled_token_is_refused() {
        assert!(SealedProvenance::new("a".repeat(8193)).is_err());
        assert!(SealedProvenance::new("eyJhbGc iOiJFZERTQSJ9.abc.def").is_err());
        assert!(SealedProvenance::new("eyJhbGciOiJFZERTQSJ9\".abc").is_err());
        assert!(SealedProvenance::new("short").is_err());
    }
}
