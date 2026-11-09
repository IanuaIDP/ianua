//! The ticket a run reaches the network with: the hosts its version may
//! reach and when the ticket ends, signed with the key the worker and the
//! network filter alone share.
//!
//! The run's code holds the ticket, so it can reach its hosts through the
//! filter, and nothing else: a changed host list or a later end fails the
//! signature, and an ended ticket is refused.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::keys::{KEY_BYTES, decoded_key, hmac_sha256};

/// The most hosts a ticket names, as a version may allow.
const MAX_HOSTS: usize = 20;

/// The most bytes of a ticket, past which it is not read.
pub(super) const MAX_TICKET: usize = 8 * 1024;

/// The key tickets are signed with, shared by the worker and the network
/// filter and nothing else. It never prints.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TicketKey([u8; KEY_BYTES]);

impl fmt::Debug for TicketKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TicketKey(<redacted>)")
    }
}

impl TicketKey {
    /// The key `value` writes, as 64 hex characters or as base64 of 32
    /// bytes; `None` when it is neither. A short key is never padded.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        decoded_key(value).map(Self)
    }
}

/// What a ticket lets a run reach, and until when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Ticket {
    /// The hosts it may reach, by their DNS names in lower case.
    pub(super) hosts: Vec<String>,
    /// When it ends, in seconds since the Unix epoch.
    pub(super) ends_at: u64,
}

impl Ticket {
    /// This ticket, signed with `key`.
    pub(super) fn signed(&self, key: &TicketKey) -> String {
        let claims = URL_SAFE_NO_PAD.encode(self.claims());
        let signature = URL_SAFE_NO_PAD.encode(hmac_sha256(&key.0, &[claims.as_bytes()]));
        format!("{claims}.{signature}")
    }

    /// The ticket `token` holds, when `key` signed it and it has not ended
    /// by `now`, in seconds since the Unix epoch.
    pub(super) fn verified(key: &TicketKey, token: &str, now: u64) -> Option<Self> {
        if token.len() > MAX_TICKET {
            return None;
        }
        let (claims, signature) = token.split_once('.')?;
        let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
        let expected = hmac_sha256(&key.0, &[claims.as_bytes()]);
        if !bool::from(expected.as_slice().ct_eq(&signature)) {
            return None;
        }
        let claims = String::from_utf8(URL_SAFE_NO_PAD.decode(claims).ok()?).ok()?;
        let ticket = Self::read(&claims)?;
        (ticket.ends_at > now).then_some(ticket)
    }

    /// Whether the ticket lets its run reach `host`.
    pub(super) fn allows(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.hosts.contains(&host)
    }

    /// What the ticket says, before it is signed: its end, then its hosts.
    fn claims(&self) -> String {
        format!("{}\n{}", self.ends_at, self.hosts.join(","))
    }

    /// The ticket `claims` say.
    fn read(claims: &str) -> Option<Self> {
        let (ends_at, hosts) = claims.split_once('\n')?;
        let hosts: Vec<String> = hosts
            .split(',')
            .filter(|host| !host.is_empty())
            .map(str::to_owned)
            .collect();
        if hosts.is_empty() || hosts.len() > MAX_HOSTS {
            return None;
        }
        Some(Self {
            hosts,
            ends_at: ends_at.parse().ok()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> TicketKey {
        TicketKey([byte; KEY_BYTES])
    }

    fn ticket() -> Ticket {
        Ticket {
            hosts: vec!["api.github.com".to_owned(), "pypi.org".to_owned()],
            ends_at: 1_000,
        }
    }

    /// A ticket signed with the key reads back before it ends, and lets
    /// its run reach exactly its hosts.
    #[test]
    fn a_signed_ticket_reads_back_until_it_ends() {
        let token = ticket().signed(&key(7));

        let read = Ticket::verified(&key(7), &token, 999).unwrap();

        assert_eq!(read, ticket());
        assert!(read.allows("API.github.com"));
        assert!(!read.allows("evil.example.com"));
        assert_eq!(Ticket::verified(&key(7), &token, 1_000), None);
    }

    /// Verification rejects another key's ticket, altered host claims and malformed token text.
    #[test]
    fn a_forged_or_changed_ticket_is_refused() {
        let forged = ticket().signed(&key(8));
        let token = ticket().signed(&key(7));
        let (_, signature) = token.split_once('.').unwrap();
        let widened = format!(
            "{}.{signature}",
            URL_SAFE_NO_PAD.encode("1000\napi.github.com,evil.example.com")
        );

        assert_eq!(Ticket::verified(&key(7), &forged, 0), None);
        assert_eq!(Ticket::verified(&key(7), &widened, 0), None);
        assert_eq!(Ticket::verified(&key(7), "not a ticket", 0), None);
    }

    /// A key is read from 64 hex characters; a short one is refused.
    #[test]
    fn a_key_is_read_only_whole() {
        assert!(TicketKey::parse(&"ab".repeat(32)).is_some());
        assert!(TicketKey::parse("abcd").is_none());
    }
}
