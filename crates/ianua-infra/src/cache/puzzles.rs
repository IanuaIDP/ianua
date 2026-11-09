//! The platform's own sign-in challenge: a proof-of-work puzzle a browser
//! solves before it may sign in while sign-in is under pressure, so a
//! flood costs its sender CPU for every attempt.
//!
//! A puzzle is a payload sealed with an HMAC under a key the control
//! plane's root derives for puzzles alone: when it stops counting, how hard
//! it is, a random nonce, and a digest of the address that asked for it.
//! Nobody without the key can make one, change its difficulty or move it
//! to another address. The browser looks for a counter whose SHA-256 with
//! the puzzle starts with that many zero bits and sends back
//! `<puzzle>.<counter>`. Checking it costs one HMAC and one SHA-256,
//! whatever was sent: the proof's length is bounded before anything is
//! read. A solved puzzle is spent in the state every node shares, so it
//! lets one sign-in through and no other.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_app::ports::authentication::{ChallengeIssuer, ChallengePuzzle, ChallengeVerifier};
use ianua_domain::domains::authentication::risk_engine::challenge::{
    ChallengeKind, ChallengeProof, ChallengeVerdict,
};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Fact, IpAddress, TokenHash};
use rand::RngCore as _;
use rand::rngs::OsRng;
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

use crate::cache::state::{SharedState, key};
use crate::crypto::keys::{Purpose, PurposeKey, RootSecret, hmac_sha256};

/// The shape of a puzzle's payload this release writes and reads.
const VERSION: u8 = 1;

/// The longest proof read; anything longer is refused unread.
const MOST_PROOF_CHARS: usize = 160;

/// The most digits a counter may have: any `u64`.
const MOST_COUNTER_DIGITS: usize = 20;

/// The hardest puzzle that may be set: past this a browser would take far
/// longer than a sign-in waits.
pub const HARDEST_PUZZLE_BITS: u8 = 32;

/// How hard puzzles are and how long they count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PuzzleSettings {
    /// The leading zero bits a solution's hash must start with, at most
    /// [`HARDEST_PUZZLE_BITS`].
    pub difficulty_bits: u8,
    /// How long a puzzle counts from when it was set.
    pub lifetime: Duration,
}

/// Sets and checks the platform's sign-in puzzles.
pub struct Puzzles {
    key: PurposeKey,
    settings: PuzzleSettings,
    state: Arc<dyn SharedState>,
}

impl std::fmt::Debug for Puzzles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Puzzles")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

/// What a puzzle's payload holds.
struct Payload {
    expires: OffsetDateTime,
    difficulty_bits: u8,
    nonce: [u8; 16],
    address: [u8; 32],
}

impl Puzzles {
    /// Puzzles sealed under the key `root` derives for them, set as
    /// `settings` says, spent on `state`, which every node shares.
    #[must_use]
    pub fn new(root: &RootSecret, settings: PuzzleSettings, state: Arc<dyn SharedState>) -> Self {
        Self {
            key: root.derive(Purpose::SignInPuzzles),
            settings: PuzzleSettings {
                difficulty_bits: settings.difficulty_bits.min(HARDEST_PUZZLE_BITS),
                ..settings
            },
            state,
        }
    }

    /// The digest `client_ip` is bound under, the same for every unknown
    /// address.
    fn address_of(&self, client_ip: Fact<&IpAddress>) -> [u8; 32] {
        let address = match client_ip {
            Fact::Known(address) => address.as_str(),
            Fact::Unknown => "",
        };
        hmac_sha256(self.key.bytes(), &[b"address", address.as_bytes()])
    }

    /// The seal on `payload`.
    fn seal(&self, payload: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(hmac_sha256(self.key.bytes(), &[b"puzzle", payload]))
    }

    /// The puzzle `challenge` holds, once its seal holds.
    fn opened(&self, challenge: &str) -> Option<Payload> {
        let (payload, seal) = challenge.split_once('.')?;
        let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
        if TokenHash::from_stored(self.seal(&bytes)) != TokenHash::from_stored(seal.to_owned()) {
            return None;
        }
        payload_of(&bytes)
    }

    /// Whether `proof` solves a puzzle this platform set for `client_ip`
    /// that still counts at `now` and is as hard as puzzles are now, and
    /// the nonce to spend when it does.
    fn solved(
        &self,
        proof: &str,
        client_ip: Fact<&IpAddress>,
        now: OffsetDateTime,
    ) -> Option<(OffsetDateTime, [u8; 16])> {
        if proof.len() > MOST_PROOF_CHARS {
            return None;
        }
        let (challenge, counter) = proof.rsplit_once('.')?;
        let well_formed = !counter.is_empty()
            && counter.len() <= MOST_COUNTER_DIGITS
            && counter.bytes().all(|byte| byte.is_ascii_digit());
        if !well_formed {
            return None;
        }
        let puzzle = self.opened(challenge)?;
        let fits = puzzle.expires > now
            && puzzle.difficulty_bits >= self.settings.difficulty_bits
            && TokenHash::from_stored(URL_SAFE_NO_PAD.encode(puzzle.address))
                == TokenHash::from_stored(URL_SAFE_NO_PAD.encode(self.address_of(client_ip)));
        if !fits {
            return None;
        }
        let hash = Sha256::digest(format!("{challenge}:{counter}").as_bytes());
        (leading_zero_bits(&hash) >= u32::from(puzzle.difficulty_bits))
            .then_some((puzzle.expires, puzzle.nonce))
    }
}

/// The payload of a puzzle.
fn payload(puzzle: &Payload) -> Vec<u8> {
    let mut bytes = vec![VERSION];
    bytes.extend_from_slice(&puzzle.expires.unix_timestamp().to_be_bytes());
    bytes.push(puzzle.difficulty_bits);
    bytes.extend_from_slice(&puzzle.nonce);
    bytes.extend_from_slice(&puzzle.address);
    bytes
}

/// The puzzle `bytes` hold, or `None` when they are not a payload this
/// release writes.
fn payload_of(bytes: &[u8]) -> Option<Payload> {
    let (&[version], rest) = bytes.split_first_chunk::<1>()?;
    let (expires, rest) = rest.split_first_chunk::<8>()?;
    let (&[difficulty_bits], rest) = rest.split_first_chunk::<1>()?;
    let (nonce, rest) = rest.split_first_chunk::<16>()?;
    let address: [u8; 32] = rest.try_into().ok()?;
    if version != VERSION {
        return None;
    }
    Some(Payload {
        expires: OffsetDateTime::from_unix_timestamp(i64::from_be_bytes(*expires)).ok()?,
        difficulty_bits,
        nonce: *nonce,
        address,
    })
}

/// How many zero bits `hash` starts with.
fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut zeros = 0_u32;
    for byte in hash {
        zeros = zeros.saturating_add(byte.leading_zeros());
        if *byte != 0 {
            break;
        }
    }
    zeros
}

impl Puzzles {
    /// A new puzzle for `client_ip`, as hard and as long-lived as puzzles
    /// are now.
    ///
    /// # Errors
    ///
    /// [`DomainError::Infrastructure`] when no random nonce can be drawn or
    /// the lifetime is past the clock's range.
    pub fn issue(&self, client_ip: Fact<&IpAddress>) -> Result<ChallengePuzzle, DomainError> {
        let mut nonce = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(DomainError::infra)?;
        let expires = clock::now().saturating_add(
            time::Duration::try_from(self.settings.lifetime).map_err(DomainError::infra)?,
        );
        let puzzle = Payload {
            expires,
            difficulty_bits: self.settings.difficulty_bits,
            nonce,
            address: self.address_of(client_ip),
        };
        let bytes = payload(&puzzle);
        Ok(ChallengePuzzle {
            challenge: format!("{}.{}", URL_SAFE_NO_PAD.encode(&bytes), self.seal(&bytes)),
            difficulty_bits: puzzle.difficulty_bits,
            expires_at: expires,
        })
    }

    /// Whether `proof` solves a puzzle set for `client_ip` that still
    /// counts, spending it on the shared state so it passes once.
    ///
    /// # Errors
    ///
    /// [`DomainError::Infrastructure`] when the shared state cannot be
    /// reached.
    pub async fn verify(
        &self,
        proof: &ChallengeProof,
        client_ip: Fact<&IpAddress>,
    ) -> Result<ChallengeVerdict, DomainError> {
        let now = clock::now();
        let Some((expires, nonce)) = self.solved(proof.as_str(), client_ip, now) else {
            return Ok(ChallengeVerdict::Failed);
        };
        let left = u64::try_from(
            expires
                .unix_timestamp()
                .saturating_sub(now.unix_timestamp()),
        )
        .map_or(Duration::ZERO, Duration::from_secs);
        let spent = key(&["puzzle", &data_encoding::HEXLOWER.encode(&nonce)]);
        let first = self
            .state
            .claim_once(&spent, left.max(Duration::from_secs(1)))
            .await
            .map_err(DomainError::from)?;
        Ok(if first {
            ChallengeVerdict::Passed
        } else {
            ChallengeVerdict::Failed
        })
    }
}

/// Sets the platform's sign-in puzzles.
#[derive(Debug, Clone)]
pub struct CacheChallengeIssuer(Arc<Puzzles>);

impl CacheChallengeIssuer {
    /// Sets `puzzles`.
    #[must_use]
    pub fn new(puzzles: Arc<Puzzles>) -> Self {
        Self(puzzles)
    }
}

impl ChallengeIssuer for CacheChallengeIssuer {
    fn issue(&self, client_ip: Fact<&IpAddress>) -> Result<ChallengePuzzle, DomainError> {
        self.0.issue(client_ip)
    }
}

/// Checks the platform's sign-in puzzles, each passing once.
#[derive(Debug, Clone)]
pub struct CacheChallengeVerifier(Arc<Puzzles>);

impl CacheChallengeVerifier {
    /// Checks `puzzles`.
    #[must_use]
    pub fn new(puzzles: Arc<Puzzles>) -> Self {
        Self(puzzles)
    }
}

#[async_trait]
impl ChallengeVerifier for CacheChallengeVerifier {
    fn kind(&self) -> ChallengeKind {
        ChallengeKind::ProofOfWork
    }

    async fn verify(
        &self,
        proof: &ChallengeProof,
        client_ip: Fact<&IpAddress>,
    ) -> Result<ChallengeVerdict, DomainError> {
        self.0.verify(proof, client_ip).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::MemoryState;

    fn root() -> RootSecret {
        RootSecret::parse(&"cd".repeat(32)).unwrap()
    }

    fn puzzles_at(difficulty_bits: u8, lifetime: Duration) -> Puzzles {
        Puzzles::new(
            &root(),
            PuzzleSettings {
                difficulty_bits,
                lifetime,
            },
            Arc::new(MemoryState::new(1_000)),
        )
    }

    fn puzzles() -> Puzzles {
        puzzles_at(8, Duration::from_secs(120))
    }

    fn ann() -> IpAddress {
        IpAddress::new("203.0.113.7").unwrap()
    }

    /// The first counter that solves `puzzle`, as a browser finds it.
    fn solve(puzzle: &ChallengePuzzle) -> ChallengeProof {
        let counter = (0_u64..)
            .find(|counter| {
                let hash = Sha256::digest(format!("{}:{counter}", puzzle.challenge).as_bytes());
                leading_zero_bits(&hash) >= u32::from(puzzle.difficulty_bits)
            })
            .unwrap();
        ChallengeProof::new(format!("{}.{counter}", puzzle.challenge)).unwrap()
    }

    /// A browser solves the puzzle it was set and signs in once.
    #[tokio::test]
    async fn a_solved_puzzle_passes() {
        let puzzles = puzzles();
        let puzzle = puzzles.issue(Fact::Known(&ann())).unwrap();

        let verdict = puzzles
            .verify(&solve(&puzzle), Fact::Known(&ann()))
            .await
            .unwrap();

        assert_eq!(verdict, ChallengeVerdict::Passed);
    }

    /// A correct puzzle solution passes once and fails when submitted again.
    #[tokio::test]
    async fn a_solved_puzzle_passes_once() {
        let puzzles = puzzles();
        let proof = solve(&puzzles.issue(Fact::Known(&ann())).unwrap());
        puzzles.verify(&proof, Fact::Known(&ann())).await.unwrap();

        let again = puzzles.verify(&proof, Fact::Known(&ann())).await.unwrap();

        assert_eq!(again, ChallengeVerdict::Failed);
    }

    /// A counter without the required proof of work fails puzzle verification.
    #[tokio::test]
    async fn a_wrong_solution_fails() {
        let puzzles = puzzles_at(16, Duration::from_secs(120));
        let puzzle = puzzles.issue(Fact::Known(&ann())).unwrap();
        let wrong = (0_u64..)
            .find(|counter| {
                let hash = Sha256::digest(format!("{}:{counter}", puzzle.challenge).as_bytes());
                leading_zero_bits(&hash) < 16
            })
            .unwrap();
        let proof = ChallengeProof::new(format!("{}.{wrong}", puzzle.challenge)).unwrap();

        let verdict = puzzles.verify(&proof, Fact::Known(&ann())).await.unwrap();

        assert_eq!(verdict, ChallengeVerdict::Failed);
    }

    /// A solved puzzle with a zero lifetime is already expired and fails verification.
    #[tokio::test]
    async fn an_expired_puzzle_fails() {
        let puzzles = puzzles_at(4, Duration::ZERO);
        let proof = solve(&puzzles.issue(Fact::Known(&ann())).unwrap());

        let verdict = puzzles.verify(&proof, Fact::Known(&ann())).await.unwrap();

        assert_eq!(verdict, ChallengeVerdict::Failed);
    }

    /// A puzzle sealed under another root key fails verification even with a solution.
    #[tokio::test]
    async fn a_forged_puzzle_fails() {
        let other = Puzzles::new(
            &RootSecret::parse(&"ef".repeat(32)).unwrap(),
            PuzzleSettings {
                difficulty_bits: 8,
                lifetime: Duration::from_secs(120),
            },
            Arc::new(MemoryState::new(10)),
        );
        let proof = solve(&other.issue(Fact::Known(&ann())).unwrap());

        let verdict = puzzles().verify(&proof, Fact::Known(&ann())).await.unwrap();

        assert_eq!(verdict, ChallengeVerdict::Failed);
    }

    /// A solved puzzle cannot be verified from a different client address.
    #[tokio::test]
    async fn a_puzzle_from_another_address_fails() {
        let puzzles = puzzles();
        let proof = solve(&puzzles.issue(Fact::Known(&ann())).unwrap());
        let other = IpAddress::new("198.51.100.9").unwrap();

        let verdict = puzzles.verify(&proof, Fact::Known(&other)).await.unwrap();

        assert_eq!(verdict, ChallengeVerdict::Failed);
    }

    /// A solution to a four-bit puzzle fails after the required difficulty rises to twelve bits.
    #[tokio::test]
    async fn a_puzzle_easier_than_the_deployment_asks_fails() {
        let easy = puzzles_at(4, Duration::from_secs(120));
        let proof = solve(&easy.issue(Fact::Known(&ann())).unwrap());
        let harder = puzzles_at(12, Duration::from_secs(120));

        let verdict = harder.verify(&proof, Fact::Known(&ann())).await.unwrap();

        assert_eq!(verdict, ChallengeVerdict::Failed);
    }
}
