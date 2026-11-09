//! Which of the backends taking traffic gets the next request.
//!
//! Pure choices over what the pool hands in: the backends' weights, their
//! requests in flight, or their addresses and a key to pin by. Each answers
//! with an index into what it was given, or nothing when given nothing.

/// The next backend in turn, each taken as often as its weight says.
///
/// `turn` is a counter the caller advances once per request.
pub(super) fn weighted_turn(weights: &[u32], turn: usize) -> Option<usize> {
    let total: u64 = weights.iter().map(|weight| u64::from(*weight)).sum();
    if total == 0 {
        return None;
    }
    let tick = u64::try_from(turn).unwrap_or(u64::MAX) % total;
    let mut reached = 0_u64;
    weights.iter().position(|weight| {
        reached = reached.saturating_add(u64::from(*weight));
        tick < reached
    })
}

/// The backend with the fewest requests in flight. Ties are broken from
/// `turn` on, so equally busy backends take turns.
pub(super) fn least_busy(in_flight: &[usize], turn: usize) -> Option<usize> {
    let len = in_flight.len();
    (0..len)
        .map(|offset| turn.wrapping_add(offset) % len)
        .min_by_key(|index| in_flight.get(*index).copied().unwrap_or(usize::MAX))
}

/// The backend `key` is pinned to: the one scoring highest for it, each
/// score scaled by weight.
///
/// This is rendezvous hashing. The same key lands on the same backend for
/// as long as that backend takes traffic, and when a backend comes or goes
/// only the keys that were on it move, so a cache on each backend stays
/// warm.
pub(super) fn pinned<'a>(
    backends: impl Iterator<Item = (&'a str, u32)>,
    key: &str,
) -> Option<usize> {
    backends
        .enumerate()
        .map(|(index, (address, weight))| (index, score(key, address, weight)))
        .max_by(|a, b| a.1.total_cmp(&b.1))
        .map(|(index, _)| index)
}

/// How strongly `key` draws to `address`, scaled by `weight`.
fn score(key: &str, address: &str, weight: u32) -> f64 {
    let seeded = fnv1a(address.as_bytes(), FNV_OFFSET);
    let separated = fnv1a(&[0xff], seeded);
    let hash = mix(fnv1a(key.as_bytes(), separated));
    let unit = ((hash >> 11) as f64 + 0.5) / (1_u64 << 53) as f64;
    f64::from(weight) / -unit.ln()
}

/// FNV-1a's starting value.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

/// FNV-1a over `bytes`, continuing from `hash`.
fn fnv1a(bytes: &[u8], hash: u64) -> u64 {
    bytes.iter().fold(hash, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// Spreads a hash's bits, so keys that differ in one byte score apart.
fn mix(hash: u64) -> u64 {
    let hash = (hash ^ (hash >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    let hash = (hash ^ (hash >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    hash ^ (hash >> 31)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn picks(weights: &[u32], rounds: usize) -> Vec<usize> {
        let mut counts = vec![0; weights.len()];
        for turn in 0..rounds {
            counts[weighted_turn(weights, turn).unwrap()] += 1;
        }
        counts
    }

    #[test]
    fn equal_weights_take_equal_turns() {
        assert_eq!(picks(&[1, 1, 1], 300), vec![100, 100, 100]);
    }

    /// A service at weight 100 beside a canary at 10 sends the canary one
    /// request in eleven.
    #[test]
    fn a_heavier_backend_takes_more_turns() {
        assert_eq!(picks(&[100, 10], 1_100), vec![1_000, 100]);
    }

    #[test]
    fn nothing_to_pick_from_picks_nothing() {
        assert_eq!(weighted_turn(&[], 3), None);
        assert_eq!(least_busy(&[], 3), None);
        assert_eq!(pinned(std::iter::empty(), "ann"), None);
    }

    #[test]
    fn the_least_busy_backend_takes_the_request() {
        assert_eq!(least_busy(&[4, 1, 3], 0), Some(1));
    }

    #[test]
    fn equally_busy_backends_take_turns() {
        assert_eq!(least_busy(&[2, 2], 0), Some(0));
        assert_eq!(least_busy(&[2, 2], 1), Some(1));
    }

    fn backends<'a>(addresses: &'a [&'a str]) -> impl Iterator<Item = (&'a str, u32)> + 'a {
        addresses.iter().map(|address| (*address, 1))
    }

    #[test]
    fn a_key_stays_on_its_backend() {
        let addresses = ["http://a:80", "http://b:80", "http://c:80"];

        let first = pinned(backends(&addresses), "user-123");

        for _ in 0..20 {
            assert_eq!(pinned(backends(&addresses), "user-123"), first);
        }
    }

    #[test]
    fn keys_spread_across_backends() {
        let addresses = ["http://a:80", "http://b:80", "http://c:80"];

        let mut seen = std::collections::HashSet::new();
        for user in 0..100 {
            seen.insert(pinned(backends(&addresses), &format!("user-{user}")));
        }

        assert_eq!(seen.len(), 3);
    }

    proptest! {
        /// When a backend leaves, only the keys that were on it move.
        #[test]
        fn a_leaving_backend_moves_only_its_own_keys(
            key in "[a-z0-9]{1,24}",
            leaving in 0_usize..4,
        ) {
            let all = ["http://a:80", "http://b:80", "http://c:80", "http://d:80"];
            let staying: Vec<&str> = all
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != leaving)
                .map(|(_, address)| *address)
                .collect();

            let before = all[pinned(backends(&all), &key).unwrap()];
            let after = staying[pinned(backends(&staying), &key).unwrap()];

            prop_assert!(before == all[leaving] || before == after);
        }

        #[test]
        fn a_turn_always_lands_on_a_backend(
            weights in prop::collection::vec(1_u32..1_000, 1..8),
            turn in any::<usize>(),
        ) {
            let picked = weighted_turn(&weights, turn);

            prop_assert!(picked.is_some_and(|index| index < weights.len()));
        }
    }
}
