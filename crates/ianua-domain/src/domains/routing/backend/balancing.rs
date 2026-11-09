//! How the gateway picks one backend of several for a request.

/// How the gateway picks one of a service's backends for each request.
///
/// It works with the upstream's sticky session key, which says what to pin
/// a request by. Each way of picking says whether it needs one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum LoadBalancing {
    /// In turn, each backend as often as its weight says. With a sticky
    /// key, a request goes where earlier ones with the same key went.
    #[default]
    RoundRobin,
    /// The backend with the fewest requests in flight. For requests that
    /// take very different times, where taking turns piles slow ones up on
    /// one backend.
    ///
    /// It takes no sticky key: pinning a request to a backend overrides
    /// picking the least busy one.
    LeastConnections,
    /// A hash ring over the sticky key. When a backend comes or goes, only
    /// the keys that were on it move, so a cache on each backend stays warm.
    ///
    /// It needs a sticky key to hash.
    ConsistentHash,
}

/// What a way of picking backends asks of the sticky key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StickyKeyNeed {
    /// A sticky key may be set or not.
    Either,
    /// A sticky key must be set.
    Required,
    /// No sticky key may be set.
    Refused,
}

impl LoadBalancing {
    /// What this way of picking asks of the sticky key.
    #[must_use]
    pub fn sticky_key(self) -> StickyKeyNeed {
        match self {
            Self::RoundRobin => StickyKeyNeed::Either,
            Self::LeastConnections => StickyKeyNeed::Refused,
            Self::ConsistentHash => StickyKeyNeed::Required,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Taking turns works with or without a sticky key. Least connections
    /// refuses one, and consistent hashing needs one.
    #[test]
    fn each_way_of_picking_says_what_it_asks_of_the_sticky_key() {
        assert_eq!(
            LoadBalancing::RoundRobin.sticky_key(),
            StickyKeyNeed::Either
        );
        assert_eq!(
            LoadBalancing::LeastConnections.sticky_key(),
            StickyKeyNeed::Refused
        );
        assert_eq!(
            LoadBalancing::ConsistentHash.sticky_key(),
            StickyKeyNeed::Required
        );
    }

    /// A service that says nothing takes turns.
    #[test]
    fn backends_take_turns_by_default() {
        assert_eq!(LoadBalancing::default(), LoadBalancing::RoundRobin);
    }
}
