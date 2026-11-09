//! Spots two agents meeting at the same upstream path.
//!
//! Channels cover the exchanges ianua can refuse. It cannot refuse a path
//! that two agents may each reach. If one writes there and the other reads,
//! they can pass messages. Each request is allowed, so the pattern is the
//! signal. Two agents touching the same path within a short time, at least
//! one of them writing, have met there.
//!
//! The rule has no I/O. Given the recent touches on a path and a new touch,
//! it says which agents the new touch meets for the first time. A meeting
//! already reported is not reported again while it stays recent.

use std::collections::HashSet;

use crate::types::{ActionClass, AgentId, CanonicalPath, HttpMethod};

/// How many collections above a path still count as the same place.
const MEETING_DEPTH: usize = 3;

/// Whether a request could leave something behind for the next reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchKind {
    /// A request that only reads.
    Read,
    /// A request that may change what the next reader sees.
    Write,
}

impl TouchKind {
    /// The kind of a request with this HTTP method.
    ///
    /// Only `GET`, `HEAD` and `OPTIONS` read. Anything else may write. A
    /// method the proxy does not know has no [`HttpMethod`], and the caller
    /// counts it as a write.
    #[must_use]
    pub fn of_method(method: HttpMethod) -> Self {
        if method.is_safe() {
            return Self::Read;
        }
        Self::Write
    }

    /// The kind of a request with this HTTP method, to a route the proxy
    /// classed as `class`.
    ///
    /// A `GET` still writes when the route says it does. Some upstreams
    /// change state on a `GET`.
    #[must_use]
    pub fn of_action(method: HttpMethod, class: ActionClass) -> Self {
        match (Self::of_method(method), class) {
            (Self::Read, ActionClass::Read) => Self::Read,
            _ => Self::Write,
        }
    }

    /// The stored form.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }

    /// Whether either of two touches writes, so data could pass between them.
    #[must_use]
    pub fn could_pass(self, other: Self) -> bool {
        self == Self::Write || other == Self::Write
    }
}

/// One agent's request to a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Touch {
    /// The identity responsible for this access to the path.
    pub agent: AgentId,
    /// Whether it read or may have written.
    pub kind: TouchKind,
}

/// Records the canonical path and up to `MEETING_DEPTH` ancestor collections.
/// With [`places_met`], writing an item meets a collection read; sibling writes do not.
/// Equivalent encoded paths must be canonicalized or refused before calling.
/// Case is ignored to avoid missing meetings on case-insensitive upstreams.
#[must_use]
pub fn places_touched(path: &CanonicalPath) -> Vec<String> {
    let path = place(path);
    let mut places = vec![path.clone()];
    places.extend(ancestors(&path).map(|ancestor| under(&ancestor)));
    places
}

/// Where to look for earlier touches that meet a touch on `path`.
///
/// That is the path itself, anything under it, and each collection above it.
/// Places are spelled as [`places_touched`] spells them.
#[must_use]
pub fn places_met(path: &CanonicalPath) -> Vec<String> {
    let path = place(path);
    let mut places = vec![path.clone(), under(&path)];
    places.extend(ancestors(&path));
    places
}

/// The place `path` names, in lower case.
fn place(path: &CanonicalPath) -> String {
    path.as_str().to_lowercase()
}

fn under(place: &str) -> String {
    format!("{}/*", place.trim_end_matches('/'))
}

fn ancestors(path: &str) -> impl Iterator<Item = String> + '_ {
    std::iter::successors(parent(path), |p| parent(p))
        .take(MEETING_DEPTH)
        .map(str::to_owned)
}

fn parent(path: &str) -> Option<&str> {
    let (parent, _) = path.rsplit_once('/')?;
    if parent.is_empty() {
        return None;
    }
    Some(parent)
}

/// The agents `new` meets for the first time at this path.
///
/// `earlier` holds the recent touches already there. The agents come back in
/// the order they first touched the path. Empty when it meets nobody new.
#[must_use]
pub fn newly_met(earlier: &[Touch], new: &Touch) -> Vec<AgentId> {
    let met_before = partners(earlier, new.agent);
    let mut met = Vec::new();
    for other in earlier {
        let meets = other.agent != new.agent && other.kind.could_pass(new.kind);
        if meets && !met_before.contains(&other.agent) && !met.contains(&other.agent) {
            met.push(other.agent);
        }
    }
    met
}

/// Every agent `agent` had already met among `touches`.
fn partners(touches: &[Touch], agent: AgentId) -> HashSet<AgentId> {
    let own: Vec<&Touch> = touches.iter().filter(|t| t.agent == agent).collect();
    touches
        .iter()
        .filter(|other| other.agent != agent)
        .filter(|other| own.iter().any(|mine| mine.kind.could_pass(other.kind)))
        .map(|other| other.agent)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(agent: AgentId, kind: TouchKind) -> Touch {
        Touch { agent, kind }
    }

    fn meets(written: &str, read: &str) -> bool {
        let touched = places_touched(&CanonicalPath::new(written).unwrap());
        places_met(&CanonicalPath::new(read).unwrap())
            .iter()
            .any(|place| touched.contains(place))
    }

    /// Repeated slashes and percent-encoded digits resolve to the same place
    /// as the plain path, so neither spelling hides a meeting.
    #[test]
    fn other_spellings_of_one_path_meet() {
        assert!(meets("/board//42/", "/board/42"));
        assert!(meets("/board/%34%32", "/board/42"));
    }

    /// A write and read differing only in path letter case still meet,
    /// covering upstreams whose paths ignore case.
    #[test]
    fn a_path_spelled_in_other_letter_case_meets() {
        assert!(meets("/Board/42", "/board/42"));
    }

    /// The root `/` is one place, and touching it meets nothing above it.
    #[test]
    fn the_root_is_its_own_place() {
        let root = CanonicalPath::root();

        assert_eq!(places_touched(&root), ["/"]);
        assert!(meets("/", "/"));
    }

    /// One agent writes `/board/42`, or a reply three levels down. Another
    /// lists `/board/`. They meet, because the lister sees what was written.
    #[test]
    fn writing_an_item_meets_listing_its_collection() {
        assert!(meets("/board/42", "/board/"));
        assert!(meets("/board/42/replies/7", "/board"));
    }

    /// One agent touches `/board` and another touches `/board/42`. The
    /// meeting is found whichever of the two paths came first.
    #[test]
    fn listing_a_collection_meets_writing_an_item_in_it() {
        assert!(meets("/board", "/board/42"));
    }

    /// One agent works on `/orders/1` and another on `/orders/2`. They do not
    /// meet, because each working on its own record is ordinary API use.
    #[test]
    fn sibling_items_do_not_meet() {
        assert!(!meets("/orders/1", "/orders/2"));
    }

    /// `/board/1` and `/board/1/` are the same place. A trailing slash does
    /// not hide a meeting.
    #[test]
    fn the_same_path_meets() {
        assert!(meets("/board/1", "/board/1/"));
    }

    /// A `GET` to a route the proxy classes as writing counts as a write. The
    /// same `GET` to a read route stays a read.
    #[test]
    fn a_read_on_a_route_that_writes_is_a_write() {
        assert_eq!(
            TouchKind::of_action(HttpMethod::Get, ActionClass::Write),
            TouchKind::Write
        );
        assert_eq!(
            TouchKind::of_action(HttpMethod::Get, ActionClass::Read),
            TouchKind::Read
        );
    }

    /// The whole table: a touch reads only when a safe method meets a route
    /// classed as reading. Any other method on a read route, and any method
    /// on a route of any other class, may write.
    #[test]
    fn a_touch_reads_only_by_a_safe_method_on_a_read_route() {
        let cases = [
            (HttpMethod::Get, ActionClass::Read, TouchKind::Read),
            (HttpMethod::Head, ActionClass::Read, TouchKind::Read),
            (HttpMethod::Options, ActionClass::Read, TouchKind::Read),
            (HttpMethod::Post, ActionClass::Read, TouchKind::Write),
            (HttpMethod::Put, ActionClass::Read, TouchKind::Write),
            (HttpMethod::Patch, ActionClass::Read, TouchKind::Write),
            (HttpMethod::Delete, ActionClass::Read, TouchKind::Write),
            (HttpMethod::Any, ActionClass::Read, TouchKind::Write),
            (HttpMethod::Get, ActionClass::Write, TouchKind::Write),
            (HttpMethod::Head, ActionClass::Delete, TouchKind::Write),
            (
                HttpMethod::Options,
                ActionClass::Configure,
                TouchKind::Write,
            ),
            (HttpMethod::Get, ActionClass::Communicate, TouchKind::Write),
            (HttpMethod::Post, ActionClass::Financial, TouchKind::Write),
            (HttpMethod::Get, ActionClass::Admin, TouchKind::Write),
        ];

        for (method, class, kind) in cases {
            assert_eq!(
                TouchKind::of_action(method, class),
                kind,
                "{method:?} on a {class:?} route"
            );
        }
    }

    /// `GET`, `HEAD` and `OPTIONS` read. `POST`, `PUT`, `PATCH`, `DELETE`
    /// and the route wildcard count as writes.
    #[test]
    fn only_safe_methods_read() {
        for method in [HttpMethod::Get, HttpMethod::Head, HttpMethod::Options] {
            assert_eq!(TouchKind::of_method(method), TouchKind::Read, "{method:?}");
        }
        for method in [
            HttpMethod::Post,
            HttpMethod::Put,
            HttpMethod::Patch,
            HttpMethod::Delete,
            HttpMethod::Any,
        ] {
            assert_eq!(TouchKind::of_method(method), TouchKind::Write, "{method:?}");
        }
    }

    /// One agent wrote a path, then another reads it. The reader meets the
    /// writer.
    #[test]
    fn a_reader_meets_an_earlier_writer() {
        let (writer, reader) = (AgentId::new(), AgentId::new());

        let met = newly_met(
            &[touch(writer, TouchKind::Write)],
            &touch(reader, TouchKind::Read),
        );

        assert_eq!(met, [writer]);
    }

    /// One agent read a path, then another writes it. The writer meets the
    /// reader, since the reader may come back for what was written.
    #[test]
    fn a_writer_meets_an_earlier_reader() {
        let (reader, writer) = (AgentId::new(), AgentId::new());

        let met = newly_met(
            &[touch(reader, TouchKind::Read)],
            &touch(writer, TouchKind::Write),
        );

        assert_eq!(met, [reader]);
    }

    /// Two agents both only read a path. Nobody left anything behind, so no
    /// meeting is reported.
    #[test]
    fn readers_alone_never_meet() {
        let (a, b) = (AgentId::new(), AgentId::new());

        let met = newly_met(&[touch(a, TouchKind::Read)], &touch(b, TouchKind::Read));

        assert!(met.is_empty());
    }

    /// An agent writes a path and then reads it back. It meets nobody.
    #[test]
    fn an_agent_does_not_meet_itself() {
        let agent = AgentId::new();

        let met = newly_met(
            &[touch(agent, TouchKind::Write)],
            &touch(agent, TouchKind::Read),
        );

        assert!(met.is_empty());
    }

    /// A reader has already met a writer on a path and reads it again. No new
    /// meeting is reported while the old one stays recent.
    #[test]
    fn a_meeting_already_made_is_not_made_again() {
        let (writer, reader) = (AgentId::new(), AgentId::new());
        let earlier = [
            touch(writer, TouchKind::Write),
            touch(reader, TouchKind::Read),
        ];

        let met = newly_met(&earlier, &touch(reader, TouchKind::Read));

        assert!(met.is_empty());
    }

    /// A writer and a reader already met on a path. A third agent then reads
    /// it and meets the writer only, not the other reader.
    #[test]
    fn a_third_agent_is_a_new_meeting() {
        let (writer, reader, third) = (AgentId::new(), AgentId::new(), AgentId::new());
        let earlier = [
            touch(writer, TouchKind::Write),
            touch(reader, TouchKind::Read),
        ];

        let met = newly_met(&earlier, &touch(third, TouchKind::Read));

        assert_eq!(met, [writer]);
    }

    /// Two agents have only read a path. When one of them then writes it, it
    /// meets the other for the first time.
    #[test]
    fn starting_to_write_meets_the_readers_already_there() {
        let (a, b) = (AgentId::new(), AgentId::new());
        let earlier = [touch(a, TouchKind::Read), touch(b, TouchKind::Read)];

        let met = newly_met(&earlier, &touch(a, TouchKind::Write));

        assert_eq!(met, [b]);
    }
}
