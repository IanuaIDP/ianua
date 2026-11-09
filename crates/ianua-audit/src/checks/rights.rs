//! Rights: changes of stored aggregates a use case calls that check none.
//!
//! The domain decides who may change what: a public creator or change of
//! a stored aggregate takes a caller proof (a type holding a right, such
//! as a `*Control`), or checks a right by a call (`ensure_may`,
//! `ensure_holds`, `ensure_controls`, an `ensure_*` handed a right), or is
//! listed in the domain conventions' `UNCALLED_CHANGES` as nobody's. One
//! that a use case calls and does none of these lets any caller of that
//! use case make the change, whatever the app checks around it.
//!
//! The proofs and the list are read from the conventions' `lists.rs`, as
//! the conventions hold them. A finding must be true, so a change whose
//! rights may be checked beyond what the reader followed (a helper more
//! than two calls away, or a method of another file called on a value of
//! unknown type) is not reported, and is counted instead.

use crate::finding::{Check, Finding, Found, Unsaid};
use crate::model::Model;
use crate::model::facts::{CallerRef, ChangeFacts, Facts};
use crate::source::Place;

/// Every rights finding.
pub(crate) fn run(model: &Model, facts: &Facts) -> Found {
    let mut found = Found::default();
    for change in facts.changes.iter().filter(|change| suspect(model, change)) {
        if model
            .domain
            .raising
            .rights_unread(Some(&change.owner), &change.name)
        {
            found.leave_unsaid(Unsaid::new(
                Check::UncheckedChange,
                change.subject(),
                change.place.clone(),
                "a right may be checked in a helper the reader does not follow: one more than two calls away, or a method of another file on a value of unknown type",
            ));
            continue;
        }
        found.findings.push(finding(change));
    }
    found
}

/// Whether `change` is of a stored aggregate, called by a use case, takes
/// no proof, checks no right and is not listed as nobody's.
fn suspect(model: &Model, change: &ChangeFacts) -> bool {
    let stored = model
        .domain
        .aggregates
        .iter()
        .any(|aggregate| aggregate.name == change.owner && aggregate.stored);
    let listed = model
        .domain
        .uncalled
        .contains(&(change.owner.clone(), change.name.clone()));
    stored
        && !listed
        && !change.callers.is_empty()
        && change.takes.is_empty()
        && change.rights.is_empty()
}

fn finding(change: &ChangeFacts) -> Finding {
    let changed = location(&change.place);
    let mut detail = vec![format!("change: {changed}  {}", change.subject())];
    detail.extend(change.callers.iter().map(caller_line));
    detail.push(
        "why: the domain is where a right is decided; a change that asks for none can be made by whoever reaches a use case calling it, and each new caller must remember the check itself".to_owned(),
    );
    detail.push(format!(
        "fix: take the context's control or a caller proof and check the right inside (`control.ensure_may(..)`), or list `{}` in UNCALLED_CHANGES with why no person makes it",
        change.subject()
    ));
    Finding::new(
        Check::UncheckedChange,
        change.place.clone(),
        change.subject(),
        unchecked_message(change),
    )
    .with_detail(detail)
}

/// Why `change`, which use cases call, needs a right it does not check.
fn unchecked_message(change: &ChangeFacts) -> String {
    let verb = match change.kind {
        "create" => "creates",
        _ => "changes",
    };
    let first = &change.callers[0];
    format!(
        "`{}` {verb} a stored `{}` that `{}` ({}) calls, yet it takes no caller proof and checks no right",
        change.subject(),
        change.owner,
        first.use_case,
        first.context
    )
}

/// Where `caller` calls the change, and through what.
fn caller_line(caller: &CallerRef) -> String {
    let via = (caller.via.as_deref()).map_or_else(String::new, |via| format!(" via {via}"));
    format!(
        "caller: {}  {} ({}){via}",
        location(&caller.place),
        caller.use_case,
        caller.context
    )
}

fn location(place: &Place) -> String {
    format!("{}:{}", place.file, place.line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::domain::DomainLists;
    use crate::source::planted::{app, domain, workspace};

    const ARCHIVE: &str = r"
        use crate::use_cases::messaging::lookup::topic;
        pub struct ArchivePorts { pub topics: Arc<dyn TopicStore> }
        pub struct ArchiveUseCase { ports: ArchivePorts }
        impl Command for ArchiveUseCase {
            async fn execute(&self, caller: &CallerContext, auditor: &RequestAuditor, id: TopicId) -> Result<(), AppError> {
                let mut found: Topic = self.ports.topics.find(&id).await.or_internal()?;
                found.archive();
                self.ports.topics.save(&found).await.or_internal()
            }
        }
    ";

    const PORTS: &str = r"
        pub trait TopicStore {
            async fn find(&self, id: &TopicId) -> Result<Topic, DomainError>;
            async fn save(&self, topic: &Topic) -> Result<(), DomainError>;
        }
    ";

    fn found(topic: &str, uncalled: &[(&str, &str)]) -> Found {
        let ws = workspace(vec![
            domain("domains/messaging/topic.rs", topic),
            app("ports/messaging.rs", PORTS),
            app("use_cases/messaging/archive.rs", ARCHIVE),
        ]);
        let lists = DomainLists {
            proofs: vec!["MessagingControl".to_owned()],
            uncalled: uncalled
                .iter()
                .map(|(owner, name)| ((*owner).to_owned(), (*name).to_owned()))
                .collect(),
            ..DomainLists::default()
        };
        let model = Model::build(&ws, &lists);
        let facts = Facts::build(&ws, &model);
        run(&model, &facts)
    }

    const UNCHECKED: &str = r"
        pub struct Topic { archived: bool }
        impl Topic {
            pub fn reconstitute(row: TopicRow) -> Result<Self, DomainError> { make() }
            pub fn archive(&mut self) { self.archived = true; }
        }
    ";

    #[test]
    fn a_called_change_that_checks_no_right_is_reported() {
        let found = found(UNCHECKED, &[]);

        let finding = &found.findings[0];
        assert_eq!(finding.subject, "Topic::archive");
        assert_eq!(
            finding.message,
            "`Topic::archive` changes a stored `Topic` that `ArchiveUseCase` (messaging) calls, yet it takes no caller proof and checks no right"
        );
        assert!(
            finding.detail[1]
                .starts_with("caller: crates/ianua-app/src/use_cases/messaging/archive.rs:")
        );
    }

    #[test]
    fn a_change_bound_to_a_proof_or_listed_as_nobodys_stays_quiet() {
        let bound = found(
            r"
            pub struct Topic { archived: bool }
            impl Topic {
                pub fn reconstitute(row: TopicRow) -> Result<Self, DomainError> { make() }
                pub fn archive<C: MessagingControl>(&mut self, by: &C) { self.archived = true; }
            }
            ",
            &[],
        );
        let listed = found(UNCHECKED, &[("Topic", "archive")]);

        assert!(bound.findings.is_empty());
        assert!(listed.findings.is_empty());
        assert!(bound.silenced.is_empty());
    }

    /// The change calls a method of another file on a value of unknown
    /// type; a right may be checked there, so it stays quiet and counts.
    #[test]
    fn a_change_whose_rights_may_lie_beyond_the_reader_keeps_it_quiet() {
        let topic = domain(
            "domains/messaging/topic.rs",
            r"
            pub struct Topic { archived: bool, rules: Rules }
            impl Topic {
                pub fn reconstitute(row: TopicRow) -> Result<Self, DomainError> { make() }
                pub fn archive(&mut self) { self.rules.allow(); self.archived = true; }
            }
            ",
        );
        let rules = domain(
            "domains/messaging/rules.rs",
            "impl Rules { pub fn allow(&self) { self.held.ensure_holds(SystemPermission::Messaging); } }",
        );
        let ws = workspace(vec![
            topic,
            rules,
            app("ports/messaging.rs", PORTS),
            app("use_cases/messaging/archive.rs", ARCHIVE),
        ]);
        let model = Model::build(&ws, &DomainLists::default());
        let facts = Facts::build(&ws, &model);

        let found = run(&model, &facts);

        assert!(found.findings.is_empty());
        assert_eq!(found.silenced.get(&Check::UncheckedChange), Some(&1));
    }
}
