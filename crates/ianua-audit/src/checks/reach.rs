//! Domain to app reach: what the domain offers that the app never uses.
//!
//! - A public creator or change of an aggregate no use case calls, and no
//!   other domain file calls on its behalf.
//! - A public `ensure_*` rule nothing in the domain or the app calls.
//! - A caller proof the app never holds: no use case names a type carrying
//!   it (the proof, or a domain type implementing it), and none calls a
//!   domain function handing one out.
//! - An event nothing raises: no domain change builds it, and no listed
//!   observation that anything calls (see [`crate::model::raising`]). One
//!   only an adapter builds is reported apart.
//!
//! Reach is read by name. A change (`&mut self`) counts as reached when the
//! app calls a method of that name on anything; a creator when the app
//! writes `Owner::name`, or the same through an alias of the owner.

use crate::finding::{Check, Finding};
use crate::model::domain::{Behaviour, BehaviourKind, Event, Proof};
use crate::model::raising::{RaiseKind, Raiser};
use crate::model::{Model, Reach};

/// Every reach finding.
pub(crate) fn run(model: &Model) -> Vec<Finding> {
    let mut found = unreached_behaviours(model);
    found.extend(unreached_ensure_rules(model));
    found.extend(unreached_proofs(model));
    found.extend(unraised_events(model));
    found
}

fn unreached_behaviours(model: &Model) -> Vec<Finding> {
    model
        .domain
        .behaviours
        .iter()
        .filter(|behaviour| !app_reaches(model, behaviour))
        .filter(|behaviour| !other_domain_file_reaches(model, behaviour))
        .map(|behaviour| {
            Finding::new(
                Check::UnreachedBehaviour,
                behaviour.place.clone(),
                behaviour.subject(),
                format!(
                    "no use case calls `{}` ({}): the domain offers it and nothing drives it",
                    behaviour.subject(),
                    behaviour.kind.as_str()
                ),
            )
        })
        .collect()
}

/// Whether the app calls `behaviour`.
pub(crate) fn app_reaches(model: &Model, behaviour: &Behaviour) -> bool {
    reaches(model, &model.app_reach, behaviour)
}

/// Whether `reach` calls `behaviour`. A creator counts when written through
/// the owner or any alias of it, such as `OrgVerificationToken::issue` for
/// `OrgToken::issue`.
fn reaches(model: &Model, reach: &Reach, behaviour: &Behaviour) -> bool {
    match behaviour.kind {
        BehaviourKind::Change => reach.methods.contains(&behaviour.name),
        BehaviourKind::Create => {
            names_of(model, &behaviour.owner).any(|owner| reach.names_pair(owner, &behaviour.name))
        }
    }
}

/// `owner` and every alias standing for it.
fn names_of<'a>(model: &'a Model, owner: &'a str) -> impl Iterator<Item = &'a str> {
    let aliases = model
        .domain
        .aliases
        .iter()
        .filter(move |(_, target)| target.as_str() == owner)
        .map(|(alias, _)| alias.as_str());
    std::iter::once(owner).chain(aliases)
}

fn other_domain_file_reaches(model: &Model, behaviour: &Behaviour) -> bool {
    model
        .domain_files
        .iter()
        .filter(|(path, _)| *path != behaviour.place.file)
        .any(|(_, reach)| reaches(model, reach, behaviour))
}

fn unreached_ensure_rules(model: &Model) -> Vec<Finding> {
    model
        .domain
        .ensure_rules
        .iter()
        .filter(|rule| !model.domain_reach.calls(&rule.name) && !model.app_reach.calls(&rule.name))
        .map(|rule| {
            Finding::new(
                Check::UnreachedEnsure,
                rule.place.clone(),
                rule.subject(),
                format!(
                    "nothing calls `{}`: the rule is never enforced",
                    rule.subject()
                ),
            )
        })
        .collect()
}

fn unreached_proofs(model: &Model) -> Vec<Finding> {
    model
        .domain
        .proofs
        .iter()
        .filter(|proof| !app_holds(model, proof))
        .filter_map(|proof| {
            Some(Finding::new(
                Check::UnreachedProof,
                proof.place.clone()?,
                proof.name.clone(),
                format!(
                    "the app never names `{}`: no use case builds it or passes it on",
                    proof.name
                ),
            ))
        })
        .collect()
}

/// Whether the app holds `proof`: it names a type carrying it, or calls a
/// domain function handing one out and passes the value on unnamed.
fn app_holds(model: &Model, proof: &Proof) -> bool {
    let reach = &model.app_reach;
    proof
        .carriers
        .iter()
        .any(|carrier| reach.idents.contains(carrier))
        || proof.makers.iter().any(|maker| match &maker.owner {
            Some(owner) => {
                reach.names_pair(owner, &maker.name) || reach.methods.contains(&maker.name)
            }
            None => reach.functions.contains(&maker.name),
        })
}

/// Whether a raiser records its event when the code runs: a change does,
/// since whether a use case calls it is [`unreached_behaviours`]' question,
/// and an observation does once anything calls it.
fn raises_when_run(model: &Model, raiser: &Raiser) -> bool {
    match raiser.kind {
        RaiseKind::Change => true,
        RaiseKind::Observation => [&model.domain_reach, &model.app_reach, &model.adapter_reach]
            .iter()
            .any(|reach| calls_raiser(reach, raiser)),
    }
}

fn calls_raiser(reach: &Reach, raiser: &Raiser) -> bool {
    match &raiser.owner {
        Some(owner) => {
            reach.names_pair(owner, &raiser.name) || reach.methods.contains(&raiser.name)
        }
        None => reach.functions.contains(&raiser.name),
    }
}

fn unraised_events(model: &Model) -> Vec<Finding> {
    model
        .domain
        .events
        .iter()
        .filter_map(|event| {
            let raisers = model.domain.raising.raisers_of(&event.name);
            if raisers.iter().any(|raiser| raises_when_run(model, raiser)) {
                return None;
            }
            Some(unraised(model, event, raisers))
        })
        .collect()
}

/// The finding for an event no running code raises. `uncalled` are the
/// observations that would build it if anything called them.
fn unraised(model: &Model, event: &Event, uncalled: &[Raiser]) -> Finding {
    let name = &event.name;
    let observations = uncalled
        .iter()
        .map(|raiser| format!("`{}`", raiser.subject()))
        .collect::<Vec<_>>()
        .join(", ");
    let in_adapter = model.adapter_reach.makes(name);
    let check = match in_adapter {
        true => Check::AdapterRaisedEvent,
        false => Check::UnraisedEvent,
    };
    let message = match (in_adapter, uncalled.is_empty()) {
        (true, true) => format!(
            "`{name}` is built only in an adapter: no domain change or listed observation builds it"
        ),
        (true, false) => format!(
            "`{name}` is built in an adapter rather than through {observations}, which nothing calls"
        ),
        (false, true) => {
            format!("nothing raises `{name}`: no domain change or listed observation builds it")
        }
        (false, false) => format!(
            "nothing raises `{name}`: only {observations} builds it, and nothing calls that"
        ),
    };
    Finding::new(check, event.place.clone(), name.clone(), message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::domain::DomainLists;
    use crate::source::planted::{adapter, app, domain, workspace};

    const TOPIC: &str = r"
        pub struct Topic;
        impl Topic {
            pub fn create(by: &MessagingControl<'_>) -> Result<Self, DomainError> { make() }
            pub fn reconstitute(row: TopicRow) -> Result<Self, DomainError> { make() }
            pub fn archive(&mut self, by: &MessagingControl<'_>) {
                self.ensure_open();
                self.raised.raise(TopicArchived { at: now() });
            }
            pub fn pause(&mut self, by: &MessagingControl<'_>) {}
            pub fn ensure_open(&self) {}
            pub fn ensure_forgotten(&self) {}
        }
        pub struct MessagingControl;
        pub struct SignedIn;
        tenant_event! { TopicArchived => MessagingEvent::TopicArchived }
        tenant_event! { TopicPaused => MessagingEvent::TopicPaused }
        tenant_event! { TopicMoved => MessagingEvent::TopicMoved }
        tenant_event! { AgentActed => AgentsEvent::Acted }
    ";

    const THREATS: &str = r"
        tenant_event! { HoneypotHit => ProxyEvent::HoneypotHit }
        impl HoneypotHit {
            pub fn observed(tenant: TenantId) -> DomainEvent { scoped(tenant, Self { at: now() }) }
        }
        tenant_event! { CanaryLeaked => ProxyEvent::CanaryLeaked }
        impl CanaryLeaked {
            pub fn observed(tenant: TenantId) -> DomainEvent { scoped(tenant, Self { at: now() }) }
        }
        tenant_event! { AgentDenied => AgentsEvent::Denied }
        impl AgentDenied {
            pub fn observed(tenant: TenantId) -> DomainEvent { scoped(tenant, Self { at: now() }) }
        }
    ";

    const USE_CASE: &str = r"
        impl Command for ArchiveUseCase {
            async fn execute(&self) {
                let topic = Topic::create(&MessagingControl::new(&authority))?;
                topic.archive(&control);
                store.save(&tenant, &topic).await?;
                auditor.dispatch_by(&actor, topic.take_events(&tenant)).await?;
                auditor.dispatch(&[moved(TopicMoved { at: now() })]).await
            }
        }
    ";

    fn findings() -> Vec<Finding> {
        let ws = workspace(vec![
            domain("domains/messaging/topic.rs", TOPIC),
            domain("domains/proxy/events/threats.rs", THREATS),
            app("use_cases/messaging/archive_topic.rs", USE_CASE),
            adapter(
                "ianua-server",
                "worker.rs",
                "fn f() { emit(AgentActed { at: now() }); }",
            ),
            adapter(
                "ianua-zero",
                "handler.rs",
                "use events::HoneypotHit as Hit;
                 fn f() { let event = Hit::observed(tenant); }
                 fn g() { emit(DomainEvent::tenant(Box::new(AgentDenied { at: now() }))); }",
            ),
        ]);
        let lists = DomainLists {
            proofs: vec!["SignedIn".to_owned()],
            observations: ["HoneypotHit", "CanaryLeaked", "AgentDenied"]
                .iter()
                .map(|owner| ((*owner).to_owned(), "observed".to_owned()))
                .collect(),
            ..DomainLists::default()
        };
        run(&Model::build(&ws, &lists))
    }

    fn subjects(found: &[Finding], check: Check) -> Vec<String> {
        found
            .iter()
            .filter(|finding| finding.check == check)
            .map(|finding| finding.subject.clone())
            .collect()
    }

    #[test]
    fn a_change_no_use_case_calls_is_unreached() {
        let found = findings();

        assert_eq!(
            subjects(&found, Check::UnreachedBehaviour),
            ["Topic::pause"]
        );
    }

    #[test]
    fn an_ensure_rule_nothing_calls_is_unreached() {
        let found = findings();

        assert_eq!(
            subjects(&found, Check::UnreachedEnsure),
            ["Topic::ensure_forgotten"]
        );
    }

    #[test]
    fn a_proof_the_app_never_names_is_unreached() {
        let found = findings();

        assert_eq!(subjects(&found, Check::UnreachedProof), ["SignedIn"]);
    }

    const HELD_UNNAMED: &str = r"
        pub struct Token<P>(P);
        pub type ResetToken = Token<Reset>;
        impl<P> Token<P> {
            pub fn issue(new: NewToken) -> Result<Self, DomainError> { make() }
            pub fn reconstitute(row: TokenRow) -> Result<Self, DomainError> { make() }
        }
        pub trait Keeper: Sealed {}
        pub struct SignedIn;
        impl Keeper for SignedIn {}
        pub struct Released;
        pub struct Approval;
        impl Approval {
            pub fn release(&mut self) -> Result<Released, DomainError> { make() }
        }
    ";

    const PASSES_ON: &str = r"
        async fn execute(&self) {
            let link = ResetToken::issue(new)?;
            let person: SignedIn = signed_in()?;
            let released = approval.release()?;
            run.resume(&released);
        }
    ";

    fn held_unnamed() -> Vec<Finding> {
        let ws = workspace(vec![
            domain("domains/access/token.rs", HELD_UNNAMED),
            app("use_cases/access/reset.rs", PASSES_ON),
        ]);
        let lists = DomainLists {
            proofs: ["Keeper", "Released"].map(str::to_owned).to_vec(),
            ..DomainLists::default()
        };
        run(&Model::build(&ws, &lists))
    }

    /// The app issues a reset link through the alias `ResetToken`, which
    /// stands for `Token`: the creator is reached.
    #[test]
    fn a_creator_called_through_an_alias_is_reached() {
        let found = held_unnamed();

        assert!(subjects(&found, Check::UnreachedBehaviour).is_empty());
    }

    /// The app never writes `Keeper` or `Released`, but holds a `SignedIn`,
    /// which implements `Keeper`, and passes on the `Released` that
    /// `Approval::release` hands out. Both proofs are held.
    #[test]
    fn a_proof_held_through_an_implementor_or_a_maker_is_reached() {
        let found = held_unnamed();

        assert!(subjects(&found, Check::UnreachedProof).is_empty());
    }

    #[test]
    fn an_event_an_adapter_writes_out_past_its_observation_is_flagged() {
        let found = findings();

        let denied = found
            .iter()
            .find(|finding| finding.subject == "AgentDenied")
            .unwrap();

        assert_eq!(denied.check, Check::AdapterRaisedEvent);
        assert!(
            denied
                .message
                .contains("rather than through `AgentDenied::observed`")
        );
    }

    #[test]
    fn an_event_a_mutator_raises_or_a_called_observation_builds_is_raised() {
        let found = findings();

        let unraised = subjects(&found, Check::UnraisedEvent);

        assert!(!unraised.contains(&"TopicArchived".to_owned()));
        assert!(!unraised.contains(&"HoneypotHit".to_owned()));
    }

    #[test]
    fn an_event_only_a_use_case_builds_is_unraised() {
        let found = findings();

        assert!(subjects(&found, Check::UnraisedEvent).contains(&"TopicMoved".to_owned()));
    }

    #[test]
    fn an_event_whose_observation_nothing_calls_is_unraised_and_says_so() {
        let found = findings();

        let canary = found
            .iter()
            .find(|finding| finding.subject == "CanaryLeaked")
            .unwrap();

        assert_eq!(canary.check, Check::UnraisedEvent);
        assert!(
            canary
                .message
                .contains("only `CanaryLeaked::observed` builds it")
        );
    }

    #[test]
    fn an_event_nothing_builds_is_unraised_and_one_only_an_adapter_builds_is_flagged() {
        let found = findings();

        assert_eq!(
            subjects(&found, Check::UnraisedEvent),
            ["CanaryLeaked", "TopicMoved", "TopicPaused"]
        );
        assert_eq!(
            subjects(&found, Check::AdapterRaisedEvent),
            ["AgentActed", "AgentDenied"]
        );
    }
}
