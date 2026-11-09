//! The intent compiler for a deployment with no embeddings endpoint: it
//! reads the action classes from the statement's keywords.
//!
//! A keyword counts only as a whole word of the statement, or as one of its
//! regular forms such as "deleted", "notifies" or "dropping". A keyword
//! inside another word never counts, so "already" never reads as reading,
//! "william" as administering, "payload" as paying or "dropdown" as
//! deleting. Nor does one count where one of the two words before it turns
//! it around, so "never delete" never reads as deleting. Either way a
//! statement only ever reads as less, never as more than it says.

use async_trait::async_trait;
use ianua_app::ports::agents::IntentCompiler;
use ianua_domain::domains::agents::authority::capability::CapabilitySet;
use ianua_domain::domains::agents::authority::intent::{
    CompiledIntent, IntentEnvelope, IntentStatement,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::words::{is_form_of, words_of};
use ianua_domain::types::ActionClass;

use crate::reading::intent::compiled;

/// The words that put a statement in each class. A keyword of two words
/// counts where both stand in a row.
const RULES: &[(ActionClass, &[&str])] = &[
    (
        ActionClass::Delete,
        &[
            "delete",
            "remove",
            "removal",
            "purge",
            "drop",
            "revoke",
            "revocation",
            "cancel",
            "cancellation",
            "deactivate",
            "wipe",
            "erase",
            "erasure",
            "destroy",
            "destruction",
        ],
    ),
    (
        ActionClass::Financial,
        &[
            "pay",
            "paid",
            "payment",
            "payout",
            "refund",
            "charge",
            "invoice",
            "bill",
            "reimburse",
            "reimbursement",
            "transfer",
        ],
    ),
    (
        ActionClass::Admin,
        &[
            "admin",
            "administer",
            "administration",
            "administrator",
            "grant",
            "role",
            "permission",
            "iam",
            "authorize",
            "authorise",
            "authorization",
            "authorisation",
            "access control",
        ],
    ),
    (
        ActionClass::Communicate,
        &[
            "send",
            "sent",
            "notify",
            "notification",
            "email",
            "message",
            "alert",
            "publish",
            "dispatch",
            "reply",
            "respond",
        ],
    ),
    (
        ActionClass::Configure,
        &[
            "config",
            "configure",
            "configuration",
            "setting",
            "enable",
            "disable",
            "provision",
            "deploy",
            "deployment",
            "rotate",
        ],
    ),
    (
        ActionClass::Write,
        &[
            "write",
            "wrote",
            "written",
            "create",
            "update",
            "insert",
            "insertion",
            "modify",
            "modification",
            "edit",
            "book",
            "schedule",
            "submit",
            "submission",
            "reconcile",
            "reconciliation",
            "process",
            "generate",
            "draft",
            "save",
        ],
    ),
    (
        ActionClass::Read,
        &[
            "read",
            "view",
            "list",
            "fetch",
            "summary",
            "summarize",
            "summarise",
            "report",
            "analyze",
            "analyse",
            "analysis",
            "analytics",
            "inspect",
            "inspection",
            "check",
            "monitor",
            "audit",
            "search",
            "query",
            "look",
        ],
    ),
];

/// Reads an intent's classes by keyword. A statement naming none of them
/// gets the read-only floor: the least a well-formed task needs.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeywordIntentCompiler;

#[async_trait]
impl IntentCompiler for KeywordIntentCompiler {
    async fn compile(
        &self,
        intent: &IntentStatement,
        requested: &CapabilitySet,
    ) -> Result<CompiledIntent, DomainError> {
        Ok(compiled(intent, requested, classes_named_in(intent)))
    }
}

/// The words that turn a keyword after them around. `t` is what is left
/// of "don't" and "won't" once the statement is split into words.
const NEGATIONS: &[&str] = &["not", "never", "no", "nor", "without", "avoid", "t"];

/// How many words before a keyword a negation reaches.
const NEGATION_REACH: usize = 2;

/// The classes whose keywords `intent` states, or reading alone when it
/// states none.
fn classes_named_in(intent: &IntentStatement) -> IntentEnvelope {
    let named = classes_stated(&words_of(intent.as_str()));
    if named.is_empty() {
        return IntentEnvelope::new([ActionClass::Read]);
    }
    IntentEnvelope::new(named)
}

/// The classes one of whose keywords `words` state, in the order of
/// [`RULES`].
fn classes_stated(words: &[String]) -> Vec<ActionClass> {
    RULES
        .iter()
        .filter(|(_, keywords)| keywords.iter().any(|keyword| stated(words, keyword)))
        .map(|(class, _)| *class)
        .collect()
}

/// Whether `words` state `keyword`: its words stand there in a row, each
/// whole or in a regular form, and no negation just before turns them
/// around.
fn stated(words: &[String], keyword: &str) -> bool {
    let parts: Vec<&str> = keyword.split(' ').collect();
    (0..words.len()).any(|at| stands_at(words, at, &parts) && !negated(words, at))
}

/// Whether each of `parts` is the word at its place from `at` on.
fn stands_at(words: &[String], at: usize, parts: &[&str]) -> bool {
    words.get(at..).is_some_and(|rest| {
        rest.len() >= parts.len()
            && rest
                .iter()
                .zip(parts)
                .all(|(word, part)| is_form_of(word, part))
    })
}

/// Whether a negation sits among the few words before the one at `at`.
fn negated(words: &[String], at: usize) -> bool {
    words
        .get(at.saturating_sub(NEGATION_REACH)..at)
        .is_some_and(|before| before.iter().any(|word| NEGATIONS.contains(&word.as_str())))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::agents::authority::capability::{
        PubSub, TopicCapability, TopicPattern,
    };
    use ianua_domain::domains::authorization::permission::{RoutingAction, SystemPermission};
    use ianua_domain::types::HttpMethod;
    use proptest::prelude::*;

    use super::*;

    async fn compile(intent: &str, requested: &CapabilitySet) -> CompiledIntent {
        KeywordIntentCompiler
            .compile(&IntentStatement::new(intent).unwrap(), requested)
            .await
            .unwrap()
    }

    fn stated_in(text: &str) -> Vec<ActionClass> {
        classes_stated(&words_of(text))
    }

    fn publishing_and_reading() -> CapabilitySet {
        CapabilitySet::new(
            vec![SystemPermission::Routing(RoutingAction::View)],
            vec![TopicCapability::new(
                TopicPattern::new("orders.*").unwrap(),
                PubSub::Both,
            )],
        )
    }

    /// Where other letters are glued to a keyword.
    #[derive(Debug, Clone, Copy)]
    enum Glue {
        Before,
        After,
        Both,
    }

    /// Every keyword of one word, as a statement may glue letters to it.
    fn single_word_keywords() -> Vec<&'static str> {
        RULES
            .iter()
            .flat_map(|(_, keywords)| keywords.iter().copied())
            .filter(|keyword| !keyword.contains(' '))
            .collect()
    }

    /// A read-only purpose permits reads and nothing that changes state.
    #[tokio::test]
    async fn a_read_intent_compiles_to_reading_alone() {
        let compiled = compile(
            "read the orders ledger and summarize it",
            &CapabilitySet::empty(),
        )
        .await;

        let envelope = compiled.envelope();
        assert!(envelope.permits_action(HttpMethod::Get, "/orders/ledger"));
        assert!(!envelope.permits_action(HttpMethod::Delete, "/orders/ledger"));
        assert!(!envelope.permits_action(HttpMethod::Post, "/admin/roles"));
    }

    /// A purpose that names deleting reaches deletes as well.
    #[tokio::test]
    async fn a_destructive_intent_reaches_deletes() {
        let compiled = compile(
            "read and then delete stale export files",
            &CapabilitySet::empty(),
        )
        .await;

        let envelope = compiled.envelope();
        assert!(envelope.permits_action(HttpMethod::Get, "/exports"));
        assert!(envelope.permits_action(HttpMethod::Delete, "/exports/old"));
    }

    /// An intent containing no recognized keyword compiles to reading alone.
    #[tokio::test]
    async fn an_unplaceable_intent_gets_the_read_only_floor() {
        let compiled = compile("xyzzy plugh", &CapabilitySet::empty()).await;

        assert_eq!(compiled.envelope().allowed(), &[ActionClass::Read]);
    }

    /// Embedded keyword fragments in names and compound words grant no extra
    /// action classes; the resulting intent permits reading alone.
    #[tokio::test]
    async fn a_keyword_inside_another_word_reaches_nothing() {
        let compiled = compile(
            "display the diamond payload of william's dropdown",
            &CapabilitySet::empty(),
        )
        .await;

        assert_eq!(compiled.envelope().allowed(), &[ActionClass::Read]);
    }

    /// The word "already" does not contribute a read action class.
    #[test]
    fn already_states_no_class() {
        assert!(stated_in("already done").is_empty());
    }

    /// A keyword counts in its regular forms: "deleted" and "dropping" are
    /// deleting, "payments" paying, "notifies" sending.
    #[test]
    fn a_keyword_counts_in_its_regular_forms() {
        let stated = stated_in("it deleted rows, keeps dropping payments and notifies us");

        let expected = [
            ActionClass::Delete,
            ActionClass::Financial,
            ActionClass::Communicate,
        ];
        assert_eq!(stated, expected);
    }

    /// A read intent that forbids deleting and emailing compiles to reading
    /// alone.
    #[tokio::test]
    async fn a_negated_keyword_reaches_nothing() {
        let compiled = compile(
            "read the ledger, never delete it and don't email anyone",
            &CapabilitySet::empty(),
        )
        .await;

        assert_eq!(compiled.envelope().allowed(), &[ActionClass::Read]);
    }

    /// A keyword of two words counts when both are there in a row.
    #[tokio::test]
    async fn a_keyword_of_two_words_counts_in_a_row() {
        let compiled = compile(
            "review access controls for the team",
            &CapabilitySet::empty(),
        )
        .await;

        assert!(compiled.envelope().permits(ActionClass::Admin));
    }

    /// Compiling a read purpose against publishing and reading capabilities
    /// yields a strict subset of the requested scope.
    #[tokio::test]
    async fn the_scope_is_only_ever_narrowed() {
        let requested = publishing_and_reading();

        let compiled = compile("look up the open orders", &requested).await;

        assert!(compiled.scope().subset_of(&requested));
        assert_ne!(compiled.scope(), &requested);
    }

    proptest! {
        /// Adding a generated z-prefixed fragment before, after or on both sides
        /// of a keyword leaves the resulting word without an action class.
        #[test]
        fn a_keyword_glued_inside_another_word_states_no_class(
            keyword in prop::sample::select(single_word_keywords()),
            before in "z[a-z]{0,4}",
            after in "z[a-z]{0,4}",
            glue in prop_oneof![Just(Glue::Before), Just(Glue::After), Just(Glue::Both)],
        ) {
            let word = match glue {
                Glue::Before => format!("{before}{keyword}"),
                Glue::After => format!("{keyword}{after}"),
                Glue::Both => format!("{before}{keyword}{after}"),
            };

            prop_assert!(stated_in(&word).is_empty(), "{word}");
        }
    }
}
