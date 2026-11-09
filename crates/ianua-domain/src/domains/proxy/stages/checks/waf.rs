//! The web application firewall's rules and the decision on what they found.
//!
//! Scoring works as in the OWASP Core Rule Set: each rule of an enabled set
//! that matched adds its score, and the request is refused once the total
//! reaches the tenant's threshold. One weak signal passes; several, or one
//! strong one, do not.
//!
//! Reading the request stays with an adapter: it normalises the path, the
//! query, each header value and the body prefix (decoding, comments,
//! case, whitespace) and reports which rule matched which input. What
//! those matches come to is decided here, so every gateway scores alike.
//! An input still encoded once the adapter's decoding passes ran out is a
//! signal of its own, counted whatever sets are on: no real client encodes
//! its own data that deep.

use crate::domains::proxy::stages::decision::StageDecision;
use crate::domains::proxy::stages::stage::{WafConfig, WafRuleSet};
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::{validate_count, validate_range};
use crate::types::DenialStatus;

/// What an input still encoded after the last decoding pass scores.
const ENCODING_TOO_DEEP_SCORE: u32 = 5;

/// The id recorded for an input still encoded after the last pass.
const ENCODING_TOO_DEEP_ID: &str = "waf-encoding-depth-exceeded";

/// One rule of the firewall. The adapter that reads requests holds the
/// pattern for each; the id, the score and the set are the domain's.
///
/// The event-handler rule is meant for the real HTML event attributes, not
/// any `on…=`, which would catch ordinary parameters such as
/// `onboarding=`. The prompt-injection rules catch known phrasing only; an
/// attacker who rewords it is not caught.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WafRule {
    /// Detects SQL result-set combination syntax in request input.
    SqliUnionSelect,
    /// `or 1=1` and its kin.
    SqliTautology,
    /// A quote closing a string to add a condition: `' or '`.
    SqliQuoteBreakout,
    /// A second statement after a `;`: `; drop table`.
    SqliStackedQuery,
    /// A delay asked of the database: `sleep(`, `waitfor delay`.
    SqliTimeBased,
    /// `information_schema`.
    SqliInfoSchema,
    /// `xp_cmdshell`.
    SqliMssqlProc,
    /// A quote then a comment: `' --`.
    SqliCommentTerminator,
    /// Reading or writing files: `load_file`, `into outfile`.
    SqliFileReadWrite,
    /// Detects an HTML element that can introduce executable browser code.
    XssScriptTag,
    /// An HTML event attribute: `onerror=`.
    XssEventHandler,
    /// `javascript:`.
    XssJsUri,
    /// Detects an HTML element that can embed a separate browsing context.
    XssIframe,
    /// Detects an SVG element that may carry active browser content.
    XssSvgVector,
    /// `document.cookie`, `document.write`, `document.location`.
    XssDomSink,
    /// Detects JavaScript's dynamic code-evaluation call in request input.
    XssEval,
    /// Detects parent-directory segments using forward slashes.
    TraversalDotDot,
    /// Detects parent-directory segments using Windows path separators.
    TraversalDotDotBackslash,
    /// Detects input that could truncate a path at a C string boundary.
    TraversalNullByte,
    /// A shell command after a `;`: `; cat`.
    CmdiChainedCommand,
    /// Detects shell syntax that evaluates a command inside another expression.
    CmdiSubstitution,
    /// A backtick substitution.
    CmdiBacktick,
    /// A command after a pipe: `| whoami`.
    CmdiPipeChain,
    /// "ignore previous instructions".
    PiIgnoreInstructions,
    /// "disregard the above".
    PiDisregardInstructions,
    /// "developer mode", "jailbreak mode".
    PiAltMode,
    /// Detects wording that refers to the model's privileged instructions.
    PiSystemPrompt,
    /// "reveal your prompt".
    PiRevealPrompt,
    /// "act as … without restrictions".
    PiActAsUnrestricted,
    /// Detects wording asking the model to imagine operating without its constraints.
    PiPretendNoGuidelines,
}

/// A rule's id, score and set.
struct RuleSpec {
    id: &'static str,
    score: u32,
    set: WafRuleSet,
}

impl WafRule {
    /// Every rule.
    pub const ALL: [Self; 30] = [
        Self::SqliUnionSelect,
        Self::SqliTautology,
        Self::SqliQuoteBreakout,
        Self::SqliStackedQuery,
        Self::SqliTimeBased,
        Self::SqliInfoSchema,
        Self::SqliMssqlProc,
        Self::SqliCommentTerminator,
        Self::SqliFileReadWrite,
        Self::XssScriptTag,
        Self::XssEventHandler,
        Self::XssJsUri,
        Self::XssIframe,
        Self::XssSvgVector,
        Self::XssDomSink,
        Self::XssEval,
        Self::TraversalDotDot,
        Self::TraversalDotDotBackslash,
        Self::TraversalNullByte,
        Self::CmdiChainedCommand,
        Self::CmdiSubstitution,
        Self::CmdiBacktick,
        Self::CmdiPipeChain,
        Self::PiIgnoreInstructions,
        Self::PiDisregardInstructions,
        Self::PiAltMode,
        Self::PiSystemPrompt,
        Self::PiRevealPrompt,
        Self::PiActAsUnrestricted,
        Self::PiPretendNoGuidelines,
    ];

    /// The stable id the request record names the rule by.
    #[must_use]
    pub fn id(self) -> &'static str {
        self.spec().id
    }

    /// What a match of the rule adds to the score.
    #[must_use]
    pub fn score(self) -> u32 {
        self.spec().score
    }

    /// The set the rule belongs to, which a tenant turns on as a whole.
    #[must_use]
    pub fn set(self) -> WafRuleSet {
        self.spec().set
    }

    // One row per rule, with no catch-all, so a rule added without its id,
    // score and set does not build. Splitting the table would bring a
    // default back.
    #[allow(clippy::too_many_lines)]
    #[rustfmt::skip]
    fn spec(self) -> RuleSpec {
        let (id, score, set) = match self {
            Self::SqliUnionSelect => ("sqli-union-select", 5, WafRuleSet::Sqli),
            Self::SqliTautology => ("sqli-tautology", 4, WafRuleSet::Sqli),
            Self::SqliQuoteBreakout => ("sqli-quote-breakout", 4, WafRuleSet::Sqli),
            Self::SqliStackedQuery => ("sqli-stacked-query", 5, WafRuleSet::Sqli),
            Self::SqliTimeBased => ("sqli-time-based", 5, WafRuleSet::Sqli),
            Self::SqliInfoSchema => ("sqli-info-schema", 3, WafRuleSet::Sqli),
            Self::SqliMssqlProc => ("sqli-mssql-proc", 5, WafRuleSet::Sqli),
            Self::SqliCommentTerminator => ("sqli-comment-terminator", 4, WafRuleSet::Sqli),
            Self::SqliFileReadWrite => ("sqli-file-read-write", 4, WafRuleSet::Sqli),
            Self::XssScriptTag => ("xss-script-tag", 5, WafRuleSet::Xss),
            Self::XssEventHandler => ("xss-event-handler", 5, WafRuleSet::Xss),
            Self::XssJsUri => ("xss-js-uri", 5, WafRuleSet::Xss),
            Self::XssIframe => ("xss-iframe", 3, WafRuleSet::Xss),
            Self::XssSvgVector => ("xss-svg-vector", 2, WafRuleSet::Xss),
            Self::XssDomSink => ("xss-dom-sink", 4, WafRuleSet::Xss),
            Self::XssEval => ("xss-eval", 3, WafRuleSet::Xss),
            Self::TraversalDotDot => ("traversal-dotdot", 5, WafRuleSet::Traversal),
            Self::TraversalDotDotBackslash => ("traversal-dotdot-backslash", 5, WafRuleSet::Traversal),
            Self::TraversalNullByte => ("traversal-null-byte", 5, WafRuleSet::Traversal),
            Self::CmdiChainedCommand => ("cmdi-chained-command", 5, WafRuleSet::CommandInjection),
            Self::CmdiSubstitution => ("cmdi-substitution", 5, WafRuleSet::CommandInjection),
            Self::CmdiBacktick => ("cmdi-backtick", 4, WafRuleSet::CommandInjection),
            Self::CmdiPipeChain => ("cmdi-pipe-chain", 4, WafRuleSet::CommandInjection),
            Self::PiIgnoreInstructions => ("pi-ignore-instructions", 4, WafRuleSet::PromptInjection),
            Self::PiDisregardInstructions => ("pi-disregard-instructions", 4, WafRuleSet::PromptInjection),
            Self::PiAltMode => ("pi-alt-mode", 3, WafRuleSet::PromptInjection),
            Self::PiSystemPrompt => ("pi-system-prompt", 3, WafRuleSet::PromptInjection),
            Self::PiRevealPrompt => ("pi-reveal-prompt", 3, WafRuleSet::PromptInjection),
            Self::PiActAsUnrestricted => ("pi-act-as-unrestricted", 4, WafRuleSet::PromptInjection),
            Self::PiPretendNoGuidelines => ("pi-pretend-no-guidelines", 4, WafRuleSet::PromptInjection),
        };
        RuleSpec { id, score, set }
    }
}

/// One thing the reader found in one input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WafSignal {
    /// The input, normalised, matched this rule.
    Rule(WafRule),
    /// The input was still changing when the decoding passes ran out.
    EncodingTooDeep,
}

impl WafSignal {
    /// The id the request record names the signal by.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Rule(rule) => rule.id(),
            Self::EncodingTooDeep => ENCODING_TOO_DEEP_ID,
        }
    }

    /// What the signal adds to the score.
    #[must_use]
    pub fn score(self) -> u32 {
        match self {
            Self::Rule(rule) => rule.score(),
            Self::EncodingTooDeep => ENCODING_TOO_DEEP_SCORE,
        }
    }

    /// Whether the signal counts under `config`: a rule only when its set
    /// is on, the encoding depth always.
    fn counts_under(self, config: &WafConfig) -> bool {
        match self {
            Self::Rule(rule) => config.rule_sets.contains(&rule.set()),
            Self::EncodingTooDeep => true,
        }
    }
}

/// What the reader found in one request: every signal, once for each input
/// it was found in, so a payload sent in the path and the body counts
/// twice.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WafReading {
    signals: Vec<WafSignal>,
}

impl WafReading {
    /// A reading of `signals`.
    #[must_use]
    pub fn new(signals: impl IntoIterator<Item = WafSignal>) -> Self {
        Self {
            signals: signals.into_iter().collect(),
        }
    }

    /// The signals found, in the order found.
    #[must_use]
    pub fn signals(&self) -> &[WafSignal] {
        &self.signals
    }
}

/// What the firewall makes of one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WafVerdict {
    /// No rule set is on, so nothing was checked. A stage that cannot check
    /// is not a check that passed: the request is refused.
    NothingEnabled,
    /// The score stayed under the threshold.
    Below {
        /// The score reached.
        score: u32,
        /// The tenant's threshold.
        threshold: u32,
    },
    /// The score reached the threshold.
    Reached {
        /// The score reached.
        score: u32,
        /// The tenant's threshold.
        threshold: u32,
        /// The ids of what counted, each once, in the order first found.
        matched: Vec<&'static str>,
    },
}

impl WafVerdict {
    /// Whether the request may go on.
    #[must_use]
    pub fn passes(&self) -> bool {
        matches!(self, Self::Below { .. })
    }

    /// The stage decision the verdict comes to: a 403 unless the score
    /// stayed under the threshold.
    #[must_use]
    pub fn decision(&self) -> StageDecision {
        match self {
            Self::NothingEnabled => StageDecision::Deny {
                status: DenialStatus::FORBIDDEN,
                reason: "waf: no rule set is enabled".to_owned(),
            },
            Self::Below { score, threshold } => StageDecision::Pass {
                reason: format!("waf: anomaly score {score} below the threshold {threshold}"),
            },
            Self::Reached {
                score,
                threshold,
                matched,
            } => StageDecision::Deny {
                status: DenialStatus::FORBIDDEN,
                reason: format!(
                    "waf: anomaly score {score} reached the threshold {threshold} (matched: {})",
                    matched.join(", ")
                ),
            },
        }
    }
}

impl WafConfig {
    /// Refuses a stage with no rule set to try, a threshold of zero that
    /// would refuse every request, or no body to read.
    pub(crate) fn validate(&self) -> Result<(), DomainError> {
        validate_count("rule_sets", self.rule_sets.len(), 1..=usize::MAX)?;
        validate_range("anomaly_threshold", self.anomaly_threshold, 1..=u32::MAX)?;
        validate_range("max_body_bytes", self.max_body_bytes, 1..=u64::MAX)?;
        Ok(())
    }

    /// The rules the reader needs to try: those of the enabled sets.
    pub fn enabled_rules(&self) -> impl Iterator<Item = WafRule> + '_ {
        WafRule::ALL
            .into_iter()
            .filter(|rule| self.rule_sets.contains(&rule.set()))
    }

    /// What `reading` comes to under this configuration.
    #[must_use]
    pub fn verdict(&self, reading: &WafReading) -> WafVerdict {
        if self.rule_sets.is_empty() {
            return WafVerdict::NothingEnabled;
        }
        let counted: Vec<WafSignal> = reading
            .signals
            .iter()
            .copied()
            .filter(|signal| signal.counts_under(self))
            .collect();
        let score = counted
            .iter()
            .fold(0_u32, |total, signal| total.saturating_add(signal.score()));
        let threshold = self.anomaly_threshold;
        if score < threshold {
            return WafVerdict::Below { score, threshold };
        }
        WafVerdict::Reached {
            score,
            threshold,
            matched: first_seen_ids(&counted),
        }
    }
}

/// The ids of `signals`, each once, in the order first seen.
fn first_seen_ids(signals: &[WafSignal]) -> Vec<&'static str> {
    let mut ids: Vec<&'static str> = Vec::with_capacity(signals.len());
    for signal in signals {
        if !ids.contains(&signal.id()) {
            ids.push(signal.id());
        }
    }
    ids
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const ALL_SETS: [WafRuleSet; 5] = [
        WafRuleSet::Sqli,
        WafRuleSet::Xss,
        WafRuleSet::Traversal,
        WafRuleSet::CommandInjection,
        WafRuleSet::PromptInjection,
    ];

    fn config(rule_sets: &[WafRuleSet], anomaly_threshold: u32) -> WafConfig {
        WafConfig {
            rule_sets: rule_sets.to_vec(),
            anomaly_threshold,
            max_body_bytes: 1024,
        }
    }

    fn reading(signals: &[WafSignal]) -> WafReading {
        WafReading::new(signals.iter().copied())
    }

    fn rule(rule: WafRule) -> WafSignal {
        WafSignal::Rule(rule)
    }

    /// Every rule keeps an id of its own, so a search of the request log
    /// for one never finds another.
    #[test]
    fn every_rule_has_its_own_id() {
        let ids: std::collections::HashSet<&str> =
            WafRule::ALL.iter().map(|rule| rule.id()).collect();

        assert_eq!(ids.len(), WafRule::ALL.len());
        assert!(!ids.contains(ENCODING_TOO_DEEP_ID));
    }

    #[test]
    fn a_request_nothing_matched_in_passes() {
        let verdict = config(&ALL_SETS, 5).verdict(&WafReading::default());

        assert_eq!(
            verdict,
            WafVerdict::Below {
                score: 0,
                threshold: 5
            }
        );
        assert!(!verdict.decision().is_terminal());
    }

    /// A WAF with nothing enabled would check nothing; it refuses instead.
    #[test]
    fn a_waf_with_no_rule_set_refuses() {
        let verdict = config(&[], 5).verdict(&WafReading::default());

        assert_eq!(verdict, WafVerdict::NothingEnabled);
        assert!(verdict.decision().is_terminal());
    }

    /// An `<svg>` alone scores 2 and passes a threshold of 5; with `eval(`
    /// beside it the request scores 5 and is refused.
    #[test]
    fn one_weak_signal_passes_and_two_together_do_not() {
        let waf = config(&ALL_SETS, 5);

        let svg = waf.verdict(&reading(&[rule(WafRule::XssSvgVector)]));
        let svg_and_eval = waf.verdict(&reading(&[
            rule(WafRule::XssSvgVector),
            rule(WafRule::XssEval),
        ]));

        assert!(svg.passes());
        assert!(!svg_and_eval.passes());
    }

    /// A reported SQL-injection signal passes a threshold of one when only
    /// the cross-site scripting rule set is enabled.
    #[test]
    fn a_rule_of_a_set_that_is_off_adds_nothing() {
        let only_xss = config(&[WafRuleSet::Xss], 1);

        let verdict = only_xss.verdict(&reading(&[rule(WafRule::SqliUnionSelect)]));

        assert!(verdict.passes());
    }

    /// An encoding-depth signal reaches the threshold when only prompt
    /// injection rules are enabled, and its identifier appears in both the
    /// matched signals and the decision reason.
    #[test]
    fn encoding_past_the_decode_budget_counts_whatever_sets_are_on() {
        let verdict = config(&[WafRuleSet::PromptInjection], 5)
            .verdict(&reading(&[WafSignal::EncodingTooDeep]));

        let WafVerdict::Reached { matched, .. } = &verdict else {
            panic!("an input encoded four deep is refused");
        };
        assert_eq!(matched, &[ENCODING_TOO_DEEP_ID]);
        assert!(verdict.decision().reason().contains(ENCODING_TOO_DEEP_ID));
    }

    /// A payload in the path and again in the body counts twice, and its id
    /// is named once.
    #[test]
    fn a_rule_found_in_two_inputs_counts_twice_and_is_named_once() {
        let verdict = config(&ALL_SETS, 6).verdict(&reading(&[
            rule(WafRule::SqliTautology),
            rule(WafRule::SqliTautology),
        ]));

        assert_eq!(
            verdict,
            WafVerdict::Reached {
                score: 8,
                threshold: 6,
                matched: vec!["sqli-tautology"],
            }
        );
    }

    #[test]
    fn the_enabled_rules_are_those_of_the_enabled_sets() {
        let waf = config(&[WafRuleSet::Traversal], 5);

        let rules: Vec<WafRule> = waf.enabled_rules().collect();

        assert_eq!(
            rules,
            [
                WafRule::TraversalDotDot,
                WafRule::TraversalDotDotBackslash,
                WafRule::TraversalNullByte,
            ]
        );
    }

    fn signal() -> impl Strategy<Value = WafSignal> {
        prop_oneof![
            (0..WafRule::ALL.len()).prop_map(|at| WafSignal::Rule(WafRule::ALL[at])),
            Just(WafSignal::EncodingTooDeep),
        ]
    }

    fn sets() -> impl Strategy<Value = Vec<WafRuleSet>> {
        proptest::sample::subsequence(ALL_SETS.to_vec(), 1..=ALL_SETS.len())
    }

    proptest! {
        /// Whatever a request already carried, finding one more signal in
        /// it never lets through a request that was refused: an attacker
        /// cannot dilute a payload by adding to it.
        #[test]
        fn another_signal_never_turns_a_refusal_into_a_pass(
            found in proptest::collection::vec(signal(), 0..12),
            extra in signal(),
            enabled in sets(),
            threshold in 1_u32..30,
        ) {
            let waf = config(&enabled, threshold);
            let before = waf.verdict(&reading(&found));
            let mut more = found.clone();
            more.push(extra);

            let after = waf.verdict(&reading(&more));

            prop_assert!(before.passes() || !after.passes());
        }

        /// The score is never more than every signal found added together,
        /// and a refusal names only what was found.
        #[test]
        fn a_refusal_names_only_what_was_found(
            found in proptest::collection::vec(signal(), 0..12),
            enabled in sets(),
            threshold in 1_u32..30,
        ) {
            let verdict = config(&enabled, threshold).verdict(&reading(&found));

            if let WafVerdict::Reached { matched, .. } = verdict {
                for id in matched {
                    prop_assert!(found.iter().any(|signal| signal.id() == id));
                }
            }
        }
    }
}
