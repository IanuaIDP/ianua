//! Dead ends: a capability a deployment may not have, needed on a path that
//! never asks whether it is there, or owed by a rule that cannot know.
//!
//! The gates are read from the code (see [`crate::model::gates`]). Two
//! things are asked of each gate whose port answers whether it is set up:
//!
//! - **Paths.** A use case that holds the gate's port, and so knows the
//!   capability may be missing, has a path to a call of a port the gate
//!   governs that never asks the gate first: where it is not set up, that
//!   path neither refuses before the call nor takes another way. Asking on
//!   the way counts as deciding on it; what is then done with the answer is
//!   for the rules that take it, below. A use case that never holds the
//!   gate is not judged: its code does not say the call needs the
//!   deployment's capability rather than, say, a tenant's own.
//! - **Rules.** An answer of a decision rule (see
//!   [`crate::model::rules::decisions`]) is completed only by the gate when
//!   some use case, on a path its branches narrowed to that answer (`if
//!   owes_email_confirmation(owed)`, a `match` arm), calls a port the gate
//!   governs. A rule that can give such an answer and takes no input of
//!   the gate's answer, or gives it while that input says the capability is
//!   not set up, owes what a deployment without it can never complete.

use std::collections::{BTreeMap, BTreeSet};

use crate::finding::{Check, Finding, Found, Unsaid};
use crate::model::facts::flow::{
    Answer, Exit, Flow, Point, Question, Step, Unread, exits, holds as flow_holds, reaches_without,
};
use crate::model::facts::{Facts, UseCaseFacts};
use crate::model::gates::{Gate, GateKind};
use crate::model::rules::Rules;
use crate::model::rules::decisions::{Decision, Reading, Row};
use crate::source::Place;

/// Every dead-end finding.
pub(crate) fn run(gates: &[Gate], rules: &Rules, facts: &Facts) -> Found {
    let mut found = Found::default();
    for asked in gates.iter().filter_map(Asked::of) {
        let gate = asked.gate;
        for use_case in facts
            .use_cases
            .iter()
            .filter(|found| holds(found, asked.port))
        {
            unasked_path(&asked, use_case, &mut found);
        }
        let completed = completed_by(gate, &outcomes(rules), facts);
        for decision in rules
            .decisions
            .iter()
            .filter(|decision| decision.reading == Reading::WorkedOut)
        {
            found
                .findings
                .extend(owed_without(&asked, decision, &completed));
        }
    }
    found
}

/// A gate whose port answers whether it is set up: its port method, the
/// answer naming whether it is, and the values of it that say not.
struct Asked<'g> {
    gate: &'g Gate,
    port: &'g str,
    method: &'g str,
    answer: &'g str,
    off: &'g [String],
}

impl<'g> Asked<'g> {
    /// `gate`, when its port answers whether it is set up and it governs
    /// some calls.
    fn of(gate: &'g Gate) -> Option<Self> {
        let GateKind::Asked {
            port,
            method,
            answer,
            off,
            ..
        } = &gate.kind
        else {
            return None;
        };
        (!gate.acts.is_empty()).then_some(Self {
            gate,
            port,
            method,
            answer,
            off,
        })
    }

    /// The first row of `decision` answering `variant` where the gate may
    /// be off: any row, when no input of the rule says whether it is set up.
    fn first_row_owing<'d>(&self, decision: &'d Decision, variant: &str) -> Option<&'d Row> {
        let gate_input = decision.input_of(self.answer);
        (decision.rows.iter())
            .filter(|row| row.outcome.as_deref() == Some(variant))
            .find(|row| match gate_input {
                None => true,
                Some(at) => row.when[at]
                    .as_ref()
                    .is_none_or(|value| self.off.contains(value)),
            })
    }

    /// Why `decision` owing `variant` is a dead end where the gate is off.
    fn owed_message(&self, decision: &Decision, variant: &str) -> String {
        let (answer, gate) = (self.answer, self.gate.name());
        match decision.input_of(answer).is_some() {
            false => format!(
                "`{}` can answer `{variant}`, which only `{}` completes, and no input of it says whether `{gate}` is set up",
                decision.subject,
                self.gate.acts.join("` or `")
            ),
            true => format!(
                "`{}` still answers `{variant}` when its `{answer}` input says not set up, and only `{}` completes `{variant}`",
                decision.subject,
                self.gate.acts.join("` or `")
            ),
        }
    }

    fn asks(&self, step: &Step) -> bool {
        matches!(step, Step::Port { trait_name: Some(name), method, .. }
            if name == self.port && method == self.method)
    }

    fn acts(&self, step: &Step) -> bool {
        matches!(step, Step::Port { trait_name: Some(name), .. } if self.gate.acts.contains(name))
    }
}

/// Whether `use_case` holds the port `port`.
fn holds(use_case: &UseCaseFacts, port: &str) -> bool {
    use_case
        .ports
        .iter()
        .any(|held| held.trait_name.as_deref() == Some(port))
}

fn unasked_path(asked: &Asked<'_>, use_case: &UseCaseFacts, found: &mut Found) {
    let failing = failing_calls_only(&use_case.flow, asked);
    let answer = reaches_without(
        &failing,
        |step| asked.asks(step),
        |step| asked.acts(step),
        &use_case.end,
    );
    match answer {
        Answer::No => {}
        Answer::Unknown(unread) => found.leave_unsaid(Unsaid::new(
            Check::GateDeadEnd,
            format!(
                "{}::{} {}",
                use_case.context,
                use_case.name,
                asked.gate.name()
            ),
            unread.place,
            unread.what,
        )),
        Answer::Yes(places) => found.findings.push(unasked(asked, use_case, &places)),
    }
}

/// `flow` with each call of a governed port whose failure the path goes on
/// past taken out, since only a call that fails the path where the
/// capability is missing is a dead end. A call whose result the reader
/// sees matched with no way out on its error arm goes; one whose result it
/// does not see matched at all becomes a not-read point.
fn failing_calls_only(flow: &Flow, asked: &Asked<'_>) -> Flow {
    match flow {
        Flow::Point(point) if asked.acts(&point.step) => Flow::Unread(Unread {
            place: point.place.clone(),
            what: format!(
                "`{}`: whether the path goes on when this call fails is not read",
                port_of(&point.step)
            ),
        }),
        Flow::Split { head, ok, err } => {
            let kept = match head.as_ref() {
                Flow::Point(point) if asked.acts(&point.step) && !leaves_failed(err) => {
                    Flow::Nothing
                }
                Flow::Point(point) => Flow::Point(point.clone()),
                other => failing_calls_only(other, asked),
            };
            Flow::Split {
                head: Box::new(kept),
                ok: Box::new(failing_calls_only(ok, asked)),
                err: Box::new(failing_calls_only(err, asked)),
            }
        }
        other => other.with_parts(|part| failing_calls_only(part, asked)),
    }
}

/// Whether some way through `flow` leaves the function with an error, or
/// with a value that may be one.
fn leaves_failed(flow: &Flow) -> bool {
    match flow {
        Flow::Exit(exit, _) => *exit != Exit::Ok,
        Flow::Seq(parts) | Flow::Choice(parts) => parts.iter().any(leaves_failed),
        Flow::Loop { body: inner, .. } | Flow::Call { inner, .. } | Flow::Unit { inner, .. } => {
            leaves_failed(inner)
        }
        Flow::Split { head, ok, err } => {
            [head, ok, err].into_iter().any(|part| leaves_failed(part))
        }
        Flow::Point(_) | Flow::Nothing | Flow::LoopExit | Flow::Halt | Flow::Unread(_) => false,
    }
}

/// The port trait a step calls, as written.
fn port_of(step: &Step) -> String {
    match step {
        Step::Port {
            trait_name: Some(name),
            method,
            ..
        } => format!("{name}::{method}"),
        _ => "the call".to_owned(),
    }
}

fn unasked(asked: &Asked<'_>, use_case: &UseCaseFacts, places: &[Place]) -> Finding {
    let at = places
        .first()
        .cloned()
        .unwrap_or_else(|| use_case.place.clone());
    let gate = asked.gate.name();
    Finding::new(
        Check::GateDeadEnd,
        at.clone(),
        format!("{}::{} {gate}", use_case.context, use_case.name),
        format!(
            "`{}` ({}) holds `{}` but has a path to `{}` that never asks it: where the capability is not set up, the path neither refuses first nor takes another way",
            use_case.name,
            use_case.context,
            asked.port,
            asked.gate.acts.join("` or `")
        ),
    )
    .with_detail([
        format!("call:    {}:{}  reaches it unasked", at.file, at.line),
        format!("gate:    {}:{}  {gate}", asked.gate.place.file, asked.gate.place.line),
        format!(
            "command: {}:{}  {}",
            use_case.place.file, use_case.place.line, use_case.name
        ),
        "why: a deployment without the capability sends a person down a path that cannot finish".to_owned(),
        format!("fix: ask `{gate}` before the call and refuse, or go another way, when it says not set up"),
    ])
}

/// The enums the worked-out rules answer with.
fn outcomes(rules: &Rules) -> BTreeSet<&str> {
    rules
        .decisions
        .iter()
        .filter(|decision| decision.reading == Reading::WorkedOut)
        .map(|decision| decision.outcome.as_str())
        .collect()
}

/// Each call of a port `gate` governs, by where it is and the use case,
/// with what each path that reaches it narrowed the enums of `outcomes`
/// to, and what the paths of that use case that succeed without any such
/// call narrowed.
fn completed_by(gate: &Gate, outcomes: &BTreeSet<&str>, facts: &Facts) -> Vec<Reached> {
    let mut reached = Vec::new();
    let acts = |step: &Step| matches!(step, Step::Port { trait_name: Some(name), .. } if gate.acts.contains(name));
    for use_case in facts
        .use_cases
        .iter()
        .filter(|use_case| flow_holds(&use_case.flow, &acts))
    {
        let mut question = Narrowed {
            acts: &gate.acts,
            outcomes,
            hits: BTreeMap::new(),
        };
        let bypasses = bypasses_in(use_case, &mut question);
        reached.extend(question.hits.into_iter().map(|(place, paths)| Reached {
            place,
            use_case: use_case.name.clone(),
            paths,
            bypasses: bypasses.clone(),
        }));
    }
    reached
}

/// The variants each enum was narrowed to on one path, by enum.
type Narrowing = BTreeMap<String, BTreeSet<String>>;

/// A call of a governed port, with what each path reaching it narrowed.
struct Reached {
    place: Place,
    use_case: String,
    paths: BTreeSet<Narrowing>,
    bypasses: BTreeSet<Narrowing>,
}

impl Reached {
    /// The variants of `enum_name` only the call completes: every path
    /// reaching it narrowed the enum, and not to every one of its
    /// `variants`; a variant some path of the use case still allows when it
    /// succeeds without the call is completed another way and left out.
    fn deciding(&self, enum_name: &str, variants: &[String]) -> Option<BTreeSet<String>> {
        let mut under = BTreeSet::new();
        for narrowed in &self.paths {
            under.extend(narrowed.get(enum_name)?.iter().cloned());
        }
        if under.len() >= variants.len() {
            return None;
        }
        for bypass in &self.bypasses {
            let Some(allowed) = bypass.get(enum_name) else {
                continue;
            };
            under.retain(|variant| !allowed.contains(variant));
        }
        Some(under)
    }
}

/// Whether a path called a governed port.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
enum Acted {
    /// Not yet.
    #[default]
    No,
    /// It did.
    Yes,
}

/// What one path knows: the enums it narrowed and whether it called a
/// governed port.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
struct OnPath {
    narrowed: Narrowing,
    acted: Acted,
}

/// Tracks, on each path, the variants each enum of `outcomes` was
/// narrowed to; notes them where a port of `acts` is called.
struct Narrowed<'a> {
    acts: &'a [String],
    outcomes: &'a BTreeSet<&'a str>,
    hits: BTreeMap<Place, BTreeSet<Narrowing>>,
}

impl Question for Narrowed<'_> {
    type State = OnPath;

    fn point(&mut self, state: &Self::State, point: &Point) -> Self::State {
        let mut state = state.clone();
        match &point.step {
            Step::Narrow {
                enum_name,
                variants,
            } if self.outcomes.contains(enum_name.as_str()) => {
                let narrowed = match state.narrowed.get(enum_name) {
                    Some(held) => held.intersection(variants).cloned().collect(),
                    None => variants.clone(),
                };
                state.narrowed.insert(enum_name.clone(), narrowed);
            }
            Step::Port {
                trait_name: Some(name),
                ..
            } if self.acts.contains(name) => {
                self.hits
                    .entry(point.place.clone())
                    .or_default()
                    .insert(state.narrowed.clone());
                state.acted = Acted::Yes;
            }
            _ => {}
        }
        state
    }

    fn unread(&mut self, state: &Self::State, _unread: &Unread) -> Self::State {
        state.clone()
    }
}

/// What each path of `use_case` that succeeds without a governed call
/// narrowed, `question` noting each call it reaches.
fn bypasses_in(use_case: &UseCaseFacts, question: &mut Narrowed<'_>) -> BTreeSet<Narrowing> {
    let left = exits(&use_case.flow, question, OnPath::default(), &use_case.end);
    left.into_iter()
        .filter(|(exit, path, _)| *exit != Exit::Err && path.acted == Acted::No)
        .map(|(_, path, _)| path.narrowed)
        .collect()
}

/// The findings of `decision` owing an answer only the gate completes,
/// where it cannot know the gate is open.
fn owed_without(asked: &Asked<'_>, decision: &Decision, completed: &[Reached]) -> Vec<Finding> {
    let mut owed: BTreeMap<String, &Reached> = BTreeMap::new();
    for reached in completed {
        let Some(under) = reached.deciding(&decision.outcome, &decision.outcome_values) else {
            continue;
        };
        for variant in under {
            owed.entry(variant).or_insert(reached);
        }
    }
    owed.iter()
        .filter_map(|(variant, reached)| {
            let row = asked.first_row_owing(decision, variant)?;
            let owed = Owed { variant, reached };
            Some(owed_finding(asked, decision, &owed, row))
        })
        .collect()
}

/// An answer a rule owes that only the gate completes: the variant, and
/// the call of a use case that completes it.
struct Owed<'o> {
    variant: &'o str,
    reached: &'o Reached,
}

fn owed_finding(asked: &Asked<'_>, decision: &Decision, owed: &Owed<'_>, row: &Row) -> Finding {
    let (variant, site, use_case) = (owed.variant, &owed.reached.place, &owed.reached.use_case);
    let answer = asked.answer;
    let gate = asked.gate.name();
    let message = asked.owed_message(decision, variant);
    let when: Vec<String> = decision
        .inputs
        .iter()
        .zip(&row.when)
        .map(|(input, value)| format!("{} = {}", input.name, value.as_deref().unwrap_or("any")))
        .collect();
    let place = row.place.clone().unwrap_or_else(|| decision.place.clone());
    Finding::new(
        Check::GateDeadEnd,
        place.clone(),
        format!("{} {variant}", decision.subject),
        message,
    )
    .with_detail([
        format!("rule:    {}:{}  {}", decision.place.file, decision.place.line, decision.subject),
        format!("answers: {}:{}  {variant} when {}", place.file, place.line, when.join(", ")),
        format!("needs:   {}:{}  {use_case} completes {variant} through {}", site.file, site.line, asked.gate.acts.join(" or ")),
        format!("gate:    {}:{}  {gate} answers {answer}", asked.gate.place.file, asked.gate.place.line),
        format!("why: where `{gate}` says not set up, a person owed `{variant}` waits for something that never comes"),
        format!("fix: take `{answer}` as an input of the rule and answer something the deployment can complete when it says not set up"),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::domain::DomainLists;
    use crate::model::{Model, gates};
    use crate::source::planted::{app, domain, workspace};

    /// The mail ports: whether mail goes out, and the mailer.
    const MAIL: &str = "
        pub trait MailSetup: Send + Sync { fn reach(&self) -> MailReach; }
        pub trait Mailer: Send + Sync {
            async fn send_to_person(&self, to: &Email) -> Result<(), DomainError>;
        }";

    /// A sign-in that mails a confirmation link when the rule owes one,
    /// asking whether mail goes out only as an input of the rule.
    const LOGIN: &str = "
        pub struct LoginPorts { pub mailer: Arc<dyn Mailer>, pub mail: Arc<dyn MailSetup> }
        pub struct LoginUseCase { ports: LoginPorts }
        impl Command for LoginUseCase {
            async fn execute(&self, caller: &(), auditor: &RequestAuditor, request: LoginRequest) -> Result<(), AppError> {
                let mail = self.ports.mail.reach();
                let owed = owed_for(request, mail);
                if !owes_email_confirmation(owed) {
                    return Ok(());
                }
                self.ports.mailer.send_to_person(&request.email).await.or_internal()
            }
        }
        fn owes_email_confirmation(owed: SecondFactor) -> bool {
            matches!(owed, SecondFactor::ConfirmByEmail)
        }";

    /// The rule before this week's fix: what a sign-in owes, decided with no
    /// word of whether a mail could reach the person.
    const BEFORE: &str = "
        pub enum MailReach { Available, NotSetUp }
        pub enum MfaPolicy { Disabled, Required }
        pub enum Enrolment { Enrolled, NotEnrolled }
        pub enum SecondFactor { NotOwed, Verify, Enrol, ConfirmByEmail }
        impl SecondFactor {
            pub fn under(policy: MfaPolicy, enrolment: Enrolment) -> Self {
                match (policy, enrolment) {
                    (MfaPolicy::Disabled, Enrolment::Enrolled) => Self::NotOwed,
                    (MfaPolicy::Disabled, Enrolment::NotEnrolled) => Self::ConfirmByEmail,
                    (MfaPolicy::Required, Enrolment::Enrolled) => Self::Verify,
                    (MfaPolicy::Required, Enrolment::NotEnrolled) => Self::Enrol,
                }
            }
        }";

    /// The rule as fixed: without mail, someone owed a confirmation sets up
    /// a factor instead.
    const AFTER: &str = "
        pub enum MailReach { Available, NotSetUp }
        pub enum MfaPolicy { Disabled, Required }
        pub enum Enrolment { Enrolled, NotEnrolled }
        pub enum SecondFactor { NotOwed, Verify, Enrol, ConfirmByEmail }
        impl SecondFactor {
            pub fn under(policy: MfaPolicy, enrolment: Enrolment, mail: MailReach) -> Self {
                Self::with_mail(policy, enrolment).reached_by(mail)
            }
            fn with_mail(policy: MfaPolicy, enrolment: Enrolment) -> Self {
                match (policy, enrolment) {
                    (MfaPolicy::Disabled, Enrolment::Enrolled) => Self::NotOwed,
                    (MfaPolicy::Disabled, Enrolment::NotEnrolled) => Self::ConfirmByEmail,
                    (MfaPolicy::Required, Enrolment::Enrolled) => Self::Verify,
                    (MfaPolicy::Required, Enrolment::NotEnrolled) => Self::Enrol,
                }
            }
            fn reached_by(self, mail: MailReach) -> Self {
                match (self, mail) {
                    (Self::ConfirmByEmail, MailReach::NotSetUp) => Self::Enrol,
                    _ => self,
                }
            }
        }";

    fn found(rule: &str, login: &str) -> Found {
        let ws = workspace(vec![
            domain("domains/authentication/mfa/owed.rs", rule),
            app("ports/shared/mail.rs", MAIL),
            app("use_cases/authentication/login.rs", login),
        ]);
        let model = Model::build(&ws, &DomainLists::default());
        let facts = Facts::build(&ws, &model);
        let rules = Rules::build(&ws, &model, &facts);
        run(&gates::find(&ws, &model), &rules, &facts)
    }

    /// Calibrated on the bug fixed this week: a first sign-in on a
    /// deployment with no mail server could be owed a confirmation by
    /// mail, and never finish.
    #[test]
    fn a_rule_owing_a_mailed_confirmation_with_no_word_of_mail_is_a_dead_end() {
        let found = found(BEFORE, LOGIN);

        let finding = &found.findings[0];
        assert_eq!(finding.subject, "SecondFactor::under ConfirmByEmail");
        assert_eq!(
            finding.message,
            "`SecondFactor::under` can answer `ConfirmByEmail`, which only `Mailer` completes, and no input of it says whether `MailSetup::reach` is set up"
        );
        assert!(finding.detail[2].contains("LoginUseCase completes ConfirmByEmail through Mailer"));
    }

    /// The fixed shape: the rule takes whether mail reaches the person,
    /// and owes no mailed confirmation where it does not.
    #[test]
    fn a_rule_that_takes_mail_reach_and_never_owes_mail_without_it_passes() {
        let found = found(AFTER, LOGIN);

        assert!(found.findings.is_empty());
    }

    /// The rule takes the input but ignores it: without mail it still owes
    /// the mailed confirmation.
    #[test]
    fn a_rule_that_takes_mail_reach_and_still_owes_mail_without_it_is_a_dead_end() {
        let ignoring = AFTER.replace(
            "(Self::ConfirmByEmail, MailReach::NotSetUp) => Self::Enrol,",
            "",
        );

        let found = found(&ignoring, LOGIN);

        assert!(found.findings[0].message.starts_with(
            "`SecondFactor::under` still answers `ConfirmByEmail` when its `MailReach` input says not set up"
        ));
    }

    /// A use case that holds the gate mails a link on a path that never
    /// asks whether mail goes out.
    #[test]
    fn a_path_to_a_gated_call_that_never_asks_the_gate_is_a_dead_end() {
        let mailing = "
            pub struct InvitePorts { pub mailer: Arc<dyn Mailer>, pub mail: Arc<dyn MailSetup> }
            pub struct InviteUseCase { ports: InvitePorts }
            impl Command for InviteUseCase {
                async fn execute(&self, caller: &(), auditor: &RequestAuditor, request: InviteRequest) -> Result<(), AppError> {
                    if request.quiet {
                        let reach = self.ports.mail.reach();
                    }
                    self.ports.mailer.send_to_person(&request.email).await.or_internal()
                }
            }";

        let found = found(AFTER, mailing);

        assert_eq!(
            found.findings[0].subject,
            "authentication::InviteUseCase MailSetup::reach"
        );
    }

    /// A sign-in that holds the gate mails a notice on a path that never
    /// asks it, but logs a failed send and goes on: without mail the path
    /// still finishes.
    #[test]
    fn a_gated_call_whose_failure_the_path_goes_on_past_is_no_dead_end() {
        let notice = "
            pub struct NoticePorts { pub mailer: Arc<dyn Mailer>, pub mail: Arc<dyn MailSetup> }
            pub struct NoticeUseCase { ports: NoticePorts }
            impl Command for NoticeUseCase {
                async fn execute(&self, caller: &(), auditor: &RequestAuditor, request: NoticeRequest) -> Result<(), AppError> {
                    let sent = self.ports.mailer.send_to_person(&request.email).await;
                    if let Err(error) = sent {
                        tracing::warn!(%error, \"could not send the notice\");
                    }
                    Ok(())
                }
            }";

        let found = found(AFTER, notice);

        assert!(found.findings.is_empty());
        assert!(found.unsaid.is_empty());
    }

    /// A change refuses one answer of its rule, then mails a notice only
    /// on some paths, for a reason of its own. Every path to the mailer
    /// went through the refusal, but a path with the same answer succeeds
    /// without mail: the mail does not complete that answer.
    #[test]
    fn an_answer_that_also_succeeds_without_the_gated_call_is_not_owed_to_it() {
        let rule = "
            pub enum MailReach { Available, NotSetUp }
            pub enum Reason { Expired, SetByAdmin }
            pub enum ChangeProof { PasswordAlone, NotPossible }
            impl ChangeProof {
                pub fn for_change(reason: Reason) -> Self {
                    match reason {
                        Reason::Expired => Self::PasswordAlone,
                        Reason::SetByAdmin => Self::NotPossible,
                    }
                }
            }";
        let change = "
            pub struct ChangePorts { pub mailer: Arc<dyn Mailer> }
            pub struct ChangeUseCase { ports: ChangePorts }
            impl Command for ChangeUseCase {
                async fn execute(&self, caller: &(), auditor: &RequestAuditor, request: ChangeRequest) -> Result<(), AppError> {
                    let proof = ChangeProof::for_change(request.reason);
                    if proof == ChangeProof::NotPossible {
                        return Err(AppError::Forbidden);
                    }
                    if request.new_device {
                        self.ports.mailer.send_to_person(&request.email).await.or_internal()?;
                    }
                    Ok(())
                }
            }";

        let found = found(rule, change);

        assert!(found.findings.is_empty());
    }
}
