//! `rules.weaker-when-off`: a rule that answers something weaker when a
//! capability is not set up than when it is, all else the same.

use crate::finding::{Check, Finding, Found, Unsaid};
use crate::model::evaluate::{Body, EnumInfo, Evaluator, Index, Value};
use crate::model::gates::{Gate, GateKind};
use crate::model::rules::Rules;
use crate::model::rules::decisions::{Decision, Reading, Row};
use crate::source::syntax::core_type;

/// Every finding of the check.
pub(super) fn run(index: &Index<'_>, gates: &[Gate], rules: &Rules) -> Found {
    let evaluator = Evaluator::new(index);
    let mut found = Found::default();
    let worked_out = rules
        .decisions
        .iter()
        .filter(|decision| decision.reading == Reading::WorkedOut);
    for decision in worked_out {
        for gate in gates {
            let Some(switch) = Switch::of(gate, decision) else {
                continue;
            };
            let judge = Judge {
                decision,
                switch: &switch,
                order: order_of(index, &decision.outcome),
                evaluator: &evaluator,
            };
            judge.pairs(&mut found);
        }
    }
    found
}

/// A gate as one input of a rule: where it stands among the inputs, and
/// which of its values say set up and which do not.
struct Switch<'g> {
    gate: &'g Gate,
    answer: &'g str,
    at: usize,
    on: Vec<String>,
    off: &'g [String],
}

impl<'g> Switch<'g> {
    /// The input of `decision` that takes `gate`'s answer, when one does.
    fn of(gate: &'g Gate, decision: &Decision) -> Option<Self> {
        let (answer, off) = match &gate.kind {
            GateKind::Asked { answer, off, .. } | GateKind::Setting { answer, off } => {
                (answer.as_str(), off.as_slice())
            }
            GateKind::Optional { .. } => return None,
        };
        let at = decision.input_of(answer)?;
        let on = decision.inputs[at]
            .values
            .iter()
            .filter(|value| !off.contains(value))
            .cloned()
            .collect();
        Some(Self {
            gate,
            answer,
            at,
            on,
            off,
        })
    }

    fn says_off(&self, row: &Row) -> bool {
        row.when[self.at]
            .as_ref()
            .is_some_and(|value| self.off.contains(value))
    }

    fn may_say_on(&self, row: &Row) -> bool {
        row.when[self.at]
            .as_ref()
            .is_none_or(|value| self.on.contains(value))
    }
}

/// How the answers of a rule compare, as the code orders them.
enum Order<'i> {
    /// The answer enum derives `PartialOrd`: declared earlier is lower.
    Declared(&'i EnumInfo),
    /// One method maps each answer to an enum that derives `PartialOrd`.
    Mapped { method: Body<'i>, to: &'i EnumInfo },
    /// No order, and why.
    Unknown(String),
}

/// Where an answer stands in an order, and how to say so.
struct Rank {
    position: usize,
    said: String,
}

/// The order the code gives the answers of the enum `outcome`.
fn order_of<'i>(index: &'i Index<'_>, outcome: &str) -> Order<'i> {
    let Some(info) = index.enum_named(outcome) else {
        return Order::Unknown(format!("`{outcome}` is not one enum of the domain"));
    };
    if info.ordered {
        return Order::Declared(info);
    }
    let mappings: Vec<(Body<'i>, &'i EnumInfo)> = index
        .bodies()
        .filter(|body| body.owner.is_some_and(|owner| owner == outcome))
        .filter_map(|body| Some((body, ordered_answer(index, body, outcome)?)))
        .collect();
    match mappings.as_slice() {
        [(method, to)] => Order::Mapped {
            method: *method,
            to,
        },
        [] => Order::Unknown(format!(
            "`{outcome}` derives no `PartialOrd`, and no method maps it to an enum that does"
        )),
        _ => Order::Unknown(format!(
            "several methods map `{outcome}` to an ordered enum, and the code does not say which one orders it"
        )),
    }
}

/// The ordered enum `body`, a method of `outcome` taking only `self`,
/// answers with.
fn ordered_answer<'i>(index: &'i Index<'_>, body: Body<'_>, outcome: &str) -> Option<&'i EnumInfo> {
    let [syn::FnArg::Receiver(_)] = body.sig.inputs.iter().collect::<Vec<_>>().as_slice() else {
        return None;
    };
    let syn::ReturnType::Type(_, returned) = &body.sig.output else {
        return None;
    };
    let name = core_type(returned, Some(outcome)).filter(|name| name != outcome)?;
    index
        .enum_named(&name)
        .filter(|info| info.ordered && info.is_plain())
}

/// Compares the rows of one rule across one gate.
struct Judge<'a, 'i, 'f> {
    decision: &'a Decision,
    switch: &'a Switch<'a>,
    order: Order<'i>,
    evaluator: &'a Evaluator<'i, 'f>,
}

/// Two rows the same but for the gate, and their answers: `off` where it
/// says not set up, answering `weaker`, and `on` where it says set up,
/// answering `stronger`.
struct Paired<'r> {
    off: &'r Row,
    on: &'r Row,
    weaker: &'r str,
    stronger: &'r str,
}

impl Judge<'_, '_, '_> {
    /// Judges each pair of rows the same but for the gate, once per pair
    /// of answers.
    fn pairs(&self, found: &mut Found) {
        let mut judged: Vec<(Option<&str>, &str)> = Vec::new();
        for off in self
            .decision
            .rows
            .iter()
            .filter(|row| self.switch.says_off(row))
        {
            for on in self
                .decision
                .rows
                .iter()
                .filter(|row| self.pairs_with(off, row))
            {
                let Some(stronger) = on.outcome.as_deref() else {
                    continue;
                };
                let answers = (off.outcome.as_deref(), stronger);
                if answers.0 == Some(stronger) || judged.contains(&answers) {
                    continue;
                }
                judged.push(answers);
                self.judge(off, on, found);
            }
        }
    }

    /// Whether `on` may say set up where `off` says not, all else able to
    /// be the same.
    fn pairs_with(&self, off: &Row, on: &Row) -> bool {
        self.switch.may_say_on(on)
            && off
                .when
                .iter()
                .zip(&on.when)
                .enumerate()
                .filter(|(position, _)| *position != self.switch.at)
                .all(|(_, (a, b))| a.is_none() || b.is_none() || a == b)
    }

    fn judge(&self, off: &Row, on: &Row, found: &mut Found) {
        let Some(stronger) = on.outcome.as_deref() else {
            return;
        };
        let Some(weaker) = off.outcome.as_deref() else {
            found.leave_unsaid(self.unsaid(
                format!("{} when not set up", self.decision.subject),
                "the answer where it is not set up was not worked out".to_owned(),
            ));
            return;
        };
        let subject = format!("{} {weaker} when off", self.decision.subject);
        let ranks = self.rank(weaker).zip(self.rank(stronger));
        let Some((low, high)) = ranks else {
            found.leave_unsaid(self.unsaid(subject, self.unranked(weaker, stronger)));
            return;
        };
        if low.position >= high.position {
            return;
        }
        let paired = Paired {
            off,
            on,
            weaker,
            stronger,
        };
        let order = self.order_line(&low, &high);
        found.findings.push(self.finding(&paired, subject, order));
    }

    /// Why `weaker` and `stronger` are not compared: the order is not
    /// known, or where one of them stands in it was not worked out.
    fn unranked(&self, weaker: &str, stronger: &str) -> String {
        match &self.order {
            Order::Unknown(why) => format!(
                "it answers `{weaker}` where `{}` says not set up and `{stronger}` where it says set up, and {why}, so the two are not compared",
                self.switch.gate.name()
            ),
            Order::Declared(_) | Order::Mapped { .. } => {
                format!("where `{weaker}` or `{stronger}` stands in the order was not worked out")
            }
        }
    }

    /// Where `variant` stands in the order, when the code gives one.
    fn rank(&self, variant: &str) -> Option<Rank> {
        match &self.order {
            Order::Declared(info) => Some(Rank {
                position: info.position(variant)?,
                said: format!("`{variant}`"),
            }),
            Order::Mapped { method, to } => {
                let receiver = Value::variant(&self.decision.outcome, variant);
                let outcome = self.evaluator.run(*method, Some(receiver), Vec::new())?;
                let Value::Variant { ty, name } = outcome.value else {
                    return None;
                };
                (ty == to.name).then_some(())?;
                Some(Rank {
                    position: to.position(&name)?,
                    said: format!("`{variant}` to `{}::{name}`", to.name),
                })
            }
            Order::Unknown(_) => None,
        }
    }

    fn unsaid(&self, subject: String, why: String) -> Unsaid {
        Unsaid::new(
            Check::WeakerWhenOff,
            subject,
            self.decision.place.clone(),
            why,
        )
    }

    fn finding(&self, paired: &Paired<'_>, subject: String, order: String) -> Finding {
        let (weaker, stronger) = (paired.weaker, paired.stronger);
        let decision = self.decision;
        let gate = self.switch.gate.name();
        Finding::new(
            Check::WeakerWhenOff,
            paired.off.place.clone().unwrap_or_else(|| decision.place.clone()),
            subject,
            format!(
                "`{}` answers `{weaker}` where `{gate}` says not set up and `{stronger}` where it says set up, all else the same, and `{weaker}` is weaker in the order the code gives",
                decision.subject
            ),
        )
        .with_detail([
            format!(
                "rule:    {}:{}  {}",
                decision.place.file, decision.place.line, decision.subject
            ),
            row_said(decision, "off:     ", paired.off, weaker),
            row_said(decision, "on:      ", paired.on, stronger),
            order,
            format!(
                "gate:    {}:{}  {gate} answers {}",
                self.switch.gate.place.file, self.switch.gate.place.line, self.switch.answer
            ),
            "why: a deployment without the capability lets a person through on less than one with it".to_owned(),
            format!(
                "fix: answer `{stronger}`, or something as strong the deployment can complete, when `{}` says not set up",
                self.switch.answer
            ),
        ])
    }

    fn order_line(&self, low: &Rank, high: &Rank) -> String {
        match &self.order {
            Order::Declared(info) => format!(
                "order:   {}:{}  `{}` derives PartialOrd, and {} is declared before {}",
                info.place.file, info.place.line, info.name, low.said, high.said
            ),
            Order::Mapped { method, to } => {
                let at = method.place();
                format!(
                    "order:   {}:{}  `{}` maps {} and {}, and `{}` derives PartialOrd",
                    at.file,
                    at.line,
                    method.subject(),
                    low.said,
                    high.said,
                    to.name
                )
            }
            Order::Unknown(why) => format!("order:   {why}"),
        }
    }
}

/// Where `row` of `decision` answers `answer`, and when, after `label`.
fn row_said(decision: &Decision, label: &str, row: &Row, answer: &str) -> String {
    let at = row.place.clone().unwrap_or_else(|| decision.place.clone());
    let when = conditions(decision, row);
    format!("{label}{}:{}  {answer} when {when}", at.file, at.line)
}

/// A row's inputs, as `name = value`, `any` where it takes every value.
fn conditions(decision: &Decision, row: &Row) -> String {
    decision
        .inputs
        .iter()
        .zip(&row.when)
        .map(|(input, value)| format!("{} = {}", input.name, value.as_deref().unwrap_or("any")))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::domain::DomainLists;
    use crate::model::facts::Facts;
    use crate::model::{Model, gates};
    use crate::source::planted::{app, domain, workspace};

    /// Whether mail goes out, asked by a port.
    const MAIL: &str = "
        pub trait MailSetup: Send + Sync { fn reach(&self) -> MailReach; }
        pub trait Mailer: Send + Sync {
            async fn send_to_person(&self, to: &Email) -> Result<(), DomainError>;
        }";

    /// A rule of what a sign-in asks, mail reach among its inputs; `ORDER`
    /// is replaced by how the answer is ordered.
    const RULE: &str = "
        pub enum MailReach { Available, NotSetUp }
        pub enum Enrolment { Enrolled, NotEnrolled }
        ORDER
        pub enum Asked { Nothing, Password, Code }
        impl Asked {
            pub fn under(enrolment: Enrolment, mail: MailReach) -> Self {
                match (enrolment, mail) {
                    (Enrolment::Enrolled, MailReach::Available | MailReach::NotSetUp) => Self::Code,
                    (Enrolment::NotEnrolled, MailReach::Available) => Self::Password,
                    (Enrolment::NotEnrolled, MailReach::NotSetUp) => WHEN_OFF,
                }
            }
        }";

    fn found(order: &str, when_off: &str) -> Found {
        let rule = RULE.replace("ORDER", order).replace("WHEN_OFF", when_off);
        let ws = workspace(vec![
            domain("domains/authentication/asked.rs", &rule),
            app("ports/shared/mail.rs", MAIL),
        ]);
        let model = Model::build(&ws, &DomainLists::default());
        let facts = Facts::build(&ws, &model);
        let rules = Rules::build(&ws, &model, &facts);
        let files: Vec<_> = ws.layer(crate::source::Layer::Domain).collect();
        let index = Index::of(&files);
        run(&index, &gates::find(&ws, &model), &rules)
    }

    /// The answer enum derives `PartialOrd`; without mail the rule asks
    /// nothing where with mail it asks a password.
    #[test]
    fn an_answer_declared_lower_when_the_gate_is_off_is_weaker() {
        let found = found("#[derive(PartialOrd)]", "Self::Nothing");

        assert_eq!(found.findings.len(), 1);
        assert_eq!(found.findings[0].subject, "Asked::under Nothing when off");
        assert!(found.findings[0].message.starts_with(
            "`Asked::under` answers `Nothing` where `MailSetup::reach` says not set up and `Password` where it says set up"
        ));
    }

    /// Without mail the rule asks a code, which stands higher.
    #[test]
    fn an_answer_as_strong_or_stronger_when_the_gate_is_off_passes() {
        let found = found("#[derive(PartialOrd)]", "Self::Code");

        assert!(found.findings.is_empty());
        assert!(found.unsaid.is_empty());
    }

    /// No derive: one method maps each answer to an ordered strength.
    #[test]
    fn a_method_mapping_answers_to_an_ordered_enum_orders_them() {
        let mapping = "
            #[derive(PartialOrd)]
            pub enum Strength { None, Weak, Strong }
            impl Asked {
                pub fn strength(self) -> Strength {
                    match self {
                        Self::Nothing => Strength::None,
                        Self::Password => Strength::Weak,
                        Self::Code => Strength::Strong,
                    }
                }
            }";

        let found = found(mapping, "Self::Nothing");

        assert_eq!(found.findings.len(), 1);
        assert!(
            found.findings[0].detail[3]
                .contains("`Asked::strength` maps `Nothing` to `Strength::None`")
        );
    }

    /// No order at all: the answers differ, and the check says nothing but
    /// counts it.
    #[test]
    fn answers_with_no_order_in_the_code_are_left_unsaid() {
        let found = found("", "Self::Nothing");

        assert!(found.findings.is_empty());
        assert_eq!(found.unsaid[0].subject, "Asked::under Nothing when off");
        assert!(found.unsaid[0].why.contains("derives no `PartialOrd`"));
    }
}
