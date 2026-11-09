//! A card per status machine: its states, the moves it allows, its final
//! states, and the domain changes that move a value into each state, with
//! the use cases that call them and the rights they take.
//!
//! A change moves its aggregate into a state when it, or one of its own
//! functions it calls at most [`CALL_DEPTH`] deep, asks the machine for it
//! (`try_transition(Status::Done)`), writes it (`self.status =
//! State::Done(..)`, a state enum's variant read as the machine's state it
//! stands for), or, for a creator, starts the value in it (`Self { status:
//! Status::Pending, .. }`).

use std::collections::BTreeSet;

use serde::Serialize;
use syn::visit::{self, Visit};
use syn::{Expr, Member};

use crate::model::Model;
use crate::model::evaluate::{Body, Index};
use crate::model::facts::{ChangeFacts, Facts};
use crate::model::machines::{Machine, Machines, TRANSITION};
use crate::source::Place;
use crate::source::syntax::line_of;

/// How many of its own functions deep a change is read for the states it
/// moves into.
const CALL_DEPTH: usize = 2;

/// One status machine, with who moves it.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct MachineCard {
    /// The machine's enum.
    pub(crate) machine: String,
    /// The context it is in.
    pub(crate) context: String,
    /// Where its `try_transition` is.
    pub(crate) place: Place,
    /// Its states, in the order they are declared.
    pub(crate) states: Vec<String>,
    /// The moves it allows, `None` when its body is not worked out.
    pub(crate) moves: Option<Vec<(String, String)>>,
    /// The states no move leaves.
    pub(crate) finals: Vec<String>,
    /// The changes that move a value into a state.
    pub(crate) movers: Vec<Mover>,
}

/// A change that moves a value into a state.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Mover {
    /// The state.
    pub(crate) to: String,
    /// The change, as `Owner::name`.
    pub(crate) change: String,
    /// Where it moves it.
    pub(crate) place: Place,
    /// The caller proofs it takes.
    pub(crate) proofs: Vec<String>,
    /// The rights it checks, as written.
    pub(crate) rights: Vec<String>,
    /// The use cases that call it, as `UseCase (context)`.
    pub(crate) callers: Vec<String>,
}

/// A card for every machine of `model`, its movers read through `index`.
pub(crate) fn cards(model: &Model, facts: &Facts, index: &Index<'_>) -> Vec<MachineCard> {
    let machines = &model.domain.machines;
    let movers = movers(machines, facts, index);
    let mut cards: Vec<MachineCard> = machines
        .machines
        .iter()
        .map(|machine| card(machine, &movers))
        .collect();
    cards.sort_by(|a, b| (&a.context, &a.machine).cmp(&(&b.context, &b.machine)));
    cards
}

fn card(machine: &Machine, movers: &[(String, Mover)]) -> MachineCard {
    MachineCard {
        machine: machine.name.clone(),
        context: crate::model::context_of_path(&machine.place.file),
        place: machine.place.clone(),
        states: machine
            .variants
            .iter()
            .map(|(state, _)| state.clone())
            .collect(),
        moves: machine.moves.as_ref().map(|moves| {
            moves
                .iter()
                .filter(|(from, to)| from != to)
                .cloned()
                .collect()
        }),
        finals: machine
            .finals()
            .into_iter()
            .map(|(state, _)| state.clone())
            .collect(),
        movers: movers
            .iter()
            .filter(|(of, _)| *of == machine.name)
            .map(|(_, mover)| mover.clone())
            .collect(),
    }
}

/// Every change that moves a value of a machine into a state, as the
/// machine's name and the mover.
fn movers(machines: &Machines, facts: &Facts, index: &Index<'_>) -> Vec<(String, Mover)> {
    let mut found = Vec::new();
    for change in &facts.changes {
        let Some(body) = index.method(&change.owner, &change.name) else {
            continue;
        };
        let mut moves = OwnMoves {
            machines,
            index,
            owner: &change.owner,
            seen: BTreeSet::new(),
        };
        let mut moved = BTreeSet::new();
        for (machine, to, place) in moves.targets(body, 0) {
            if moved.insert((machine.clone(), to.clone())) {
                found.push((machine, mover(change, to, place)));
            }
        }
    }
    found
}

fn mover(change: &ChangeFacts, to: String, place: Place) -> Mover {
    Mover {
        to,
        change: change.subject(),
        place,
        proofs: change.takes.clone(),
        rights: change
            .rights
            .iter()
            .filter_map(|found| found.check.right.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        callers: change
            .callers
            .iter()
            .map(|caller| format!("{} ({})", caller.use_case, caller.context))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    }
}

/// The moves of one aggregate's change, read through its own functions:
/// the machines, every body, the aggregate, and the bodies read so far.
struct OwnMoves<'m, 'f> {
    machines: &'m Machines,
    index: &'m Index<'f>,
    owner: &'m str,
    seen: BTreeSet<String>,
}

impl OwnMoves<'_, '_> {
    /// The states `body`, and the aggregate's own functions it calls,
    /// move a value into, as `(machine, state, where)`.
    fn targets(&mut self, body: Body<'_>, depth: usize) -> Vec<(String, String, Place)> {
        if depth > CALL_DEPTH || !self.seen.insert(body.name()) {
            return Vec::new();
        }
        let mut finder = Targets {
            machines: self.machines,
            body,
            found: Vec::new(),
            calls: Vec::new(),
            handed: Vec::new(),
        };
        finder.visit_block(body.block);
        let mut found = finder.found;
        for (name, target) in finder.handed {
            if (self.index.method(self.owner, &name)).is_some_and(moves_what_it_is_handed) {
                found.push(target);
            }
        }
        for name in finder.calls {
            if let Some(inner) = self.index.method(self.owner, &name) {
                found.extend(self.targets(inner, depth + 1));
            }
        }
        found
    }
}

/// Whether `body` moves a value into a state it is handed: it asks the
/// machine, or writes a parameter to a field of `self`.
fn moves_what_it_is_handed(body: Body<'_>) -> bool {
    let mut finder = HandedMoves {
        params: body
            .sig
            .inputs
            .iter()
            .filter_map(|input| match input {
                syn::FnArg::Typed(typed) => match typed.pat.as_ref() {
                    syn::Pat::Ident(name) => Some(name.ident.to_string()),
                    _ => None,
                },
                syn::FnArg::Receiver(_) => None,
            })
            .collect(),
        moves: false,
    };
    finder.visit_block(body.block);
    finder.moves
}

/// Finds whether a body asks the machine or writes one of `params` to a
/// field of `self`.
struct HandedMoves {
    params: Vec<String>,
    moves: bool,
}

impl<'ast> Visit<'ast> for HandedMoves {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.moves |= call.method == TRANSITION;
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_assign(&mut self, assign: &'ast syn::ExprAssign) {
        let writes_self = matches!(assign.left.as_ref(), Expr::Field(field)
            if matches!(field.base.as_ref(), Expr::Path(path) if path.path.is_ident("self")));
        let handed = matches!(assign.right.as_ref(), Expr::Path(path)
            if path.path.get_ident().is_some_and(|name| self.params.contains(&name.to_string())));
        self.moves |= writes_self && handed;
        visit::visit_expr_assign(self, assign);
    }
}

/// Finds the states one body moves a value into, and the aggregate's own
/// functions it calls, with the states it hands them.
struct Targets<'m, 'f> {
    machines: &'m Machines,
    body: Body<'f>,
    found: Vec<(String, String, Place)>,
    calls: Vec<String>,
    handed: Vec<(String, (String, String, Place))>,
}

impl Targets<'_, '_> {
    /// The machine and its state the path `expr` names, such as
    /// `RunStatus::Completed`, or a state enum's `RunState::Completed(..)`.
    fn state_of(&self, expr: &Expr) -> Option<(String, String)> {
        let path = match expr {
            Expr::Path(path) => &path.path,
            Expr::Call(call) => match call.func.as_ref() {
                Expr::Path(path) => &path.path,
                _ => return None,
            },
            Expr::Struct(literal) => &literal.path,
            Expr::Paren(inner) => return self.state_of(&inner.expr),
            _ => return None,
        };
        let names: Vec<String> = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        let [.., ty, variant] = names.as_slice() else {
            return None;
        };
        let machine = self.machines.machine_of(ty)?;
        let state = self.machines.status_of(ty, variant)?;
        Some((machine.name.clone(), state))
    }

    fn note(&mut self, expr: &Expr, at: &impl syn::spanned::Spanned) {
        if let Some((machine, state)) = self.state_of(expr) {
            let place = Place::at(self.body.file, line_of(at));
            self.found.push((machine, state, place));
        }
    }
}

impl<'ast> Visit<'ast> for Targets<'_, '_> {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == TRANSITION
            && let Some(to) = call.args.first()
        {
            self.note(to, &call.method);
        }
        if matches!(call.receiver.as_ref(), Expr::Path(path) if path.path.is_ident("self")) {
            let name = call.method.to_string();
            for arg in &call.args {
                if let Some((machine, state)) = self.state_of(arg) {
                    let place = Place::at(self.body.file, line_of(&call.method));
                    self.handed.push((name.clone(), (machine, state, place)));
                }
            }
            self.calls.push(name);
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_assign(&mut self, assign: &'ast syn::ExprAssign) {
        if let Expr::Field(field) = assign.left.as_ref()
            && matches!(field.base.as_ref(), Expr::Path(path) if path.path.is_ident("self"))
        {
            self.note(&assign.right, &assign.left);
        }
        visit::visit_expr_assign(self, assign);
    }

    fn visit_expr_struct(&mut self, literal: &'ast syn::ExprStruct) {
        let own = literal.path.is_ident("Self");
        for field in literal.fields.iter().filter(|_| own) {
            if let Member::Named(_) = &field.member {
                self.note(&field.expr, &field.member);
            }
        }
        visit::visit_expr_struct(self, literal);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = call.func.as_ref()
            && let [first, second] = path.path.segments.iter().collect::<Vec<_>>()[..]
            && first.ident == "Self"
        {
            self.calls.push(second.ident.to_string());
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_item(&mut self, _item: &'ast syn::Item) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::domain::DomainLists;
    use crate::source::planted::{app, domain, workspace};

    /// An export's status machine: pending to ready to expired.
    const EXPORT_STATUS: &str = "pub enum ExportStatus { Pending, Ready, Expired }
                 impl ExportStatus {
                     pub fn try_transition(self, to: Self) -> Result<Self, InvalidTransition<Self>> {
                         checked(self, to, |from, to| {
                             matches!((from, to), (Self::Pending, Self::Ready) | (Self::Ready, Self::Expired))
                         })
                     }
                 }";

    /// An export finished with a right, and expired through a helper.
    const EXPORT: &str = "pub struct Export { status: ExportStatus }
                 impl Export {
                     pub fn reconstitute(row: ExportRow) -> Result<Self, DomainError> { make() }
                     pub fn finish(&mut self, by: &AuditControl<'_>) -> Result<(), DomainError> {
                         by.ensure_may(AuditAction::Export)?;
                         self.status = self.status.try_transition(ExportStatus::Ready)?;
                         Ok(())
                     }
                     pub fn expire(&mut self) -> Result<(), DomainError> { self.lapse() }
                     fn lapse(&mut self) -> Result<(), DomainError> {
                         self.status = self.status.try_transition(ExportStatus::Expired)?;
                         Ok(())
                     }
                 }";

    /// A command that finishes an export.
    const FINISH: &str = "pub struct FinishPorts;
                 pub struct FinishUseCase { ports: FinishPorts }
                 impl Command for FinishUseCase {
                     async fn execute(&self, caller: &CallerContext, auditor: &RequestAuditor, (): ()) -> Result<(), AppError> {
                         let mut export: Export = loaded();
                         export.finish(&control).map_err(AppError::from_domain)
                     }
                 }";

    /// An export moves to `Ready` by a change a use case calls with its
    /// right, and to `Expired` through a helper of its own.
    #[test]
    fn a_machine_card_names_its_moves_finals_and_who_moves_it() {
        let ws = workspace(vec![
            domain("domains/audit/status.rs", EXPORT_STATUS),
            domain("domains/audit/export.rs", EXPORT),
            app("use_cases/audit/finish.rs", FINISH),
        ]);
        let model = Model::build(&ws, &DomainLists::default());
        let facts = Facts::build(&ws, &model);
        let files: Vec<_> = ws.layer(crate::source::Layer::Domain).collect();
        let index = Index::of(&files);

        let found = cards(&model, &facts, &index);

        let card = &found[0];
        assert_eq!(card.finals, ["Expired"]);
        let moves = [("Pending", "Ready"), ("Ready", "Expired")]
            .map(|(from, to)| (from.to_owned(), to.to_owned()));
        assert_eq!(card.moves.as_deref(), Some(&moves[..]));
        let ready = card
            .movers
            .iter()
            .find(|mover| mover.to == "Ready")
            .unwrap();
        assert_eq!(ready.change, "Export::finish");
        assert_eq!(ready.rights, ["AuditAction::Export"]);
        assert_eq!(ready.callers, ["FinishUseCase (audit)"]);
        assert!(
            card.movers
                .iter()
                .any(|mover| mover.to == "Expired" && mover.change == "Export::expire")
        );
    }
}
