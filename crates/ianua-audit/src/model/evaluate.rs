//! Working out what a domain function hands back for given enum values.
//!
//! The domain decides many things by a `match` over enums, or over tuples
//! of them: what a sign-in still owes, which step a run takes next, whether
//! a status may move. Given a value for each input, those bodies can be
//! worked out by reading them: `match` and `if` with their guards, `let`
//! and `let .. else`, early returns and `?`, `Ok` and `Err`, comparisons,
//! `&&`, `||` and `!`, `matches!`, a variant written as `Type::Variant` or
//! `Self::Variant`, a field of `self` the caller set, and the functions of
//! any domain type or the file's free functions they call, at most
//! [`CALL_DEPTH`] deep. An enum that derives `PartialOrd` compares by the
//! order its variants are declared in. Anything else is not worked out:
//! the answer is `None`, never a guess.

use std::cell::RefCell;
use std::collections::BTreeMap;

use quote::ToTokens as _;
use syn::parse::{ParseStream, Parser};
use syn::{
    BinOp, Block, Expr, FnArg, ImplItemFn, Item, ItemEnum, ItemFn, Pat, Signature, Stmt, UnOp,
};

use crate::source::syntax::{impl_fns, inherent_impl_of, items_of, line_of};
use crate::source::{Place, SourceFile};

/// How many calls deep a body is worked out.
const CALL_DEPTH: usize = 8;

/// One enum of the domain.
#[derive(Clone, Debug)]
pub(crate) struct EnumInfo {
    /// Its name.
    pub(crate) name: String,
    /// Its variants, in the order they are declared.
    pub(crate) variants: Vec<VariantInfo>,
    /// Whether it derives `PartialOrd`, so its variants compare in the
    /// order they are declared.
    pub(crate) ordered: bool,
    /// Where it is declared.
    pub(crate) place: Place,
}

impl EnumInfo {
    /// Whether every variant carries no data, so its values can be listed.
    pub(crate) fn is_plain(&self) -> bool {
        self.variants.iter().all(|variant| !variant.fields)
    }

    /// The position of `variant` in the declaration.
    pub(crate) fn position(&self, variant: &str) -> Option<usize> {
        self.variants.iter().position(|found| found.name == variant)
    }
}

/// One variant of an enum.
#[derive(Clone, Debug)]
pub(crate) struct VariantInfo {
    /// Its name.
    pub(crate) name: String,
    /// Whether it carries data.
    pub(crate) fields: bool,
}

/// A function with a body, and the file it is written in.
#[derive(Clone, Copy)]
pub(crate) struct Body<'f> {
    /// The file.
    pub(crate) file: &'f SourceFile,
    /// The type whose `impl` holds it, or `None` for a free function.
    pub(crate) owner: Option<&'f proc_macro2::Ident>,
    /// Its signature.
    pub(crate) sig: &'f Signature,
    /// Its body.
    pub(crate) block: &'f Block,
    /// Its visibility.
    pub(crate) vis: &'f syn::Visibility,
    /// Its attributes, its doc comment among them.
    pub(crate) attrs: &'f [syn::Attribute],
}

impl<'f> Body<'f> {
    fn of_impl(
        file: &'f SourceFile,
        owner: &'f proc_macro2::Ident,
        function: &'f ImplItemFn,
    ) -> Self {
        Self {
            file,
            owner: Some(owner),
            sig: &function.sig,
            block: &function.block,
            vis: &function.vis,
            attrs: &function.attrs,
        }
    }

    fn free(file: &'f SourceFile, function: &'f ItemFn) -> Self {
        Self {
            file,
            owner: None,
            sig: &function.sig,
            block: &function.block,
            vis: &function.vis,
            attrs: &function.attrs,
        }
    }

    /// `Owner::name`, or the bare name of a free function.
    pub(crate) fn subject(&self) -> String {
        match self.owner {
            Some(owner) => format!("{owner}::{}", self.sig.ident),
            None => self.sig.ident.to_string(),
        }
    }

    /// Its name.
    pub(crate) fn name(&self) -> String {
        self.sig.ident.to_string()
    }

    /// Where it is declared.
    pub(crate) fn place(&self) -> Place {
        Place::of(self.file, &self.sig.ident)
    }
}

/// The domain's enums and the functions of its types, to work bodies out
/// with.
pub(crate) struct Index<'f> {
    enums: BTreeMap<String, Vec<Declared>>,
    methods: BTreeMap<String, BTreeMap<String, Vec<Body<'f>>>>,
    free: BTreeMap<String, Vec<Body<'f>>>,
}

/// An enum as declared: what it is, the file it is in, and whether code
/// outside its module sees it.
struct Declared {
    info: EnumInfo,
    file: String,
    shared: bool,
}

impl<'f> Index<'f> {
    /// The enums and functions of `files`.
    pub(crate) fn of(files: &[&'f SourceFile]) -> Self {
        let mut index = Self {
            enums: BTreeMap::new(),
            methods: BTreeMap::new(),
            free: BTreeMap::new(),
        };
        for file in files {
            index.read(file);
        }
        index
    }

    fn read(&mut self, file: &'f SourceFile) {
        let Some(syntax) = file.syntax() else {
            return;
        };
        for item in items_of(syntax) {
            match item {
                Item::Enum(declared) => self.add_enum(file, declared),
                Item::Fn(function) => self
                    .free
                    .entry(function.sig.ident.to_string())
                    .or_default()
                    .push(Body::free(file, function)),
                Item::Impl(block) => self.add_impl(file, block),
                _ => {}
            }
        }
    }

    fn add_enum(&mut self, file: &SourceFile, declared: &ItemEnum) {
        let info = EnumInfo {
            name: declared.ident.to_string(),
            variants: declared
                .variants
                .iter()
                .map(|variant| VariantInfo {
                    name: variant.ident.to_string(),
                    fields: !variant.fields.is_empty(),
                })
                .collect(),
            ordered: derives(&declared.attrs, "PartialOrd"),
            place: Place::of(file, &declared.ident),
        };
        self.enums
            .entry(info.name.clone())
            .or_default()
            .push(Declared {
                info,
                file: file.display_path(),
                shared: !matches!(declared.vis, syn::Visibility::Inherited),
            });
    }

    fn add_impl(&mut self, file: &'f SourceFile, block: &'f syn::ItemImpl) {
        if inherent_impl_of(block).is_none() {
            return;
        }
        let Some(owner) = owner_ident(block) else {
            return;
        };
        for function in impl_fns(block) {
            self.methods
                .entry(owner.to_string())
                .or_default()
                .entry(function.sig.ident.to_string())
                .or_default()
                .push(Body::of_impl(file, owner, function));
        }
    }

    /// The enum named `name` code across the domain sees: the only one of
    /// that name, or the only one of them not private to its module.
    pub(crate) fn enum_named(&self, name: &str) -> Option<&EnumInfo> {
        let declared = self.enums.get(name)?;
        if let [only] = declared.as_slice() {
            return Some(&only.info);
        }
        let shared: Vec<&Declared> = declared.iter().filter(|found| found.shared).collect();
        match shared.as_slice() {
            [only] => Some(&only.info),
            _ => None,
        }
    }

    /// The function `name` of the type `owner`, when it has exactly one,
    /// those of a type of that name private to its module left out when
    /// there are several.
    pub(crate) fn method(&self, owner: &str, name: &str) -> Option<Body<'f>> {
        let bodies = self.methods.get(owner)?.get(name)?;
        if let [only] = bodies.as_slice() {
            return Some(*only);
        }
        let private: Vec<&str> = self
            .enums
            .get(owner)
            .into_iter()
            .flatten()
            .filter(|found| !found.shared)
            .map(|found| found.file.as_str())
            .collect();
        let seen: Vec<&Body<'f>> = bodies
            .iter()
            .filter(|body| !private.contains(&body.file.display_path().as_str()))
            .collect();
        match seen.as_slice() {
            [only] => Some(**only),
            _ => None,
        }
    }

    /// Every function with a body: those of every type, then the free ones.
    pub(crate) fn bodies(&self) -> impl Iterator<Item = Body<'f>> + '_ {
        self.methods
            .values()
            .flat_map(BTreeMap::values)
            .chain(self.free.values())
            .flatten()
            .copied()
    }

    /// The free function `name` written in `file`, or the only one of that
    /// name in the domain.
    fn free_function(&self, file: &SourceFile, name: &str) -> Option<Body<'f>> {
        let found = self.free.get(name)?;
        if let Some(local) = found.iter().find(|body| std::ptr::eq(body.file, file)) {
            return Some(*local);
        }
        match found.as_slice() {
            [only] => Some(*only),
            _ => None,
        }
    }
}

/// The last name of the type an `impl` block is for.
fn owner_ident(block: &syn::ItemImpl) -> Option<&proc_macro2::Ident> {
    let syn::Type::Path(path) = block.self_ty.as_ref() else {
        return None;
    };
    path.path.segments.last().map(|segment| &segment.ident)
}

/// Whether `attributes` derive `name`.
pub(crate) fn derives(attributes: &[syn::Attribute], name: &str) -> bool {
    attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("derive"))
        .any(|attribute| {
            attribute
                .meta
                .to_token_stream()
                .to_string()
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .any(|word| word == name)
        })
}

/// A value a body is worked out with.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Value {
    /// A variant of an enum, by the enum's and the variant's names.
    Variant {
        /// The enum.
        ty: String,
        /// The variant.
        name: String,
    },
    /// A truth value.
    Bool(bool),
    /// A tuple.
    Tuple(Vec<Value>),
    /// A list, such as `&[Self::Active, Self::Closed]`.
    List(Vec<Value>),
    /// `Ok(..)`.
    Ok(Box<Value>),
    /// `Err(..)`, whatever it holds.
    Err,
    /// Nothing.
    Unit,
    /// A value of a struct, with the fields the caller set.
    Record {
        /// The struct.
        ty: String,
        /// Its fields that are known.
        fields: BTreeMap<String, Value>,
    },
}

impl Value {
    /// The variant `name` of the enum `ty`.
    pub(crate) fn variant(ty: &str, name: &str) -> Self {
        Self::Variant {
            ty: ty.to_owned(),
            name: name.to_owned(),
        }
    }

    /// The type whose functions a method called on it is looked up in.
    fn type_name(&self) -> Option<&str> {
        match self {
            Self::Variant { ty, .. } | Self::Record { ty, .. } => Some(ty),
            _ => None,
        }
    }
}

/// What a body worked out to, and the last branch that decided it.
#[derive(Clone, Debug)]
pub(crate) struct Outcome {
    /// The value it hands back.
    pub(crate) value: Value,
    /// Where the last `match` arm or `if` branch taken on its way is.
    pub(crate) decided_at: Option<Place>,
}

/// Where a body goes on: on with a value, or back to its caller.
enum Flow {
    On(Value),
    Back(Value),
}

/// Local names and what they hold.
type Env = BTreeMap<String, Value>;

/// Whether a pattern matched, with what it bound.
enum Matched {
    Yes(Vec<(String, Value)>),
    No,
}

/// Works bodies out against an [`Index`].
pub(crate) struct Evaluator<'i, 'f> {
    index: &'i Index<'f>,
    taken: RefCell<Vec<Place>>,
}

/// What a function is called with: the value it is called on, if any,
/// and its arguments in order.
struct Called {
    receiver: Option<Value>,
    args: Vec<Value>,
}

impl Called {
    /// A call with no value to call it on.
    fn free(args: Vec<Value>) -> Self {
        Self {
            receiver: None,
            args,
        }
    }

    /// A method call on `receiver`.
    fn on(receiver: Value, args: Vec<Value>) -> Self {
        Self {
            receiver: Some(receiver),
            args,
        }
    }
}

/// The function a body is in, while it is worked out.
#[derive(Clone, Copy)]
struct Frame<'f> {
    body: Body<'f>,
    depth: usize,
}

impl<'i, 'f> Evaluator<'i, 'f> {
    /// An evaluator over `index`.
    pub(crate) fn new(index: &'i Index<'f>) -> Self {
        Self {
            index,
            taken: RefCell::new(Vec::new()),
        }
    }

    /// `body` called on `receiver` with `args`, worked out; `None` when any
    /// part of its way is not.
    pub(crate) fn run(
        &self,
        body: Body<'f>,
        receiver: Option<Value>,
        args: Vec<Value>,
    ) -> Option<Outcome> {
        self.taken.borrow_mut().clear();
        let value = self.call(body, Called { receiver, args }, 0)?;
        Some(Outcome {
            value,
            decided_at: self.taken.borrow().last().cloned(),
        })
    }

    /// Whether a statement of `body` written before `line` is sure to turn
    /// `receiver` away: a `let .. else` whose pattern it does not match, an
    /// `if` that returns and whose condition holds for it, or a `?` on a
    /// call that fails for it, the aggregate's own functions read for the
    /// same guards. A statement the evaluator cannot work out is passed
    /// over, so `false` says only that no exit was shown.
    pub(crate) fn turned_away(&self, body: Body<'f>, receiver: Value, line: usize) -> bool {
        self.turned_away_at(Frame { body, depth: 0 }, receiver, line)
    }

    fn turned_away_at(&self, frame: Frame<'f>, receiver: Value, line: usize) -> bool {
        if frame.depth > CALL_DEPTH {
            return false;
        }
        let mut vars = Env::new();
        vars.insert("self".to_owned(), receiver);
        frame
            .body
            .block
            .stmts
            .iter()
            .take_while(|statement| line_of(*statement) < line)
            .any(|statement| self.exits(statement, &mut vars, frame))
    }

    /// Whether `statement` is sure to leave the function.
    fn exits(&self, statement: &Stmt, vars: &mut Env, frame: Frame<'f>) -> bool {
        match statement {
            Stmt::Local(local) => self.let_exits(local, vars, frame),
            Stmt::Expr(Expr::If(branch), _)
                if branch.else_branch.is_none() && diverges(&branch.then_branch) =>
            {
                self.value(&branch.cond, vars, frame) == Some(Value::Bool(true))
            }
            Stmt::Expr(expr @ Expr::Try(_), _) => self.tried_exits(expr, vars, frame),
            Stmt::Expr(..) | Stmt::Item(_) | Stmt::Macro(_) => false,
        }
    }

    fn let_exits(&self, local: &syn::Local, vars: &mut Env, frame: Frame<'f>) -> bool {
        let Some(init) = &local.init else {
            return false;
        };
        if init.diverge.is_none() {
            return matches!(init.expr.as_ref(), Expr::Try(_))
                && self.tried_exits(&init.expr, vars, frame);
        }
        let Some(value) = self.value(&init.expr, vars, frame) else {
            return false;
        };
        match self.matches(&local.pat, &value) {
            Some(Matched::Yes(bound)) => {
                vars.extend(bound);
                false
            }
            Some(Matched::No) => true,
            None => false,
        }
    }

    /// Whether `expr`, a `?`, is sure to fail: worked out whole, or, for a
    /// call of the aggregate's own function such as `self.push(..)?` that is
    /// not, through that function's own guards.
    fn tried_exits(&self, expr: &Expr, vars: &mut Env, frame: Frame<'f>) -> bool {
        match self.expr(expr, vars, frame) {
            Some(Flow::Back(_)) => true,
            Some(Flow::On(_)) => false,
            None => self.own_exits(expr, vars, frame),
        }
    }

    fn own_exits(&self, expr: &Expr, vars: &Env, frame: Frame<'f>) -> bool {
        let Expr::Try(tried) = expr else {
            return false;
        };
        let Expr::MethodCall(call) = strip_await(&tried.expr) else {
            return false;
        };
        let Some(receiver) = self.value(&call.receiver, &mut vars.clone(), frame) else {
            return false;
        };
        let Some(body) = receiver
            .type_name()
            .and_then(|ty| self.index.method(ty, &call.method.to_string()))
        else {
            return false;
        };
        let end = body.block.stmts.last().map_or(0, line_of) + 1;
        let inner = Frame {
            body,
            depth: frame.depth + 1,
        };
        self.turned_away_at(inner, receiver, end)
    }

    fn call(&self, body: Body<'f>, called: Called, depth: usize) -> Option<Value> {
        if depth > CALL_DEPTH {
            return None;
        }
        let Called { mut receiver, args } = called;
        let mut vars = Env::new();
        let mut args = args.into_iter();
        for input in &body.sig.inputs {
            match input {
                FnArg::Receiver(_) => {
                    vars.insert("self".to_owned(), receiver.take()?);
                }
                FnArg::Typed(typed) => {
                    let value = args.next()?;
                    bind(&typed.pat, value, &mut vars)?;
                }
            }
        }
        let frame = Frame { body, depth };
        match self.block(body.block, &mut vars, frame)? {
            Flow::On(value) | Flow::Back(value) => Some(value),
        }
    }

    fn block(&self, block: &Block, vars: &mut Env, frame: Frame<'f>) -> Option<Flow> {
        let mut last = Value::Unit;
        for statement in &block.stmts {
            last = match statement {
                Stmt::Local(local) => {
                    if let Some(back) = self.local(local, vars, frame)? {
                        return Some(Flow::Back(back));
                    }
                    Value::Unit
                }
                Stmt::Expr(expr, semi) => match self.expr(expr, vars, frame)? {
                    Flow::Back(value) => return Some(Flow::Back(value)),
                    Flow::On(_) if semi.is_some() => Value::Unit,
                    Flow::On(value) => value,
                },
                Stmt::Macro(invoked) => {
                    let value = self.macro_value(&invoked.mac, vars, frame)?;
                    match invoked.semi_token {
                        Some(_) => Value::Unit,
                        None => value,
                    }
                }
                Stmt::Item(_) => return None,
            };
        }
        Some(Flow::On(last))
    }

    /// Binds a `let`; hands back what a `let .. else` leaves with.
    fn local(&self, local: &syn::Local, vars: &mut Env, frame: Frame<'f>) -> Option<Option<Value>> {
        let init = local.init.as_ref()?;
        let value = match self.expr(&init.expr, vars, frame)? {
            Flow::On(value) => value,
            Flow::Back(back) => return Some(Some(back)),
        };
        let Some((_, otherwise)) = &init.diverge else {
            bind(&local.pat, value, vars)?;
            return Some(None);
        };
        match self.matches(&local.pat, &value)? {
            Matched::Yes(bound) => {
                vars.extend(bound);
                Some(None)
            }
            Matched::No => match self.expr(otherwise, &mut vars.clone(), frame)? {
                Flow::Back(back) => Some(Some(back)),
                Flow::On(_) => None,
            },
        }
    }

    fn value(&self, expr: &Expr, vars: &mut Env, frame: Frame<'f>) -> Option<Value> {
        match self.expr(expr, vars, frame)? {
            Flow::On(value) => Some(value),
            Flow::Back(_) => None,
        }
    }

    /// `return`, with what it hands back.
    fn returned(&self, back: &syn::ExprReturn, vars: &mut Env, frame: Frame<'f>) -> Option<Flow> {
        let value = match &back.expr {
            Some(inner) => self.value(inner, vars, frame)?,
            None => Value::Unit,
        };
        Some(Flow::Back(value))
    }

    /// `expr?`: on with what an `Ok` holds, back with an `Err`.
    fn tried(&self, tried: &syn::ExprTry, vars: &mut Env, frame: Frame<'f>) -> Option<Flow> {
        match self.value(&tried.expr, vars, frame)? {
            Value::Ok(inner) => Some(Flow::On(*inner)),
            Value::Err => Some(Flow::Back(Value::Err)),
            _ => None,
        }
    }

    fn expr(&self, expr: &Expr, vars: &mut Env, frame: Frame<'f>) -> Option<Flow> {
        let value = match expr {
            Expr::Paren(inner) => return self.expr(&inner.expr, vars, frame),
            Expr::Group(inner) => return self.expr(&inner.expr, vars, frame),
            Expr::Block(inner) => return self.block(&inner.block, &mut vars.clone(), frame),
            Expr::If(branch) => return self.branch(branch, vars, frame),
            Expr::Match(choice) => return self.choice(choice, vars, frame),
            Expr::Return(back) => return self.returned(back, vars, frame),
            Expr::Try(tried) => return self.tried(tried, vars, frame),
            Expr::Reference(inner) => self.value(&inner.expr, vars, frame)?,
            Expr::Unary(unary) => self.unary(unary, vars, frame)?,
            Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Bool(truth),
                ..
            }) => Value::Bool(truth.value),
            Expr::Path(path) => self.path_value(&path.path, vars, frame)?,
            Expr::Field(field) => self.field(field, vars, frame)?,
            Expr::Tuple(tuple) => Value::Tuple(self.values(tuple.elems.iter(), vars, frame)?),
            Expr::Array(array) => Value::List(self.values(array.elems.iter(), vars, frame)?),
            Expr::Binary(binary) => self.binary(binary, vars, frame)?,
            Expr::Call(call) => self.function_call(call, vars, frame)?,
            Expr::MethodCall(call) => self.method_call(call, vars, frame)?,
            Expr::Macro(invoked) => self.macro_value(&invoked.mac, vars, frame)?,
            _ => return None,
        };
        Some(Flow::On(value))
    }

    fn branch(&self, branch: &syn::ExprIf, vars: &mut Env, frame: Frame<'f>) -> Option<Flow> {
        let Value::Bool(holds) = self.value(&branch.cond, vars, frame)? else {
            return None;
        };
        if holds {
            self.take(Place::of(frame.body.file, &branch.then_branch));
            return self.block(&branch.then_branch, &mut vars.clone(), frame);
        }
        match &branch.else_branch {
            Some((_, otherwise)) => {
                self.take(Place::of(frame.body.file, otherwise));
                self.expr(otherwise, vars, frame)
            }
            None => Some(Flow::On(Value::Unit)),
        }
    }

    fn choice(&self, choice: &syn::ExprMatch, vars: &mut Env, frame: Frame<'f>) -> Option<Flow> {
        let scrutinee = self.value(&choice.expr, vars, frame)?;
        for arm in &choice.arms {
            let Matched::Yes(bound) = self.matches(&arm.pat, &scrutinee)? else {
                continue;
            };
            let mut inner = vars.clone();
            inner.extend(bound);
            if let Some((_, guard)) = &arm.guard {
                let Value::Bool(holds) = self.value(guard, &mut inner, frame)? else {
                    return None;
                };
                if !holds {
                    continue;
                }
            }
            if !hands_on(&arm.body) {
                self.take(Place::of(frame.body.file, &arm.pat));
            }
            return self.expr(&arm.body, &mut inner, frame);
        }
        None
    }

    fn take(&self, place: Place) {
        self.taken.borrow_mut().push(place);
    }

    fn unary(&self, unary: &syn::ExprUnary, vars: &mut Env, frame: Frame<'f>) -> Option<Value> {
        let inner = self.value(&unary.expr, vars, frame)?;
        match (unary.op, inner) {
            (UnOp::Not(_), Value::Bool(truth)) => Some(Value::Bool(!truth)),
            (UnOp::Deref(_), value) => Some(value),
            _ => None,
        }
    }

    fn binary(&self, binary: &syn::ExprBinary, vars: &mut Env, frame: Frame<'f>) -> Option<Value> {
        let left = self.value(&binary.left, vars, frame)?;
        match (binary.op, &left) {
            (BinOp::And(_), Value::Bool(false)) => return Some(Value::Bool(false)),
            (BinOp::Or(_), Value::Bool(true)) => return Some(Value::Bool(true)),
            _ => {}
        }
        let right = self.value(&binary.right, vars, frame)?;
        match binary.op {
            BinOp::And(_) | BinOp::Or(_) => match right {
                Value::Bool(truth) => Some(Value::Bool(truth)),
                _ => None,
            },
            BinOp::Eq(_) => self.equal(&left, &right).map(Value::Bool),
            BinOp::Ne(_) => self.equal(&left, &right).map(|same| Value::Bool(!same)),
            BinOp::Lt(_) => Some(Value::Bool(self.order(&left, &right)?.is_lt())),
            BinOp::Le(_) => Some(Value::Bool(self.order(&left, &right)?.is_le())),
            BinOp::Gt(_) => Some(Value::Bool(self.order(&left, &right)?.is_gt())),
            BinOp::Ge(_) => Some(Value::Bool(self.order(&left, &right)?.is_ge())),
            _ => None,
        }
    }

    /// Whether two values are equal; `None` for two variants of one name
    /// that carry data the evaluator does not hold.
    fn equal(&self, left: &Value, right: &Value) -> Option<bool> {
        match (left, right) {
            (Value::Variant { ty, name }, Value::Variant { name: other, .. })
                if name == other && self.carries_data(ty, name) =>
            {
                None
            }
            (Value::Variant { name, .. }, Value::Variant { name: other, .. }) => {
                Some(name == other)
            }
            (Value::Bool(a), Value::Bool(b)) => Some(a == b),
            (Value::Tuple(a), Value::Tuple(b)) if a.len() == b.len() => a
                .iter()
                .zip(b)
                .try_fold(true, |all, (x, y)| Some(all && self.equal(x, y)?)),
            _ => None,
        }
    }

    fn carries_data(&self, ty: &str, name: &str) -> bool {
        self.index.enum_named(ty).is_none_or(|info| {
            info.variants
                .iter()
                .any(|variant| variant.name == name && variant.fields)
        })
    }

    /// How two variants of an ordered enum compare.
    fn order(&self, left: &Value, right: &Value) -> Option<std::cmp::Ordering> {
        let (
            Value::Variant { ty, name },
            Value::Variant {
                ty: other,
                name: right,
            },
        ) = (left, right)
        else {
            return None;
        };
        let info = self
            .index
            .enum_named(ty)
            .filter(|info| info.ordered && ty == other)?;
        Some(info.position(name)?.cmp(&info.position(right)?))
    }

    fn path_value(&self, path: &syn::Path, vars: &Env, frame: Frame<'f>) -> Option<Value> {
        let names: Vec<String> = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        match names.as_slice() {
            [name] => vars.get(name).cloned(),
            [.., owner, variant] => {
                let ty = self.enum_type(owner, frame)?;
                self.index.enum_named(&ty)?.position(variant)?;
                Some(Value::variant(&ty, variant))
            }
            [] => None,
        }
    }

    /// The enum `written` names in `frame`'s body: itself, or the body's own
    /// type for `Self`.
    fn enum_type(&self, written: &str, frame: Frame<'f>) -> Option<String> {
        let name = match written {
            "Self" => frame.body.owner?.to_string(),
            other => other.to_owned(),
        };
        self.index.enum_named(&name).map(|info| info.name.clone())
    }

    fn field(&self, field: &syn::ExprField, vars: &mut Env, frame: Frame<'f>) -> Option<Value> {
        let syn::Member::Named(member) = &field.member else {
            return None;
        };
        let Value::Record { fields, .. } = self.value(&field.base, vars, frame)? else {
            return None;
        };
        fields.get(&member.to_string()).cloned()
    }

    /// `Ok(inner)`, with the value of its one argument.
    fn ok_value(&self, call: &syn::ExprCall, vars: &mut Env, frame: Frame<'f>) -> Option<Value> {
        let [inner] = call.args.iter().collect::<Vec<_>>()[..] else {
            return None;
        };
        Some(Value::Ok(Box::new(self.value(inner, vars, frame)?)))
    }

    fn function_call(
        &self,
        call: &syn::ExprCall,
        vars: &mut Env,
        frame: Frame<'f>,
    ) -> Option<Value> {
        let Expr::Path(function) = call.func.as_ref() else {
            return None;
        };
        let names: Vec<String> = (function.path.segments.iter())
            .map(|segment| segment.ident.to_string())
            .collect();
        match names.as_slice() {
            [name] if name == "Ok" => self.ok_value(call, vars, frame),
            [name] if name == "Err" => Some(Value::Err),
            [name] => {
                let body = self.index.free_function(frame.body.file, name)?;
                let args = self.values(call.args.iter(), vars, frame)?;
                self.call(body, Called::free(args), frame.depth + 1)
            }
            [.., owner, name] => {
                let owner = (owner != "Self").then(|| owner.clone());
                let owner = owner.or_else(|| Some(frame.body.owner?.to_string()))?;
                if let Some(info) = self.index.enum_named(&owner)
                    && info.position(name).is_some()
                {
                    return Some(Value::variant(&owner, name));
                }
                let body = self.index.method(&owner, name)?;
                let args = self.values(call.args.iter(), vars, frame)?;
                self.call(body, Called::free(args), frame.depth + 1)
            }
            [] => None,
        }
    }

    fn method_call(
        &self,
        call: &syn::ExprMethodCall,
        vars: &mut Env,
        frame: Frame<'f>,
    ) -> Option<Value> {
        let receiver = self.value(&call.receiver, vars, frame)?;
        let name = call.method.to_string();
        let args = self.values(call.args.iter(), vars, frame)?;
        if let Some(found) = self.built_in(&name, &receiver, &args) {
            return found;
        }
        let body = self.index.method(receiver.type_name()?, &name)?;
        self.call(body, Called::on(receiver, args), frame.depth + 1)
    }

    /// The standard methods worked out without a body; `None` when `name`
    /// is not one of them.
    fn built_in(&self, name: &str, receiver: &Value, args: &[Value]) -> Option<Option<Value>> {
        let found = match (name, receiver, args) {
            ("contains", Value::List(items), [wanted]) => {
                let mut found = false;
                for item in items {
                    match self.equal(item, wanted) {
                        Some(same) => found |= same,
                        None => return Some(None),
                    }
                }
                Some(Value::Bool(found))
            }
            ("is_ok", Value::Ok(_), []) | ("is_err", Value::Err, []) => Some(Value::Bool(true)),
            ("is_ok", Value::Err, []) | ("is_err", Value::Ok(_), []) => Some(Value::Bool(false)),
            ("clone" | "to_owned", _, []) => Some(receiver.clone()),
            ("max", _, [other]) => (self.order(receiver, other))
                .map(|order| (if order.is_lt() { other } else { receiver }).clone()),
            ("min", _, [other]) => (self.order(receiver, other))
                .map(|order| (if order.is_gt() { other } else { receiver }).clone()),
            _ => return None,
        };
        Some(found)
    }

    fn values<'x>(
        &self,
        exprs: impl Iterator<Item = &'x Expr>,
        vars: &mut Env,
        frame: Frame<'f>,
    ) -> Option<Vec<Value>> {
        exprs.map(|expr| self.value(expr, vars, frame)).collect()
    }

    /// `matches!(value, pattern)`; any other macro is not worked out.
    fn macro_value(&self, invoked: &syn::Macro, vars: &mut Env, frame: Frame<'f>) -> Option<Value> {
        if !invoked.path.is_ident("matches") {
            return None;
        }
        let (expr, pattern) = matches_parts.parse2(invoked.tokens.clone()).ok()?;
        let value = self.value(&expr, vars, frame)?;
        match self.matches(&pattern, &value)? {
            Matched::Yes(_) => Some(Value::Bool(true)),
            Matched::No => Some(Value::Bool(false)),
        }
    }

    /// Whether one of the `choices` matches `value`, with what the first
    /// that does binds; `None` once one cannot be decided.
    fn any_matches(&self, choices: &syn::PatOr, value: &Value) -> Option<Matched> {
        for case in &choices.cases {
            if let Matched::Yes(bound) = self.matches(case, value)? {
                return Some(Matched::Yes(bound));
            }
        }
        Some(Matched::No)
    }

    /// Whether `pattern` matches `value`; `None` for a pattern the
    /// evaluator cannot decide.
    fn matches(&self, pattern: &Pat, value: &Value) -> Option<Matched> {
        match pattern {
            Pat::Wild(_) | Pat::Rest(_) => Some(Matched::Yes(Vec::new())),
            Pat::Paren(inner) => self.matches(&inner.pat, value),
            Pat::Reference(inner) => self.matches(&inner.pat, value),
            Pat::Ident(binding) if binding.subpat.is_none() => {
                let name = binding.ident.to_string();
                if name.starts_with(|c: char| c.is_ascii_uppercase()) {
                    return variant_matches(&name, value);
                }
                Some(Matched::Yes(vec![(name, value.clone())]))
            }
            Pat::Path(path) => variant_matches(&last_name(&path.path)?, value),
            Pat::TupleStruct(tuple) => self.tuple_struct_matches(tuple, value),
            Pat::Struct(fields) => variant_matches(&last_name(&fields.path)?, value),
            Pat::Tuple(tuple) => self.tuple_matches(tuple, value),
            Pat::Or(choices) => self.any_matches(choices, value),
            Pat::Lit(syn::PatLit {
                lit: syn::Lit::Bool(truth),
                ..
            }) => match value {
                Value::Bool(held) if *held == truth.value => Some(Matched::Yes(Vec::new())),
                Value::Bool(_) => Some(Matched::No),
                _ => None,
            },
            _ => None,
        }
    }

    /// `Ok(x)`, `Err(_)` or `Variant(..)`: the inner patterns of a variant
    /// bind nothing, since the evaluator does not hold variants' data.
    fn tuple_struct_matches(&self, tuple: &syn::PatTupleStruct, value: &Value) -> Option<Matched> {
        let name = last_name(&tuple.path)?;
        match (name.as_str(), value) {
            ("Ok", Value::Ok(inner)) => {
                let [only] = tuple.elems.iter().collect::<Vec<_>>()[..] else {
                    return None;
                };
                self.matches(only, inner)
            }
            ("Ok", Value::Err) | ("Err", Value::Ok(_)) => Some(Matched::No),
            ("Err", Value::Err) => Some(Matched::Yes(Vec::new())),
            _ => variant_matches(&name, value),
        }
    }

    fn tuple_matches(&self, tuple: &syn::PatTuple, value: &Value) -> Option<Matched> {
        let Value::Tuple(parts) = value else {
            return None;
        };
        if parts.len() != tuple.elems.len() {
            return None;
        }
        let mut bound = Vec::new();
        for (pattern, part) in tuple.elems.iter().zip(parts) {
            match self.matches(pattern, part)? {
                Matched::Yes(more) => bound.extend(more),
                Matched::No => return Some(Matched::No),
            }
        }
        Some(Matched::Yes(bound))
    }
}

/// Whether an arm only hands on a value decided before it: `self`, or a
/// name it bound.
fn hands_on(body: &Expr) -> bool {
    matches!(body, Expr::Path(path) if path
        .path
        .get_ident()
        .is_some_and(|name| name.to_string().starts_with(|c: char| c.is_ascii_lowercase())))
}

/// Whether `block` always leaves the function: it ends in `return`.
fn diverges(block: &Block) -> bool {
    matches!(block.stmts.last(), Some(Stmt::Expr(Expr::Return(_), _)))
}

fn strip_await(expr: &Expr) -> &Expr {
    match expr {
        Expr::Await(inner) => strip_await(&inner.base),
        Expr::Paren(inner) => strip_await(&inner.expr),
        Expr::MethodCall(call) if call.method == "map_err" => strip_await(&call.receiver),
        other => other,
    }
}

/// Whether the variant named `name` matches `value`.
fn variant_matches(name: &str, value: &Value) -> Option<Matched> {
    let Value::Variant { name: held, .. } = value else {
        return None;
    };
    Some(match held == name {
        true => Matched::Yes(Vec::new()),
        false => Matched::No,
    })
}

fn last_name(path: &syn::Path) -> Option<String> {
    path.segments
        .last()
        .map(|segment| segment.ident.to_string())
}

/// Binds `value` to a parameter or `let` pattern: a name, `_`, or a name
/// with its type written.
fn bind(pattern: &Pat, value: Value, vars: &mut Env) -> Option<()> {
    match pattern {
        Pat::Ident(binding) if binding.subpat.is_none() => {
            vars.insert(binding.ident.to_string(), value);
            Some(())
        }
        Pat::Type(typed) => bind(&typed.pat, value, vars),
        Pat::Wild(_) => Some(()),
        _ => None,
    }
}

/// The parts of `matches!(expr, pattern)`; a guard is refused.
fn matches_parts(input: ParseStream<'_>) -> syn::Result<(Expr, Pat)> {
    let expr: Expr = input.parse()?;
    input.parse::<syn::Token![,]>()?;
    let pattern = Pat::parse_multi_with_leading_vert(input)?;
    if input.peek(syn::Token![if]) {
        return Err(input.error("a guard"));
    }
    input.parse::<Option<syn::Token![,]>>()?;
    Ok((expr, pattern))
}
