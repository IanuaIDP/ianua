//! How code is cut into pieces.
//!
//! - **No copy and paste.** Two functions whose bodies differ only in their
//!   literals are one function taking that value.
//! - **No abstraction just in case.** A trait with one implementation, in
//!   its own crate, and no stand-in for tests is that implementation's own
//!   methods. A trait one crate defines and another implements is a port.
//! - **No piece too small to name.** A private function of one short line,
//!   called once, reads better written where it is called.
//! - **No formula.** One label opening hundreds of comments, such as
//!   `Stops:`, reads as made by a machine; say it in each comment's words.

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;
use syn::visit::{self, Visit};
use syn::{ImplItemFn, ItemFn, ItemImpl, ItemTrait};

use crate::conventions::infra::source::{Findings, SourceFile, line_of};

/// The fewest tokens a body has before two alike ones count as a copy.
const COPIED_TOKENS: usize = 40;

/// The longest a body may be, in characters, to count as one short line.
const SHORT_BODY: usize = 60;

/// How many comments one opening label may start before it is a formula.
const FORMULA_COUNT: usize = 100;

/// Copies kept on purpose, by the repeating file and function, each with
/// why one function would be worse. An entry matching nothing is flagged.
const COPIES_ALLOWED: &[(&str, &str, &str)] = &[
    (
        "ianua-domain/src/domains/routing/matching/parameter/mod.rs",
        "rules",
        "route parameters and agent tool inputs read alike by chance; they change for different reasons",
    ),
    (
        "ianua-domain/src/domains/organization/members/privacy/erasure.rs",
        "retry",
        "a member's erasure and a tenant user's erasure are separate aggregates with their own states and events",
    ),
    (
        "ianua-domain/src/domains/organization/members/privacy/erasure.rs",
        "start_processing",
        "a member's erasure and a tenant user's erasure are separate aggregates with their own states and events",
    ),
    (
        "ianua-domain/src/domains/organization/access/passkey.rs",
        "consume",
        "the organization's passkey ceremony and the tenant's are separate aggregates kept apart by scope",
    ),
    (
        "ianua-app/src/services/authentication/passkey_answer.rs",
        "spent_state",
        "one step for the tenant ceremony and one for the organization's, each over its own type",
    ),
    (
        "ianua-infra/src/postgres/organization/credentials/mfa_enrollments/record.rs",
        "factor_from",
        "organization and tenant enrolments are separate tables mapped to separate domain types",
    ),
    (
        "ianua-api/src/dto/organization/invitations.rs",
        "from",
        "organization invitations and tenant links are separate response types; one shape would change the API's JSON",
    ),
    (
        "ianua-runner/src/handler.rs",
        "refused",
        "the runner and the egress proxy are separate binaries, each with its own refusal and body types",
    ),
    (
        "postgres/src/lib.rs",
        "call_through",
        "each database integration has its own operation kinds and limits",
    ),
    (
        "postgres/src/lib.rs",
        "inputs_of",
        "each database integration has its own operation kinds and limits",
    ),
    (
        "postgres/src/guides.rs",
        "inputs_for",
        "each database integration describes its own steps",
    ),
    (
        "ianua-infra/src/postgres/authorization/principals.rs",
        "from",
        "storage and the API each map principals to their own row and response shapes",
    ),
];

/// Every pair of functions among `files` whose bodies are alike but for
/// their literals, but for the copies kept on purpose.
pub(crate) fn copied_functions(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    let mut used = BTreeSet::new();
    for repeat in copies(files) {
        let allowed = COPIES_ALLOWED
            .iter()
            .position(|(at, function, _)| *at == repeat.path && *function == repeat.name);
        match allowed {
            Some(entry) => {
                used.insert(entry);
            }
            None => found.flag_at(&repeat.path, repeat.line, repeat.message),
        }
    }
    let stale = COPIES_ALLOWED
        .iter()
        .enumerate()
        .filter(|(entry, _)| !used.contains(entry));
    for (_, (path, name, _)) in stale {
        found.flag_at(
            path,
            0,
            format!("`{name}` is allowed as a copy but repeats nothing; remove it from the list"),
        );
    }
    found
}

/// Every function among `files` whose body repeats an earlier one's but
/// for its literals: where it is, its name and what to say about it.
fn copies(files: &[SourceFile]) -> Vec<Repeat> {
    let mut bodies: BTreeMap<String, Vec<(String, usize, String)>> = BTreeMap::new();
    for file in files {
        let mut collecting = Bodies {
            file,
            bodies: &mut bodies,
            owner: None,
            local: free_functions(file),
        };
        file.items()
            .iter()
            .for_each(|item| collecting.visit_item(item));
    }
    let mut found = Vec::new();
    for copies in bodies.values().filter(|copies| copies.len() > 1) {
        let Some((first_path, first_line, first_name)) = copies.first() else {
            continue;
        };
        for (path, line, name) in copies.iter().skip(1) {
            let message = format!(
                "`{name}` repeats the body of `{first_name}` ({first_path}:{first_line}); make one function taking what differs"
            );
            found.push(Repeat {
                path: path.clone(),
                line: *line,
                name: name.clone(),
                message,
            });
        }
    }
    found
}

/// A function repeating an earlier one's body.
struct Repeat {
    path: String,
    line: usize,
    name: String,
    message: String,
}

/// The traits `shipping` define, by name, with where each is.
fn traits_defined(shipping: &[SourceFile]) -> BTreeMap<String, (String, usize)> {
    let mut traits = BTreeMap::new();
    for file in shipping {
        let mut defined = Defined {
            file,
            traits: &mut traits,
        };
        file.items()
            .iter()
            .for_each(|item| defined.visit_item(item));
    }
    traits
}

/// The crates whose files among `every` implement each trait, by name,
/// once for each implementation.
fn implementing_crates(every: &[SourceFile]) -> Implementations {
    let mut found = Implementations::default();
    for file in every {
        let mut counting = Implemented {
            file,
            found: &mut found,
        };
        file.items()
            .iter()
            .for_each(|item| counting.visit_item(item));
    }
    found
}

/// Each trait's implementations by crate, and the traits that are more
/// than their written implementations: used as a bound or a `dyn`, which
/// asks for a role rather than a type; implemented by a macro; or adding
/// methods to a type from outside, which has one implementation by its
/// nature.
#[derive(Default)]
struct Implementations {
    crates: BTreeMap<String, Vec<String>>,
    roles: BTreeSet<String>,
}

/// Every trait defined among `shipping` that `every` implements exactly
/// once, with no stand-in for tests.
pub(crate) fn single_implementation_traits(
    shipping: &[SourceFile],
    every: &[SourceFile],
) -> Findings {
    let traits = traits_defined(shipping);
    let implemented = implementing_crates(every);
    let mut found = Findings::default();
    for (name, (path, line)) in &traits {
        let Some([only]) = implemented.crates.get(name).map(Vec::as_slice) else {
            continue;
        };
        if *only == crate_of(path) && !implemented.roles.contains(name) {
            found.flag_at(
                path,
                *line,
                format!("trait `{name}` has one implementation and no stand-in; make its methods the implementation's own"),
            );
        }
    }
    found
}

/// Every private function among `files` of one short line called once in
/// its file.
pub(crate) fn tiny_functions_used_once(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files {
        let text = file.lines().join("\n");
        let mut tiny = Tiny {
            file,
            text: &text,
            found: &mut found,
        };
        file.items().iter().for_each(|item| tiny.visit_item(item));
    }
    found
}

/// The one-word label, such as `Stops`, the doc comment starting at line
/// `at` of `lines` opens with, if it opens with one.
fn opening_label<'l>(lines: &[&'l str], at: usize) -> Option<&'l str> {
    let doc = lines[at].trim_start().strip_prefix("///").map(str::trim)?;
    let starts_comment = at == 0 || !lines[at.saturating_sub(1)].trim_start().starts_with("///");
    let (label, _) = doc.split_once(':').filter(|_| starts_comment)?;
    (label.split_whitespace().count() == 1 && !label.is_empty()).then_some(label)
}

/// Every doc comment among `files` opening with a label, such as `Stops:`,
/// that starts more than [`FORMULA_COUNT`] of them, so the list shrinks as
/// each is reworded.
pub(crate) fn formula_openers(files: &[SourceFile]) -> Findings {
    let mut labels: BTreeMap<String, Vec<(String, usize)>> = BTreeMap::new();
    for file in files {
        let lines = file.lines();
        for at in 0..lines.len() {
            if let Some(label) = opening_label(&lines, at) {
                let place = (file.path.clone(), at.saturating_add(1));
                labels.entry(label.to_owned()).or_default().push(place);
            }
        }
    }
    let mut found = Findings::default();
    for (label, places) in labels
        .iter()
        .filter(|(_, places)| places.len() > FORMULA_COUNT)
    {
        let count = places.len();
        for (path, line) in places {
            found.flag_at(
                path,
                *line,
                format!("`{label}:` opens {count} comments; say this one in its own words"),
            );
        }
    }
    found
}

/// A body's tokens with every number made alike, so bodies differing only
/// in their numbers read the same. Text is kept: two mappings to different
/// words say different things. A number handed to a macro is kept too: a
/// macro takes it as written, so it cannot be passed in from outside.
fn shape_of(body: &TokenStream, in_macro: bool) -> (String, usize) {
    let mut shape = String::new();
    let mut count: usize = 0;
    let mut after_bang = false;
    for token in body.clone() {
        let bang = matches!(&token, TokenTree::Punct(punct) if punct.as_char() == '!');
        match token {
            TokenTree::Literal(literal) if in_macro || !is_number(&literal) => {
                shape.push_str(&format!("{literal} "));
            }
            TokenTree::Literal(_) => shape.push_str("LIT "),
            TokenTree::Group(group) => {
                let (inner, inner_count) = shape_of(&group.stream(), in_macro || after_bang);
                shape.push_str(&format!("{:?}( {inner}) ", group.delimiter()));
                count = count.saturating_add(inner_count);
            }
            other => shape.push_str(&format!("{other} ")),
        }
        after_bang = bang;
        count = count.saturating_add(1);
    }
    (shape, count)
}

/// Whether `attrs` mark a route handler, which carries its route's own
/// API description: two bindings of one action each need one, so they may
/// read alike while each only orchestrates.
fn is_route_handler(attrs: &[syn::Attribute]) -> bool {
    (attrs.iter()).any(|attribute| {
        let path = &attribute.path().segments;
        path.len() == 2 && path[0].ident == "utoipa" && path[1].ident == "path"
    })
}

/// Whether `body` only declares a value: one expression with no branch,
/// loop or binding, such as a table of limits. Its numbers are what it
/// says, so two such bodies differing in them are not copies.
fn declares_values(body: &syn::Block) -> bool {
    let [syn::Stmt::Expr(expression, None)] = body.stmts.as_slice() else {
        return false;
    };
    let written = expression.to_token_stream().to_string();
    !["if ", "match ", "for ", "while ", "loop ", "let "]
        .iter()
        .any(|keyword| written.starts_with(keyword) || written.contains(&format!(" {keyword}")))
}

/// The names of the free functions `file` defines.
fn free_functions(file: &SourceFile) -> BTreeSet<String> {
    (file.items().iter())
        .filter_map(|item| match item {
            syn::Item::Fn(function) => Some(function.sig.ident.to_string()),
            _ => None,
        })
        .collect()
}

/// Whether `literal` is a number, as opposed to text, a character or a
/// byte string.
fn is_number(literal: &proc_macro2::Literal) -> bool {
    literal
        .to_string()
        .starts_with(|c: char| c.is_ascii_digit())
}

/// Gathers function bodies by their shape.
struct Bodies<'a> {
    file: &'a SourceFile,
    bodies: &'a mut BTreeMap<String, Vec<(String, usize, String)>>,
    /// The type of the `impl` block being read, which `Self` stands for.
    owner: Option<String>,
    /// The free functions the file defines. Two bodies alike in words
    /// that call their own file's functions do different work.
    local: BTreeSet<String>,
}

impl Bodies<'_> {
    fn add(&mut self, ident: &syn::Ident, body: &syn::Block) {
        let tokens = body.to_token_stream();
        let (mut shape, count) = shape_of(&tokens, declares_values(body));
        if count < COPIED_TOKENS {
            return;
        }
        if let Some(owner) = self.owner.as_ref().filter(|_| shape.contains("Self ")) {
            shape = format!("{owner}: {shape}");
        }
        let calls_local =
            (self.local.iter()).any(|name| shape.contains(&format!("{name} Parenthesis(")));
        if calls_local {
            shape = format!("{}: {shape}", self.file.path);
        }
        self.bodies.entry(shape).or_default().push((
            self.file.path.clone(),
            line_of(ident),
            ident.to_string(),
        ));
    }
}

impl<'ast> Visit<'ast> for Bodies<'_> {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        if !is_route_handler(&item.attrs) {
            self.add(&item.sig.ident, &item.block);
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.add(&item.sig.ident, &item.block);
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        let outer = self
            .owner
            .replace(item.self_ty.to_token_stream().to_string());
        visit::visit_item_impl(self, item);
        self.owner = outer;
    }
}

/// Gathers the traits a file defines.
struct Defined<'a> {
    file: &'a SourceFile,
    traits: &'a mut BTreeMap<String, (String, usize)>,
}

impl<'ast> Visit<'ast> for Defined<'_> {
    fn visit_item_trait(&mut self, item: &'ast ItemTrait) {
        self.traits.insert(
            item.ident.to_string(),
            (self.file.path.clone(), line_of(&item.ident)),
        );
    }
}

/// Gathers, for each trait by its last name, the crate of each of its
/// implementations.
struct Implemented<'a> {
    file: &'a SourceFile,
    found: &'a mut Implementations,
}

impl<'ast> Visit<'ast> for Implemented<'_> {
    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        let implemented = item
            .trait_
            .as_ref()
            .and_then(|(_, path, _)| path.segments.last());
        if let Some(last) = implemented {
            let name = last.ident.to_string();
            if is_from_outside(item) {
                self.found.roles.insert(name.clone());
            }
            let crates = self.found.crates.entry(name).or_default();
            crates.push(crate_of(&self.file.path));
        }
        visit::visit_item_impl(self, item);
    }

    fn visit_trait_bound(&mut self, bound: &'ast syn::TraitBound) {
        if let Some(last) = bound.path.segments.last() {
            self.found.roles.insert(last.ident.to_string());
        }
        visit::visit_trait_bound(self, bound);
    }

    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        let written: Vec<TokenTree> = item.mac.tokens.clone().into_iter().collect();
        for window in written.windows(4) {
            if let [
                TokenTree::Ident(word),
                TokenTree::Ident(name),
                TokenTree::Ident(for_word),
                TokenTree::Punct(dollar),
            ] = window
                && word == "impl"
                && for_word == "for"
                && dollar.as_char() == '$'
            {
                self.found.roles.insert(name.to_string());
            }
        }
    }
}

/// Whether `item` implements its trait for a type parameter or a
/// standard type, which only an extension trait does.
fn is_from_outside(item: &ItemImpl) -> bool {
    let syn::Type::Path(target) = item.self_ty.as_ref() else {
        return false;
    };
    let Some(last) = target.path.segments.last() else {
        return false;
    };
    let generic = (item.generics.type_params()).any(|param| param.ident == last.ident);
    generic
        || ["Result", "Option", "Vec", "String", "Box"].contains(&last.ident.to_string().as_str())
}

/// The crate a workspace path is in: its first folder. A trait one crate
/// defines and another implements is a port, kept for the dependency to
/// point inward.
fn crate_of(path: &str) -> String {
    path.split('/').next().unwrap_or_default().to_owned()
}

/// Finds private one-line functions called once.
struct Tiny<'a> {
    file: &'a SourceFile,
    text: &'a str,
    found: &'a mut Findings,
}

impl Tiny<'_> {
    /// Flags `ident` when its body is one short line and it is used once.
    /// One named in quotes, such as a `serde` default, is called by that
    /// name and must stay a function.
    fn check(&mut self, visibility: &syn::Visibility, ident: &syn::Ident, body: &syn::Block) {
        let short = body.stmts.len() == 1 && body.to_token_stream().to_string().len() <= SHORT_BODY;
        if !matches!(visibility, syn::Visibility::Inherited) || !short {
            return;
        }
        let name = ident.to_string();
        let quoted = self.text.contains(&format!("\"{name}\""))
            || self.text.contains(&format!("::{name}\""));
        if quoted || has_child_files(self.text) {
            return;
        }
        let uses = self
            .text
            .match_indices(&name)
            .filter(|(at, _)| {
                let before = self.text[..*at].chars().last();
                let after = self.text[at.saturating_add(name.len())..].chars().next();
                before.is_none_or(|c| !c.is_alphanumeric() && c != '_')
                    && after.is_none_or(|c| !c.is_alphanumeric() && c != '_')
            })
            .count();
        if uses == 2 {
            self.found.flag_at(
                &self.file.path,
                line_of(ident),
                format!("`{name}` is one short line called once; write it where it is called"),
            );
        }
    }
}

impl<'ast> Visit<'ast> for Tiny<'_> {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        if !gives_a_reason(&item.attrs) {
            self.check(&item.vis, &item.sig.ident, &item.block);
        }
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        if item.trait_.is_some() {
            return;
        }
        visit::visit_item_impl(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        if !gives_a_reason(&item.attrs) {
            self.check(&item.vis, &item.sig.ident, &item.block);
        }
    }
}

/// Whether `text` declares a module kept in a file of its own, which sees
/// the private functions of `text` and may be where they are called.
fn has_child_files(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim_start();
        let declared = line.strip_prefix("pub(crate) ").unwrap_or(line);
        declared.starts_with("mod ") && line.ends_with(';')
    })
}

/// Whether a function's doc comment runs to two lines or more, saying
/// why as well as what. Written in at its call, that reason would have to
/// become a comment inside a body, which the house rules forbid.
fn gives_a_reason(attrs: &[syn::Attribute]) -> bool {
    (attrs.iter())
        .filter(|attribute| attribute.path().is_ident("doc"))
        .count()
        >= 2
}
