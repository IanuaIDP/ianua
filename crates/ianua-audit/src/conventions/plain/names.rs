//! Names a newcomer reads at once.
//!
//! - **An action is named by its verb.** A function that changes something
//!   and gives nothing back is called `save`, `publish` or `check_offered`,
//!   never `kept`, `registered_and_kept` or `put_in_service`: a past
//!   participle reads as a value it would return.
//! - **No vague words.** No function called `helper` or `process_data`, no
//!   type called `ThingManager`, no binding called `tmp` or `res`.
//! - **A test says what it shows** in at least three words, never
//!   `test_parse` or `it_works`.

use syn::visit::{self, Visit};
use syn::{
    Attribute, ImplItemFn, ItemEnum, ItemFn, ItemImpl, ItemStruct, ItemTrait, Local, Pat,
    ReturnType, Signature, TraitItemFn, Type,
};

use crate::conventions::infra::source::{Findings, SourceFile, line_of};
use crate::conventions::plain::words::{is_participle, name_words};

/// Words that name nothing in particular.
const VAGUE_WORDS: &[&str] = &[
    "helper", "helpers", "util", "utils", "misc", "stuff", "tmp", "temp", "foo", "bar", "baz",
    "thing", "things",
];

/// Endings of type names that say a type exists, not what it does.
const VAGUE_TYPE_ENDINGS: &[&str] = &[
    "Manager", "Helper", "Helpers", "Util", "Utils", "Misc", "Wrapper", "Stuff", "Thing",
];

/// Bindings that say nothing of what they hold.
const VAGUE_BINDINGS: &[&str] = &[
    "tmp", "temp", "foo", "bar", "baz", "res", "ret", "obj", "thing", "stuff", "val2", "data2",
];

/// Functions a framework or the language names, whose names are not ours.
const GIVEN_NAMES: &[&str] = &["main"];

/// Every function among `files` that changes something, gives nothing back
/// and is named by a past participle.
pub(crate) fn actions_named_as_results(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files {
        let mut names = ActionNames {
            file,
            found: &mut found,
        };
        file.items().iter().for_each(|item| names.visit_item(item));
    }
    found
}

/// The most words a function's name may have in code that ships; a test's
/// name says what it shows and may run longer.
pub(crate) const MOST_NAME_WORDS: usize = 6;

/// Every function among `files` named in more than [`MOST_NAME_WORDS`]
/// words.
pub(crate) fn long_names(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files {
        let mut names = LongNames {
            file,
            found: &mut found,
        };
        file.items().iter().for_each(|item| names.visit_item(item));
    }
    found
}

/// Every private function among `files` that only hands its own arguments,
/// in order, to one other function: a second name for that function.
pub(crate) fn pass_through_functions(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files {
        let mut names = PassThroughs {
            file,
            found: &mut found,
        };
        file.items().iter().for_each(|item| names.visit_item(item));
    }
    found
}

/// Every vague function, type or binding name among `files`.
pub(crate) fn vague_names(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files {
        let mut names = VagueNames {
            file,
            found: &mut found,
        };
        file.items().iter().for_each(|item| names.visit_item(item));
    }
    found
}

/// Every test among `files` named `test_…`, `it_works`, or in fewer than
/// three words.
pub(crate) fn tests_named_vaguely(files: &[SourceFile]) -> Findings {
    let mut found = Findings::default();
    for file in files {
        let mut names = TestNames {
            file,
            found: &mut found,
        };
        file.items().iter().for_each(|item| names.visit_item(item));
    }
    found
}

/// Finds actions named as results, skipping trait implementations, whose
/// names are the trait's.
struct ActionNames<'a> {
    file: &'a SourceFile,
    found: &'a mut Findings,
}

impl ActionNames<'_> {
    fn check(&mut self, signature: &Signature) {
        let name = signature.ident.to_string();
        let Some(first) = name_words(&name).into_iter().next() else {
            return;
        };
        if GIVEN_NAMES.contains(&name.as_str())
            || !is_participle(&first)
            || !gives_nothing(signature)
        {
            return;
        }
        self.found.flag_at(
            &self.file.path,
            line_of(&signature.ident),
            format!(
                "`{name}` changes something and gives nothing back, but reads as a value; name it by its verb, such as `save` or `publish`"
            ),
        );
    }
}

impl<'ast> Visit<'ast> for ActionNames<'_> {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.check(&item.sig);
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        if item.trait_.is_some() {
            return;
        }
        visit::visit_item_impl(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.check(&item.sig);
    }

    fn visit_trait_item_fn(&mut self, item: &'ast TraitItemFn) {
        self.check(&item.sig);
    }
}

/// Finds functions named in too many words, skipping trait
/// implementations, whose names are the trait's.
struct LongNames<'a> {
    file: &'a SourceFile,
    found: &'a mut Findings,
}

impl LongNames<'_> {
    fn check(&mut self, signature: &Signature) {
        let name = signature.ident.to_string();
        let words = name_words(&name).len();
        if words > MOST_NAME_WORDS {
            self.found.flag_at(
                &self.file.path,
                line_of(&signature.ident),
                format!("`{name}` takes {words} words; name it in {MOST_NAME_WORDS} or fewer"),
            );
        }
    }
}

impl<'ast> Visit<'ast> for LongNames<'_> {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.check(&item.sig);
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        if item.trait_.is_some() {
            return;
        }
        visit::visit_item_impl(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.check(&item.sig);
    }

    fn visit_trait_item_fn(&mut self, item: &'ast TraitItemFn) {
        self.check(&item.sig);
    }
}

/// Finds private functions that only pass their arguments on.
struct PassThroughs<'a> {
    file: &'a SourceFile,
    found: &'a mut Findings,
}

impl PassThroughs<'_> {
    fn check(&mut self, visibility: &syn::Visibility, signature: &Signature, body: &syn::Block) {
        if !matches!(visibility, syn::Visibility::Inherited) || !passes_through(signature, body) {
            return;
        }
        self.found.flag_at(
            &self.file.path,
            line_of(&signature.ident),
            format!(
                "`{}` only hands its arguments to another function; call that one",
                signature.ident
            ),
        );
    }
}

impl<'ast> Visit<'ast> for PassThroughs<'_> {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.check(&item.vis, &item.sig, &item.block);
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        if item.trait_.is_some() {
            return;
        }
        visit::visit_item_impl(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.check(&item.vis, &item.sig, &item.block);
    }
}

/// Whether `body` is one call handing on exactly `signature`'s own
/// arguments, in order, and nothing more.
fn passes_through(signature: &Signature, body: &syn::Block) -> bool {
    let [syn::Stmt::Expr(expression, None)] = body.stmts.as_slice() else {
        return false;
    };
    let arguments: Vec<String> = match expression {
        syn::Expr::Call(call) => call.args.iter().map(argument_name).collect(),
        syn::Expr::MethodCall(call) => call.args.iter().map(argument_name).collect(),
        _ => return false,
    };
    let parameters: Vec<String> = signature
        .inputs
        .iter()
        .filter_map(|input| match input {
            syn::FnArg::Typed(typed) => match typed.pat.as_ref() {
                Pat::Ident(binding) => Some(binding.ident.to_string()),
                _ => None,
            },
            syn::FnArg::Receiver(_) => None,
        })
        .collect();
    !parameters.is_empty() && arguments == parameters
}

/// The name an argument passes on unchanged, or nothing for any other
/// expression.
fn argument_name(argument: &syn::Expr) -> String {
    match argument {
        syn::Expr::Path(path) => path
            .path
            .get_ident()
            .map(ToString::to_string)
            .unwrap_or_default(),
        _ => String::new(),
    }
}

/// Whether a function gives nothing back: no return type, `()`, or a
/// `Result` of `()`.
fn gives_nothing(signature: &Signature) -> bool {
    let ReturnType::Type(_, returned) = &signature.output else {
        return true;
    };
    is_unit(returned) || result_of_unit(returned)
}

fn is_unit(returned: &Type) -> bool {
    matches!(returned, Type::Tuple(tuple) if tuple.elems.is_empty())
}

fn result_of_unit(returned: &Type) -> bool {
    let Type::Path(path) = returned else {
        return false;
    };
    let Some(last) = path.path.segments.last() else {
        return false;
    };
    let syn::PathArguments::AngleBracketed(arguments) = &last.arguments else {
        return false;
    };
    last.ident == "Result"
        && matches!(arguments.args.first(), Some(syn::GenericArgument::Type(inner)) if is_unit(inner))
}

/// Finds vague function, type and binding names.
struct VagueNames<'a> {
    file: &'a SourceFile,
    found: &'a mut Findings,
}

impl VagueNames<'_> {
    fn function(&mut self, signature: &Signature) {
        let name = signature.ident.to_string();
        let words = name_words(&name);
        let vague = words
            .iter()
            .any(|word| VAGUE_WORDS.contains(&word.as_str()))
            || name.ends_with("_v2")
            || name.ends_with("_new2")
            || name.ends_with("_old");
        if vague {
            self.found.flag_at(
                &self.file.path,
                line_of(&signature.ident),
                format!("`{name}` says nothing of what it does; name what it gives or does"),
            );
        }
    }

    fn type_name(&mut self, ident: &syn::Ident) {
        let name = ident.to_string();
        if VAGUE_TYPE_ENDINGS
            .iter()
            .any(|ending| name.ends_with(ending))
        {
            self.found.flag_at(
                &self.file.path,
                line_of(ident),
                format!("`{name}` says a type exists, not what it does; name its role"),
            );
        }
    }
}

impl<'ast> Visit<'ast> for VagueNames<'_> {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.function(&item.sig);
        visit::visit_item_fn(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.function(&item.sig);
        visit::visit_impl_item_fn(self, item);
    }

    fn visit_item_struct(&mut self, item: &'ast ItemStruct) {
        self.type_name(&item.ident);
        visit::visit_item_struct(self, item);
    }

    fn visit_item_enum(&mut self, item: &'ast ItemEnum) {
        self.type_name(&item.ident);
        visit::visit_item_enum(self, item);
    }

    fn visit_item_trait(&mut self, item: &'ast ItemTrait) {
        self.type_name(&item.ident);
        visit::visit_item_trait(self, item);
    }

    fn visit_local(&mut self, local: &'ast Local) {
        if let Pat::Ident(binding) = &local.pat {
            let name = binding.ident.to_string();
            if VAGUE_BINDINGS.contains(&name.as_str()) {
                self.found.flag_at(
                    &self.file.path,
                    line_of(&binding.ident),
                    format!("`{name}` says nothing of what it holds; name it"),
                );
            }
        }
        visit::visit_local(self, local);
    }
}

/// Finds tests named vaguely.
struct TestNames<'a> {
    file: &'a SourceFile,
    found: &'a mut Findings,
}

impl<'ast> Visit<'ast> for TestNames<'_> {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        if is_test(&item.attrs) {
            let name = item.sig.ident.to_string();
            let words = name_words(&name);
            if name.starts_with("test_") || name == "it_works" || words.len() < 3 {
                self.found.flag_at(
                    &self.file.path,
                    line_of(&item.sig.ident),
                    format!("test `{name}` does not say what it shows; name the behaviour, such as `a_paused_key_signs_in_nothing`"),
                );
            }
        }
        visit::visit_item_fn(self, item);
    }
}

/// Whether `attributes` mark a test: `#[test]` or `#[tokio::test]`.
fn is_test(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute
            .path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "test")
    })
}
