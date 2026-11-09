//! The security core's own conventions: shapes that keep a hole closed once
//! it was closed, so new code cannot reopen it without failing the build.
//!
//! - An emailed link has no public way to be spent, or asked about, without
//!   the account it is for.
//! - A proof has no public constructor: only the domain says a thing was
//!   checked.
//! - A human is never stored without the person behind them.
//! - A text type that carries a secret never prints.
//! - A secret, or a digest of one, is never compared with a derived `==`.
//! - A value guarding a rule has no public field to step around it with, and
//!   no public way to be rebuilt from parts.

use proc_macro2::TokenTree;
use syn::{ImplItem, ItemImpl, ReturnType, Visibility};

use crate::conventions::domain::lists::{
    EMAILED_LINKS, FLAG_PARAMETERS_ALLOWED, GUARDED_VALUES, LINK_SHORTCUTS,
    OPTIONAL_PARAMETERS_ALLOWED, PROOFS, SECRET_DIGESTS, SECRET_TEXT, UNTYPED_CHOICES_ALLOWED,
};
use crate::conventions::domain::source::{
    Findings, SourceFile, option_of, tokens_name, type_mentions, type_name,
};

/// The name an inherent or trait `impl` is for, e.g. `SecureToken`.
fn implemented_for(item: &ItemImpl) -> Option<String> {
    type_name(&item.self_ty).map(ToString::to_string)
}

/// The trait an `impl` implements, by its last segment.
fn trait_of(item: &ItemImpl) -> Option<String> {
    item.trait_
        .as_ref()
        .and_then(|(_, path, _)| path.segments.last())
        .map(|segment| segment.ident.to_string())
}

fn is_public(visibility: &Visibility) -> bool {
    matches!(visibility, Visibility::Public(_))
}

fn is_proof(name: &str) -> bool {
    PROOFS.iter().any(|(proof, _)| *proof == name)
}

/// Public shortcuts that spend or check an emailed link without its account.
pub(crate) fn links_spent_without_their_account(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let inventory = file.inventory();
        let link_impls = inventory.impls.iter().filter(|item| {
            item.trait_.is_none()
                && implemented_for(item).is_some_and(|name| EMAILED_LINKS.contains(&name.as_str()))
        });
        for item in link_impls {
            for function in item.items.iter().filter_map(|member| match member {
                ImplItem::Fn(function) => Some(function),
                _ => None,
            }) {
                let name = function.sig.ident.to_string();
                if is_public(&function.vis) && LINK_SHORTCUTS.contains(&name.as_str()) {
                    findings.flag(
                        file,
                        &function.sig,
                        format!("an emailed link may not offer `{name}`: spend it with `redeem`, `complete` or `confirm`, against its account"),
                    );
                }
            }
        }
    }
    findings
}

/// Public ways to make a proof without the check it stands for.
pub(crate) fn proofs_made_outside_the_domain(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let inventory = file.inventory();
        for item in &inventory.impls {
            let Some(name) = implemented_for(item).filter(|name| is_proof(name)) else {
                continue;
            };
            if trait_of(item)
                .is_some_and(|tr| matches!(tr.as_str(), "From" | "TryFrom" | "Default" | "FromStr"))
            {
                findings.flag(
                    file,
                    *item,
                    format!("a proof `{name}` may not be converted into from anything"),
                );
            }
            for signature in public_makers(item, &name) {
                let why = format!("a proof `{name}` may not have a public constructor");
                findings.flag(file, signature, why);
            }
        }
        for item in &inventory.structs {
            let name = item.ident.to_string();
            if is_proof(&name) && derives_deserialize(item) {
                let why = format!("a proof `{name}` may not be read from JSON");
                findings.flag(file, *item, why);
            }
        }
    }
    findings
}

/// The public functions of `item` that hand back a `name`, its own type.
fn public_makers<'i>(item: &'i syn::ItemImpl, name: &str) -> Vec<&'i syn::Signature> {
    (item.items.iter())
        .filter_map(|member| match member {
            ImplItem::Fn(function) if is_public(&function.vis) => Some(&function.sig),
            _ => None,
        })
        .filter(|signature| match &signature.output {
            ReturnType::Type(_, output) => {
                type_mentions(output, "Self") || type_mentions(output, name)
            }
            ReturnType::Default => false,
        })
        .collect()
}

/// Whether `item` derives `Deserialize`.
fn derives_deserialize(item: &syn::ItemStruct) -> bool {
    item.attrs.iter().any(|attribute| match &attribute.meta {
        syn::Meta::List(list) => tokens_name(&list.tokens, "Deserialize"),
        syn::Meta::Path(_) | syn::Meta::NameValue(_) => false,
    })
}

/// A field that stores a person as optional, so a human could be recorded
/// without the person every two-person rule compares.
pub(crate) fn people_without_a_person(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for field in file.inventory().fields {
            let optional_person = option_of(&field.field.ty)
                .and_then(type_name)
                .is_some_and(|inner| inner == "PersonKey");
            if optional_person {
                findings.flag(
                    file,
                    field.field,
                    format!(
                        "`{}.{}` holds an optional person: hold a `Human` or an `Initiator`",
                        field.owner, field.name
                    ),
                );
            }
        }
    }
    findings
}

/// The type a `text_value!` call declares, and whether it is `redacted`.
fn declared_text(tokens: &proc_macro2::TokenStream) -> Option<(String, bool)> {
    let tokens: Vec<TokenTree> = tokens.clone().into_iter().collect();
    let redacted = matches!(tokens.first(), Some(TokenTree::Ident(ident)) if ident == "redacted");
    let name = tokens.windows(2).find_map(|pair| match pair {
        [TokenTree::Ident(keyword), TokenTree::Ident(name)] if keyword == "struct" => {
            Some(name.to_string())
        }
        _ => None,
    })?;
    Some((name, redacted))
}

/// Every text type a file declares with `text_value!`, and whether it is
/// `redacted`.
pub(crate) fn text_types_declared(file: &SourceFile) -> Vec<(String, bool)> {
    file.inventory()
        .item_macros
        .iter()
        .filter(|item| item.mac.path.is_ident("text_value"))
        .filter_map(|item| declared_text(&item.mac.tokens))
        .collect()
}

/// A text type carrying a secret that would print.
pub(crate) fn secrets_that_print(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for item in file.inventory().item_macros {
            if !item.mac.path.is_ident("text_value") {
                continue;
            }
            let Some((name, redacted)) = declared_text(&item.mac.tokens) else {
                continue;
            };
            let secret = SECRET_TEXT.iter().any(|(listed, _)| *listed == name);
            if secret && !redacted {
                findings.flag(
                    file,
                    item,
                    format!("`{name}` carries a secret: declare it `redacted`"),
                );
            }
        }
    }
    findings
}

/// A secret, or a digest of one, whose equality is derived: a derived `==`
/// stops at the first differing byte, so its timing shows how much of a
/// guess was right.
pub(crate) fn secrets_compared_byte_by_byte(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for item in file.inventory().structs {
            let name = item.ident.to_string();
            if !SECRET_DIGESTS.iter().any(|(listed, _)| *listed == name) {
                continue;
            }
            let derives_equality = item.attrs.iter().any(|attribute| match &attribute.meta {
                syn::Meta::List(list) => {
                    list.path.is_ident("derive") && tokens_name(&list.tokens, "PartialEq")
                }
                syn::Meta::Path(_) | syn::Meta::NameValue(_) => false,
            });
            if derives_equality {
                findings.flag(
                    file,
                    item,
                    format!("`{name}` holds a secret: compare it with `same_secret`, not a derived `PartialEq`"),
                );
            }
        }
    }
    findings
}

/// A public way to rebuild a value that guards a rule from its stored
/// parts: whatever the parts say becomes true, so the value is rebuilt only
/// by the aggregate that stored it.
pub(crate) fn guarded_values_rebuilt_in_public(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let inventory = file.inventory();
        let guarded_impls = inventory.impls.iter().filter(|item| {
            item.trait_.is_none()
                && implemented_for(item).is_some_and(|name| GUARDED_VALUES.contains(&name.as_str()))
        });
        for item in guarded_impls {
            let name = implemented_for(item).unwrap_or_default();
            for member in &item.items {
                let ImplItem::Fn(function) = member else {
                    continue;
                };
                if is_public(&function.vis) && function.sig.ident == "reconstitute" {
                    findings.flag(
                        file,
                        &function.sig,
                        format!(
                            "`{name}` guards a rule: only the aggregate that stores it rebuilds it"
                        ),
                    );
                }
            }
        }
    }
    findings
}

/// A public field on a value that guards a rule.
pub(crate) fn guarded_values_with_public_fields(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for item in file.inventory().structs {
            let name = item.ident.to_string();
            if !GUARDED_VALUES.contains(&name.as_str()) {
                continue;
            }
            for field in item.fields.iter().filter(|field| is_public(&field.vis)) {
                findings.flag(
                    file,
                    field,
                    format!("`{name}` guards a rule: its fields stay private"),
                );
            }
        }
    }
    findings
}

/// Whether a type is an `Option` or a `bool`.
fn is_choice(ty: &syn::Type) -> bool {
    option_of(ty).is_some() || is_flag(ty)
}

/// Whether a type is `bool`.
fn is_flag(ty: &syn::Type) -> bool {
    type_name(ty).is_some_and(|name| name == "bool")
}

/// Fields that hold an `Option` or a `bool` without being listed with a
/// reason.
///
/// A record's JSON form is exempt; see [`is_wire_form`]. A storage row, and
/// the parameters a record is made from, follow the record: when a record in the same file holds the field as an `Option` or
/// a `bool` too, the record's entry covers them, and when the record has
/// given the field a type, they are flagged for dropping it.
pub(crate) fn untyped_choices(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let inventory = file.inventory();
        let record_choices: Vec<&str> = inventory
            .fields
            .iter()
            .filter(|named| !follows_a_record(named.owner) && is_choice(&named.field.ty))
            .map(|named| named.name.as_str())
            .collect();
        for named in &inventory.fields {
            let field = format!("{}.{}", named.owner, named.name);
            let ty = &named.field.ty;
            let kind = match (option_of(ty).is_some(), is_flag(ty)) {
                (true, _) => "an `Option`",
                (false, true) => "a `bool`",
                (false, false) => continue,
            };
            let inherited =
                follows_a_record(named.owner) && record_choices.contains(&named.name.as_str());
            if inherited || is_wire_form(named.owner) || choice_listed(&file.path, &field) {
                continue;
            }
            findings.flag(
                file,
                named.field,
                format!("`{field}` is {kind}; give it a type that names each case, or list it with the reason it stays"),
            );
        }
    }
    findings
}

/// Whether a struct only carries a record's values: its storage row, its
/// JSON form, or the parameters it is made from.
fn follows_a_record(owner: &syn::Ident) -> bool {
    let name = owner.to_string();
    name.ends_with("Row") || name.ends_with("Params") || is_wire_form(owner)
}

/// Whether a struct is a record's JSON form: read only to be checked into
/// the record by its `TryFrom`, so it spells the stored JSON as it is, and
/// the record holds the typed value.
fn is_wire_form(owner: &syn::Ident) -> bool {
    owner.to_string().ends_with("Wire")
}

/// Whether `field` (`Owner.name`) in the file at `path` holds an `Option`
/// or a `bool`.
pub(crate) fn is_untyped_choice(files: &[SourceFile], path: &str, field: &str) -> bool {
    files
        .iter()
        .filter(|file| file.path == path)
        .flat_map(|file| file.inventory().fields)
        .any(|named| {
            format!("{}.{}", named.owner, named.name) == field && is_choice(&named.field.ty)
        })
}

fn choice_listed(path: &str, field: &str) -> bool {
    UNTYPED_CHOICES_ALLOWED
        .iter()
        .any(|(listed_path, listed, _)| *listed_path == path && *listed == field)
}

/// Functions that take a `bool`: a call reads `f(x, true)`, and nothing at
/// the call site says what `true` chose.
///
/// A `from` or `try_from` is exempt: turning a stored or sent `bool` into a
/// type that names its cases is exactly the step this check asks for.
pub(crate) fn flag_parameters(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for function in file.inventory().functions {
            let name = function.signature.ident.to_string();
            if name == "from" || name == "try_from" {
                continue;
            }
            for argument in &function.signature.inputs {
                let syn::FnArg::Typed(typed) = argument else {
                    continue;
                };
                if !is_flag(&typed.ty)
                    || flag_parameter_listed(&file.path, &parameter_name(function.signature, typed))
                {
                    continue;
                }
                findings.flag(
                    file,
                    typed,
                    format!(
                        "`{}` takes a `bool`; take a type that names each case",
                        function.signature.ident
                    ),
                );
            }
        }
    }
    findings
}

/// Functions that read a value from storage or the wire, where a missing
/// value arrives as an `Option` and is turned into a type that names it.
const OPTION_READERS: &[&str] = &[
    "from_stored",
    "from_option",
    "from_claim",
    "from",
    "try_from",
    "optional",
    "optional_reference",
    "between",
    "change_between",
];

/// The name a parameter is listed under: `function.parameter`.
fn parameter_name(function: &syn::Signature, typed: &syn::PatType) -> String {
    let pattern = match typed.pat.as_ref() {
        syn::Pat::Ident(ident) => ident.ident.to_string(),
        _ => "_".to_owned(),
    };
    format!("{}.{pattern}", function.ident)
}

/// Functions that take an `Option`: a call reads `f(x, None)`, and nothing at
/// the call site says whether none means unknown, unset or unlimited. Each
/// takes a type that names it, is a reader turning stored or sent data into
/// one, or is listed with the reason it stays.
pub(crate) fn optional_parameters(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for function in file.inventory().functions {
            let name = function.signature.ident.to_string();
            if OPTION_READERS.contains(&name.as_str()) {
                continue;
            }
            for argument in &function.signature.inputs {
                let syn::FnArg::Typed(typed) = argument else {
                    continue;
                };
                if option_of(&typed.ty).is_none() {
                    continue;
                }
                let parameter = parameter_name(function.signature, typed);
                if optional_parameter_listed(&file.path, &parameter) {
                    continue;
                }
                findings.flag(
                    file,
                    typed,
                    format!(
                        "`{parameter}` takes an `Option`; take a type that names each case, or list it with the reason it stays"
                    ),
                );
            }
        }
    }
    findings
}

fn flag_parameter_listed(path: &str, parameter: &str) -> bool {
    FLAG_PARAMETERS_ALLOWED
        .iter()
        .any(|(listed_path, listed, _)| *listed_path == path && *listed == parameter)
}

/// Whether `parameter` (`function.parameter`) in the file at `path` still
/// takes a `bool`.
pub(crate) fn is_flag_parameter(files: &[SourceFile], path: &str, parameter: &str) -> bool {
    files
        .iter()
        .filter(|file| file.path == path)
        .flat_map(|file| file.inventory().functions)
        .any(|function| {
            function.signature.inputs.iter().any(|argument| {
                let syn::FnArg::Typed(typed) = argument else {
                    return false;
                };
                is_flag(&typed.ty) && parameter_name(function.signature, typed) == parameter
            })
        })
}

fn optional_parameter_listed(path: &str, parameter: &str) -> bool {
    OPTIONAL_PARAMETERS_ALLOWED
        .iter()
        .any(|(listed_path, listed, _)| *listed_path == path && *listed == parameter)
}

/// Whether `parameter` (`function.parameter`) in the file at `path` still
/// takes an `Option`.
pub(crate) fn is_optional_parameter(files: &[SourceFile], path: &str, parameter: &str) -> bool {
    files
        .iter()
        .filter(|file| file.path == path)
        .flat_map(|file| file.inventory().functions)
        .any(|function| {
            function.signature.inputs.iter().any(|argument| {
                let syn::FnArg::Typed(typed) = argument else {
                    return false;
                };
                option_of(&typed.ty).is_some()
                    && parameter_name(function.signature, typed) == parameter
            })
        })
}
