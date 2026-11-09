//! The shape every domain file keeps, checked over the parsed source so a
//! file that drifts fails the build instead of waiting for a reviewer to
//! notice.
//!
//! - A record loads from storage through `reconstitute(row: XRow)`, never
//!   from loose values, and refuses a row that breaks the rules it keeps.
//! - A status machine moves through `try_transition(self, to: Self)`, and
//!   no status is set around it.
//! - A change is a named action that checks its rules; no function is a
//!   `set_` setter.
//! - A file holds one topic: no more than 550 lines of code before its
//!   tests.
//! - Imports name their source from `crate::`, at the top of a module: no
//!   `super::` but a test module's `use super::*;`, no glob but a folder
//!   re-exporting its parts, no `use` inside a function.
//! - `parse` reads outside input and never reports a server fault;
//!   `from_stored` reads storage and never blames the caller.
//! - An id is its own type: no `id` or `*_id` field is a bare `Uuid`, and a
//!   fresh `Uuid` is only made inside the id types.
//! - A digest of a secret is a `TokenHash` or `PasswordHash`, never a bare
//!   `String`.
//! - A text wrapper is declared with `text_value!`, and one that can be read
//!   from JSON is read through its constructor.
//! - Input is checked by the shared rules, and a value with a meaning holds
//!   a type that names it.
//! - A choice names its cases: a field that is an `Option` or a `bool` is
//!   listed with the reason it stays, and no function takes a `bool` unless
//!   it is listed with the reason it stays.
//! - Function bodies carry no comments, no `if` sits inside another, and
//!   every `#[allow]` says why.
//! - Events use the event macros, only a listed observation names an
//!   event's tenant by hand, and the domain reaches for no adapter library.
//! - A file keeps one test module, last, and no section dividers; it
//!   imports what it uses itself. No em dash appears outside tests.
//! - JSON and storage reach a value only through its checks: no derived
//!   `Deserialize` past a refusing constructor, no public `stored`.
//! - Audit payloads record stable names, never `Debug` output; every event
//!   of a folder with an `every_event` list is on it; a list is checked for
//!   repeats with the shared helper; a doc names no `None` that is not
//!   there.

pub(crate) mod callers;
pub(crate) mod imports;
pub(crate) mod layers;
pub(crate) mod lists;
pub(crate) mod observations;
pub(crate) mod security;
pub(crate) mod shape;
pub(crate) mod source;

use lists::{
    ADAPTER_LIBRARIES, HAND_CHECKS, HAND_CHECKS_ALLOWED, HAND_WRITTEN_EVENTS, HAND_WRITTEN_TEXT,
    HASH_FIELDS_ALLOWED, PLAIN_DESERIALIZE_ALLOWED, PLAIN_DURATIONS_ALLOWED, TEXT_FIELDS_ALLOWED,
    UUID_FIELDS_ALLOWED,
};
use source::{
    DeclaredField, Findings, Inventory, SourceFile, body_lines, every_file, is_or_maybe, line_of,
    path_text, paths_in, planted_file, production_files, tokens_name, type_mentions, type_name,
    use_roots,
};
use syn::{Expr, FnArg, Pat, Stmt, Type};

/// The name of a single argument written as `name: Type`, with its type.
fn typed_argument(argument: &FnArg) -> Option<(String, &Type)> {
    let FnArg::Typed(typed) = argument else {
        return None;
    };
    let Pat::Ident(name) = typed.pat.as_ref() else {
        return None;
    };
    Some((name.ident.to_string(), typed.ty.as_ref()))
}

/// Where the source breaks the convention [`every_record_loads_from_a_row`] holds it to.
fn records_loaded_from_loose_values(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for function in file.inventory().functions {
            let signature = function.signature;
            if !function.public || signature.ident != "reconstitute" {
                continue;
            }
            let arguments: Vec<_> = signature.inputs.iter().collect();
            let takes_row = matches!(arguments.as_slice(), [only] if typed_argument(only)
                .is_some_and(|(name, ty)| name == "row"
                    && type_name(ty).is_some_and(|ty| ty.to_string().ends_with("Row"))));
            if !takes_row {
                findings.flag(
                    file,
                    signature,
                    "`reconstitute` must take a single `row: XRow`",
                );
            }
        }
    }
    findings
}

/// Whether a signature is `(self, to: Self)`.
fn takes_self_and_target(signature: &syn::Signature) -> bool {
    let arguments: Vec<_> = signature.inputs.iter().collect();
    let [FnArg::Receiver(receiver), target] = arguments.as_slice() else {
        return false;
    };
    let by_value = receiver.reference.is_none() && receiver.mutability.is_none();
    let to_self = typed_argument(target).is_some_and(|(name, ty)| {
        name == "to" && matches!(ty, Type::Path(path) if path.path.is_ident("Self"))
    });
    by_value && to_self
}

/// Where the source breaks the convention [`every_status_machine_moves_through_try_transition`] holds it to.
fn misshapen_status_machines(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for function in file.inventory().functions {
            let signature = function.signature;
            let message = match signature.ident.to_string().as_str() {
                "transition_to" => "rename to `try_transition(self, to: Self)`",
                "try_transition" if !takes_self_and_target(signature) => {
                    "`try_transition` takes `(self, to: Self)`"
                }
                _ => continue,
            };
            findings.flag(file, signature, message);
        }
    }
    findings
}

/// Whether an expression is `status` or `<something>.status`.
fn is_status(expr: &Expr) -> bool {
    match expr {
        Expr::Field(field) => matches!(&field.member, syn::Member::Named(name) if name == "status"),
        Expr::Path(path) => path.path.is_ident("status"),
        _ => false,
    }
}

/// Where the source breaks the convention [`no_status_is_set_without_its_machine`] holds it to.
fn statuses_set_around_their_machine(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for assignment in file.inventory().assignments {
            let names_a_variant = matches!(assignment.right.as_ref(), Expr::Path(path) if path.path.segments.len() > 1);
            if is_status(&assignment.left) && names_a_variant {
                findings.flag(file, assignment, "move the status through `try_transition`");
            }
        }
    }
    findings
}

/// Where the source breaks the convention [`parse_reads_input_and_from_stored_reads_storage`] holds it to.
fn readers_blaming_the_wrong_side(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for function in file.inventory().functions {
            if !function.public {
                continue;
            }
            let paths = paths_in(function.body);
            let blames_server = paths
                .iter()
                .any(|path| path.ends_with("infra_msg") || path.ends_with("DomainError::infra"));
            let blames_caller = paths
                .iter()
                .any(|path| path.starts_with("DomainError::Validation"));
            let message = match function.signature.ident.to_string().as_str() {
                "parse" if blames_server => {
                    "`parse` reports a server fault; reading storage is `from_stored`"
                }
                "from_stored" if blames_caller => {
                    "`from_stored` blames the caller; stored data is a server fault"
                }
                _ => continue,
            };
            findings.flag(file, function.signature, message);
        }
    }
    findings
}

/// Whether a field's name says it holds an id.
fn names_an_id(name: &str) -> bool {
    name == "id" || name.ends_with("_id")
}

/// Whether a field is listed in `allowed` for its file, by a reason that
/// starts with its name.
fn listed_by_reason(allowed: &[(&str, &str)], file: &SourceFile, name: &str) -> bool {
    allowed
        .iter()
        .any(|(path, reason)| *path == file.path && reason.starts_with(name))
}

/// Where the source breaks the convention [`no_id_is_a_bare_uuid`] holds it to.
fn bare_uuid_ids(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for DeclaredField { name, field, .. } in file.inventory().fields {
            let bare = names_an_id(&name) && is_or_maybe(&field.ty, "Uuid");
            if bare && !listed_by_reason(UUID_FIELDS_ALLOWED, file, &name) {
                findings.flag(
                    file,
                    field,
                    format!("`{name}` is a bare Uuid; give it its id type"),
                );
            }
        }
    }
    findings
}

/// Where the source breaks the convention [`fresh_uuids_are_made_only_by_the_id_types`] holds it to.
fn uuids_made_outside_the_id_types(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        if file.path.starts_with("types/id/") {
            continue;
        }
        for path in file.inventory().paths {
            let text = path_text(path);
            if text.ends_with("Uuid::now_v7") || text.ends_with("Uuid::new_v4") {
                findings.flag(file, path, "make the id through its id type's `new()`");
            }
        }
    }
    findings
}

/// Where the source breaks the convention [`no_digest_is_a_bare_string`] holds it to.
fn digests_held_as_strings(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for named in file.inventory().fields {
            let name = &named.name;
            let digest = name.contains("hash") && !name.starts_with("fingerprint");
            let plain = is_or_maybe(&named.field.ty, "String");
            if digest && plain && !listed_by_reason(HASH_FIELDS_ALLOWED, file, name) {
                findings.flag(
                    file,
                    named.field,
                    format!("`{name}` holds a digest as a String; use `TokenHash`"),
                );
            }
        }
    }
    findings
}

/// A struct that wraps a single `String`: a text type.
fn wraps_text(item: &syn::ItemStruct) -> bool {
    let syn::Fields::Unnamed(fields) = &item.fields else {
        return false;
    };
    let only = fields.unnamed.len() == 1;
    only && fields
        .unnamed
        .iter()
        .all(|field| type_name(&field.ty).is_some_and(|ty| ty == "String"))
}

/// Where the source breaks the convention [`text_wrappers_read_from_json_go_through_their_constructor`] holds it to.
fn text_read_from_json_unchecked(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for item in file.inventory().structs {
            let name = item.ident.to_string();
            if !wraps_text(item) || PLAIN_DESERIALIZE_ALLOWED.contains(&name.as_str()) {
                continue;
            }
            let attributes: Vec<String> = item.attrs.iter().map(|a| file.text_of(a)).collect();
            let deserializes = attributes.iter().any(|a| a.contains("Deserialize"));
            let checked = attributes.iter().any(|a| {
                a.contains("try_from") || a.contains("from =") || a.contains("transparent")
            });
            if deserializes && !checked {
                findings.flag(
                    file,
                    item,
                    format!("`{name}` deserializes without its constructor; add `serde(try_from)`"),
                );
            }
        }
    }
    findings
}

/// Whether a line is a comment of its own, not a doc comment.
fn is_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("// ") || trimmed == "//"
}

/// Where the source breaks the convention [`function_bodies_carry_no_comments`] holds it to.
fn comments_in_function_bodies(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let inventory = file.inventory();
        let lines = file.lines();
        for line in body_lines(file, &inventory) {
            if is_comment(lines[line - 1]) {
                findings.flag_line(file, line, "comment inside a function body");
            }
        }
    }
    findings
}

/// Whether the lines directly above line `line` (1-based), through other
/// attributes and comments, include a comment that explains.
fn explained_above(lines: &[&str], line: usize) -> bool {
    lines[..line - 1]
        .iter()
        .rev()
        .map(|l| l.trim_start())
        .take_while(|l| l.starts_with("//") || l.starts_with("#["))
        .any(|l| l.starts_with("// ") || l.starts_with("/// "))
}

/// Where the source breaks the convention [`every_allow_says_why`] holds it to.
fn unexplained_allows(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let lines = file.lines();
        for attribute in file.inventory().attributes {
            let silences =
                attribute.path().is_ident("allow") || attribute.path().is_ident("expect");
            if silences && !explained_above(&lines, line_of(attribute)) {
                findings.flag(file, attribute, "an `allow` without a comment saying why");
            }
        }
    }
    findings
}

/// The refusals a file turns into domain errors with
/// `refusal_is_a_domain_error!`, invoked next to the status machine.
fn converted_refusals(inventory: &Inventory<'_>) -> proc_macro2::TokenStream {
    inventory
        .item_macros
        .iter()
        .filter(|item| {
            item.mac
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "refusal_is_a_domain_error")
        })
        .flat_map(|item| item.mac.tokens.clone())
        .collect()
}

/// Whether `impl From<Refusal> for DomainError` is in the inventory: the
/// way a generic refusal, which the macro cannot list, converts.
fn converts_by_hand(inventory: &Inventory<'_>, refusal: &str) -> bool {
    inventory.impls.iter().any(|item| {
        let Some((_, path, _)) = &item.trait_ else {
            return false;
        };
        let Some(from) = path
            .segments
            .last()
            .filter(|segment| segment.ident == "From")
        else {
            return false;
        };
        let syn::PathArguments::AngleBracketed(arguments) = &from.arguments else {
            return false;
        };
        let source_is_refusal = arguments.args.iter().any(|argument| {
            matches!(argument, syn::GenericArgument::Type(ty)
                if type_name(ty).is_some_and(|ty| ty == refusal))
        });
        let target_is_domain_error = type_name(&item.self_ty).is_some_and(|ty| ty == "DomainError");
        source_is_refusal && target_is_domain_error
    })
}

/// Where the source breaks the convention [`every_status_refusal_is_an_error_that_converts`] holds it to.
fn refusals_that_are_not_errors(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let inventory = file.inventory();
        let converted = converted_refusals(&inventory);
        for item in &inventory.structs {
            let name = item.ident.to_string();
            if !(name.starts_with("Invalid") && name.ends_with("Transition")) {
                continue;
            }
            let derives_error = item
                .attrs
                .iter()
                .any(|attribute| file.text_of(attribute).contains("thiserror::Error"));
            let converts = tokens_name(&converted, &name) || converts_by_hand(&inventory, &name);
            let message = match (derives_error, converts) {
                (false, _) => format!("`{name}` must derive `thiserror::Error`"),
                (true, false) => format!(
                    "`{name}` must be listed in a `refusal_is_a_domain_error!` beside it, \
                     or convert into `DomainError` itself if it is generic"
                ),
                (true, true) => continue,
            };
            findings.flag(file, item, message);
        }
    }
    findings
}

/// Where the source breaks the convention [`events_use_the_event_macros`] holds it to.
fn events_written_by_hand(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        if !file.path.starts_with("domains/") {
            continue;
        }
        for item in file.inventory().impls {
            let implements_core = item
                .trait_
                .as_ref()
                .and_then(|(_, path, _)| path.segments.last())
                .is_some_and(|segment| segment.ident == "DomainEventCore");
            let Some(name) = type_name(&item.self_ty).map(ToString::to_string) else {
                continue;
            };
            let listed = HAND_WRITTEN_EVENTS.iter().any(|(event, _)| *event == name);
            if implements_core && !listed {
                findings.flag(
                    file,
                    item,
                    format!("`{name}` writes its accessors by hand; use `tenant_event!` and its siblings"),
                );
            }
        }
    }
    findings
}

/// Where the source breaks the convention [`the_domain_uses_no_adapter_library`] holds it to.
fn adapter_libraries_used(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        let inventory = file.inventory();
        let from_uses = inventory.uses.iter().flat_map(|item| use_roots(&item.tree));
        let from_paths = inventory
            .paths
            .iter()
            .filter(|path| path.segments.len() > 1)
            .filter_map(|path| path.segments.first().map(|segment| &segment.ident));
        for root in from_uses.chain(from_paths) {
            if let Some(library) = ADAPTER_LIBRARIES.iter().find(|library| root == *library) {
                findings.flag(
                    file,
                    root,
                    format!("uses `{library}`; put it behind a port"),
                );
            }
        }
    }
    findings
}

/// Whether a condition opens with `let`, as `if let` and let chains do.
fn opens_with_let(condition: &Expr) -> bool {
    match condition {
        Expr::Let(_) => true,
        Expr::Binary(binary) => opens_with_let(&binary.left),
        _ => false,
    }
}

/// The blocks an `if` runs: its own, and a plain `else` block.
fn branches(expr: &syn::ExprIf) -> Vec<&syn::Block> {
    let otherwise = expr
        .else_branch
        .as_ref()
        .and_then(|(_, other)| match other.as_ref() {
            Expr::Block(block) => Some(&block.block),
            _ => None,
        });
    std::iter::once(&expr.then_branch)
        .chain(otherwise)
        .collect()
}

/// Where the source breaks the convention [`no_if_is_nested_in_another`] holds it to.
fn nested_ifs(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for outer in file.inventory().ifs {
            let nested = branches(outer)
                .into_iter()
                .flat_map(|block| &block.stmts)
                .filter_map(|stmt| match stmt {
                    Stmt::Expr(Expr::If(inner), _) => Some(inner),
                    _ => None,
                })
                .filter(|inner| !opens_with_let(&inner.cond));
            for inner in nested {
                findings.flag(
                    file,
                    inner,
                    "an `if` inside another; flatten it or extract a function",
                );
            }
        }
    }
    findings
}

/// Where the source breaks the convention [`text_types_are_declared_with_text_value`] holds it to.
fn text_types_written_by_hand(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        for item in file.inventory().structs {
            let name = item.ident.to_string();
            let exempt = HAND_WRITTEN_TEXT.iter().any(|(listed, _)| *listed == name);
            if wraps_text(item) && !exempt {
                findings.flag(
                    file,
                    item,
                    format!("`{name}` is written by hand; declare it with `text_value!`"),
                );
            }
        }
    }
    findings
}

/// Where the source breaks the convention [`input_is_checked_by_the_shared_rules`] holds it to.
fn input_checked_by_hand(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        if file.path.starts_with("shared/validation") {
            continue;
        }
        for guard in file.inventory().guards {
            if !guard.refuses || guard.in_a_rule {
                continue;
            }
            let condition = format!(" {} ", file.text_of(guard.test));
            let Some((pattern, replacement)) = HAND_CHECKS
                .iter()
                .find(|(pattern, _)| condition.contains(pattern))
            else {
                continue;
            };
            let allowed = HAND_CHECKS_ALLOWED
                .iter()
                .any(|(path, needle)| *path == file.path && condition.contains(needle));
            if !allowed {
                findings.flag(
                    file,
                    guard.test,
                    format!("`{pattern}` checked by hand; use {replacement}"),
                );
            }
        }
    }
    findings
}

/// Whether a field holds a plain number of seconds.
fn plain_seconds(name: &str, ty: &Type) -> bool {
    let counts_seconds = name.ends_with("_secs") || name.ends_with("_seconds");
    let number = type_name(ty).is_some_and(|ty| ty == "u32" || ty == "u64");
    counts_seconds && number
}

/// Whether `field`, written `Owner.field` in the file at `path`, is listed
/// as text or as plain seconds on purpose.
fn untyped_allowed(path: &str, field: &str) -> bool {
    (TEXT_FIELDS_ALLOWED.iter())
        .any(|(listed_in, listed, _)| *listed_in == path && *listed == field)
        || (PLAIN_DURATIONS_ALLOWED.iter()).any(|(listed, _)| *listed == field)
}

/// Where the source breaks the convention [`domain_values_are_typed`] holds it to.
fn untyped_values(files: &[SourceFile]) -> Findings {
    let mut findings = Findings::default();
    for file in files {
        if file.path.starts_with("shared/validation") {
            continue;
        }
        for named in file.inventory().fields {
            let owner = named.owner.to_string();
            let name = &named.name;
            let field = format!("{owner}.{name}");
            let ty = &named.field.ty;
            let text = type_mentions(ty, "String") || type_mentions(ty, "Uuid");
            let exempt = owner.ends_with("Wire") || untyped_allowed(&file.path, &field);
            if (text || plain_seconds(name, ty)) && !exempt {
                findings.flag(
                    file,
                    named.field,
                    format!(
                        "`{field}` is `{}`; give it a type that names the value",
                        file.text_of(ty)
                    ),
                );
            }
        }
    }
    findings
}

#[cfg_attr(test, test)]
pub(crate) fn every_record_loads_from_a_row() {
    records_loaded_from_loose_values(&production_files())
        .assert_none("records loaded from loose values");
}

#[cfg_attr(test, test)]
pub(crate) fn every_status_machine_moves_through_try_transition() {
    misshapen_status_machines(&production_files()).assert_none("status machines in another shape");
}

/// A status set straight to a variant skips the machine that says whether
/// the move is allowed.
#[cfg_attr(test, test)]
pub(crate) fn no_status_is_set_without_its_machine() {
    statuses_set_around_their_machine(&production_files())
        .assert_none("statuses set without their machine");
}

#[cfg_attr(test, test)]
pub(crate) fn parse_reads_input_and_from_stored_reads_storage() {
    readers_blaming_the_wrong_side(&production_files())
        .assert_none("readers that report the wrong kind of error");
}

#[cfg_attr(test, test)]
pub(crate) fn no_id_is_a_bare_uuid() {
    bare_uuid_ids(&production_files()).assert_none("ids held as bare UUIDs");
}

#[cfg_attr(test, test)]
pub(crate) fn fresh_uuids_are_made_only_by_the_id_types() {
    uuids_made_outside_the_id_types(&production_files())
        .assert_none("bare UUIDs made outside the id types");
}

#[cfg_attr(test, test)]
pub(crate) fn no_digest_is_a_bare_string() {
    digests_held_as_strings(&production_files()).assert_none("digests held as plain strings");
}

#[cfg_attr(test, test)]
pub(crate) fn text_wrappers_read_from_json_go_through_their_constructor() {
    text_read_from_json_unchecked(&production_files())
        .assert_none("text wrappers read from JSON unchecked");
}

#[cfg_attr(test, test)]
pub(crate) fn function_bodies_carry_no_comments() {
    comments_in_function_bodies(&every_file()).assert_none("comments inside function bodies");
}

#[cfg_attr(test, test)]
pub(crate) fn every_allow_says_why() {
    unexplained_allows(&production_files()).assert_none("unexplained allows");
}

#[cfg_attr(test, test)]
pub(crate) fn every_status_refusal_is_an_error_that_converts() {
    refusals_that_are_not_errors(&production_files())
        .assert_none("status refusals that are not errors");
}

#[cfg_attr(test, test)]
pub(crate) fn events_use_the_event_macros() {
    events_written_by_hand(&production_files()).assert_none("events written by hand");
}

#[cfg_attr(test, test)]
pub(crate) fn the_domain_uses_no_adapter_library() {
    adapter_libraries_used(&production_files()).assert_none("adapter libraries in the domain");
}

#[cfg_attr(test, test)]
pub(crate) fn no_if_is_nested_in_another() {
    nested_ifs(&production_files()).assert_none("nested ifs");
}

/// Every text type is declared with `text_value!`, so its rules are the
/// shared ones and it can only be built through them.
#[cfg_attr(test, test)]
pub(crate) fn text_types_are_declared_with_text_value() {
    text_types_written_by_hand(&production_files()).assert_none("text types written by hand");
}

/// A constructor that checks its input by hand writes a rule the shared
/// validation already has, and drifts from it.
#[cfg_attr(test, test)]
pub(crate) fn input_is_checked_by_the_shared_rules() {
    input_checked_by_hand(&production_files()).assert_none("input checked by hand");
}

/// A value with a meaning holds a type that names it, so a field that is a
/// plain `String` or a bare number of seconds is either text on purpose,
/// listed above, or a type still to be written.
#[cfg_attr(test, test)]
pub(crate) fn domain_values_are_typed() {
    untyped_values(&production_files()).assert_none("untyped domain values");
}

/// An emailed link is spent, and asked about, only against its account.
#[cfg_attr(test, test)]
pub(crate) fn emailed_links_have_no_shortcuts() {
    security::links_spent_without_their_account(&production_files())
        .assert_none("emailed links spent without their account");
}

/// Only the domain says a thing was checked.
#[cfg_attr(test, test)]
pub(crate) fn proofs_have_no_public_constructor() {
    security::proofs_made_outside_the_domain(&production_files())
        .assert_none("proofs made outside the domain");
}

/// A human is stored with the person behind them, or a two-person rule
/// quietly compares accounts only.
#[cfg_attr(test, test)]
pub(crate) fn no_person_is_optional() {
    security::people_without_a_person(&production_files())
        .assert_none("people stored without a person");
}

#[cfg_attr(test, test)]
pub(crate) fn text_carrying_a_secret_never_prints() {
    security::secrets_that_print(&production_files()).assert_none("secrets that print");
}

#[cfg_attr(test, test)]
pub(crate) fn secrets_are_compared_in_constant_time() {
    security::secrets_compared_byte_by_byte(&production_files())
        .assert_none("secrets compared byte by byte");
}

#[cfg_attr(test, test)]
pub(crate) fn values_guarding_a_rule_are_rebuilt_only_by_their_aggregate() {
    security::guarded_values_rebuilt_in_public(&production_files())
        .assert_none("guarded values rebuilt in public");
}

/// A choice held as an `Option` or a `bool` reads as `None` or `false` at
/// every call site, and a check that forgets one case passes the other by
/// default. Each one left is listed with the reason it stays.
#[cfg_attr(test, test)]
pub(crate) fn every_choice_names_its_cases() {
    security::untyped_choices(&production_files()).assert_none("untyped choices");
}

/// A `bool` argument reads as `true` or `false` where it is passed, and says
/// nothing about which case it chose.
#[cfg_attr(test, test)]
pub(crate) fn no_function_takes_a_flag() {
    security::flag_parameters(&production_files()).assert_none("functions taking a bool");
}

/// A listed field that has been given a type, renamed or removed must leave
/// the list, so the list only ever shrinks to what is really left.
#[cfg_attr(test, test)]
pub(crate) fn every_listed_choice_is_still_one() {
    let files = production_files();
    let stale: Vec<String> = lists::UNTYPED_CHOICES_ALLOWED
        .iter()
        .filter(|(path, field, _)| !security::is_untyped_choice(&files, path, field))
        .map(|(path, field, _)| format!("{path}: {field}"))
        .collect();
    assert!(
        stale.is_empty(),
        "listed but no longer an untyped choice: {stale:?}"
    );
}

/// A creation or change of a stored value names who makes it, so every
/// rule that asks "may this person do it" has the person to ask about.
#[cfg_attr(test, test)]
pub(crate) fn every_creation_and_change_names_its_caller() {
    callers::stored_changes_without_a_caller(&production_files())
        .assert_none("creations and changes that name no caller");
}

#[cfg_attr(test, test)]
pub(crate) fn values_guarding_a_rule_keep_their_fields_private() {
    security::guarded_values_with_public_fields(&production_files())
        .assert_none("guarded values with public fields");
}

/// A listed type that was renamed or removed would leave its guard checking
/// nothing, so every listed name must still be declared.
#[cfg_attr(test, test)]
pub(crate) fn every_guarded_name_still_exists() {
    let files = production_files();
    let structs: std::collections::BTreeSet<String> = files
        .iter()
        .flat_map(|file| {
            let mut names: Vec<String> = file
                .inventory()
                .structs
                .iter()
                .map(|item| item.ident.to_string())
                .collect();
            names.extend(
                security::text_types_declared(file)
                    .into_iter()
                    .map(|(name, _)| name),
            );
            names
        })
        .collect();
    let listed = lists::EMAILED_LINKS
        .iter()
        .chain(lists::GUARDED_VALUES)
        .copied()
        .chain(lists::PROOFS.iter().map(|(name, _)| *name))
        .chain(lists::SECRET_TEXT.iter().map(|(name, _)| *name))
        .chain(lists::SECRET_DIGESTS.iter().map(|(name, _)| *name));
    let missing: Vec<&str> = listed.filter(|name| !structs.contains(*name)).collect();
    assert!(missing.is_empty(), "listed but not declared: {missing:?}");
}

#[cfg_attr(test, test)]
pub(crate) fn one_test_module_sits_last_in_each_file() {
    shape::misplaced_test_modules(&every_file()).assert_none("misplaced test modules");
}

#[cfg_attr(test, test)]
pub(crate) fn no_file_is_split_by_divider_comments() {
    shape::divider_comments(&production_files()).assert_none("section dividers");
}

#[cfg_attr(test, test)]
pub(crate) fn no_file_holds_an_em_dash() {
    shape::em_dashes(&production_files()).assert_none("em dashes");
}

#[cfg_attr(test, test)]
pub(crate) fn json_reaches_a_value_only_through_its_constructor() {
    shape::deserialize_skipping_the_constructor(&production_files())
        .assert_none("derived Deserialize past a refusing constructor");
}

#[cfg_attr(test, test)]
pub(crate) fn dependencies_point_down_the_context_layers() {
    layers::context_dependencies(&production_files())
        .assert_none("dependencies against the context layers");
}

#[cfg_attr(test, test)]
pub(crate) fn every_context_is_placed_in_a_layer() {
    let wrong = layers::unplaced_contexts(&production_files());
    assert!(wrong.is_empty(), "context layers out of date: {wrong:?}");
}

#[cfg_attr(test, test)]
pub(crate) fn every_reconstitute_checks_its_row() {
    shape::infallible_reconstitutes(&production_files())
        .assert_none("reconstitutes that cannot refuse a row");
}

/// Stored records and the dashboard read payloads by key, so every key is
/// pinned: a new one adds a line here, and a misspelt or renamed one fails.
/// `IANUA_WRITE_SNAPSHOTS=1` rewrites the snapshot after a deliberate change.
#[cfg_attr(test, test)]
pub(crate) fn every_payload_key_is_pinned() {
    let keys: Vec<String> = shape::payload_keys(&production_files())
        .into_iter()
        .collect();
    let written = keys.join("\n") + "\n";
    let path = crate::conventions::own_file("domain/payload_keys.snapshot");
    if std::env::var_os("IANUA_WRITE_SNAPSHOTS").is_some() {
        std::fs::write(&path, &written).unwrap();
        return;
    }

    assert_eq!(written, std::fs::read_to_string(&path).unwrap());
}

#[cfg_attr(test, test)]
pub(crate) fn a_types_methods_sit_in_one_impl() {
    shape::split_impls(&production_files(), lists::SPLIT_IMPLS_ALLOWED)
        .assert_none("types with split impl blocks");
}

#[cfg_attr(test, test)]
pub(crate) fn imports_name_their_source_from_the_crate() {
    imports::parent_imports(&every_file()).assert_none("imports through `super::`");
}

#[cfg_attr(test, test)]
pub(crate) fn no_path_climbs_two_levels() {
    imports::climbing_paths(&every_file()).assert_none("paths through `super::super::`");
}

#[cfg_attr(test, test)]
pub(crate) fn production_code_imports_no_globs() {
    imports::glob_imports(&production_files()).assert_none("glob imports");
}

#[cfg_attr(test, test)]
pub(crate) fn imports_sit_at_the_top_of_their_module() {
    imports::imports_inside_functions(&every_file()).assert_none("imports inside functions");
}

#[cfg_attr(test, test)]
pub(crate) fn no_file_repeats_its_folder() {
    shape::files_repeating_their_folder(&every_file(), lists::FILE_NAMES_ALLOWED)
        .assert_none("files repeating their folder");
}

#[cfg_attr(test, test)]
pub(crate) fn no_path_climbs_with_super() {
    shape::relative_paths(&every_file()).assert_none("paths climbing with super");
}

#[cfg_attr(test, test)]
pub(crate) fn every_listed_file_name_still_exists() {
    let files = every_file();
    let stale: Vec<&str> = lists::FILE_NAMES_ALLOWED
        .iter()
        .map(|(path, _)| *path)
        .filter(|path| !files.iter().any(|file| file.path == *path))
        .collect();
    assert!(
        stale.is_empty(),
        "listed file names that no longer exist: {stale:?}"
    );
}

#[cfg_attr(test, test)]
pub(crate) fn the_folder_check_finds_its_planted_repeat() {
    let mut planted = planted_file();
    planted.path = "domains/oauth/grants/refresh_grant.rs".to_owned();
    assert!(!shape::files_repeating_their_folder(&[planted], &[]).is_empty());
}

#[cfg_attr(test, test)]
pub(crate) fn every_file_holds_one_topic() {
    shape::files_longer_than(&production_files(), shape::MAX_CODE_LINES)
        .assert_none("files too long to hold one topic");
}

#[cfg_attr(test, test)]
pub(crate) fn every_change_is_a_named_action_not_a_setter() {
    shape::setters(&production_files()).assert_none("setters");
}

#[cfg_attr(test, test)]
pub(crate) fn nothing_is_rebuilt_from_loose_stored_parts_in_public() {
    shape::public_stored_constructors(&production_files())
        .assert_none("public stored constructors");
}

#[cfg_attr(test, test)]
pub(crate) fn audit_payloads_record_stable_names() {
    shape::debug_formatting_in_payloads(&production_files())
        .assert_none("payloads written through Debug");
}

#[cfg_attr(test, test)]
pub(crate) fn docs_name_only_the_none_that_is_there() {
    shape::docs_naming_a_none_that_is_not_there(&production_files())
        .assert_none("docs naming a None the field cannot hold");
}

#[cfg_attr(test, test)]
pub(crate) fn repeats_are_found_by_the_shared_helper() {
    shape::repeat_checks_by_hand(&production_files()).assert_none("repeat checks by hand");
}

/// Event fields are the domain's own: the application takes what an
/// aggregate raised and reads it through its payload, never a field.
#[cfg_attr(test, test)]
pub(crate) fn events_keep_their_fields_to_the_domain() {
    shape::public_event_fields(&production_files()).assert_none("public event fields");
}

#[cfg_attr(test, test)]
pub(crate) fn every_event_of_a_listed_folder_is_on_its_list() {
    shape::events_missing_from_their_list(&every_file())
        .assert_none("events missing from every_event");
}

#[cfg_attr(test, test)]
pub(crate) fn no_function_takes_an_unexplained_option() {
    security::optional_parameters(&production_files()).assert_none("functions taking an Option");
}

/// A listed parameter that was given a type, renamed or removed must leave
/// the list.
#[cfg_attr(test, test)]
pub(crate) fn every_listed_optional_parameter_is_still_one() {
    let files = production_files();
    let stale: Vec<String> = lists::OPTIONAL_PARAMETERS_ALLOWED
        .iter()
        .filter(|(path, parameter, _)| !security::is_optional_parameter(&files, path, parameter))
        .map(|(path, parameter, _)| format!("{path}: {parameter}"))
        .collect();
    assert!(
        stale.is_empty(),
        "listed but no longer an Option parameter: {stale:?}"
    );
}

/// A listed `bool` parameter that has been given a type, renamed or removed
/// must leave the list.
#[cfg_attr(test, test)]
pub(crate) fn every_listed_flag_parameter_is_still_one() {
    let files = production_files();
    let stale: Vec<String> = lists::FLAG_PARAMETERS_ALLOWED
        .iter()
        .filter(|(path, parameter, _)| !security::is_flag_parameter(&files, path, parameter))
        .map(|(path, parameter, _)| format!("{path}: {parameter}"))
        .collect();
    assert!(
        stale.is_empty(),
        "listed but no longer a bool parameter: {stale:?}"
    );
}

#[cfg_attr(test, test)]
pub(crate) fn each_file_imports_what_it_uses() {
    shape::imports_held_for_others(&production_files()).assert_none("imports held for others");
}

/// A check: the places in some files that break one convention.
type Check = fn(&[SourceFile]) -> Findings;

/// Every check, by name.
const CHECKS: &[(&str, Check)] = &[
    (
        "records_loaded_from_loose_values",
        records_loaded_from_loose_values,
    ),
    ("misshapen_status_machines", misshapen_status_machines),
    (
        "statuses_set_around_their_machine",
        statuses_set_around_their_machine,
    ),
    (
        "readers_blaming_the_wrong_side",
        readers_blaming_the_wrong_side,
    ),
    ("bare_uuid_ids", bare_uuid_ids),
    (
        "uuids_made_outside_the_id_types",
        uuids_made_outside_the_id_types,
    ),
    ("digests_held_as_strings", digests_held_as_strings),
    (
        "text_read_from_json_unchecked",
        text_read_from_json_unchecked,
    ),
    ("comments_in_function_bodies", comments_in_function_bodies),
    ("unexplained_allows", unexplained_allows),
    ("refusals_that_are_not_errors", refusals_that_are_not_errors),
    ("events_written_by_hand", events_written_by_hand),
    (
        "events_built_outside_an_aggregate",
        observations::events_built_outside_an_aggregate,
    ),
    ("adapter_libraries_used", adapter_libraries_used),
    ("nested_ifs", nested_ifs),
    ("text_types_written_by_hand", text_types_written_by_hand),
    ("input_checked_by_hand", input_checked_by_hand),
    ("untyped_values", untyped_values),
    (
        "links_spent_without_their_account",
        security::links_spent_without_their_account,
    ),
    (
        "proofs_made_outside_the_domain",
        security::proofs_made_outside_the_domain,
    ),
    ("people_without_a_person", security::people_without_a_person),
    ("secrets_that_print", security::secrets_that_print),
    (
        "secrets_compared_byte_by_byte",
        security::secrets_compared_byte_by_byte,
    ),
    (
        "guarded_values_rebuilt_in_public",
        security::guarded_values_rebuilt_in_public,
    ),
    (
        "guarded_values_with_public_fields",
        security::guarded_values_with_public_fields,
    ),
    ("untyped_choices", security::untyped_choices),
    ("flag_parameters", security::flag_parameters),
    ("optional_parameters", security::optional_parameters),
    ("misplaced_test_modules", shape::misplaced_test_modules),
    ("divider_comments", shape::divider_comments),
    ("em_dashes", shape::em_dashes),
    (
        "deserialize_skipping_the_constructor",
        shape::deserialize_skipping_the_constructor,
    ),
    (
        "public_stored_constructors",
        shape::public_stored_constructors,
    ),
    ("infallible_reconstitutes", shape::infallible_reconstitutes),
    ("setters", shape::setters),
    ("split_impls", |files| shape::split_impls(files, &[])),
    ("parent_imports", imports::parent_imports),
    ("climbing_paths", imports::climbing_paths),
    ("glob_imports", imports::glob_imports),
    (
        "imports_inside_functions",
        imports::imports_inside_functions,
    ),
    ("files_longer_than", |files| {
        shape::files_longer_than(files, 10)
    }),
    ("context_dependencies", layers::context_dependencies),
    (
        "debug_formatting_in_payloads",
        shape::debug_formatting_in_payloads,
    ),
    (
        "docs_naming_a_none_that_is_not_there",
        shape::docs_naming_a_none_that_is_not_there,
    ),
    ("repeat_checks_by_hand", shape::repeat_checks_by_hand),
    (
        "events_missing_from_their_list",
        shape::events_missing_from_their_list,
    ),
    ("imports_held_for_others", shape::imports_held_for_others),
    ("public_event_fields", shape::public_event_fields),
];

/// A check that finds nothing in a file written to break it has stopped
/// looking, and would pass over the real source just as quietly.
#[cfg_attr(test, test)]
pub(crate) fn every_check_finds_its_planted_break() {
    let planted = [planted_file()];
    let blind: Vec<&str> = CHECKS
        .iter()
        .filter(|(_, check)| check(&planted).is_empty())
        .map(|(name, _)| *name)
        .collect();
    assert!(
        blind.is_empty(),
        "checks that missed their planted break: {blind:?}"
    );
}
