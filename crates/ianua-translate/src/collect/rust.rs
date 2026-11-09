//! Production Rust literals, outward error arguments and unresolved message expressions.

pub(crate) mod calls;
pub(crate) mod cfg;
mod events;

use quote::ToTokens as _;
use syn::spanned::Spanned as _;
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, Item};

use crate::catalog::{DynamicMessage, Evidence, Message, Occurrence, Syntax};
use crate::collect::rust::calls::{has_message_literal, internal_call, message_index};
use crate::collect::rust::cfg::{attributes, excluded};
use crate::collect::tokens::{prose, strings};
use crate::error::{Error, Result};

/// Everything the collector learned from one parsed production file.
#[derive(Default)]
pub(crate) struct Collected {
    /// Literal messages and prose candidates with their evidence.
    pub(crate) messages: Vec<Message>,
    /// Outward constructors whose messages must be followed through another expression.
    pub(crate) dynamic: Vec<DynamicMessage>,
    /// External modules explicitly disabled in production.
    pub(crate) excluded_modules: Vec<String>,
}

/// Parses a file and extracts its production messages without executing macros.
///
/// # Errors
///
/// Returns invalid data if Rust syntax cannot be parsed, never a partial successful catalog.
pub(crate) fn collect(path: &str, text: &str) -> Result<Collected> {
    let parsed = syn::parse_file(text).map_err(|source| Error::Rust {
        path: path.to_owned(),
        source,
    })?;
    let mut collector = Collector {
        path,
        context: String::new(),
        evidence: Evidence::Review,
        keyed: None,
        found: Collected::default(),
    };
    collector.visit_file(&parsed);
    Ok(collector.found)
}

/// The source context inherited while visiting nested expressions.
struct Collector<'a> {
    path: &'a str,
    context: String,
    evidence: Evidence,
    keyed: Option<String>,
    found: Collected,
}

impl Collector<'_> {
    /// Records a literal when its source proves visibility or its prose needs review.
    fn literal(&mut self, literal: &syn::LitStr, syntax: Syntax, evidence: Evidence) {
        let text = literal.value();
        if !self.worth_recording(&text, evidence) {
            return;
        }
        let occurrence = self.occurrence(literal.span(), evidence);
        self.found
            .messages
            .push(Message::new(text, syntax, occurrence));
    }

    /// Records what `record` finds under `context` rather than its
    /// enclosing item, such as the event type a description belongs to.
    fn under(&mut self, context: String, record: impl FnOnce(&mut Self)) {
        let enclosing = std::mem::replace(&mut self.context, context);
        record(self);
        self.context = enclosing;
    }

    /// Whether text is a message: anything an outward constructor or event
    /// receives, and otherwise prose or a renderer's short label. A subject
    /// that is only a template expression has nothing to translate.
    fn worth_recording(&self, text: &str, evidence: Evidence) -> bool {
        if text.trim().is_empty() {
            return false;
        }
        match evidence {
            Evidence::CustomerError | Evidence::ErrorDisplay | Evidence::Event => true,
            Evidence::Presentation | Evidence::Template | Evidence::Subject | Evidence::Review => {
                prose(text) || self.presentation_word(text)
            }
        }
    }

    /// Retains short labels in renderers without treating every identifier as a message.
    fn presentation_word(&self, text: &str) -> bool {
        presentation(self.path)
            && text
                .chars()
                .all(|character| character.is_alphabetic() || character == '-')
            && [
                "word",
                "verb",
                "noun",
                "title",
                "label",
                "note",
                "greeting",
                "duration",
                "body",
                "text",
                "description",
                "characters",
                "entries",
            ]
            .iter()
            .any(|part| self.context.contains(part))
    }

    /// The evidence a plain literal inherits from the surrounding call and owning module.
    fn evidence(&self) -> Evidence {
        match self.evidence {
            Evidence::Review if presentation(self.path) => Evidence::Presentation,
            evidence => evidence,
        }
    }

    /// Makes a source location without losing its enclosing function or error variant.
    fn occurrence(&self, span: proc_macro2::Span, evidence: Evidence) -> Occurrence {
        let start = span.start();
        Occurrence {
            path: self.path.to_owned(),
            line: start.line,
            column: start.column + 1,
            context: self.context.clone(),
            evidence,
            keyed: self.keyed.clone(),
        }
    }

    /// Records a dynamic error argument, then visits it as outward message source.
    fn message_argument(&mut self, argument: &Expr) {
        if !has_message_literal(argument) {
            self.found.dynamic.push(DynamicMessage {
                occurrence: self.occurrence(argument.span(), Evidence::CustomerError),
                expression: argument.to_token_stream().to_string(),
            });
        }
        let previous = self.evidence;
        self.evidence = Evidence::CustomerError;
        self.visit_expr(argument);
        self.evidence = previous;
    }

    /// Reads descriptions deliberately published from event declaration comments.
    fn event_descriptions(&mut self, invocation: &syn::Macro) {
        let Ok(declaration) = syn::parse2::<events::Declaration>(invocation.tokens.clone()) else {
            self.found.dynamic.push(DynamicMessage {
                occurrence: self.occurrence(invocation.span(), Evidence::Event),
                expression: invocation.to_token_stream().to_string(),
            });
            return;
        };
        for description in declaration.descriptions {
            self.under(description.event_type, |this| {
                this.literal(&description.text, Syntax::Plain, Evidence::Event);
            });
        }
    }

    /// Keeps a mail subject, named after its template, under the template grammar.
    fn subject(&mut self, found: &[syn::LitStr]) {
        let [template, subject, ..] = found else {
            return;
        };
        self.under(template.value(), |this| {
            this.literal(subject, Syntax::MiniJinja, Evidence::Subject);
        });
    }

    /// Keeps a mail subject or ordinary macro literals under their original interpolation grammar.
    fn macro_literals(&mut self, name: &str, invocation: &syn::Macro) {
        let found = strings(invocation.tokens.clone());
        if name == "template" && self.path.ends_with("/mail/compose/platform.rs") {
            self.subject(&found);
            return;
        }
        let formatting = matches!(
            name,
            "format" | "write" | "writeln" | "println" | "eprintln"
        );
        for (position, literal) in found.iter().enumerate() {
            match (position, formatting) {
                (0, true) => self.literal(literal, Syntax::RustFormat, self.evidence()),
                (_, true) if !prose(&literal.value()) => {}
                _ => self.literal(literal, Syntax::Plain, self.evidence()),
            }
        }
    }

    /// Marks both possible filesystem layouts of an external test-only module as excluded.
    fn exclude_module(&mut self, module: &syn::ItemMod) {
        if module.content.is_some() {
            return;
        }
        let (directory, file) = self.path.rsplit_once('/').unwrap_or(("", self.path));
        let parent = match file {
            "mod.rs" | "lib.rs" | "main.rs" => directory.to_owned(),
            _ => format!("{directory}/{}", file.trim_end_matches(".rs")),
        };
        self.found
            .excluded_modules
            .push(format!("{parent}/{}", module.ident));
    }
}

impl<'ast> Visit<'ast> for Collector<'_> {
    /// Leaves test-only items and their external modules out of the production inventory.
    fn visit_item(&mut self, item: &'ast Item) {
        if excluded(attributes(item)) {
            if let Item::Mod(module) = item {
                self.exclude_module(module);
            }
            return;
        }
        visit::visit_item(self, item);
    }

    /// Gives messages the name of their owning free function.
    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        let previous = std::mem::replace(&mut self.context, function.sig.ident.to_string());
        visit::visit_item_fn(self, function);
        self.context = previous;
    }

    /// Gives messages their owning method, excluding methods compiled only for tests.
    fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
        if excluded(&function.attrs) {
            return;
        }
        let previous = std::mem::replace(&mut self.context, function.sig.ident.to_string());
        visit::visit_impl_item_fn(self, function);
        self.context = previous;
    }

    /// Gives constant text its source name, so reviewers can follow indirect message uses.
    fn visit_item_const(&mut self, constant: &'ast syn::ItemConst) {
        let previous = std::mem::replace(&mut self.context, constant.ident.to_string());
        visit::visit_item_const(self, constant);
        self.context = previous;
    }

    /// Associates error display attributes with the variant that supplies them.
    fn visit_variant(&mut self, variant: &'ast syn::Variant) {
        if excluded(&variant.attrs) {
            return;
        }
        let previous = std::mem::replace(&mut self.context, variant.ident.to_string());
        visit::visit_variant(self, variant);
        self.context = previous;
    }

    /// Reads error display text while excluding documentation, schema and serialization metadata.
    fn visit_attribute(&mut self, attribute: &'ast Attribute) {
        if !attribute.path().is_ident("error") {
            return;
        }
        let Ok(list) = attribute.meta.require_list() else {
            return;
        };
        let Some(literal) = strings(list.tokens.clone()).into_iter().next() else {
            return;
        };
        self.literal(&literal, Syntax::RustFormat, display_evidence(self.path));
    }

    /// Collects ordinary expression literals without treating field names as message text.
    fn visit_expr_lit(&mut self, expression: &'ast syn::ExprLit) {
        if let syn::Lit::Str(literal) = &expression.lit {
            self.literal(literal, Syntax::Plain, self.evidence());
        }
    }

    /// Retains short validation vocabulary used inside complete error sentences.
    fn visit_field_value(&mut self, field: &'ast syn::FieldValue) {
        let previous = self.context.clone();
        if self.path.contains("/shared/validation/")
            && matches!(&field.member, syn::Member::Named(name) if name == "description")
        {
            self.context = "description_label".to_owned();
        }
        visit::visit_field_value(self, field);
        self.context = previous;
    }

    /// Validation structs carry public prose in `message`, while their
    /// field names and stable error codes remain protocol identifiers.
    fn visit_expr_struct(&mut self, expression: &'ast syn::ExprStruct) {
        let validation = expression
            .path
            .segments
            .iter()
            .any(|part| part.ident == "ValidationError");
        for field in &expression.fields {
            if validation && matches!(&field.member, syn::Member::Named(name) if name == "message")
            {
                self.message_argument(&field.expr);
            } else {
                self.visit_field_value(field);
            }
        }
        if let Some(rest) = &expression.rest {
            self.visit_expr(rest);
        }
    }

    /// Recognizes outward error constructors and keeps internal failure details out.
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let Expr::Path(function) = call.func.as_ref() else {
            visit::visit_expr_call(self, call);
            return;
        };
        let names: Vec<_> = function
            .path
            .segments
            .iter()
            .map(|part| part.ident.to_string())
            .collect();
        if internal_call(&names) {
            return;
        }
        let Some(index) = message_index(&names) else {
            visit::visit_expr_call(self, call);
            return;
        };
        for (position, argument) in call.args.iter().enumerate() {
            if position == index {
                self.message_argument(argument);
            } else {
                self.visit_expr(argument);
            }
        }
    }

    /// Recognizes the existing lookup helpers that turn absence and stale writes into refusals.
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if !matches!(
            call.method.to_string().as_str(),
            "or_not_found" | "or_conflict"
        ) {
            visit::visit_expr_method_call(self, call);
            return;
        }
        self.visit_expr(&call.receiver);
        for argument in &call.args {
            self.message_argument(argument);
        }
    }

    /// Reads formatted messages and built-in mail subjects without reading logging macros as copy.
    fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
        let Some(name) = invocation
            .path
            .segments
            .last()
            .map(|part| part.ident.to_string())
        else {
            return;
        };
        match name.as_str() {
            "trace" | "debug" | "info" | "warn" | "error" | "include_str" | "include_bytes"
            | "env" | "option_env" => {}
            "event_types" => self.event_descriptions(invocation),
            "message" => self.collect_keyed_refusal(invocation),
            other => self.macro_literals(other, invocation),
        }
    }
}

/// A `message!` call: the key, which is no message, and the message.
struct KeyedRefusal {
    key: syn::LitStr,
    message: Expr,
}

impl syn::parse::Parse for KeyedRefusal {
    fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
        let key = input.parse()?;
        input.parse::<syn::Token![,]>()?;
        Ok(Self {
            key,
            message: input.parse()?,
        })
    }
}

impl Collector<'_> {
    /// Reads a keyed refusal's message as a refusal's text, each place it
    /// is found at noting the key, which is no text of its own.
    fn collect_keyed_refusal(&mut self, invocation: &syn::Macro) {
        let Ok(refusal) = invocation.parse_body::<KeyedRefusal>() else {
            self.found.dynamic.push(DynamicMessage {
                occurrence: self.occurrence(invocation.span(), Evidence::CustomerError),
                expression: invocation.to_token_stream().to_string(),
            });
            return;
        };
        let outer = self.keyed.replace(refusal.key.value());
        self.message_argument(&refusal.message);
        self.keyed = outer;
    }
}

/// The shared error types render their displays directly; every other
/// display waits for a traced public caller.
fn display_evidence(path: &str) -> Evidence {
    let shared = path.ends_with("/shared/validation/error.rs")
        || path == "crates/ianua-app/src/error.rs"
        || path == "crates/ianua-domain/src/shared/errors.rs";
    if shared {
        return Evidence::Presentation;
    }
    Evidence::ErrorDisplay
}

/// Modules that put platform text into emails, pages, SMS, notifications and activity feeds.
fn presentation(path: &str) -> bool {
    [
        "/mail/compose/",
        "/pages/",
        "/sms/",
        "/notifications/delivery/render.rs",
        "/activity/",
        "/error/",
        "/extractors/json.rs",
        "/extractors/query.rs",
        "/extractors/form.rs",
        "/shared/validation/",
    ]
    .iter()
    .any(|part| path.contains(part))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Collects one synthetic production module as the same API source used by the real scan.
    fn collected(source: &str) -> Collected {
        collect("crates/ianua-api/src/example.rs", source).unwrap()
    }

    /// An outward formatted refusal retains its named values and exact source location.
    #[test]
    fn formatted_refusals_keep_their_source_and_placeholders() {
        let found =
            collected("fn invite() { AppError::Forbidden(format!(\"Invite {name} again\")); }");
        assert_eq!(found.messages.len(), 1);
        assert_eq!(found.messages[0].english, "Invite {name} again");
        assert!(found.messages[0].placeholders.contains("name"));
        assert_eq!(found.messages[0].occurrences[0].context, "invite");
        assert_eq!(found.messages[0].occurrences[0].line, 1);
    }

    /// The scan retains one public refusal while excluding logs, internal errors and test fixtures.
    #[test]
    fn tests_logs_and_masked_diagnostics_are_left_out() {
        let found = collected(
            r#"
            fn live() {
                tracing::warn!("the database password was rejected");
                AppError::internal_msg("the database password was rejected");
                AppError::Forbidden("You cannot invite this person".into());
            }
            #[cfg(test)] mod tests {
                fn fixture() { AppError::Forbidden("A test message".into()); }
            }
            #[cfg(all(test, feature = "extra"))] mod fixtures;
        "#,
        );
        assert_eq!(found.messages.len(), 1);
        assert_eq!(
            found.excluded_modules,
            ["crates/ianua-api/src/example/fixtures"]
        );
    }

    /// An error carried through a variable is listed for following rather than silently missed.
    #[test]
    fn dynamic_outward_arguments_are_explicit_follow_up_sources() {
        let found = collected("fn invite(message: String) { AppError::Forbidden(message); }");
        assert!(found.messages.is_empty());
        assert_eq!(found.dynamic.len(), 1);
        assert_eq!(found.dynamic[0].expression, "message");
    }

    /// Production-only cfg expressions stay readable, while disabled modules contribute no text.
    #[test]
    fn not_test_stays_but_never_enabled_code_is_skipped() {
        let found = collected(
            r#"
            #[cfg(not(test))] fn live() { DomainError::invalid("Choose a name"); }
            #[cfg(any())] fn dead() { DomainError::invalid("A dead message"); }
        "#,
        );
        assert_eq!(found.messages.len(), 1);
        assert_eq!(found.messages[0].english, "Choose a name");
    }

    /// Event declaration comments are published as runtime descriptions, unlike ordinary docs.
    #[test]
    fn event_descriptions_are_kept_without_collecting_other_macro_documentation() {
        let found = collected(
            r#"
            event_types! {
                /// The events of this context.
                pub enum TenantEvent {
                    /// A new tenant was provisioned.
                    Provisioned => "tenant.provisioned",
                }
            }
            text_value! {
                /// A documented domain value.
                pub struct Name;
            }
        "#,
        );
        assert_eq!(found.messages.len(), 1);
        assert_eq!(found.messages[0].english, "A new tenant was provisioned.");
        let occurrence = &found.messages[0].occurrences[0];
        assert_eq!(occurrence.evidence, Evidence::Event);
        assert_eq!(occurrence.context, "tenant.provisioned");
    }

    /// A mail subject is kept under the template grammar and named after its template.
    #[test]
    fn a_mail_subject_names_its_template() {
        let found = collect(
            "crates/ianua-infra/src/mail/compose/platform.rs",
            r#"fn pick() { template!("sign_in/password_reset", "Reset your password") }"#,
        )
        .unwrap();
        assert_eq!(found.messages.len(), 1);
        let message = &found.messages[0];
        assert_eq!(message.syntax, Syntax::MiniJinja);
        assert_eq!(message.occurrences[0].evidence, Evidence::Subject);
        assert_eq!(message.occurrences[0].context, "sign_in/password_reset");
    }

    /// A keyed refusal is collected as it was before its key: the message
    /// under its own grammar, a constant as a followed expression, and
    /// never the key itself as a message. Each place notes the key it is
    /// looked up by.
    #[test]
    fn a_keyed_refusal_is_collected_without_its_key() {
        let found = collected(
            r#"
            fn f() {
                DomainError::invalid(crate::message!("people-a", "Choose a name"));
                AppError::Conflict(ianua_domain::message!("people-b", format!("{name} is taken")));
                DomainError::conflict(ianua_domain::message!("people-c", CHANGED));
            }
            "#,
        );
        let texts: Vec<_> = found
            .messages
            .iter()
            .map(|m| (m.english.as_str(), m.syntax))
            .collect();
        assert_eq!(
            texts,
            [
                ("Choose a name", Syntax::Plain),
                ("{name} is taken", Syntax::RustFormat)
            ]
        );
        assert_eq!(found.dynamic.len(), 1);
        assert_eq!(found.dynamic[0].expression, "CHANGED");
        let keys: Vec<_> = found
            .messages
            .iter()
            .map(|m| m.occurrences[0].keyed.as_deref())
            .collect();
        assert_eq!(keys, [Some("people-a"), Some("people-b")]);
    }

    /// A list separator inside a formatted refusal is excluded; only the
    /// complete format string becomes a message.
    #[test]
    fn short_format_arguments_are_not_messages() {
        let found = collected(
            r#"fn f() { DomainError::invalid(format!("allowed: {}", list.join(", "))); }"#,
        );
        let texts: Vec<_> = found.messages.iter().map(|m| m.english.as_str()).collect();
        assert_eq!(texts, ["allowed: {}"]);
    }

    /// A mail subject containing only a template variable contributes no translatable message.
    #[test]
    fn a_subject_without_words_is_not_a_message() {
        let found = collect(
            "crates/ianua-infra/src/mail/compose/platform.rs",
            r#"fn pick() { template!("activity/notice", "{{ notice_title }}") }"#,
        )
        .unwrap();
        assert!(found.messages.is_empty());
    }

    /// A one-word charset description reaches validation sentences and therefore needs translation.
    #[test]
    fn short_validation_vocabulary_is_kept() {
        let found = collect(
            "crates/ianua-domain/src/shared/validation/charset.rs",
            r#"
            const DIGIT: Charset = Charset { description: "digits" };
        "#,
        )
        .unwrap();
        assert_eq!(found.messages.len(), 1);
        assert_eq!(found.messages[0].english, "digits");
    }
}
