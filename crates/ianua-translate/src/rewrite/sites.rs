//! Where a production file hands text to an outward refusal: the same
//! constructors, lookup helpers and validation messages the collector reads.

use proc_macro2::LineColumn;
use syn::spanned::Spanned as _;
use syn::visit::{self, Visit};
use syn::{Expr, Item};

use crate::catalog::Syntax;
use crate::collect::rust::calls::{internal_call, message_index};
use crate::collect::rust::cfg::{attributes, excluded};
use crate::collect::tokens::strings;

/// The macros whose first literal is a format string.
const FORMATTING: &[&str] = &["format"];

/// Error types whose text is protocol data, not a sentence for a person:
/// an OAuth `error_description` may hold only ASCII (RFC 6749 §5.2), and
/// SCIM and client-registration details follow the same rule.
const PROTOCOL_ERRORS: &[&str] = &["OAuthError", "RegistrationError", "ScimApiError"];

/// One refusal's message expression and how its text can be keyed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Site {
    /// Where the whole message expression starts.
    pub(crate) start: LineColumn,
    /// Where it ends.
    pub(crate) end: LineColumn,
    /// What the expression is.
    pub(crate) shape: Shape,
    /// What receives it.
    pub(crate) receiver: Receiver,
}

/// What a message is handed to, which decides what a message the rewrite
/// cannot key still needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Receiver {
    /// An application error variant, which holds a `Refusal`: text of any
    /// other type is converted into one.
    AppVariant,
    /// Anything that takes whatever turns into a `Refusal`.
    IntoRefusal,
}

/// The message expressions the rewrite understands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Shape {
    /// Literal text, alone or converted with `.into()`, `.to_owned()` or
    /// `.to_string()`, kept with the text of the literal itself.
    Literal { english: String, source: Span },
    /// A `format!` call, alone or converted, kept with the call itself.
    Formatted { english: String, source: Span },
    /// A constant of this name, whose text the catalog found where it is defined.
    Constant { name: String },
    /// Already a `message!`, or a conversion into one, left as it is.
    Keyed,
    /// Anything else: a variable or a helper's answer.
    Dynamic,
}

/// A stretch of source between two positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Span {
    /// Where it starts.
    pub(crate) start: LineColumn,
    /// Where it ends.
    pub(crate) end: LineColumn,
}

impl Shape {
    /// The catalog grammar the text was collected under, for a shape that has text.
    pub(crate) fn syntax(&self) -> Option<Syntax> {
        match self {
            Self::Literal { .. } => Some(Syntax::Plain),
            Self::Formatted { .. } => Some(Syntax::RustFormat),
            Self::Constant { .. } | Self::Keyed | Self::Dynamic => None,
        }
    }

    /// The English text the catalog holds for this message, when it has text.
    pub(crate) fn english(&self) -> Option<&str> {
        match self {
            Self::Literal { english, .. } | Self::Formatted { english, .. } => Some(english),
            Self::Constant { .. } | Self::Keyed | Self::Dynamic => None,
        }
    }
}

/// Whether a file's code is production code, whose refusals are keyed, or
/// test code, whose messages are only converted where a type needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Code {
    /// Code a production build compiles.
    Production,
    /// Code only tests compile.
    Test,
}

/// Every refusal message expression in a parsed file. Test-only items,
/// and every item of a test file, are found with no text to key.
pub(crate) fn sites(file: &syn::File, code: Code) -> Vec<Site> {
    let mut finder = Finder {
        found: Vec::new(),
        code,
    };
    finder.visit_file(file);
    finder.found
}

struct Finder {
    found: Vec<Site>,
    code: Code,
}

impl Finder {
    fn record(&mut self, expression: &Expr, receiver: Receiver) {
        let span = expression.span();
        let shape = match (self.code, shape(expression)) {
            (Code::Test, Shape::Keyed) => Shape::Keyed,
            (Code::Test, _) => Shape::Dynamic,
            (Code::Production, shape) => shape,
        };
        self.found.push(Site {
            start: span.start(),
            end: span.end(),
            shape,
            receiver,
        });
    }

    /// Visits test-only code as test code.
    fn in_test(&mut self, visit: impl FnOnce(&mut Self)) {
        let code = std::mem::replace(&mut self.code, Code::Test);
        visit(self);
        self.code = code;
    }
}

impl<'ast> Visit<'ast> for Finder {
    fn visit_item(&mut self, item: &'ast Item) {
        if excluded(attributes(item)) {
            self.in_test(|finder| visit::visit_item(finder, item));
            return;
        }
        visit::visit_item(self, item);
    }

    fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
        if excluded(&function.attrs) {
            self.in_test(|finder| visit::visit_impl_item_fn(finder, function));
            return;
        }
        visit::visit_impl_item_fn(self, function);
    }

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
        let index = message_index(&names).filter(|_| !protocol_error(&names));
        let Some(index) = index else {
            visit::visit_expr_call(self, call);
            return;
        };
        let receiver = receiver_of(&names);
        for (position, argument) in call.args.iter().enumerate() {
            if position == index {
                self.record(argument, receiver);
            }
            self.visit_expr(argument);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let lookup = matches!(
            call.method.to_string().as_str(),
            "or_not_found" | "or_conflict"
        );
        if lookup {
            call.args
                .iter()
                .for_each(|argument| self.record(argument, Receiver::IntoRefusal));
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_struct(&mut self, expression: &'ast syn::ExprStruct) {
        let validation = expression
            .path
            .segments
            .iter()
            .any(|part| part.ident == "ValidationError");
        let message = expression
            .fields
            .iter()
            .find(|field| matches!(&field.member, syn::Member::Named(name) if name == "message"));
        if let (true, Some(field)) = (validation, message) {
            self.record(&field.expr, Receiver::IntoRefusal);
        }
        visit::visit_expr_struct(self, expression);
    }
}

/// Whether the constructor's text is protocol data that stays English.
fn protocol_error(names: &[String]) -> bool {
    names
        .iter()
        .rev()
        .nth(1)
        .is_some_and(|owner| PROTOCOL_ERRORS.contains(&owner.as_str()))
}

/// What a constructor does with its message.
fn receiver_of(names: &[String]) -> Receiver {
    match names.iter().rev().nth(1).map(String::as_str) {
        Some("AppError") => Receiver::AppVariant,
        _ => Receiver::IntoRefusal,
    }
}

/// What a message expression is, reading through a conversion of a
/// literal or a `format!` call.
fn shape(expression: &Expr) -> Shape {
    match expression {
        Expr::Lit(literal) => literal_shape(literal),
        Expr::MethodCall(call) if converts(call) => converted_shape(&call.receiver),
        Expr::Macro(invocation) => macro_shape(&invocation.mac, expression.span()),
        Expr::Path(path) => constant_shape(path),
        _ => Shape::Dynamic,
    }
}

/// The shape of what a conversion converts.
fn converted_shape(converted: &Expr) -> Shape {
    match converted {
        Expr::Lit(literal) => literal_shape(literal),
        Expr::Macro(invocation) => macro_shape(&invocation.mac, converted.span()),
        _ => Shape::Dynamic,
    }
}

/// A constant named in screaming case, such as `CHANGED_MEANWHILE`.
fn constant_shape(path: &syn::ExprPath) -> Shape {
    let Some(name) = path.path.get_ident().map(ToString::to_string) else {
        return Shape::Dynamic;
    };
    let screaming = name.chars().all(|character| {
        character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_'
    });
    if !screaming {
        return Shape::Dynamic;
    }
    Shape::Constant { name }
}

fn literal_shape(literal: &syn::ExprLit) -> Shape {
    let syn::Lit::Str(text) = &literal.lit else {
        return Shape::Dynamic;
    };
    let span = text.span();
    Shape::Literal {
        english: text.value(),
        source: Span {
            start: span.start(),
            end: span.end(),
        },
    }
}

fn macro_shape(invocation: &syn::Macro, span: proc_macro2::Span) -> Shape {
    let Some(name) = invocation
        .path
        .segments
        .last()
        .map(|part| part.ident.to_string())
    else {
        return Shape::Dynamic;
    };
    if name == "message" {
        return Shape::Keyed;
    }
    if !FORMATTING.contains(&name.as_str()) {
        return Shape::Dynamic;
    }
    strings(invocation.tokens.clone())
        .first()
        .map_or(Shape::Dynamic, |format| Shape::Formatted {
            english: format.value(),
            source: Span {
                start: span.start(),
                end: span.end(),
            },
        })
}

/// A call that only turns a literal into an owned message.
fn converts(call: &syn::ExprMethodCall) -> bool {
    call.args.is_empty()
        && matches!(
            call.method.to_string().as_str(),
            "into" | "to_owned" | "to_string"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shapes(source: &str) -> Vec<Shape> {
        sites(&syn::parse_file(source).unwrap(), Code::Production)
            .into_iter()
            .map(|site| site.shape)
            .collect()
    }

    /// Literal, converted, formatted, constant, keyed and dynamic messages are told apart.
    #[test]
    fn each_message_expression_has_its_shape() {
        let found = shapes(
            r#"
            fn f(message: String) {
                DomainError::invalid("Choose a name");
                AppError::Forbidden("Not yours".into());
                DomainError::conflict(format!("{name} is taken").into());
                DomainError::forbidden(crate::message!("people-x", "Not here"));
                AppError::Conflict(message);
                AppError::Conflict(CHANGED_MEANWHILE.to_owned());
                DomainError::invalid(UNREACHABLE);
            }
            "#,
        );
        assert!(matches!(&found[0], Shape::Literal { english, .. } if english == "Choose a name"));
        assert!(matches!(&found[1], Shape::Literal { english, .. } if english == "Not yours"));
        assert!(
            matches!(&found[2], Shape::Formatted { english, .. } if english == "{name} is taken")
        );
        assert_eq!(found[3], Shape::Keyed);
        assert_eq!(found[4], Shape::Dynamic);
        assert_eq!(found[5], Shape::Dynamic);
        assert_eq!(
            found[6],
            Shape::Constant {
                name: "UNREACHABLE".to_owned()
            }
        );
    }

    /// Masked internal errors are never sites; refusals in test code have no text to key.
    #[test]
    fn internal_errors_are_left_alone_and_tests_are_not_keyed() {
        let found = shapes(
            r#"
            fn f() { DomainError::infra_msg("the pool is gone"); }
            #[cfg(test)] mod tests { fn g() { DomainError::invalid("A test refusal"); } }
            "#,
        );
        assert_eq!(found, [Shape::Dynamic]);
    }

    /// An OAuth protocol error is excluded from the sites selected for translation keys.
    #[test]
    fn protocol_errors_are_not_sites() {
        let found = shapes(r#"fn f() { OAuthError::invalid_request("missing code"); }"#);
        assert!(found.is_empty());
    }

    /// Lookup helpers and validation messages are refusals too.
    #[test]
    fn lookups_and_validation_messages_are_sites() {
        let found = shapes(
            r#"
            fn f() {
                store.find(id).or_not_found("No such route");
                ValidationError::Custom { field: "name", code: "bad", message: "Pick another".into() };
            }
            "#,
        );
        assert_eq!(found.len(), 2);
    }
}
