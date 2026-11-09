//! `keyed_refusal!(Path, "key", message)`: a refusal carrying its message
//! key and every value its English text was filled with.
//!
//! The message is literal text, a `format!` call or any other expression
//! that reads as text. A `format!` call's fields become named values the
//! way `ianua-translate` names them in the Fluent resources: a named field
//! keeps its name, and the `n`th unnamed field, or field `{n}`, is
//! `argn`. Each value is formatted with its field's own spec, so it reads
//! as it does in the English sentence. Every argument is evaluated once.

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{Expr, Ident, LitStr, Path, Token};

/// The macro's input: the refusal type, the key and the message.
struct Input {
    refusal: Path,
    key: LitStr,
    message: Expr,
}

impl Parse for Input {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let refusal = input.parse()?;
        input.parse::<Token![,]>()?;
        let key = input.parse()?;
        input.parse::<Token![,]>()?;
        let message = input.parse()?;
        Ok(Self {
            refusal,
            key,
            message,
        })
    }
}

/// The arguments of a `format!` call: its format string, then positional
/// and named arguments.
struct FormatCall {
    format: LitStr,
    arguments: Vec<Argument>,
}

/// One argument of a `format!` call.
enum Argument {
    Positional(Expr),
    Named(Ident, Expr),
}

impl Parse for FormatCall {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let format = input.parse()?;
        if input.is_empty() {
            return Ok(Self {
                format,
                arguments: Vec::new(),
            });
        }
        input.parse::<Token![,]>()?;
        let arguments = Punctuated::<Argument, Token![,]>::parse_terminated(input)?
            .into_iter()
            .collect();
        Ok(Self { format, arguments })
    }
}

impl Parse for Argument {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        if input.peek(Ident) && input.peek2(Token![=]) && !input.peek2(Token![==]) {
            let name = input.parse()?;
            input.parse::<Token![=]>()?;
            return Ok(Self::Named(name, input.parse()?));
        }
        Ok(Self::Positional(input.parse()?))
    }
}

/// One replacement field of a format string: what it names and its spec.
#[derive(Debug, PartialEq, Eq)]
struct Field {
    target: Target,
    spec: String,
}

/// What a replacement field reads.
#[derive(Debug, PartialEq, Eq)]
enum Target {
    /// The argument at this position.
    Position(usize),
    /// A named argument, or a variable in scope.
    Name(String),
}

impl Target {
    /// The Fluent variable this field fills.
    fn variable(&self) -> String {
        match self {
            Self::Position(position) => format!("arg{position}"),
            Self::Name(name) => name.clone(),
        }
    }
}

/// Expands the macro.
///
/// # Errors
///
/// Returns a compile error for input that is not a type, a key and a message.
pub(crate) fn expand(input: TokenStream) -> syn::Result<TokenStream> {
    let Input {
        refusal,
        key,
        message,
    } = syn::parse2(input)?;
    let Some(call) = format_call(&message)? else {
        return Ok(quote! {
            #refusal::keyed(#key, #message, ::std::vec::Vec::new())
        });
    };
    Ok(formatted(&refusal, &key, &call))
}

/// The arguments of `message` when it is a `format!` call.
fn format_call(message: &Expr) -> syn::Result<Option<FormatCall>> {
    let Expr::Macro(invocation) = message else {
        return Ok(None);
    };
    let named_format = invocation
        .mac
        .path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "format");
    if !named_format {
        return Ok(None);
    }
    invocation.mac.parse_body().map(Some)
}

/// A refusal of a formatted message, every argument bound once and every
/// field passed on as a named value.
fn formatted(refusal: &Path, key: &LitStr, call: &FormatCall) -> TokenStream {
    let format = &call.format;
    let bound = bound_arguments(call);
    let bindings = bound
        .iter()
        .map(|(binding, expression)| quote! { let #binding = &(#expression); });
    let passed = call
        .arguments
        .iter()
        .zip(&bound)
        .map(|(argument, (binding, _))| match argument {
            Argument::Positional(_) => quote! { #binding },
            Argument::Named(name, _) => quote! { #name = #binding },
        });
    let values = fields(&format.value()).into_iter().map(|field| {
        let variable = field.target.variable();
        let spec = LitStr::new(&format!("{{:{}}}", field.spec), Span::call_site());
        let value = value_of(&field.target, call, &bound);
        quote! { (#variable, ::std::format!(#spec, #value)) }
    });
    quote! {
        {
            #(#bindings)*
            #refusal::keyed(
                #key,
                ::std::format!(#format #(, #passed)*),
                ::std::vec![#(#values),*],
            )
        }
    }
}

/// Assigns each argument a local name so message and field formatting share
/// the same evaluated expression.
fn bound_arguments(call: &FormatCall) -> Vec<(Ident, &Expr)> {
    call.arguments
        .iter()
        .enumerate()
        .map(|(position, argument)| match argument {
            Argument::Positional(expression) => {
                (format_ident!("__refusal_arg{position}"), expression)
            }
            Argument::Named(name, expression) => (format_ident!("__refusal_{name}"), expression),
        })
        .collect()
}

/// The expression a field reads: its bound argument, or the variable it names.
fn value_of(target: &Target, call: &FormatCall, bound: &[(Ident, &Expr)]) -> TokenStream {
    let named = |wanted: &str| {
        call.arguments
            .iter()
            .zip(bound)
            .find_map(|(argument, (binding, _))| match argument {
                Argument::Named(name, _) if name == wanted => Some(binding.clone()),
                _ => None,
            })
    };
    match target {
        Target::Position(position) => {
            let binding = bound.get(*position).map(|(binding, _)| binding.clone());
            quote! { #binding }
        }
        Target::Name(name) => match named(name) {
            Some(binding) => quote! { #binding },
            None => {
                let variable = Ident::new(name, call.format.span());
                quote! { #variable }
            }
        },
    }
}

/// Every distinct replacement field of a format string, in order.
fn fields(format: &str) -> Vec<Field> {
    let mut found: Vec<Field> = Vec::new();
    let mut next_position = 0;
    let mut characters = format.chars().peekable();
    while let Some(character) = characters.next() {
        match (character, characters.peek()) {
            ('{', Some('{')) | ('}', Some('}')) => {
                characters.next();
            }
            ('{', _) => {
                let inside: String = characters
                    .by_ref()
                    .take_while(|next| *next != '}')
                    .collect();
                let field = field(&inside, &mut next_position);
                if !found.iter().any(|known| known.target == field.target) {
                    found.push(field);
                }
            }
            _ => {}
        }
    }
    found
}

fn field(inside: &str, next_position: &mut usize) -> Field {
    let (name, spec) = inside.split_once(':').unwrap_or((inside, ""));
    let name = name.trim();
    let target = match name.parse::<usize>() {
        Ok(position) => Target::Position(position),
        Err(_) if name.is_empty() => {
            let position = *next_position;
            *next_position += 1;
            Target::Position(position)
        }
        Err(_) => Target::Name(name.to_owned()),
    };
    Field {
        target,
        spec: spec.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Named, unnamed and numbered fields are read with their specs, and
    /// escaped braces are text.
    #[test]
    fn fields_are_read_in_order_with_their_specs() {
        assert_eq!(
            fields("{{x}} {name:?} {} {:>4} {1}"),
            [
                Field {
                    target: Target::Name("name".to_owned()),
                    spec: "?".to_owned()
                },
                Field {
                    target: Target::Position(0),
                    spec: String::new()
                },
                Field {
                    target: Target::Position(1),
                    spec: ">4".to_owned()
                },
            ]
        );
    }

    /// A literal message is keyed with no values.
    #[test]
    fn a_literal_message_has_no_values() {
        let expanded = expand(quote! { Refusal, "people-invite", "Invite them" }).unwrap();
        assert_eq!(
            expanded.to_string(),
            quote! { Refusal::keyed("people-invite", "Invite them", ::std::vec::Vec::new()) }
                .to_string()
        );
    }

    /// A formatted message binds each argument once and passes every field on.
    #[test]
    fn a_formatted_message_passes_its_fields_as_values() {
        let expanded =
            expand(quote! { Refusal, "routing-move", format!("{name} from {:?}", state) }).unwrap();
        let text = expanded.to_string();
        assert!(text.contains("let __refusal_arg0 = & (state) ;"));
        assert!(text.contains("(\"name\" , :: std :: format ! (\"{:}\" , name))"));
        assert!(text.contains("(\"arg0\" , :: std :: format ! (\"{:?}\" , __refusal_arg0))"));
    }
}
