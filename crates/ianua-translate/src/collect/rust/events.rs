//! Event descriptions whose declaration comments are deliberately published as runtime text.

use syn::parse::{Parse, ParseStream};
use syn::{Attribute, Expr, Ident, Lit, LitStr, Meta, Token, Visibility, braced};

/// The descriptions a production `event_types!` declaration publishes.
pub(super) struct Declaration {
    /// Every documented variant, in declaration order.
    pub(super) descriptions: Vec<Description>,
}

/// One event's published wording and the event type it describes.
pub(super) struct Description {
    /// Joined and trimmed exactly as the domain macro's `description` method returns it.
    pub(super) text: LitStr,
    /// The event's wire name, such as `tenant.provisioned`.
    pub(super) event_type: String,
}

impl Parse for Declaration {
    /// Reads the existing domain macro's enum shape without expanding or executing it.
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        input.call(Attribute::parse_outer)?;
        input.parse::<Visibility>()?;
        input.parse::<Token![enum]>()?;
        input.parse::<Ident>()?;
        let body;
        braced!(body in input);
        let mut descriptions = Vec::new();
        while !body.is_empty() {
            let attributes = body.call(Attribute::parse_outer)?;
            let variant = body.parse::<Ident>()?;
            body.parse::<Token![=>]>()?;
            let event_type = body.parse::<LitStr>()?.value();
            body.parse::<Token![,]>()?;
            let text: String = attributes.iter().filter_map(documentation).collect();
            if !text.trim().is_empty() {
                descriptions.push(Description {
                    text: LitStr::new(text.trim(), variant.span()),
                    event_type,
                });
            }
        }
        Ok(Self { descriptions })
    }
}

/// A declaration's doc line when that attribute supplies runtime event wording.
fn documentation(attribute: &Attribute) -> Option<String> {
    if !attribute.path().is_ident("doc") {
        return None;
    }
    let Meta::NameValue(value) = &attribute.meta else {
        return None;
    };
    let Expr::Lit(literal) = &value.value else {
        return None;
    };
    let Lit::Str(text) = &literal.lit else {
        return None;
    };
    Some(text.value())
}
