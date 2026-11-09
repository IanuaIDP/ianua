//! Test-only item detection without guessing platform-specific cfg values.

use syn::punctuated::Punctuated;
use syn::{Attribute, Expr, Item, Meta, Token};

/// The attributes that control whether an item is part of the production inventory.
pub(crate) fn attributes(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

/// Whether attributes prove an item is disabled in a non-test build.
pub(crate) fn excluded(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        if attribute.path().is_ident("test") {
            return true;
        }
        if !attribute.path().is_ident("cfg") {
            return false;
        }
        attribute
            .parse_args::<Meta>()
            .ok()
            .is_some_and(|meta| enabled(&meta) == Some(false))
    })
}

/// Evaluates test-related cfg conditions, keeping unknown platform and feature conditions.
fn enabled(meta: &Meta) -> Option<bool> {
    match meta {
        Meta::Path(path) if path.is_ident("test") => Some(false),
        Meta::NameValue(value) if value.path.is_ident("feature") => match &value.value {
            Expr::Lit(literal) if matches!(&literal.lit, syn::Lit::Str(text) if text.value() == "test-support") => {
                Some(false)
            }
            _ => None,
        },
        Meta::List(list) => {
            let nested = list
                .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                .ok()?;
            let values: Vec<_> = nested.iter().map(enabled).collect();
            match list.path.get_ident()?.to_string().as_str() {
                "not" if values.len() == 1 => values[0].map(|value| !value),
                "all" if values.contains(&Some(false)) => Some(false),
                "all" if values.iter().all(|value| *value == Some(true)) => Some(true),
                "any" if values.contains(&Some(true)) => Some(true),
                "any" if values.iter().all(|value| *value == Some(false)) => Some(false),
                _ => None,
            }
        }
        _ => None,
    }
}
