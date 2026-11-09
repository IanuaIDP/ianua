//! `#[derive(Fakes)]` expansion.
//!
//! Generates, for test builds only, a `fakes()` constructor that fills every
//! field of a ports struct with `crate::test_support::Fake::fake()`:
//!
//! ```ignore
//! #[derive(Fakes)]
//! pub struct AddMemberPorts {
//!     pub group_store: Arc<dyn GroupStore>,
//!     pub authorities: Arc<dyn TenantAuthorities>,
//! }
//!
//! // expands to
//! #[cfg(any(test, feature = "test-support"))]
//! impl AddMemberPorts {
//!     pub fn fakes() -> Self {
//!         Self {
//!             group_store: crate::test_support::Fake::fake(),
//!             authorities: crate::test_support::Fake::fake(),
//!         }
//!     }
//! }
//! ```
//!
//! The struct also implements `Fake` itself (as `fakes()`), so a ports struct
//! nested in another fills in too. Each type parameter is bound by `Fake`, so
//! `HasherPorts<H>` gets `impl<H: Fake> HasherPorts<H>`.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Error, Fields, parse_quote};

/// Expands `#[derive(Fakes)]` on `input`.
///
/// # Errors
///
/// Returns a compile error when `input` is not a struct with named fields.
pub(crate) fn expand(input: TokenStream) -> Result<TokenStream, Error> {
    let mut input: DeriveInput = syn::parse2(input)?;
    let field_names = named_fields(&input)?;

    for param in input.generics.type_params_mut() {
        param.bounds.push(parse_quote!(crate::test_support::Fake));
    }

    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    Ok(quote! {
        #[cfg(any(test, feature = "test-support"))]
        impl #impl_generics #name #type_generics #where_clause {
            /// Every port filled with its neutral test fake, for a test to
            /// override only the ports it is about.
            #[must_use]
            pub fn fakes() -> Self {
                Self {
                    #( #field_names: crate::test_support::Fake::fake(), )*
                }
            }
        }

        #[cfg(any(test, feature = "test-support"))]
        impl #impl_generics crate::test_support::Fake for #name #type_generics #where_clause {
            fn fake() -> Self {
                Self::fakes()
            }
        }
    })
}

fn named_fields(input: &DeriveInput) -> Result<Vec<syn::Ident>, Error> {
    let Data::Struct(data) = &input.data else {
        return Err(Error::new_spanned(
            input,
            "Fakes can only be derived for structs",
        ));
    };
    let Fields::Named(fields) = &data.fields else {
        return Err(Error::new_spanned(input, "Fakes needs named fields"));
    };
    Ok(fields
        .named
        .iter()
        .filter_map(|f| f.ident.clone())
        .collect())
}
