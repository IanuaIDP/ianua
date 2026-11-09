//! The words a held sign-in request's binding is stored as.

use crate::postgres::foundation::stored::stored_words;

/// How a held request reached this platform, as its row tells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BindingKind {
    /// Posted in a form.
    Post,
    /// In the query string.
    Redirect,
}

stored_words! {
    BindingKind as "SAML binding" {
        Post => "post",
        Redirect => "redirect",
    }
}
