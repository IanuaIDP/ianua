//! The values an error page's template is filled with: its status, its
//! kind, the request's reference and the tenant's look. Nothing else is
//! handed over, so no reason behind a refusal can reach the page.

use ianua_app::ports::pages::ErrorPage;
use minijinja::context;
use minijinja::value::Value;

use crate::pages::look::Look;

/// The template every error page is drawn from.
pub(crate) const TEMPLATE: &str = "error.html";

/// The values `page`'s template is filled with.
pub(crate) fn context_of(page: &ErrorPage) -> Value {
    let branding = page.branding.as_ref();
    let look = Look {
        name: branding.map_or("", |b| b.name.as_str()),
        logo_url: branding.and_then(|b| b.logo_url.as_ref()),
        primary: branding.and_then(|b| b.primary_color.as_ref()),
        background: branding.and_then(|b| b.background_color.as_ref()),
        custom_css: None,
    };
    context! {
        look => look.value(),
        status => page.status.code(),
        kind => page.kind.code(),
        reference => page.reference.to_string(),
    }
}
