/// A tenant's visual customization of the login experience.
pub mod config;
/// Who may change how the tenant looks and what its mail says.
pub mod control;
/// Per-tenant overrides of transactional email templates.
pub mod email_template;
/// Domain events for tenant branding.
pub mod events;
/// A logo a tenant uploads, checked for its format, size and dimensions.
pub mod logo;
/// The mail provider a tenant's own mail goes out through.
pub mod mail_provider;
mod placeholders;
/// A rendered email ready for delivery.
pub mod renderer;
mod styles;
mod template_locale;

#[cfg(test)]
pub(crate) mod fixtures;
