//! The stores of the branding context: a tenant's look, email templates
//! and mail providers, each table under row-level security.

mod appearance;
mod email_templates;
mod mail_providers;

pub use appearance::PgBrandingStore;
pub use email_templates::PgEmailTemplateStore;
pub use mail_providers::PgTenantMailProviderStore;
