//! Branding services: choosing the template and sender of a tenant's mail,
//! reading the address it goes out from, and sending it through the
//! tenant's own provider.

pub mod mail_route;
pub mod mailer;
pub mod sender;
