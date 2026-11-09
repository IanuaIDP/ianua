//! What an agent may reach: the task templates people approve, and the
//! relations principals hold on named resources.

mod grants;
mod templates;

pub use grants::{PgRelationshipResolver, PgResourceGrantStore};
pub use templates::PgTaskTemplateStore;
