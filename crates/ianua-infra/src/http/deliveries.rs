//! Posts carrying something that happened to an endpoint a tenant or an
//! organization registered: webhook deliveries, Security Event Token
//! pushes, push-subscription messages and notification posts. Each is
//! screened when its host resolves, held to its own time and judged by
//! the status of the answer alone.

mod notifications;
mod push;
mod signals;
mod webhooks;

pub use notifications::HttpDestinationPoster;
pub use push::HttpPushDeliverer;
pub use signals::HttpSignalDeliverer;
pub use webhooks::{HttpWebhookBodies, HttpWebhookDeliverer};
