//! Get topic: retrieve a single topic by ID.

use std::sync::Arc;

use ianua_domain::domains::authorization::permission::{MessagingAction, SystemPermission};
use ianua_domain::domains::messaging::topic::Topic;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::TopicId;

use crate::acting::TenantAuthorities;
use crate::context::CallerContext;
use crate::error::AppError;
use crate::ports::messaging::TopicStore;
use crate::use_case::Query;
use crate::use_cases::messaging::lookup::existing_topic;

/// Ports needed by the get topic use case.
#[derive(ianua_macros::Fakes)]
pub struct GetPorts {
    /// Port for topic persistence.
    pub topic_store: Arc<dyn TopicStore>,
    /// What the caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Reads a message destination within the caller's tenant.
pub struct GetUseCase {
    ports: GetPorts,
}

impl GetUseCase {
    /// Creates a new use case instance.
    #[must_use]
    pub fn new(ports: GetPorts) -> Self {
        Self { ports }
    }
}

impl Query for GetUseCase {
    type Caller = CallerContext;
    type Input = TopicId;
    type Output = Result<Topic<ResolvedTenant>, AppError>;

    /// Retrieves a topic by ID.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller's session or key no
    ///   longer counts.
    /// - `AppError::Forbidden` when the caller may not view messaging.
    /// - `AppError::NotFound` if the topic doesn't exist.
    /// - `AppError::Internal` on persistence failure.
    async fn execute(
        &self,
        ctx: &CallerContext,
        id: TopicId,
    ) -> Result<Topic<ResolvedTenant>, AppError> {
        self.ports
            .tenant_authorities
            .authority(ctx)
            .await?
            .ensure_holds(SystemPermission::Messaging(MessagingAction::View))
            .map_err(AppError::from_domain)?;
        existing_topic(self.ports.topic_store.as_ref(), &ctx.tenant(), &id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::messaging::{FakeTopicStore, topic_named, topics_of_test_tenant};
    use crate::test_support::{block_on, test_ctx};

    fn with_authorities(
        store: Arc<FakeTopicStore>,
        authorities: FakeTenantAuthorities,
    ) -> GetUseCase {
        GetUseCase::new(GetPorts {
            topic_store: store,
            tenant_authorities: Arc::new(authorities),
            ..GetPorts::fakes()
        })
    }

    /// Ann may view messaging. She opens `test.topic` and sees it.
    #[test]
    fn a_viewer_gets_the_topic() {
        let topic = topic_named("test.topic");
        let id = *topic.id();
        let viewer =
            FakeTenantAuthorities::holding(&[SystemPermission::Messaging(MessagingAction::View)]);
        let use_case = with_authorities(topics_of_test_tenant(topic), viewer);

        let found = block_on(use_case.execute(&test_ctx(), id)).unwrap();

        assert_eq!(found.topic_name().as_str(), "test.topic");
    }

    /// A topic the tenant does not have is not found.
    #[test]
    fn an_unknown_topic_is_not_found() {
        let use_case = with_authorities(
            Arc::new(FakeTopicStore::empty()),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = block_on(use_case.execute(&test_ctx(), TopicId::new()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    /// Reading an existing topic without messaging view rights returns a
    /// forbidden error.
    #[test]
    fn a_caller_without_the_view_right_is_refused() {
        let topic = topic_named("test.topic");
        let id = *topic.id();
        let use_case = with_authorities(
            topics_of_test_tenant(topic),
            FakeTenantAuthorities::holding(&[]),
        );

        let result = block_on(use_case.execute(&test_ctx(), id));

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out caller receives an unauthenticated error when reading a topic.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let topic = topic_named("test.topic");
        let id = *topic.id();
        let use_case = with_authorities(
            topics_of_test_tenant(topic),
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = block_on(use_case.execute(&test_ctx(), id));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
