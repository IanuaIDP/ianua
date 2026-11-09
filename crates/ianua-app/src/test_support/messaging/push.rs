//! Fakes for push subscriptions: the secrets they sign with and the posts
//! that carry their messages.

use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::Seconds;

use crate::ports::messaging::{OutgoingPush, PushDeliverer, PushOutcome, PushSecretGenerator};
use crate::test_support::Fake;
use crate::test_support::scheduling::FakeJobQueue;
use crate::use_cases::messaging::broker::{PushJobs, PushMessagePorts, PushMessageUseCase};

/// Push secret generator that hands out `push-secret-1`, `push-secret-2`
/// and so on.
#[derive(Default)]
pub struct FakePushSecretGenerator {
    made: Mutex<u32>,
}

impl FakePushSecretGenerator {
    /// A generator that has made nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl PushSecretGenerator for FakePushSecretGenerator {
    async fn generate(&self) -> Result<Secret, DomainError> {
        let mut made = self.made.lock().unwrap();
        *made += 1;
        Ok(Secret::new(format!("push-secret-{made}")))
    }
}

impl Fake for Arc<dyn PushSecretGenerator> {
    fn fake() -> Self {
        Arc::new(FakePushSecretGenerator::new())
    }
}

/// One post a [`FakePushDeliverer`] was asked to make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MadePush {
    /// Where it went.
    pub url: String,
    /// The secrets it was signed with, unsealed, the current one first.
    pub secrets: Vec<String>,
    /// How long the endpoint had to answer.
    pub timeout: Seconds,
}

/// What a [`FakePushDeliverer`] does with every post.
#[derive(Debug, Clone, Copy)]
enum Answer {
    Outcome(PushOutcome),
    RefuseAddress,
}

/// Push deliverer that answers every post the same way and remembers each.
pub struct FakePushDeliverer {
    answer: Answer,
    made: Mutex<Vec<MadePush>>,
}

impl FakePushDeliverer {
    /// A deliverer whose every post ends in `outcome`.
    #[must_use]
    pub fn answering(outcome: PushOutcome) -> Self {
        Self {
            answer: Answer::Outcome(outcome),
            made: Mutex::new(Vec::new()),
        }
    }

    /// A deliverer that refuses every address as internal.
    #[must_use]
    pub fn refusing_address() -> Self {
        Self {
            answer: Answer::RefuseAddress,
            made: Mutex::new(Vec::new()),
        }
    }

    /// Every post made, in order.
    #[must_use]
    pub fn made(&self) -> Vec<MadePush> {
        self.made.lock().unwrap().clone()
    }
}

#[async_trait]
impl PushDeliverer for FakePushDeliverer {
    async fn push(&self, push: OutgoingPush<'_>) -> Result<PushOutcome, DomainError> {
        let Answer::Outcome(outcome) = self.answer else {
            return Err(DomainError::invalid("the address is not public"));
        };
        self.made.lock().unwrap().push(MadePush {
            url: push.url.as_str().to_owned(),
            secrets: push
                .secrets
                .iter()
                .map(|secret| secret.expose().to_owned())
                .collect(),
            timeout: push.timeout,
        });
        Ok(outcome)
    }
}

impl Fake for Arc<dyn PushDeliverer> {
    fn fake() -> Self {
        Arc::new(FakePushDeliverer::answering(PushOutcome::Accepted))
    }
}

impl Fake for Arc<PushMessageUseCase> {
    fn fake() -> Self {
        Arc::new(PushMessageUseCase::new(PushMessagePorts::fakes()))
    }
}

impl Fake for PushJobs {
    fn fake() -> Self {
        PushJobs {
            queue: Arc::new(FakeJobQueue::new()),
            attempts: NonZeroU32::MIN,
        }
    }
}
