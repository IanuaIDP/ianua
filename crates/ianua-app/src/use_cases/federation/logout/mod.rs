//! SAML single logout, both ways: the requests a person's sign-out sends to
//! the apps they signed in to and the provider they signed in through, the
//! answers to those, and the requests peers send to log the person out
//! here.

pub(crate) mod answer_app;
pub(crate) mod answer_provider;
pub mod messages;
pub(crate) mod start_single;
pub(crate) mod take_response;

pub use answer_app::{AnswerAppPorts, AnswerAppRequest, AnswerAppUseCase};
pub use answer_provider::{AnswerProviderPorts, AnswerProviderRequest, AnswerProviderUseCase};
pub use start_single::{StartSinglePorts, StartSingleRequest, StartSingleUseCase};
pub use take_response::{Answerer, TakeResponsePorts, TakeResponseRequest, TakeResponseUseCase};
