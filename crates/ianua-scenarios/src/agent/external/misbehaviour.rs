//! What an agent does wrong on purpose: an assertion used twice, another
//! agent's name or token, a token or a hand-on wider than its grant, a
//! body with a misspelt field. Each is the request a careless or hostile
//! agent sends; the scenario says what the platform must answer.

use serde_json::{Value, json};

use super::dpop::ProvenRequest;
use super::{ExternalAgent, IssuedToken};
use crate::api::agents::{relay, token};
use crate::wire::Answer;
use crate::wire::agents::authority::Granted;
use crate::wire::agents::token::{TokenAsk, TokenRequest};

impl ExternalAgent {
    /// Asks for a token again with `spent`, an assertion it already
    /// exchanged once.
    pub async fn replay(&self, spent: &str, ask: &TokenAsk) -> Answer<Granted> {
        self.exchange_with(spent, ask).await
    }

    /// Asks for a token at `victim`'s endpoint with an assertion of its
    /// own, as if signing in as `victim`.
    pub async fn pose_as(&self, victim: &ExternalAgent, ask: &TokenAsk) -> Answer<Granted> {
        let request = token_request(&self.assertion(), ask);
        token::exchange(&victim.tenant, &victim.id, &request)
            .send(&self.client)
            .await
    }

    /// Asks for a token at `victim`'s endpoint with an assertion naming
    /// `victim`, signed with its own key.
    pub async fn forge_for(&self, victim: &ExternalAgent, ask: &TokenAsk) -> Answer<Granted> {
        let request = token_request(&self.assertion_naming(&victim.id), ask);
        token::exchange(&victim.tenant, &victim.id, &request)
            .send(&self.client)
            .await
    }

    /// Publishes with `stolen`, another agent's token, beside a DPoP proof
    /// made with its own key, as a thief holding the token but not the key
    /// would; its own token is borne again afterwards.
    pub async fn publish_with_stolen(
        &mut self,
        stolen: &IssuedToken,
        topic: &str,
        message: &Value,
    ) -> Answer<()> {
        let own = self.token.take();
        self.client.authorize(stolen.token());
        let request = relay::publish(&self.tenant, topic, message);
        let url = format!("{}{}", self.audience, request.call().path);
        let proof = super::dpop::proof(
            &self.key,
            ProvenRequest {
                method: "POST",
                url: &url,
            },
            Some(stolen.token()),
            super::now(),
        );
        let answer = request.header("dpop", &proof).send(&self.client).await;
        self.client.forget_authorization();
        if let Some(own) = own {
            self.hold(own);
        }
        answer
    }

    /// Asks for a token with `ask` and the field `misspelt` set to `value`
    /// beside it, as a hand-written client that got a name wrong sends it.
    pub async fn ask_misspelt(
        &self,
        ask: &TokenAsk,
        misspelt: &str,
        value: Value,
    ) -> Answer<Granted> {
        let mut body = json!(token_request(&self.assertion(), ask));
        body[misspelt] = value;
        token::exchange_raw(&self.tenant, &self.id, &body)
            .send(&self.client)
            .await
    }
}

/// The exchange of `assertion` for `ask`.
fn token_request(assertion: &str, ask: &TokenAsk) -> TokenRequest {
    TokenRequest {
        assertion: assertion.to_owned(),
        ask: ask.clone(),
    }
}
