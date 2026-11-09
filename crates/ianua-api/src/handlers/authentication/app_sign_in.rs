//! App sign-in: the internal endpoint the gateway relays sign-in requests
//! from an app's host to.

use axum::body::Bytes;
use axum::extract::State;
use axum::response::Response;
use ianua_app::use_case::Command as _;
use ianua_app::use_cases::authentication::app_sign_in::ReceiveRequest;
use ianua_assembly::authentication::AuthenticationState;

use crate::dto::authentication::app_sign_in::RelayAnswer;
use crate::extractors::authentication::GatewayRelay;

#[utoipa::path(
    post,
    path = "/internal/app-sign-in",
    tag = "Authentication",
    request_body(content = String, description = "The sealed request, exactly as the gateway sealed it", content_type = "application/json"),
    responses(
        (status = 200, description = "The outcome, or the refusal, for the gateway to act on, sealed for the request it answers",
            headers(("x-ianua-seal" = String, description = "The API's seal over the answer, bound to the request's nonce"))),
        (status = 401, description = "Unsealed, stale or seen before; the body is empty")
    )
)]
/// Relay an app sign-in (gateway only)
///
/// Serves app-host password, factor, mail and provider sign-ins, passkeys,
/// password resets, signup, address verification, sign-out, service tokens,
/// sign-in pages and cross-host session handoffs through the gateway.
/// Runs only on the internal listener, outside ingress routing. Unsealed,
/// stale or replayed requests receive an empty `401`; other requests receive
/// `200` with a typed outcome, including refusals. Client address and user
/// agent come from the sealed body. `Accepted` replies use the dashboard's
/// timing floor to conceal whether an address has an account.
/// Replies carry `x-ianua-seal`, signed with the channel key and bound to
/// the request nonce; the gateway refuses unsigned or substituted answers.
pub(crate) async fn relay(
    State(auth): State<AuthenticationState>,
    relayed: GatewayRelay,
    body: Bytes,
) -> Response {
    let request = ReceiveRequest {
        body: body.to_vec(),
        seal: relayed.seal,
    };
    let reply = auth
        .app_sign_in
        .execute(&(), &relayed.auditor, request)
        .await;
    RelayAnswer::new(reply.answer, auth.pages.as_ref()).sealed(reply.seal)
}
