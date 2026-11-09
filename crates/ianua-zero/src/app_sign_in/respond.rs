//! Answering a person at an app's sign-in address.
//!
//! The API says what happened; this decides what the browser gets. A form
//! post is sent on with `303 See Other`, a script gets JSON, a page is served
//! under a policy that runs no script but the gateway's own passkey script
//! on the login page, and only the cookies named in [`super::cookies`] are
//! ever set. Nothing the API sent is passed through as a header, every answer
//! is `no-store`, and an answer that does not fit the question is refused.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HeaderValue, LOCATION, REFERRER_POLICY,
    SET_COOKIE, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use http::{StatusCode, response};
use http_body_util::Full;
use hyper::body::Bytes;
use ianua_app::ports::authentication::{WireHop, WireOutcome};
use ianua_domain::domains::routing::sign_in::app::{AppSignIn, SignInAction};
use ianua_domain::shared::clock;
use ianua_domain::types::{CeremonyId, DomainName};

use super::Response;
use super::cookies::{self, KeptSignOn};
use super::fields::Client;
use crate::request::{
    APP_CHALLENGE_COOKIE, APP_CSRF_COOKIE, APP_HOP_COOKIE, APP_SESSION_COOKIE,
    APP_SINGLE_SIGN_ON_COOKIE,
};

/// What a page may do: draw itself with its own styles and images, and post
/// its form back to its own host. Nothing else, and no script at all.
const PAGE_POLICY: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src https: data:; \
                           form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/// The script the login page signs in with a passkey through. It is the one
/// script any gateway page runs, served by the gateway itself.
const PASSKEY_SCRIPT: &str = include_str!("passkey.js");

/// Which script a page may run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PageScript<'a> {
    /// None at all.
    None,
    /// The gateway's passkey script, at this absolute address and nowhere
    /// else, and the requests it sends to the page's own host.
    Passkey(&'a str),
}

/// The reason a refusal names when the API could not be asked, or answered
/// something that does not fit the question.
pub(super) const UNAVAILABLE: &str = "unavailable";

/// Where and how to answer.
pub(super) struct Answering<'a> {
    /// How the client asked.
    pub(super) client: Client,
    /// The host the request came in on.
    pub(super) host: &'a DomainName,
    /// The host's app sign-in.
    pub(super) sign_in: &'a AppSignIn,
    /// What was asked.
    pub(super) step: Step,
    /// Where the person asked to be sent once in, as they sent it. Carried
    /// to the next page only; the API holds it to the rules before use.
    pub(super) return_to: Option<String>,
}

/// What was asked, as far as answering it goes. A reset or a change from a
/// mailed link carries the link's token, so a refused browser can try again
/// from the same link; it has no `Debug`.
pub(super) enum Step {
    /// One of the actions, other than a reset or a change.
    Action(SignInAction),
    /// Setting a new password from a mailed reset link.
    Reset {
        /// The mailed link's token.
        token: String,
    },
    /// Setting the new password a sign-in owes.
    ChangePassword {
        /// The mailed change link's token, when the page was opened from
        /// one; none when the browser's challenge cookie holds the change.
        token: Option<String>,
    },
    /// A short-lived token for a service accepting the sign-in by token.
    Token,
}

/// The session a sign-in opened, for the host's cookie, and the secret of
/// the device it just remembered, for the device cookie. Holds both, so it
/// has no `Debug`.
struct Session<'a> {
    token: &'a str,
    expires_at: i64,
    remembered_device: Option<&'a str>,
}

/// The new password a sign-in owes, as the API answered it.
struct ChangeOwed {
    challenge: Option<String>,
    proof: String,
    reason: String,
    expires_at: i64,
}

/// The answer to `outcome`.
/// Each wire outcome is dispatched explicitly so an added variant requires a browser response.
#[allow(clippy::too_many_lines)]
pub(super) fn outcome(answering: &Answering<'_>, outcome: WireOutcome) -> Response {
    match outcome {
        WireOutcome::SignedIn {
            token,
            expires_at,
            return_to,
            hops,
            remembered_device,
        } => {
            let session = Session {
                token: &token,
                expires_at,
                remembered_device: remembered_device.as_deref(),
            };
            signed_in(answering, &session, &return_to, &hops)
        }
        WireOutcome::Token {
            access_token,
            expires_at,
        } => token(answering, &access_token, expires_at),
        WireOutcome::MfaRequired {
            challenge,
            expires_at,
        } => mfa_required(answering, &challenge, expires_at),
        WireOutcome::ConfirmByEmail {
            challenge,
            expires_at,
        } => confirm_by_email(answering, &challenge, expires_at),
        WireOutcome::PasswordChangeRequired {
            challenge,
            proof,
            reason,
            expires_at,
        } => {
            let owed = ChangeOwed {
                challenge,
                proof,
                reason,
                expires_at,
            };
            password_change_required(answering, &owed)
        }
        WireOutcome::SsoRedirect {
            url,
            binding,
            hand_back,
            return_to,
        } => {
            let kept = KeptSignOn {
                binding,
                hand_back,
                return_to,
            };
            sso_redirect(answering, &url, &kept)
        }
        WireOutcome::PasskeyChallenge {
            ceremony_id,
            options,
        } => passkey_challenge(ceremony_id, &options),
        WireOutcome::SignedOut => signed_out(answering),
        WireOutcome::Accepted => accepted(answering),
        WireOutcome::Rejected { status, code } => refused(answering, status.code(), &code),
        WireOutcome::HandedOver { .. }
        | WireOutcome::HopIssued { .. }
        | WireOutcome::Page { .. } => unfitting(answering),
    }
}

/// The answer to an outcome that does not fit the question: refused.
pub(super) fn unfitting(answering: &Answering<'_>) -> Response {
    refused(answering, StatusCode::BAD_GATEWAY.as_u16(), UNAVAILABLE)
}

/// The answer to a request refused with `status` for `code`, by the API or
/// before it was asked. A browser goes back to the page it came from, told
/// why; a script gets the status and the reason.
pub(super) fn refused(answering: &Answering<'_>, status: u16, code: &str) -> Response {
    let code = query_value(code);
    match answering.client {
        Client::Browser => see_other(&refused_address(answering, &code), []),
        Client::Script => {
            let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST);
            json(status, &serde_json::json!({ "error": code }), [])
        }
    }
}

/// Where a refused browser goes: the page of the step, or the login page
/// for a step with no page of its own, which never sends it back to a link
/// that would only fail again.
fn refused_address(answering: &Answering<'_>, code: &str) -> String {
    let landing = match &answering.step {
        Step::Action(
            action @ (SignInAction::LogIn
            | SignInAction::SignUp
            | SignInAction::Mfa
            | SignInAction::ForgotPassword
            | SignInAction::ChangePassword),
        ) => *action,
        Step::Reset { .. } => SignInAction::ResetPassword,
        Step::ChangePassword { .. } => SignInAction::ChangePassword,
        Step::Action(_) | Step::Token => SignInAction::LogIn,
    };
    let mut params = vec![("error", code)];
    if let Some(token) = mailed_token(&answering.step) {
        params.push(("token", token));
    }
    params.extend(carried_return(answering, landing));
    on_host(answering, landing, &params)
}

/// The mailed link's token a step was taken with, to go back to its page.
fn mailed_token(step: &Step) -> Option<&str> {
    match step {
        Step::Reset { token } => Some(token),
        Step::ChangePassword { token } => token.as_deref(),
        Step::Action(_) | Step::Token => None,
    }
}

/// The return path as a query parameter, for a page that carries it on:
/// logging in, the second factor and the password change a sign-in owes.
fn carried_return<'a>(
    answering: &'a Answering<'_>,
    landing: SignInAction,
) -> Option<(&'static str, &'a str)> {
    let carries = matches!(
        landing,
        SignInAction::LogIn | SignInAction::Mfa | SignInAction::ChangePassword
    );
    answering
        .return_to
        .as_deref()
        .filter(|_| carries)
        .map(|path| ("return_to", path))
}

/// The address of `action` on the request's host, with `params`.
fn on_host(answering: &Answering<'_>, action: SignInAction, params: &[(&str, &str)]) -> String {
    let path = answering.sign_in.path(action);
    let address = format!("https://{}{path}", answering.host);
    if params.is_empty() {
        return address;
    }
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params)
        .finish();
    format!("{address}?{query}")
}

fn signed_in(
    answering: &Answering<'_>,
    session: &Session<'_>,
    return_to: &str,
    hops: &[WireHop],
) -> Response {
    let set = [
        cookies::session(session.token, session.expires_at),
        cookies::csrf(&csrf_value(), session.expires_at),
        cookies::cleared(APP_CHALLENGE_COOKIE),
        session.remembered_device.and_then(cookies::device),
    ];
    let lands_on = landing(answering.sign_in, return_to);
    let back = format!("https://{}{lands_on}", answering.host);
    let first_stop = hop_chain(answering, hops, back);
    match answering.client {
        Client::Browser => see_other(&first_stop, set),
        Client::Script => json(
            StatusCode::OK,
            &serde_json::json!({
                "signed_in": true,
                "return_to": lands_on,
                "hop_to": (!hops.is_empty()).then_some(first_stop),
            }),
            set,
        ),
    }
}

/// The path to land on: the one the API answered when it is a path on this
/// host, the sign-in's landing page otherwise.
fn landing<'a>(sign_in: &'a AppSignIn, return_to: &'a str) -> &'a str {
    let on_this_host =
        return_to.starts_with('/') && !return_to.starts_with("//") && !return_to.contains('\\');
    if on_this_host {
        return return_to;
    }
    sign_in.after_sign_in().as_str()
}

/// The first stop of a browser signing in: through each host of a service's
/// own cookie in turn, each passing it on to the next, and back to `back`.
/// Each hop starts without a code: the browser fetches one from this host
/// once it holds the other host's hop cookie.
fn hop_chain(answering: &Answering<'_>, hops: &[WireHop], back: String) -> String {
    let from = format!("https://{}", answering.host);
    hops.iter().rev().fold(back, |next, hop| {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("from", &from)
            .append_pair("next", &next)
            .finish();
        format!(
            "https://{}{}?{query}",
            hop.host,
            answering.sign_in.hop_path()
        )
    })
}

/// A short-lived bearer token, as OAuth answers one. Only the token address
/// is answered with one.
fn token(answering: &Answering<'_>, access_token: &str, expires_at: i64) -> Response {
    if !matches!(answering.step, Step::Token) {
        return unfitting(answering);
    }
    json(
        StatusCode::OK,
        &serde_json::json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": seconds_until(expires_at),
        }),
        [],
    )
}

fn mfa_required(answering: &Answering<'_>, challenge: &str, expires_at: i64) -> Response {
    let set = [cookies::challenge(challenge, expires_at)];
    match answering.client {
        Client::Browser => {
            let params: Vec<_> = carried_return(answering, SignInAction::Mfa)
                .into_iter()
                .collect();
            see_other(&on_host(answering, SignInAction::Mfa, &params), set)
        }
        Client::Script => json(
            StatusCode::OK,
            &serde_json::json!({ "mfa_required": true }),
            set,
        ),
    }
}

/// The sign-in waits on the mailbox: the browser keeps the challenge, and
/// the person is told to look there.
fn confirm_by_email(answering: &Answering<'_>, challenge: &str, expires_at: i64) -> Response {
    let set = [cookies::challenge(challenge, expires_at)];
    match answering.client {
        Client::Browser => see_other(&noted_login(answering, "check_email"), set),
        Client::Script => json(
            StatusCode::OK,
            &serde_json::json!({ "confirm_by_email": true }),
            set,
        ),
    }
}

/// A new password is owed. The browser keeps the change's token when the
/// API handed one back, and is sent to the change page; a mailed one is
/// waiting in the mailbox instead.
fn password_change_required(answering: &Answering<'_>, owed: &ChangeOwed) -> Response {
    let set = [owed
        .challenge
        .as_deref()
        .and_then(|challenge| cookies::challenge(challenge, owed.expires_at))];
    match answering.client {
        Client::Browser => see_other(&change_address(answering, owed.challenge.is_some()), set),
        Client::Script => json(
            StatusCode::OK,
            &serde_json::json!({
                "password_change_required": true,
                "proof": query_value(&owed.proof),
                "reason": query_value(&owed.reason),
                "expires_in": seconds_until(owed.expires_at),
            }),
            set,
        ),
    }
}

/// Where a browser owing a new password goes: the change page, saying why,
/// or the login page pointing to the mailbox when the change was mailed.
fn change_address(answering: &Answering<'_>, handed_back: bool) -> String {
    if !handed_back {
        return noted_login(answering, "check_email");
    }
    let mut params = vec![("password_change_required", "1")];
    params.extend(carried_return(answering, SignInAction::ChangePassword));
    on_host(answering, SignInAction::ChangePassword, &params)
}

/// Sends the browser to the outside identity provider, keeping the two
/// secrets and the return path in a cookie until it comes back. A provider
/// address that is not `https`, or secrets that cannot be kept, refuse.
fn sso_redirect(answering: &Answering<'_>, url: &str, kept: &KeptSignOn) -> Response {
    let Some(provider) = url::Url::parse(url)
        .ok()
        .filter(|url| url.scheme() == "https")
    else {
        return unfitting(answering);
    };
    let Some(cookie) = cookies::single_sign_on(kept) else {
        return unfitting(answering);
    };
    match answering.client {
        Client::Browser => see_other(provider.as_str(), [Some(cookie)]),
        Client::Script => json(
            StatusCode::OK,
            &serde_json::json!({ "redirect_to": provider.as_str() }),
            [Some(cookie)],
        ),
    }
}

/// A passkey challenge, always as JSON: only a script can hand it to the
/// browser's authenticator.
fn passkey_challenge(ceremony_id: CeremonyId, options: &[u8]) -> Response {
    json(
        StatusCode::OK,
        &serde_json::json!({
            "ceremony_id": ceremony_id.as_uuid().to_string(),
            "challenge": URL_SAFE_NO_PAD.encode(options),
        }),
        [],
    )
}

fn signed_out(answering: &Answering<'_>) -> Response {
    let set = [
        cookies::cleared(APP_SESSION_COOKIE),
        cookies::cleared(APP_CSRF_COOKIE),
        cookies::cleared(APP_CHALLENGE_COOKIE),
        cookies::cleared(APP_SINGLE_SIGN_ON_COOKIE),
    ];
    match answering.client {
        Client::Browser => see_other(&format!("https://{}/", answering.host), set),
        Client::Script => json(
            StatusCode::OK,
            &serde_json::json!({ "signed_out": true }),
            set,
        ),
    }
}

/// Done with nothing to hand back. A browser goes on to the login address,
/// told what happened; a sign-up and a request for a reset link are
/// answered the same whether or not the address was known.
fn accepted(answering: &Answering<'_>) -> Response {
    let note = match answering.step {
        Step::Action(SignInAction::Verify) => Some("verified"),
        Step::Reset { .. } => Some("password_reset"),
        Step::Action(SignInAction::SignUp | SignInAction::ForgotPassword) => Some("check_email"),
        Step::Action(_) | Step::ChangePassword { .. } | Step::Token => None,
    };
    match (answering.client, note) {
        (Client::Browser, Some(note)) => see_other(&noted_login(answering, note), []),
        (Client::Browser, None) => see_other(&on_host(answering, SignInAction::LogIn, &[]), []),
        (Client::Script, _) => json(
            StatusCode::ACCEPTED,
            &serde_json::json!({ "accepted": true }),
            [],
        ),
    }
}

/// The login address with `note` flagged, and the return path carried.
fn noted_login(answering: &Answering<'_>, note: &str) -> String {
    let mut params = vec![(note, "1")];
    params.extend(carried_return(answering, SignInAction::LogIn));
    on_host(answering, SignInAction::LogIn, &params)
}

/// The first leg of a hop on the host of a service's own cookie: the
/// browser keeps `value` in this host's hop cookie and goes to `fetch_code`
/// on the owner's host, which hands it the code bound to that value.
pub(super) fn hop_started(value: &str, fetch_code: &str) -> Response {
    see_other(fetch_code, [cookies::hop(value)])
}

/// The owner's host handing a browser on its way the hop's code: back to
/// the other host's hop address, `land_at`.
pub(super) fn hop_code_issued(land_at: &str) -> Response {
    see_other(land_at, [])
}

/// The session cookie a hop sets on the host of a service's own cookie, its
/// hop value spent, and the way on: to `onward` for a browser passing
/// through, or an empty answer when it names nowhere to go.
pub(super) fn handed_over(session_token: &str, expires_at: i64, onward: Option<&str>) -> Response {
    let set = [
        cookies::session(session_token, expires_at),
        cookies::csrf(&csrf_value(), expires_at),
        cookies::cleared(APP_HOP_COOKIE),
    ];
    hop_answer(StatusCode::NO_CONTENT, onward, set)
}

/// The way on from a hop that set nothing: the person is still signed in on
/// the owner's host, so a browser passing through is not stranded here.
pub(super) fn hop_failed(status: StatusCode, onward: Option<&str>) -> Response {
    hop_answer(status, onward, [])
}

fn hop_answer<const N: usize>(
    status: StatusCode,
    onward: Option<&str>,
    set: [Option<HeaderValue>; N],
) -> Response {
    if let Some(onward) = onward {
        return see_other(onward, set);
    }
    finish(http::Response::builder().status(status), set, Bytes::new())
}

/// A page the API drew, allowed to run `script` and nothing else.
pub(super) fn page(status: StatusCode, html: String, script: PageScript<'_>) -> Response {
    let builder = http::Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .header(CONTENT_SECURITY_POLICY, page_policy(script))
        .header(X_FRAME_OPTIONS, "DENY")
        .header(REFERRER_POLICY, "no-referrer");
    finish(builder, [], Bytes::from(html))
}

/// The policy a page is served under. The passkey script is allowed by its
/// one absolute address, which only the gateway answers, never by `'self'`
/// (which would let any script the app serves run) and never inline or by
/// `eval`; it may send requests to the page's own host and nowhere else.
fn page_policy(script: PageScript<'_>) -> String {
    match script {
        PageScript::None => PAGE_POLICY.to_owned(),
        PageScript::Passkey(src) => {
            format!("{PAGE_POLICY}; script-src {src}; connect-src 'self'")
        }
    }
}

/// The gateway's passkey script, the one script its login page runs.
pub(super) fn passkey_script() -> Response {
    let builder = http::Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/javascript; charset=utf-8")
        .header("cross-origin-resource-policy", "same-origin");
    finish(builder, [], Bytes::from_static(PASSKEY_SCRIPT.as_bytes()))
}

/// A page that could not be shown, such as an address under the prefix
/// that nothing answers. Never a redirect: a page sending a refused browser
/// back to itself would never stop.
#[must_use]
pub(crate) fn page_refused(status: StatusCode) -> Response {
    let reason = status.canonical_reason().unwrap_or("Unavailable");
    page(
        status,
        format!("<!doctype html><title>{reason}</title><p>{reason}</p>"),
        PageScript::None,
    )
}

/// A `303 See Other` to `location`, never cached.
#[must_use]
pub(crate) fn see_other<const N: usize>(location: &str, set: [Option<HeaderValue>; N]) -> Response {
    let builder = http::Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(LOCATION, location);
    finish(builder, set, Bytes::new())
}

fn json<const N: usize>(
    status: StatusCode,
    body: &serde_json::Value,
    set: [Option<HeaderValue>; N],
) -> Response {
    let builder = http::Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json");
    finish(builder, set, Bytes::from(body.to_string()))
}

/// The answer with the cookies of `set` that could be written. Nothing the
/// API sent becomes a header here; a response that cannot be built is a
/// bare `500`.
fn finish<const N: usize>(
    builder: response::Builder,
    set: [Option<HeaderValue>; N],
    body: Bytes,
) -> Response {
    let builder = set
        .into_iter()
        .flatten()
        .fold(builder, |builder, cookie| {
            builder.header(SET_COOKIE, cookie)
        })
        .header(CACHE_CONTROL, "no-store")
        .header(X_CONTENT_TYPE_OPTIONS, "nosniff");
    builder
        .body(Full::new(body))
        .unwrap_or_else(|_| server_error())
}

fn server_error() -> Response {
    let mut response = http::Response::new(Full::new(Bytes::new()));
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response
}

/// Adds a `Set-Cookie` clearing what a single sign-on kept, once the browser
/// came back with it, whatever the answer.
pub(super) fn ending_single_sign_on(mut answer: Response) -> Response {
    if let Some(cleared) = cookies::cleared(APP_SINGLE_SIGN_ON_COOKIE) {
        answer.headers_mut().append(SET_COOKIE, cleared);
    }
    answer
}

/// A fresh double-submit value: 32 random bytes, URL-safe.
fn csrf_value() -> String {
    let bytes: [u8; 32] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

fn seconds_until(unix: i64) -> i64 {
    unix.saturating_sub(clock::now().unix_timestamp()).max(0)
}

/// A code safe in a query string: codes are lowercase words and
/// underscores, so anything else is dropped rather than escaped.
fn query_value(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use http_body_util::BodyExt;
    use ianua_domain::domains::routing::sign_in::app::{
        AppSignInParams, SignInPath, SignedOutBrowsers,
    };
    use ianua_domain::types::{DenialStatus, Setting};

    use super::*;

    fn sign_in() -> AppSignIn {
        let mut moved = BTreeMap::new();
        moved.insert(SignInAction::LogIn, SignInPath::new("/login").unwrap());
        AppSignIn::new(AppSignInParams {
            hosts: vec![host()],
            prefix: Setting::Unset,
            moved,
            after_sign_in: Setting::Unset,
            signed_out_browsers: SignedOutBrowsers::Refuse,
        })
        .unwrap()
    }

    fn host() -> DomainName {
        DomainName::new("shop.example.com").unwrap()
    }

    fn answer(client: Client, step: Step, outcome: WireOutcome) -> Response {
        let (sign_in, host) = (sign_in(), host());
        super::outcome(&answering(&sign_in, &host, client, step), outcome)
    }

    fn answering<'a>(
        sign_in: &'a AppSignIn,
        host: &'a DomainName,
        client: Client,
        step: Step,
    ) -> Answering<'a> {
        Answering {
            client,
            host,
            sign_in,
            step,
            return_to: None,
        }
    }

    fn set_cookies(response: &Response) -> Vec<String> {
        response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect()
    }

    fn sets(response: &Response, prefix: &str) -> bool {
        set_cookies(response).iter().any(|c| c.starts_with(prefix))
    }

    async fn body_of(response: Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn location(response: &Response) -> &str {
        response.headers()[LOCATION].to_str().unwrap()
    }

    fn later() -> i64 {
        clock::now().unix_timestamp() + 3600
    }

    fn signed_in_at(return_to: &str, hops: Vec<WireHop>) -> WireOutcome {
        WireOutcome::SignedIn {
            token: "tok".to_owned(),
            expires_at: later(),
            return_to: return_to.to_owned(),
            hops,
            remembered_device: None,
        }
    }

    fn rejected(status: u16, code: &str) -> WireOutcome {
        WireOutcome::Rejected {
            status: DenialStatus::new(status).unwrap(),
            code: code.to_owned(),
        }
    }

    fn log_in() -> Step {
        Step::Action(SignInAction::LogIn)
    }

    #[test]
    fn a_browser_signing_in_is_sent_back_with_its_session() {
        let response = answer(
            Client::Browser,
            log_in(),
            signed_in_at("/projects", Vec::new()),
        );

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "https://shop.example.com/projects");
        assert!(sets(&response, "__Host-ianua_app=tok;"));
        assert!(sets(&response, "__Host-ianua_csrf="));
        assert!(sets(&response, "__Host-ianua_mfa=;"));
        assert!(!sets(&response, "__Host-ianua_device="));
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    }

    /// Bob asked to remember his laptop and the API remembered it. The
    /// browser keeps its secret in the host's device cookie.
    #[test]
    fn a_remembered_device_is_kept_in_its_cookie() {
        let remembered = WireOutcome::SignedIn {
            token: "tok".to_owned(),
            expires_at: later(),
            return_to: "/projects".to_owned(),
            hops: Vec::new(),
            remembered_device: Some("ab".repeat(32)),
        };

        let response = answer(Client::Browser, log_in(), remembered);

        assert!(sets(
            &response,
            &format!("__Host-ianua_device={};", "ab".repeat(32))
        ));
        assert!(sets(&response, "__Host-ianua_app=tok;"));
    }

    /// The API's return path is held to this host: one that would lead
    /// elsewhere lands on the sign-in's landing page instead.
    #[test]
    fn a_return_path_off_this_host_lands_on_the_landing_page() {
        for return_to in [
            "//evil.example.com/",
            "https://evil.example.com/",
            "/\\evil.com",
        ] {
            let response = answer(
                Client::Browser,
                log_in(),
                signed_in_at(return_to, Vec::new()),
            );

            assert_eq!(
                location(&response),
                "https://shop.example.com/",
                "{return_to}"
            );
        }
    }

    /// Signing in also sets the session on each host of a service's own
    /// cookie: the browser passes through each in turn, then comes back.
    #[test]
    fn a_browser_signing_in_hops_through_each_host_of_a_cookie_of_its_own() {
        let hops = vec![
            WireHop {
                host: DomainName::new("api.example.com").unwrap(),
            },
            WireHop {
                host: DomainName::new("files.example.com").unwrap(),
            },
        ];

        let response = answer(Client::Browser, log_in(), signed_in_at("/projects", hops));

        let from = "from=https%3A%2F%2Fshop.example.com";
        let back = "https%3A%2F%2Fshop.example.com%2Fprojects";
        let second = format!("https://files.example.com/.ianua/hop?{from}&next={back}");
        let second: String = url::form_urlencoded::byte_serialize(second.as_bytes()).collect();
        assert_eq!(
            location(&response),
            format!("https://api.example.com/.ianua/hop?{from}&next={second}")
        );
        assert!(!location(&response).contains("code="));
        assert!(sets(&response, "__Host-ianua_app=tok;"));
    }

    #[test]
    fn a_script_signing_in_gets_json_and_the_same_cookies() {
        let response = answer(Client::Script, log_in(), signed_in_at("/", Vec::new()));

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
        assert!(sets(&response, "__Host-ianua_app="));
    }

    /// A script signing in where hops are owed gets the first stop to send
    /// the window to: the hops are navigations, never fetches, so each
    /// host's cookie is first-party and bound to this browser.
    #[tokio::test]
    async fn a_script_signing_in_with_hops_is_told_where_to_send_the_window() {
        let hops = vec![WireHop {
            host: DomainName::new("api.example.com").unwrap(),
        }];

        let response = answer(Client::Script, log_in(), signed_in_at("/projects", hops));

        let body = body_of(response).await;
        assert!(
            body["hop_to"]
                .as_str()
                .unwrap()
                .starts_with("https://api.example.com/.ianua/hop?from=")
        );
        assert_eq!(body["return_to"], "/projects");
    }

    /// Nothing the API answers is passed through as a header: the answer
    /// holds only what the gateway writes.
    #[test]
    fn no_header_of_the_apis_reaches_the_browser() {
        let response = answer(Client::Browser, log_in(), signed_in_at("/", Vec::new()));

        let names: Vec<_> = response
            .headers()
            .keys()
            .map(http::header::HeaderName::as_str)
            .collect();
        for name in &names {
            assert!(
                [
                    "location",
                    "set-cookie",
                    "cache-control",
                    "x-content-type-options"
                ]
                .contains(name),
                "{name}"
            );
        }
    }

    #[test]
    fn a_second_factor_sends_the_browser_to_the_mfa_address_with_its_challenge() {
        let response = answer(
            Client::Browser,
            log_in(),
            WireOutcome::MfaRequired {
                challenge: "chal".to_owned(),
                expires_at: later(),
            },
        );

        assert_eq!(location(&response), "https://shop.example.com/.ianua/mfa");
        assert!(sets(&response, "__Host-ianua_mfa=chal;"));
        assert!(!sets(&response, "__Host-ianua_app="));
    }

    #[test]
    fn the_second_factor_keeps_where_the_person_was_going() {
        let (sign_in, host) = (sign_in(), host());
        let answering = Answering {
            return_to: Some("/orders".to_owned()),
            ..answering(&sign_in, &host, Client::Browser, log_in())
        };

        let response = outcome(
            &answering,
            WireOutcome::MfaRequired {
                challenge: "chal".to_owned(),
                expires_at: later(),
            },
        );

        assert_eq!(
            location(&response),
            "https://shop.example.com/.ianua/mfa?return_to=%2Forders"
        );
    }

    #[test]
    fn a_sign_in_waiting_on_the_mailbox_keeps_its_challenge_and_says_so() {
        let response = answer(
            Client::Browser,
            log_in(),
            WireOutcome::ConfirmByEmail {
                challenge: "chal".to_owned(),
                expires_at: later(),
            },
        );

        assert_eq!(
            location(&response),
            "https://shop.example.com/login?check_email=1"
        );
        assert!(sets(&response, "__Host-ianua_mfa=chal;"));
    }

    /// Ann's password was set by an administrator: no session opens, and
    /// the change's token is kept where only the gateway reads it.
    #[test]
    fn a_password_change_owed_keeps_its_token_in_the_challenge_cookie() {
        let response = answer(
            Client::Script,
            log_in(),
            WireOutcome::PasswordChangeRequired {
                challenge: Some("change".to_owned()),
                proof: "own_factor".to_owned(),
                reason: "set_by_admin".to_owned(),
                expires_at: later(),
            },
        );

        assert_eq!(response.status(), StatusCode::OK);
        assert!(sets(&response, "__Host-ianua_mfa=change;"));
        assert!(!sets(&response, "__Host-ianua_app="));
    }

    /// Ann's browser owes a new password: it is sent to the change page,
    /// which says why, keeping where she was going; never to the login page
    /// with an error.
    #[test]
    fn a_browser_owing_a_new_password_is_sent_to_the_change_page() {
        let (sign_in, host) = (sign_in(), host());
        let answering = Answering {
            return_to: Some("/orders".to_owned()),
            ..answering(&sign_in, &host, Client::Browser, log_in())
        };

        let response = outcome(
            &answering,
            WireOutcome::PasswordChangeRequired {
                challenge: Some("change".to_owned()),
                proof: "own_factor".to_owned(),
                reason: "set_by_admin".to_owned(),
                expires_at: later(),
            },
        );

        assert_eq!(
            location(&response),
            "https://shop.example.com/.ianua/change-password?password_change_required=1&return_to=%2Forders"
        );
        assert!(sets(&response, "__Host-ianua_mfa=change;"));
    }

    /// A weak new password is refused on the change page opened from a
    /// mailed link: the browser goes back to it with the link's token, so
    /// it can try again.
    #[test]
    fn a_refused_change_goes_back_to_its_page_with_the_mailed_token() {
        let response = answer(
            Client::Browser,
            Step::ChangePassword {
                token: Some("mailed".to_owned()),
            },
            rejected(422, "domain_error"),
        );

        assert_eq!(
            location(&response),
            "https://shop.example.com/.ianua/change-password?error=domain_error&token=mailed"
        );
    }

    #[test]
    fn a_password_change_by_mailed_link_sets_nothing_and_points_to_the_mailbox() {
        let response = answer(
            Client::Browser,
            log_in(),
            WireOutcome::PasswordChangeRequired {
                challenge: None,
                proof: "mailed_link".to_owned(),
                reason: "set_by_admin".to_owned(),
                expires_at: later(),
            },
        );

        assert_eq!(
            location(&response),
            "https://shop.example.com/login?check_email=1"
        );
        assert!(set_cookies(&response).is_empty());
    }

    #[test]
    fn a_single_sign_on_sends_the_browser_away_keeping_its_secrets() {
        let response = answer(
            Client::Browser,
            Step::Action(SignInAction::Sso),
            WireOutcome::SsoRedirect {
                url: "https://idp.example.com/authorize?state=s".to_owned(),
                binding: "bind".to_owned(),
                hand_back: "back".to_owned(),
                return_to: Some("/orders".to_owned()),
            },
        );

        assert_eq!(
            location(&response),
            "https://idp.example.com/authorize?state=s"
        );
        assert!(sets(&response, "__Host-ianua_sso="));
    }

    #[test]
    fn a_single_sign_on_to_an_address_that_is_not_https_is_refused() {
        let response = answer(
            Client::Script,
            Step::Action(SignInAction::Sso),
            WireOutcome::SsoRedirect {
                url: "javascript:alert(1)".to_owned(),
                binding: "bind".to_owned(),
                hand_back: "back".to_owned(),
                return_to: None,
            },
        );

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(set_cookies(&response).is_empty());
    }

    #[test]
    fn a_passkey_challenge_is_json_with_its_options_in_base64url() {
        let ceremony = CeremonyId::new();

        let response = answer(
            Client::Browser,
            Step::Action(SignInAction::Passkey),
            WireOutcome::PasskeyChallenge {
                ceremony_id: ceremony,
                options: vec![1, 2, 3],
            },
        );

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
    }

    #[test]
    fn signing_out_clears_every_cookie() {
        let response = answer(
            Client::Browser,
            Step::Action(SignInAction::LogOut),
            WireOutcome::SignedOut,
        );

        let cookies = set_cookies(&response);
        for name in [
            APP_SESSION_COOKIE,
            APP_CSRF_COOKIE,
            APP_CHALLENGE_COOKIE,
            APP_SINGLE_SIGN_ON_COOKIE,
        ] {
            assert!(
                cookies
                    .iter()
                    .any(|c| c.starts_with(&format!("{name}=;")) && c.contains("Max-Age=0")),
                "{name} not cleared"
            );
        }
    }

    #[test]
    fn a_done_request_tells_the_browser_what_happened() {
        for (step, expected) in [
            (
                Step::Action(SignInAction::SignUp),
                "https://shop.example.com/login?check_email=1",
            ),
            (
                Step::Action(SignInAction::ForgotPassword),
                "https://shop.example.com/login?check_email=1",
            ),
            (
                Step::Action(SignInAction::Verify),
                "https://shop.example.com/login?verified=1",
            ),
            (
                Step::Reset {
                    token: "reset".to_owned(),
                },
                "https://shop.example.com/login?password_reset=1",
            ),
        ] {
            let response = answer(Client::Browser, step, WireOutcome::Accepted);

            assert_eq!(location(&response), expected);
        }
    }

    #[test]
    fn a_refused_browser_goes_back_to_the_address_with_the_reason() {
        let response = answer(Client::Browser, log_in(), rejected(404, "not_found"));

        assert_eq!(
            location(&response),
            "https://shop.example.com/login?error=not_found"
        );
        assert!(set_cookies(&response).is_empty());
    }

    #[test]
    fn a_refused_script_gets_the_status() {
        let response = answer(Client::Script, log_in(), rejected(404, "not_found"));

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn a_refused_login_keeps_where_the_person_was_going() {
        let (sign_in, host) = (sign_in(), host());
        let answering = Answering {
            return_to: Some("/orders?id=1".to_owned()),
            ..answering(&sign_in, &host, Client::Browser, log_in())
        };

        let response = outcome(&answering, rejected(404, "not_found"));

        assert_eq!(
            location(&response),
            "https://shop.example.com/login?error=not_found&return_to=%2Forders%3Fid%3D1"
        );
    }

    /// A weak new password is refused; the browser goes back to the reset
    /// page from the same mailed link, so it can try again.
    #[test]
    fn a_refused_reset_goes_back_to_its_page_with_the_mailed_token() {
        let response = answer(
            Client::Browser,
            Step::Reset {
                token: "reset".to_owned(),
            },
            rejected(422, "domain_error"),
        );

        assert_eq!(
            location(&response),
            "https://shop.example.com/.ianua/reset-password?error=domain_error&token=reset"
        );
    }

    /// A verify link that fails would otherwise be sent back to itself, and
    /// fail again, forever.
    #[test]
    fn a_refused_link_goes_to_the_login_page() {
        let response = answer(
            Client::Browser,
            Step::Action(SignInAction::Verify),
            rejected(410, "link_expired"),
        );

        assert_eq!(
            location(&response),
            "https://shop.example.com/login?error=link_expired"
        );
    }

    /// A page or a hop's session is never an answer to a form: the API
    /// answered something that does not fit, and the request is refused.
    #[test]
    fn an_answer_that_does_not_fit_the_question_is_refused() {
        for outcome in [
            WireOutcome::Page {
                html: "<p>".to_owned(),
            },
            WireOutcome::HandedOver {
                token: "tok".to_owned(),
                expires_at: later(),
            },
            WireOutcome::Token {
                access_token: "tok".to_owned(),
                expires_at: later(),
            },
        ] {
            let response = answer(Client::Script, log_in(), outcome);

            assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
            assert!(set_cookies(&response).is_empty());
        }
    }

    #[test]
    fn a_token_is_answered_at_the_token_address() {
        let response = answer(
            Client::Script,
            Step::Token,
            WireOutcome::Token {
                access_token: "tok".to_owned(),
                expires_at: later(),
            },
        );

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    }

    #[test]
    fn a_page_runs_no_script_and_cannot_be_framed() {
        let response = page(
            StatusCode::OK,
            "<!doctype html>".to_owned(),
            PageScript::None,
        );

        let policy = response.headers()[CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap();
        assert!(policy.starts_with("default-src 'none'"));
        assert!(!policy.contains("script-src"));
        assert_eq!(response.headers()[X_FRAME_OPTIONS], "DENY");
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    }

    /// The login page may run the gateway's passkey script, named by its
    /// one address, and nothing else: no inline script, no `eval`, no other
    /// script of the app's host.
    #[test]
    fn the_login_page_runs_the_passkey_script_alone() {
        let src = "https://shop.example.com/.ianua/passkey.js";
        let response = page(
            StatusCode::OK,
            "<!doctype html>".to_owned(),
            PageScript::Passkey(src),
        );

        let policy = response.headers()[CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap();
        assert!(policy.starts_with("default-src 'none'"));
        assert!(policy.contains(&format!("script-src {src};")));
        assert!(policy.ends_with("connect-src 'self'"));
        assert!(!policy.contains("'unsafe-eval'"));
        assert!(!policy.contains("script-src 'self'"));
        assert_eq!(policy.matches("'unsafe-inline'").count(), 1);
        assert!(policy.contains("style-src 'unsafe-inline'"));
    }

    #[tokio::test]
    async fn the_passkey_script_is_served_as_javascript_and_never_sniffed() {
        let response = passkey_script();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[CONTENT_TYPE],
            "text/javascript; charset=utf-8"
        );
        assert_eq!(response.headers()[X_CONTENT_TYPE_OPTIONS], "nosniff");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(body.starts_with(b"\"use strict\""));
    }

    #[test]
    fn a_page_that_cannot_be_shown_is_never_a_redirect() {
        let response = page_refused(StatusCode::FORBIDDEN);

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.headers().get(LOCATION).is_none());
    }

    #[test]
    fn a_hop_sets_the_cookie_spends_its_value_and_sends_the_browser_on() {
        let response = handed_over("tok", later(), Some("https://shop.example.com/"));

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "https://shop.example.com/");
        assert!(sets(&response, "__Host-ianua_app=tok;"));
        assert!(sets(&response, "__Host-ianua_hop=;"));
    }

    /// A hop answers no other page: nothing lets a script on another origin
    /// read it, so a hop is a navigation, never a fetch.
    #[test]
    fn a_hop_naming_nowhere_to_go_answers_empty_and_to_nobody_else() {
        let response = handed_over("tok", later(), None);

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-origin")
        );
    }

    #[test]
    fn a_failed_hop_still_sends_the_browser_on() {
        let response = hop_failed(StatusCode::NOT_FOUND, Some("https://shop.example.com/"));

        assert_eq!(location(&response), "https://shop.example.com/");
        assert!(set_cookies(&response).is_empty());
    }

    /// The first leg of a hop keeps the browser's value in this host's hop
    /// cookie and sends the browser to fetch its code.
    #[test]
    fn a_hop_starts_by_keeping_the_browsers_value() {
        let response = hop_started("v4lue", "https://shop.example.com/.ianua/hop?host=x");

        assert_eq!(
            location(&response),
            "https://shop.example.com/.ianua/hop?host=x"
        );
        assert!(sets(&response, "__Host-ianua_hop=v4lue;"));
    }

    #[test]
    fn a_code_cannot_inject_into_the_redirect() {
        assert_eq!(query_value("x&next=//evil\r\n"), "xnextevil");
    }
}
