//! The command each sign-in action stands for, from the fields sent and the
//! cookies the request carries.
//!
//! A credential the gateway set rides in its cookie, never in a form field,
//! where a page script could read or forge it: the second factor's
//! challenge, the session, and what a single sign-on kept.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ianua_app::ports::authentication::{WireCommand, WirePage, WireSsoAnswer};
use ianua_domain::domains::routing::sign_in::app::SignInAction;
use ianua_domain::types::{CeremonyId, ConnectionId, DomainName};

use super::cookies::KeptSignOn;
use super::fields::{Fields, Unread};

/// The flags a page's address may carry instead of an `error`, each the note
/// of the same name.
const NOTE_FLAGS: [&str; 4] = [
    "check_email",
    "verified",
    "password_reset",
    "password_change_required",
];

/// What the request's cookies contribute to an action. Holds credentials,
/// so it has no `Debug`.
pub(super) struct Carried {
    /// The challenge cookie of a sign-in that is not finished yet.
    pub(super) challenge: Option<String>,
    /// The session cookie.
    pub(super) session: Option<String>,
    /// What a single sign-on kept while the browser was away.
    pub(super) single_sign_on: Option<KeptSignOn>,
    /// The secret of the device the browser remembered on this host.
    pub(super) device: Option<String>,
    /// A fresh secret, sent only when the person asks the second-factor
    /// page to remember this device. Never the old cookie's: a copy of a
    /// cookie taken before must not become trusted again.
    pub(super) fresh_device: String,
}

/// The command `action` stands for.
///
/// # Errors
///
/// [`Unread`] naming the first field the action needs that was not sent, or
/// one sent in a shape it cannot have.
pub(super) fn command(
    action: SignInAction,
    mut fields: Fields,
    carried: Carried,
) -> Result<WireCommand, Unread> {
    match action {
        SignInAction::LogIn => log_in(fields, carried.device),
        SignInAction::SignUp => sign_up(fields),
        SignInAction::Mfa => complete_mfa(fields, carried.challenge, carried.fresh_device),
        SignInAction::Verify => Ok(WireCommand::Verify {
            token: fields.require("token")?,
        }),
        SignInAction::ConfirmSignIn => confirm_sign_in(fields, carried.challenge),
        SignInAction::LogOut => Ok(WireCommand::LogOut {
            session: carried.session,
        }),
        SignInAction::Sso => single_sign_on(fields),
        SignInAction::SsoCallback => single_sign_on_return(fields, carried.single_sign_on),
        SignInAction::Passkey => passkey(fields),
        SignInAction::ForgotPassword => Ok(WireCommand::ForgotPassword {
            email: fields.require("email")?,
        }),
        SignInAction::ResetPassword => reset_password(fields),
        SignInAction::ChangePassword => change_password(fields, carried.challenge, carried.device),
    }
}

/// The request for a hop's code on the owner's host, from the address the
/// other host sent the browser to and the session cookie.
///
/// # Errors
///
/// [`Unread`] when the host or the browser's digest was not sent, or the
/// host is not a name.
pub(super) fn hop_code_command(
    fields: &Fields,
    session: Option<String>,
) -> Result<WireCommand, Unread> {
    let host = fields.value("host").ok_or(Unread::Missing("host"))?;
    let browser = fields.value("browser").ok_or(Unread::Missing("browser"))?;
    Ok(WireCommand::IssueHop {
        session,
        host: DomainName::new(host).map_err(|_| Unread::Malformed)?,
        browser: browser.to_owned(),
    })
}

/// The request for a short-lived token, from the audience sent and the
/// session cookie.
///
/// # Errors
///
/// [`Unread::Missing`] when no audience was sent.
pub(super) fn token_command(
    mut fields: Fields,
    session: Option<String>,
) -> Result<WireCommand, Unread> {
    Ok(WireCommand::IssueToken {
        session,
        audience: fields.require("audience")?,
    })
}

/// The request for the page of `action`, from its address's query: the note
/// it asks for, where the person is going, and for the reset and change
/// pages the mailed link's token. `None` for an action that has no page.
pub(super) fn page_command(action: SignInAction, mut fields: Fields) -> Option<WireCommand> {
    let page = page_of(action)?;
    let note = fields.take("error").or_else(|| {
        NOTE_FLAGS
            .into_iter()
            .find(|flag| fields.value(flag).is_some())
            .map(str::to_owned)
    });
    let token = match page {
        WirePage::ResetPassword | WirePage::ChangePassword => fields.take("token"),
        WirePage::LogIn | WirePage::SignUp | WirePage::Mfa | WirePage::ForgotPassword => None,
    };
    Some(WireCommand::ShowPage {
        page,
        note,
        return_to: fields.take("return_to"),
        token,
    })
}

fn page_of(action: SignInAction) -> Option<WirePage> {
    match action {
        SignInAction::LogIn => Some(WirePage::LogIn),
        SignInAction::SignUp => Some(WirePage::SignUp),
        SignInAction::Mfa => Some(WirePage::Mfa),
        SignInAction::ForgotPassword => Some(WirePage::ForgotPassword),
        SignInAction::ResetPassword => Some(WirePage::ResetPassword),
        SignInAction::ChangePassword => Some(WirePage::ChangePassword),
        SignInAction::Verify
        | SignInAction::ConfirmSignIn
        | SignInAction::LogOut
        | SignInAction::Sso
        | SignInAction::SsoCallback
        | SignInAction::Passkey => None,
    }
}

/// A password sign-in, with the device cookie the browser holds, which
/// rides in its cookie, never in the form.
fn log_in(mut fields: Fields, device: Option<String>) -> Result<WireCommand, Unread> {
    Ok(WireCommand::LogIn {
        email: fields.require("email")?,
        password: fields.require("password")?,
        device,
        return_to: fields.take("return_to"),
    })
}

fn sign_up(mut fields: Fields) -> Result<WireCommand, Unread> {
    Ok(WireCommand::SignUp {
        email: fields.require("email")?,
        display_name: fields.require("display_name")?,
        password: fields.require("password")?,
    })
}

/// A second-factor answer, and `fresh_device` to remember when the person
/// ticked "remember this device".
fn complete_mfa(
    mut fields: Fields,
    challenge: Option<String>,
    fresh_device: String,
) -> Result<WireCommand, Unread> {
    let remember_device = fields.take("remember_device").map(|_| fresh_device);
    Ok(WireCommand::CompleteMfa {
        challenge: challenge.ok_or(Unread::Missing("challenge"))?,
        code: fields.require("code")?,
        remember_device,
        return_to: fields.take("return_to"),
    })
}

/// The mailed link confirming a sign-in, opened at its own address. It
/// finishes the sign-in only in the browser whose challenge cookie holds it;
/// opened anywhere else it is refused, never read as something else.
fn confirm_sign_in(mut fields: Fields, challenge: Option<String>) -> Result<WireCommand, Unread> {
    Ok(WireCommand::ConfirmByEmail {
        challenge: challenge.ok_or(Unread::Missing("challenge"))?,
        link: fields.require("token")?,
        return_to: fields.take("return_to"),
    })
}

fn single_sign_on(mut fields: Fields) -> Result<WireCommand, Unread> {
    let connection_id = uuid_of(&fields.require("connection_id")?)?;
    Ok(WireCommand::Sso {
        connection_id: ConnectionId::from_uuid(connection_id),
        return_to: fields.take("return_to"),
    })
}

/// The provider's answer with what the browser kept since the start. A
/// browser that kept nothing did not start this sign-on.
fn single_sign_on_return(fields: Fields, kept: Option<KeptSignOn>) -> Result<WireCommand, Unread> {
    let kept = kept.ok_or(Unread::Missing("single_sign_on"))?;
    Ok(WireCommand::SsoCallback {
        answer: provider_answer(fields)?,
        binding: kept.binding,
        hand_back: kept.hand_back,
        return_to: kept.return_to,
    })
}

/// A SAML provider posts `SAMLResponse` and `RelayState`; an OIDC provider
/// sends `state` and `code`, in the query or, with `form_post`, the body.
fn provider_answer(mut fields: Fields) -> Result<WireSsoAnswer, Unread> {
    if let Some(saml_response) = fields.take("SAMLResponse") {
        return Ok(WireSsoAnswer::Saml {
            relay_state: fields.require("RelayState")?,
            saml_response,
        });
    }
    Ok(WireSsoAnswer::Oidc {
        state: fields.require("state")?,
        code: fields.require("code")?,
    })
}

/// A passkey answer when it names its ceremony, a request for a challenge
/// otherwise.
fn passkey(mut fields: Fields) -> Result<WireCommand, Unread> {
    let Some(ceremony_id) = fields.take("ceremony_id") else {
        return Ok(WireCommand::PasskeyBegin {
            email: fields.take("email"),
        });
    };
    Ok(WireCommand::PasskeyConfirm {
        ceremony_id: CeremonyId::from_uuid(uuid_of(&ceremony_id)?),
        credential_id: decoded(&fields.require("credential_id")?)?,
        response: decoded(&fields.require("response")?)?,
        return_to: fields.take("return_to"),
    })
}

/// A new password at the reset address, by the mailed reset link's `token`.
fn reset_password(mut fields: Fields) -> Result<WireCommand, Unread> {
    Ok(WireCommand::ResetPassword {
        token: fields.require("token")?,
        password: fields.require("password")?,
        mfa_code: fields.take("mfa_code"),
    })
}

/// The new password a sign-in owes, at the change address: by the `token`
/// of the mailed change link the page was opened from, or by the challenge
/// cookie of the browser that signed in.
fn change_password(
    mut fields: Fields,
    challenge: Option<String>,
    device: Option<String>,
) -> Result<WireCommand, Unread> {
    let challenge = fields
        .take("token")
        .or(challenge)
        .ok_or(Unread::Missing("token"))?;
    Ok(WireCommand::ChangePassword {
        challenge,
        password: fields.require("password")?,
        mfa_code: fields.take("mfa_code"),
        device,
        return_to: fields.take("return_to"),
    })
}

fn uuid_of(value: &str) -> Result<uuid::Uuid, Unread> {
    uuid::Uuid::parse_str(value).map_err(|_| Unread::Malformed)
}

/// Bytes a script sent as unpadded base64url, as `WebAuthn` values are.
fn decoded(value: &str) -> Result<Vec<u8>, Unread> {
    URL_SAFE_NO_PAD.decode(value).map_err(|_| Unread::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRESH: &str = "ab";

    fn nothing() -> Carried {
        Carried {
            challenge: None,
            session: None,
            single_sign_on: None,
            device: None,
            fresh_device: FRESH.repeat(32),
        }
    }

    /// Bob's browser holds the device cookie of a laptop he remembered on
    /// this host. It rides with his sign-in from the cookie, and one sent
    /// in the form is never read.
    #[test]
    fn logging_in_carries_the_device_cookie_never_a_form_field() {
        let held = Carried {
            device: Some("cookie-secret".to_owned()),
            ..nothing()
        };

        let from_cookie = command(
            SignInAction::LogIn,
            form("email=a%40example.com&password=pw"),
            held,
        );
        let from_form = command(
            SignInAction::LogIn,
            form("email=a%40example.com&password=pw&device=form-secret"),
            nothing(),
        );

        assert!(matches!(
            from_cookie,
            Ok(WireCommand::LogIn { device: Some(device), .. }) if device == "cookie-secret"
        ));
        assert!(matches!(
            from_form,
            Ok(WireCommand::LogIn { device: None, .. })
        ));
    }

    /// Bob ticks "remember this device". The second factor is sent with a
    /// fresh secret the gateway made, never the cookie he already holds.
    /// Unticked, nothing is asked to be remembered.
    #[test]
    fn remembering_the_device_sends_a_fresh_secret_only_when_asked() {
        let holding_old = Carried {
            device: Some("old-cookie".to_owned()),
            ..with_challenge()
        };

        let ticked = command(
            SignInAction::Mfa,
            form("code=123456&remember_device=yes"),
            holding_old,
        );
        let unticked = command(SignInAction::Mfa, form("code=123456"), with_challenge());

        assert!(matches!(
            ticked,
            Ok(WireCommand::CompleteMfa { remember_device: Some(secret), .. })
                if secret == FRESH.repeat(32)
        ));
        assert!(matches!(
            unticked,
            Ok(WireCommand::CompleteMfa {
                remember_device: None,
                ..
            })
        ));
    }

    fn with_challenge() -> Carried {
        Carried {
            challenge: Some("chal".to_owned()),
            ..nothing()
        }
    }

    fn form(body: &str) -> Fields {
        Fields::read(Some("application/x-www-form-urlencoded"), body.as_bytes())
    }

    fn json(body: &str) -> Fields {
        Fields::read(Some("application/json"), body.as_bytes())
    }

    fn kept() -> KeptSignOn {
        KeptSignOn {
            binding: "bind".to_owned(),
            hand_back: "back".to_owned(),
            return_to: Some("/orders".to_owned()),
        }
    }

    #[test]
    fn logging_in_reads_the_address_password_and_return_path() {
        let command = command(
            SignInAction::LogIn,
            form("email=a%40example.com&password=p%26w&return_to=%2Fhome"),
            nothing(),
        );

        let Ok(WireCommand::LogIn {
            email,
            password,
            return_to,
            ..
        }) = command
        else {
            panic!("a login was not read as one");
        };
        assert_eq!(email, "a@example.com");
        assert_eq!(password, "p&w");
        assert_eq!(return_to.as_deref(), Some("/home"));
    }

    #[test]
    fn logging_in_without_a_password_names_it() {
        let refused = command(
            SignInAction::LogIn,
            form("email=a%40example.com"),
            nothing(),
        );

        assert_eq!(refused.err(), Some(Unread::Missing("password")));
    }

    #[test]
    fn signing_up_reads_the_address_name_and_password() {
        let command = command(
            SignInAction::SignUp,
            form("email=a%40example.com&display_name=Ann&password=pw"),
            nothing(),
        );

        assert!(matches!(
            command,
            Ok(WireCommand::SignUp { display_name, .. }) if display_name == "Ann"
        ));
    }

    /// The challenge proving the password was entered rides in its cookie,
    /// never in the form, where a page script could read it.
    #[test]
    fn the_second_factor_takes_its_challenge_from_the_cookie_only() {
        let from_form = command(
            SignInAction::Mfa,
            form("code=123456&challenge=from-the-form"),
            nothing(),
        );
        let from_cookie = command(SignInAction::Mfa, form("code=123456"), with_challenge());

        assert_eq!(from_form.err(), Some(Unread::Missing("challenge")));
        assert!(matches!(
            from_cookie,
            Ok(WireCommand::CompleteMfa { challenge, .. }) if challenge == "chal"
        ));
    }

    #[test]
    fn a_mailed_link_without_a_waiting_sign_in_verifies_the_address() {
        let command = command(
            SignInAction::Verify,
            Fields::from_query(Some("token=abc123")),
            nothing(),
        );

        assert!(matches!(command, Ok(WireCommand::Verify { token }) if token == "abc123"));
    }

    /// A verify link stays a verify link in a browser holding a challenge
    /// cookie: what a link does is read from its address, never from a
    /// cookie the browser happens to hold.
    #[test]
    fn a_verify_link_in_a_browser_with_a_challenge_still_verifies() {
        let command = command(
            SignInAction::Verify,
            Fields::from_query(Some("token=abc123")),
            with_challenge(),
        );

        assert!(matches!(command, Ok(WireCommand::Verify { token }) if token == "abc123"));
    }

    /// Ann signs in and is asked to confirm from her mailbox. She opens the
    /// link in the same browser, whose challenge cookie holds the sign-in.
    #[test]
    fn a_confirm_link_in_the_browser_of_a_waiting_sign_in_confirms_it() {
        let command = command(
            SignInAction::ConfirmSignIn,
            Fields::from_query(Some("token=abc123")),
            with_challenge(),
        );

        assert!(matches!(
            command,
            Ok(WireCommand::ConfirmByEmail { challenge, link, .. })
                if challenge == "chal" && link == "abc123"
        ));
    }

    /// The confirm link opened in another browser holds no sign-in to
    /// finish: it is refused, never read as verifying the address.
    #[test]
    fn a_confirm_link_in_another_browser_is_refused() {
        let refused = command(
            SignInAction::ConfirmSignIn,
            Fields::from_query(Some("token=abc123")),
            nothing(),
        );

        assert_eq!(refused.err(), Some(Unread::Missing("challenge")));
    }

    #[test]
    fn signing_out_takes_the_session_from_its_cookie() {
        let carried = Carried {
            session: Some("tok".to_owned()),
            ..nothing()
        };

        let command = command(SignInAction::LogOut, form(""), carried);

        assert!(matches!(
            command,
            Ok(WireCommand::LogOut { session }) if session.as_deref() == Some("tok")
        ));
    }

    #[test]
    fn single_sign_on_starts_with_the_connection_picked() {
        let connection = uuid::Uuid::now_v7();

        let command = command(
            SignInAction::Sso,
            Fields::from_query(Some(&format!(
                "connection_id={connection}&return_to=%2Forders"
            ))),
            nothing(),
        );

        let Ok(WireCommand::Sso {
            connection_id,
            return_to,
        }) = command
        else {
            panic!("a single sign-on start was not read as one");
        };
        assert_eq!(connection_id.as_uuid(), &connection);
        assert_eq!(return_to.as_deref(), Some("/orders"));
    }

    #[test]
    fn single_sign_on_refuses_a_connection_that_is_not_an_id() {
        let refused = command(
            SignInAction::Sso,
            Fields::from_query(Some("connection_id=okta")),
            nothing(),
        );

        assert_eq!(refused.err(), Some(Unread::Malformed));
    }

    #[test]
    fn an_oidc_return_carries_state_code_and_what_the_browser_kept() {
        let carried = Carried {
            single_sign_on: Some(kept()),
            ..nothing()
        };

        let command = command(
            SignInAction::SsoCallback,
            Fields::from_query(Some("state=st&code=co")),
            carried,
        );

        let Ok(WireCommand::SsoCallback {
            answer: WireSsoAnswer::Oidc { state, code },
            binding,
            hand_back,
            return_to,
        }) = command
        else {
            panic!("an OIDC return was not read as one");
        };
        assert_eq!((state.as_str(), code.as_str()), ("st", "co"));
        assert_eq!((binding.as_str(), hand_back.as_str()), ("bind", "back"));
        assert_eq!(return_to.as_deref(), Some("/orders"));
    }

    #[test]
    fn a_saml_return_carries_the_posted_response() {
        let carried = Carried {
            single_sign_on: Some(kept()),
            ..nothing()
        };

        let command = command(
            SignInAction::SsoCallback,
            form("SAMLResponse=PHNhbWw%2B&RelayState=id-1"),
            carried,
        );

        assert!(matches!(
            command,
            Ok(WireCommand::SsoCallback {
                answer: WireSsoAnswer::Saml { relay_state, saml_response },
                ..
            }) if relay_state == "id-1" && saml_response == "PHNhbWw+"
        ));
    }

    /// A browser that kept nothing never started this sign-on here: the
    /// answer may be someone else's, sent to it.
    #[test]
    fn a_return_to_a_browser_that_kept_nothing_is_refused() {
        let refused = command(
            SignInAction::SsoCallback,
            Fields::from_query(Some("state=st&code=co")),
            nothing(),
        );

        assert_eq!(refused.err(), Some(Unread::Missing("single_sign_on")));
    }

    #[test]
    fn a_passkey_request_without_a_ceremony_asks_for_a_challenge() {
        let command = command(
            SignInAction::Passkey,
            json(r#"{"email":"a@example.com"}"#),
            nothing(),
        );

        assert!(matches!(
            command,
            Ok(WireCommand::PasskeyBegin { email }) if email.as_deref() == Some("a@example.com")
        ));
    }

    #[test]
    fn a_passkey_answer_names_its_ceremony_and_carries_the_signed_bytes() {
        let ceremony = uuid::Uuid::now_v7();
        let body =
            format!(r#"{{"ceremony_id":"{ceremony}","credential_id":"AQID","response":"BAUG"}}"#);

        let command = command(SignInAction::Passkey, json(&body), nothing());

        let Ok(WireCommand::PasskeyConfirm {
            ceremony_id,
            credential_id,
            response,
            ..
        }) = command
        else {
            panic!("a passkey answer was not read as one");
        };
        assert_eq!(ceremony_id.as_uuid(), &ceremony);
        assert_eq!(credential_id, vec![1, 2, 3]);
        assert_eq!(response, vec![4, 5, 6]);
    }

    #[test]
    fn a_passkey_answer_that_is_not_base64url_is_refused() {
        let ceremony = uuid::Uuid::now_v7();
        let body =
            format!(r#"{{"ceremony_id":"{ceremony}","credential_id":"!!","response":"BAUG"}}"#);

        let refused = command(SignInAction::Passkey, json(&body), nothing());

        assert_eq!(refused.err(), Some(Unread::Malformed));
    }

    #[test]
    fn asking_for_a_new_password_reads_the_address() {
        let command = command(
            SignInAction::ForgotPassword,
            form("email=a%40example.com"),
            nothing(),
        );

        assert!(matches!(
            command,
            Ok(WireCommand::ForgotPassword { email }) if email == "a@example.com"
        ));
    }

    #[test]
    fn a_new_password_with_a_mailed_reset_token_resets_it() {
        let command = command(
            SignInAction::ResetPassword,
            form("token=reset&password=new&mfa_code=123456"),
            with_challenge(),
        );

        assert!(matches!(
            command,
            Ok(WireCommand::ResetPassword { token, mfa_code, .. })
                if token == "reset" && mfa_code.as_deref() == Some("123456")
        ));
    }

    /// A new password at the reset address without a mailed reset link is
    /// refused, whatever challenge the browser holds: the change a sign-in
    /// owes has an address of its own.
    #[test]
    fn a_reset_without_its_link_is_refused_even_with_a_challenge() {
        let refused = command(
            SignInAction::ResetPassword,
            form("password=new"),
            with_challenge(),
        );

        assert_eq!(refused.err(), Some(Unread::Missing("token")));
    }

    /// Ann's password was set by an administrator. Signing in left the
    /// change's token in her challenge cookie; she types a new password and
    /// a code from her own factor.
    #[test]
    fn a_new_password_in_a_waiting_sign_in_is_the_change_it_owes() {
        let command = command(
            SignInAction::ChangePassword,
            form("password=new&mfa_code=123456&return_to=%2Forders"),
            with_challenge(),
        );

        let Ok(WireCommand::ChangePassword {
            challenge,
            password,
            mfa_code,
            return_to,
            ..
        }) = command
        else {
            panic!("a password change was not read as one");
        };
        assert_eq!(challenge, "chal");
        assert_eq!(password, "new");
        assert_eq!(mfa_code.as_deref(), Some("123456"));
        assert_eq!(return_to.as_deref(), Some("/orders"));
    }

    #[test]
    fn a_change_from_a_mailed_change_link_uses_its_token() {
        let command = command(
            SignInAction::ChangePassword,
            json(r#"{"token":"mailed","password":"new"}"#),
            nothing(),
        );

        assert!(matches!(
            command,
            Ok(WireCommand::ChangePassword { challenge, mfa_code: None, .. })
                if challenge == "mailed"
        ));
    }

    #[test]
    fn a_new_password_with_nothing_to_set_it_by_is_refused() {
        for action in [SignInAction::ResetPassword, SignInAction::ChangePassword] {
            let refused = command(action, form("password=new"), nothing());

            assert_eq!(refused.err(), Some(Unread::Missing("token")), "{action:?}");
        }
    }

    /// The other host sends the browser to the owner's host to fetch a
    /// hop's code: it names the host and the digest of its hop cookie, and
    /// the session cookie goes along.
    #[test]
    fn a_hop_code_is_asked_for_a_host_with_the_browsers_digest() {
        let fields = Fields::from_query(Some("host=api.example.com&browser=d1g35t"));

        let command = hop_code_command(&fields, Some("tok".to_owned()));

        assert!(matches!(
            command,
            Ok(WireCommand::IssueHop { session, host, browser })
                if session.as_deref() == Some("tok")
                    && host.as_str() == "api.example.com"
                    && browser == "d1g35t"
        ));
    }

    #[test]
    fn a_hop_code_without_a_host_or_digest_is_refused() {
        let no_digest = Fields::from_query(Some("host=api.example.com"));
        let no_host = Fields::from_query(Some("browser=d1g35t"));
        let bad_host = Fields::from_query(Some("host=not%20a%20host&browser=d1g35t"));

        assert_eq!(
            hop_code_command(&no_digest, None).err(),
            Some(Unread::Missing("browser"))
        );
        assert_eq!(
            hop_code_command(&no_host, None).err(),
            Some(Unread::Missing("host"))
        );
        assert_eq!(
            hop_code_command(&bad_host, None).err(),
            Some(Unread::Malformed)
        );
    }

    #[test]
    fn a_token_names_its_audience_and_carries_the_session_cookie() {
        let command = token_command(json(r#"{"audience":"shop-api"}"#), Some("tok".to_owned()));

        assert!(matches!(
            command,
            Ok(WireCommand::IssueToken { session, audience })
                if audience == "shop-api" && session.as_deref() == Some("tok")
        ));
    }

    #[test]
    fn a_token_needs_an_audience() {
        assert_eq!(
            token_command(json("{}"), None).err(),
            Some(Unread::Missing("audience"))
        );
    }

    #[test]
    fn a_page_reads_its_note_and_return_path_from_the_query() {
        let command = page_command(
            SignInAction::LogIn,
            Fields::from_query(Some("error=not_found&return_to=%2Forders")),
        );

        let Some(WireCommand::ShowPage {
            page,
            note,
            return_to,
            token,
        }) = command
        else {
            panic!("a page was not read as one");
        };
        assert_eq!(page, WirePage::LogIn);
        assert_eq!(note.as_deref(), Some("not_found"));
        assert_eq!(return_to.as_deref(), Some("/orders"));
        assert_eq!(token, None);
    }

    #[test]
    fn a_page_reads_a_flag_as_its_note() {
        let command = page_command(
            SignInAction::LogIn,
            Fields::from_query(Some("password_reset=1")),
        );

        assert!(matches!(
            command,
            Some(WireCommand::ShowPage { note, .. }) if note.as_deref() == Some("password_reset")
        ));
    }

    /// The reset and change pages carry the mailed link's token into their
    /// form; no other page takes one.
    #[test]
    fn only_the_reset_and_change_pages_carry_the_mailed_token() {
        let reset = page_command(
            SignInAction::ResetPassword,
            Fields::from_query(Some("token=reset")),
        );
        let change = page_command(
            SignInAction::ChangePassword,
            Fields::from_query(Some("token=change")),
        );
        let log_in = page_command(SignInAction::LogIn, Fields::from_query(Some("token=reset")));

        assert!(matches!(
            reset,
            Some(WireCommand::ShowPage { page: WirePage::ResetPassword, token, .. })
                if token.as_deref() == Some("reset")
        ));
        assert!(matches!(
            change,
            Some(WireCommand::ShowPage { page: WirePage::ChangePassword, token, .. })
                if token.as_deref() == Some("change")
        ));
        assert!(matches!(
            log_in,
            Some(WireCommand::ShowPage { token: None, .. })
        ));
    }

    /// A sign-in sent to change its password lands on the change page,
    /// which says why.
    #[test]
    fn the_change_page_reads_its_flag_as_its_note() {
        let command = page_command(
            SignInAction::ChangePassword,
            Fields::from_query(Some("password_change_required=1")),
        );

        assert!(matches!(
            command,
            Some(WireCommand::ShowPage { note, .. })
                if note.as_deref() == Some("password_change_required")
        ));
    }

    #[test]
    fn actions_a_person_does_not_fill_in_have_no_page() {
        for action in [
            SignInAction::Verify,
            SignInAction::ConfirmSignIn,
            SignInAction::LogOut,
            SignInAction::Sso,
            SignInAction::SsoCallback,
            SignInAction::Passkey,
        ] {
            assert!(
                page_command(action, Fields::from_query(None)).is_none(),
                "{action:?}"
            );
        }
    }
}
