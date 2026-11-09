//! The pages the gateway shows a browser, drawn from the platform's
//! templates under `templates/pages/`: the sign-in pages of an app's host
//! and the page of a refused or failed request.
//!
//! The engine and its rules are the mail's. Values are inert data: the
//! engine never reads a value as template code, and every value printed is
//! escaped, so markup in a workspace's name is shown, not run. A value a
//! template needs and was not given fails the render rather than leaving a
//! gap. No template holds a script of its own: the login page only names,
//! by its address, the one script the gateway serves itself for passkeys,
//! and the gateway serves every page under a policy that runs nothing else.

mod error;
mod look;
mod sign_in;

use std::collections::HashMap;

use ianua_app::ports::pages::{DrawnPage, ErrorPage, PageRenderer, SignInPage};
use ianua_app::ports::shared::PreferredLanguages;
use ianua_domain::shared::errors::DomainError;
use minijinja::value::Value;
use minijinja::{AutoEscape, Environment, UndefinedBehavior};

use crate::language::Language;

/// Every page template under the folder `root`, by the name it is kept under.
macro_rules! page_templates {
    ($root:literal) => {
        [
            ("layout.html", include_str!(concat!($root, "/layout.html"))),
            ("error.html", include_str!(concat!($root, "/error.html"))),
            (
                "error_texts.html",
                include_str!(concat!($root, "/error_texts.html")),
            ),
            (
                "sign_in/parts.html",
                include_str!(concat!($root, "/sign_in/parts.html")),
            ),
            (
                "sign_in/log_in.html",
                include_str!(concat!($root, "/sign_in/log_in.html")),
            ),
            (
                "sign_in/sign_up.html",
                include_str!(concat!($root, "/sign_in/sign_up.html")),
            ),
            (
                "sign_in/mfa.html",
                include_str!(concat!($root, "/sign_in/mfa.html")),
            ),
            (
                "sign_in/forgot_password.html",
                include_str!(concat!($root, "/sign_in/forgot_password.html")),
            ),
            (
                "sign_in/reset_password.html",
                include_str!(concat!($root, "/sign_in/reset_password.html")),
            ),
            (
                "sign_in/change_password.html",
                include_str!(concat!($root, "/sign_in/change_password.html")),
            ),
        ]
    };
}

/// One language's page templates, by the name each is kept under.
type Templates = [(&'static str, &'static str); 10];

/// The page templates written in `language`: the platform's own for
/// English, the generated translations for every other language.
fn templates_of(language: Language) -> Templates {
    match language {
        Language::English => page_templates!("../../templates/pages"),
        Language::German => page_templates!("../../locales/de/templates/pages"),
        Language::Spanish => page_templates!("../../locales/es/templates/pages"),
        Language::French => page_templates!("../../locales/fr/templates/pages"),
        Language::Japanese => page_templates!("../../locales/ja/templates/pages"),
        Language::Georgian => page_templates!("../../locales/ka/templates/pages"),
        Language::Ukrainian => page_templates!("../../locales/uk/templates/pages"),
        Language::SimplifiedChinese => page_templates!("../../locales/zh-Hans/templates/pages"),
    }
}

/// Draws the gateway's pages from the platform's templates, in the first
/// language the person reads that the platform ships.
#[derive(Debug)]
pub struct TemplatePageRenderer {
    engines: HashMap<Language, Environment<'static>>,
}

impl TemplatePageRenderer {
    /// A renderer with every page template of every language loaded and checked.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a template does not
    /// parse, which a test of every page rules out.
    pub fn new() -> Result<Self, DomainError> {
        let engines = Language::ALL
            .into_iter()
            .map(|language| Ok((language, environment(language)?)))
            .collect::<Result<_, DomainError>>()?;
        Ok(Self { engines })
    }

    /// The template `name` in the reader's language, filled with `values`.
    fn draw(
        &self,
        name: &str,
        languages: &PreferredLanguages,
        values: Value,
    ) -> Result<DrawnPage, DomainError> {
        let language = Language::first_shipped(languages.tags());
        self.engines
            .get(&language)
            .ok_or_else(|| DomainError::infra_msg("the pages are not loaded in this language"))?
            .get_template(name)
            .and_then(|template| template.render(values))
            .map(DrawnPage::new)
            .map_err(DomainError::infra)
    }
}

impl PageRenderer for TemplatePageRenderer {
    fn sign_in_page(&self, page: &SignInPage) -> Result<DrawnPage, DomainError> {
        self.draw(
            sign_in::template_of(page.action)?,
            &page.languages,
            sign_in::context_of(page),
        )
    }

    fn error_page(&self, page: &ErrorPage) -> Result<DrawnPage, DomainError> {
        self.draw(error::TEMPLATE, &page.languages, error::context_of(page))
    }
}

/// The engine the pages in `language` are drawn in: every template loaded
/// and parsed, every value escaped as HTML, undefined values refused.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a template does not parse.
fn environment(language: Language) -> Result<Environment<'static>, DomainError> {
    let mut engine = Environment::new();
    engine.set_undefined_behavior(UndefinedBehavior::Strict);
    engine.set_auto_escape_callback(|_| AutoEscape::Html);
    for (name, source) in templates_of(language) {
        engine
            .add_template(name, source)
            .map_err(DomainError::infra)?;
    }
    Ok(engine)
}

#[cfg(test)]
mod tests {
    use ianua_app::ports::pages::{ErrorBranding, ErrorPageKind, Refusal, SignInNote, SsoChoice};
    use ianua_domain::domains::branding::config::{CustomCss, TenantBranding, TenantBrandingRow};
    use ianua_domain::domains::routing::sign_in::app::{SignInAction, SignInPath};
    use ianua_domain::domains::routing::sign_in::return_path::ReturnPath;
    use ianua_domain::isolation::scope::{ResolvedTenant, TenantScope};
    use ianua_domain::shared::config::DisplayNameLimits;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{
        ConnectionId, CorrelationId, DisplayName, HexColor, HttpsUrl, Label, RawCss, SanitizedCss,
        Setting,
    };
    use minijinja::context;

    use super::*;
    use crate::pages::look::{DEFAULT_BACKGROUND, DEFAULT_PRIMARY};

    /// A hostile value: markup that would run a script, and template code
    /// that would be worked out.
    const HOSTILE: &str = "<img src=x onerror=alert(1)> {{ 7 * 7 }}";

    /// The steps the gateway draws a page of.
    const PAGED: [SignInAction; 6] = [
        SignInAction::LogIn,
        SignInAction::SignUp,
        SignInAction::Mfa,
        SignInAction::ForgotPassword,
        SignInAction::ResetPassword,
        SignInAction::ChangePassword,
    ];

    fn renderer() -> TemplatePageRenderer {
        TemplatePageRenderer::new().unwrap()
    }

    fn path(value: &str) -> SignInPath {
        SignInPath::new(value).unwrap()
    }

    /// A page for the Acme workspace at this step, with sign-up on and no
    /// branding, note or return path.
    fn page(action: SignInAction) -> SignInPage {
        SignInPage {
            action,
            workspace: "Acme".to_owned(),
            branding: None,
            form_path: path("/.ianua/login"),
            log_in_path: path("/.ianua/login"),
            sign_up_path: Some(path("/.ianua/signup")),
            forgot_password_path: None,
            passkey_path: None,
            passkey_script_path: None,
            sso_path: path("/.ianua/sso"),
            single_sign_on: Vec::new(),
            note: None,
            return_to: None,
            link_token: None,
            languages: PreferredLanguages::default(),
        }
    }

    fn drawn(page: &SignInPage) -> String {
        renderer().sign_in_page(page).unwrap().into_html()
    }

    /// Acme's branding: its logo, a deep blue, a white background and a
    /// rule of its own.
    fn acme_branding<T: TenantScope>() -> TenantBranding<T> {
        TenantBranding::reconstitute(TenantBrandingRow {
            logo_url: Setting::Set(HttpsUrl::new("https://acme.test/logo.png").unwrap()),
            primary_color: Setting::Set(HexColor::new("#1A237E").unwrap()),
            background_color: Setting::Set(HexColor::new("#FFFFFF").unwrap()),
            custom_css: Setting::Set(CustomCss::new(
                RawCss::new("main > h1 { color: red }").unwrap(),
                SanitizedCss::new("main > h1 { color: red }").unwrap(),
            )),
            email_from_name: Setting::Unset,
            email_from_address: Setting::Unset,
        })
        .unwrap()
    }

    fn error_page(kind: ErrorPageKind) -> ErrorPage {
        ErrorPage::new(kind, CorrelationId::new())
    }

    fn drawn_error(page: &ErrorPage) -> String {
        renderer().error_page(page).unwrap().into_html()
    }

    fn acme_name(name: &str) -> DisplayName {
        DisplayName::new(name, &DisplayNameLimits::default()).unwrap()
    }

    fn reading(tags: &[&str]) -> PreferredLanguages {
        PreferredLanguages::new(tags.iter().map(|tag| (*tag).to_owned()).collect())
    }

    /// Ann's browser asks for German. Every page is drawn in German, in
    /// every shipped language the same way, with the same form.
    #[test]
    fn every_page_is_drawn_in_every_shipped_language() {
        for language in Language::ALL {
            for action in PAGED {
                let html = drawn(&SignInPage {
                    link_token: Some(Secret::new("t")),
                    languages: reading(&[language.tag()]),
                    ..page(action)
                });
                let tag = language.tag();
                assert!(
                    html.contains(&format!("<html lang=\"{tag}\">")),
                    "{action:?} {tag}"
                );
                assert!(html.contains("<form method=\"post\""), "{action:?} {tag}");
            }
            let error = drawn_error(&ErrorPage {
                languages: reading(&[language.tag()]),
                ..error_page(ErrorPageKind::NotFound)
            });
            assert!(error.contains(&format!("lang=\"{}\"", language.tag())));
        }
    }

    /// A browser asking for a language the platform does not ship, or for
    /// none, gets the English page.
    #[test]
    fn an_unshipped_language_gets_the_english_page() {
        let html = drawn(&SignInPage {
            languages: reading(&["it", "pt-BR"]),
            ..page(SignInAction::LogIn)
        });

        assert!(html.contains("<html lang=\"en\">"));
    }

    /// Every step with a page draws it from its template, a whole document
    /// with one heading and one style element, and no script.
    #[test]
    fn every_sign_in_page_is_drawn() {
        for action in PAGED {
            let html = drawn(&SignInPage {
                link_token: Some(Secret::new("t")),
                ..page(action)
            });

            assert!(html.starts_with("<!doctype html>"), "{action:?}");
            assert!(html.contains("<html lang=\"en\">"), "{action:?}");
            assert_eq!(html.matches("<h1>").count(), 1, "{action:?}");
            assert_eq!(html.matches("</style>").count(), 1, "{action:?}");
            assert!(!html.contains("<script"), "{action:?}");
        }
    }

    /// Workspace names containing markup and template expressions are escaped
    /// on sign-in pages without evaluating the expressions.
    #[test]
    fn a_hostile_workspace_name_is_printed_as_text() {
        for action in PAGED {
            let html = drawn(&SignInPage {
                workspace: HOSTILE.to_owned(),
                ..page(action)
            });

            assert!(!html.contains("<img src=x"), "{action:?}");
            assert!(html.contains("{{ 7 * 7 }}"), "{action:?}");
        }
        let login = drawn(&SignInPage {
            workspace: HOSTILE.to_owned(),
            ..page(SignInAction::LogIn)
        });
        assert!(login.contains("&lt;img src=x onerror=alert(1)&gt; {{ 7 * 7 }}"));
    }

    /// Requesting a page for a sign-in action without a template fails.
    #[test]
    fn a_step_without_a_page_is_refused() {
        for action in [
            SignInAction::Verify,
            SignInAction::ConfirmSignIn,
            SignInAction::LogOut,
            SignInAction::Sso,
            SignInAction::SsoCallback,
            SignInAction::Passkey,
        ] {
            let refused = renderer().sign_in_page(&page(action));

            assert!(
                matches!(refused, Err(DomainError::Infrastructure(_))),
                "{action:?}"
            );
        }
    }

    /// Ann opens the sign-in page: the form asks for her email and password,
    /// posts them to the page's address, and links to signing up.
    #[test]
    fn the_login_page_posts_email_and_password_to_its_address() {
        let html = drawn(&page(SignInAction::LogIn));

        assert!(html.contains("<form method=\"post\" action=\"&#x2f;.ianua&#x2f;login\">"));
        assert!(html.contains("name=\"email\""));
        assert!(html.contains("name=\"password\""));
        assert!(html.contains("<button type=\"submit\">Sign In</button>"));
        assert!(
            html.contains("New here? <a href=\"&#x2f;.ianua&#x2f;signup\">Create an account</a>")
        );
    }

    /// A workspace that takes no sign-ups shows no link to sign up.
    #[test]
    fn a_workspace_without_sign_up_offers_no_link_to_it() {
        let html = drawn(&SignInPage {
            sign_up_path: None,
            ..page(SignInAction::LogIn)
        });

        assert!(!html.contains("signup"));
        assert!(!html.contains("New here?"));
    }

    /// Ann forgot her password: the login page links to asking for a reset,
    /// and that page asks only for her address.
    #[test]
    fn the_forgot_page_asks_for_the_address_only() {
        let login = drawn(&SignInPage {
            forgot_password_path: Some(path("/.ianua/forgot")),
            ..page(SignInAction::LogIn)
        });
        let forgot = drawn(&SignInPage {
            form_path: path("/.ianua/forgot"),
            ..page(SignInAction::ForgotPassword)
        });

        assert!(
            login.contains(
                "Forgot your password? <a href=\"&#x2f;.ianua&#x2f;forgot\">Reset it</a>"
            )
        );
        assert!(forgot.contains("action=\"&#x2f;.ianua&#x2f;forgot\""));
        assert!(forgot.contains("name=\"email\""));
        assert!(!forgot.contains("name=\"password\""));
        assert!(forgot.contains("Remembered it?"));
    }

    /// The reset form carries the mailed link's token, hidden and escaped,
    /// with the new password and an optional code.
    #[test]
    fn the_reset_page_carries_the_link_token_in_its_form() {
        let html = drawn(&SignInPage {
            link_token: Some(Secret::new("tok\"en")),
            ..page(SignInAction::ResetPassword)
        });

        assert!(html.contains("type=\"hidden\" name=\"token\" value=\"tok&quot;en\""));
        assert!(html.contains("name=\"password\""));
        assert!(html.contains("name=\"mfa_code\""));
    }

    /// Ann's password was set by an administrator. The change page asks for
    /// a new password and an optional code, says why, and posts to the
    /// change address; opened in the browser that signed in, it carries no
    /// token, which rides in that browser's cookie.
    #[test]
    fn the_change_page_asks_for_a_new_password_and_says_why() {
        let html = drawn(&SignInPage {
            form_path: path("/.ianua/change-password"),
            note: Some(SignInNote::PasswordChangeRequired),
            ..page(SignInAction::ChangePassword)
        });

        assert!(html.contains("action=\"&#x2f;.ianua&#x2f;change-password\""));
        assert!(html.contains("name=\"password\""));
        assert!(html.contains("name=\"mfa_code\""));
        assert!(html.contains("it has to be changed first"));
        assert!(!html.contains("name=\"token\""));
    }

    /// Bob opens the mailed link to change his password: the change form
    /// carries the link's token, hidden.
    #[test]
    fn the_change_page_from_a_mailed_link_carries_its_token() {
        let html = drawn(&SignInPage {
            link_token: Some(Secret::new("change-token")),
            ..page(SignInAction::ChangePassword)
        });

        assert!(html.contains("type=\"hidden\" name=\"token\" value=\"change-token\""));
    }

    /// Ann's workspace signs in through its identity provider: the login
    /// page links to it by name, carrying the connection and where she was
    /// headed, and offers a passkey.
    #[test]
    fn the_login_page_offers_single_sign_on_and_a_passkey() {
        let connection = ConnectionId::new();
        let html = drawn(&SignInPage {
            single_sign_on: vec![SsoChoice {
                connection_id: connection,
                name: Label::new("name", "Okta").unwrap(),
            }],
            passkey_path: Some(path("/.ianua/passkey")),
            passkey_script_path: Some(path("/.ianua/passkey.js")),
            return_to: Some(ReturnPath::new("/orders?id=1").unwrap()),
            ..page(SignInAction::LogIn)
        });

        assert!(html.contains(&format!(
            "href=\"&#x2f;.ianua&#x2f;sso?connection_id={}&amp;return_to=&#x2f;orders%3Fid%3D1\"",
            connection.as_uuid()
        )));
        assert!(html.contains("Continue with Okta"));
        assert!(html.contains("data-address=\"&#x2f;.ianua&#x2f;passkey\""));
        assert!(html.contains("Sign in with a passkey"));
    }

    /// The login page offering a passkey names the gateway's script by its
    /// address, and holds no script of its own: nothing between the tags
    /// for the page's policy to have to allow.
    #[test]
    fn the_passkey_script_is_named_by_address_and_never_inline() {
        let html = drawn(&SignInPage {
            passkey_path: Some(path("/.ianua/passkey")),
            passkey_script_path: Some(path("/.ianua/passkey.js")),
            ..page(SignInAction::LogIn)
        });

        assert_eq!(html.matches("<script").count(), 1);
        assert!(html.contains("<script src=\"&#x2f;.ianua&#x2f;passkey.js\" defer></script>"));
        assert!(html.contains("id=\"passkey\""));
        assert!(html.contains(" hidden>Sign in with a passkey</button>"));
    }

    /// Single sign-on is offered on the login page alone.
    #[test]
    fn only_the_login_page_offers_single_sign_on() {
        let html = drawn(&SignInPage {
            single_sign_on: vec![SsoChoice {
                connection_id: ConnectionId::new(),
                name: Label::new("name", "Okta").unwrap(),
            }],
            ..page(SignInAction::SignUp)
        });

        assert!(!html.contains("Continue with Okta"));
    }

    /// Where Ann was headed goes along in the form, escaped so its quotes and
    /// ampersands stay inside the value.
    #[test]
    fn the_return_path_rides_in_the_form() {
        let html = drawn(&SignInPage {
            return_to: Some(ReturnPath::new("/orders?id=1&x=\"2\"").unwrap()),
            ..page(SignInAction::LogIn)
        });

        assert!(html.contains("value=\"&#x2f;orders?id=1&amp;x=&quot;2&quot;\""));
    }

    /// Ann types a wrong code: the page says the code was not accepted, not
    /// that her password was wrong, marked as a refusal, and asks for the
    /// code again.
    #[test]
    fn a_refused_second_factor_says_so_on_its_own_terms() {
        let html = drawn(&SignInPage {
            note: Some(SignInNote::Refused(Refusal::NotAccepted)),
            ..page(SignInAction::Mfa)
        });

        assert!(html.contains("class=\"note refused\""));
        assert!(html.contains("That code was not accepted."));
        assert!(!html.contains("email and password"));
        assert!(html.contains("autocomplete=\"one-time-code\" required autofocus"));
    }

    /// The second-factor page offers to remember the device, left unticked
    /// unless the person ticks it.
    #[test]
    fn the_second_factor_page_offers_to_remember_the_device() {
        let html = drawn(&page(SignInAction::Mfa));

        assert!(html.contains("name=\"remember_device\" type=\"checkbox\" value=\"yes\">"));
        assert!(!html.contains("checked"));
        assert!(html.contains("Remember this device"));
    }

    /// The same note reads as the step it is on: a mailed link on the
    /// forgot page is for a new password, on the sign-up page for the
    /// address.
    #[test]
    fn a_note_is_worded_for_its_page() {
        let forgot = drawn(&SignInPage {
            note: Some(SignInNote::CheckEmail),
            ..page(SignInAction::ForgotPassword)
        });
        let sign_up = drawn(&SignInPage {
            note: Some(SignInNote::CheckEmail),
            ..page(SignInAction::SignUp)
        });

        assert!(forgot.contains("a link to set a new password is on its way"));
        assert!(sign_up.contains("If this address can sign up"));
        assert!(sign_up.contains("class=\"note\""));
    }

    /// Every note has words on every page, so none fails a page on its own.
    #[test]
    fn every_note_is_worded_on_every_page() {
        let refusals = [
            Refusal::NotAccepted,
            Refusal::Locked,
            Refusal::NotVerified,
            Refusal::TooMany,
            Refusal::NotAllowed,
            Refusal::Invalid,
            Refusal::LinkExpired,
            Refusal::CodeNeeded,
            Refusal::Unavailable,
            Refusal::Failed,
        ];
        let notes = [
            SignInNote::CheckEmail,
            SignInNote::Verified,
            SignInNote::PasswordReset,
            SignInNote::PasswordChangeRequired,
        ]
        .into_iter()
        .chain(refusals.map(SignInNote::Refused));

        for note in notes {
            for action in PAGED {
                let result = renderer().sign_in_page(&SignInPage {
                    note: Some(note),
                    link_token: Some(Secret::new("t")),
                    ..page(action)
                });
                assert!(result.is_ok(), "{note:?} on {action:?}: {:?}", result.err());
            }
        }
    }

    /// A workspace that never set its colours gets the platform's, and dark
    /// text on its green buttons.
    #[test]
    fn a_workspace_without_branding_wears_the_default_colours() {
        let html = drawn(&SignInPage {
            branding: Some(TenantBranding::default_branding()),
            ..page(SignInAction::LogIn)
        });

        assert!(html.contains(&format!("--primary: {DEFAULT_PRIMARY};")));
        assert!(html.contains(&format!("--background: {DEFAULT_BACKGROUND};")));
        assert!(html.contains("--on-primary: #000000;"));
        assert!(!html.contains("class=\"logo\""));
    }

    /// Acme's page wears its logo, colours and own rule; its deep blue
    /// buttons get light text, and its `>` selector stays CSS.
    #[test]
    fn a_branded_workspace_wears_its_look() {
        let html = drawn(&SignInPage {
            branding: Some(acme_branding()),
            ..page(SignInAction::LogIn)
        });

        assert!(html.contains("--primary: #1A237E;"));
        assert!(html.contains("--background: #FFFFFF;"));
        assert!(html.contains("--on-primary: #FFFFFF;"));
        assert!(html.contains("main > h1 { color: red }"));
        assert!(html.contains(
            "<img class=\"logo\" src=\"https:&#x2f;&#x2f;acme.test&#x2f;logo.png\" alt=\"Acme\">"
        ));
    }

    /// Every kind of error is drawn: its status, its title, its line of what
    /// to do and the reference, with no script.
    #[test]
    fn every_error_page_is_drawn() {
        for kind in ErrorPageKind::ALL {
            let page = error_page(kind);

            let html = drawn_error(&page);

            assert!(html.contains(&format!("Error {}", page.status)), "{kind:?}");
            assert!(
                html.contains(&format!("Reference: <code>{}</code>", page.reference)),
                "{kind:?}"
            );
            assert_eq!(html.matches("<h1>").count(), 1, "{kind:?}");
            assert!(!html.contains("<script"), "{kind:?}");
        }
    }

    /// Each kind has words of its own: no two kinds share a title.
    #[test]
    fn each_error_kind_has_its_own_title() {
        let titles: std::collections::HashSet<String> = ErrorPageKind::ALL
            .into_iter()
            .map(|kind| {
                let html = drawn_error(&error_page(kind));
                html.split("<h1>")
                    .nth(1)
                    .unwrap()
                    .split("</h1>")
                    .next()
                    .unwrap()
                    .to_owned()
            })
            .collect();

        assert_eq!(titles.len(), ErrorPageKind::ALL.len());
    }

    /// A refusal says what to do in plain words: a person denied access is
    /// told to ask their administrator with the reference.
    #[test]
    fn a_forbidden_page_says_what_to_do() {
        let html = drawn_error(&error_page(ErrorPageKind::Forbidden));

        assert!(html.contains("<h1>You do not have access</h1>"));
        assert!(html.contains("ask your administrator"));
        assert!(html.contains("Error 403"));
    }

    /// With no tenant known, the page wears the platform's look and no logo.
    #[test]
    fn an_unbranded_error_page_wears_the_default_colours() {
        let html = drawn_error(&error_page(ErrorPageKind::UpstreamDown));

        assert!(html.contains(&format!("--primary: {DEFAULT_PRIMARY};")));
        assert!(html.contains(&format!("--background: {DEFAULT_BACKGROUND};")));
        assert!(!html.contains("class=\"logo\""));
    }

    /// Acme's error page wears its logo, name and colours.
    #[test]
    fn a_branded_error_page_wears_the_tenants_look() {
        let branding = acme_branding::<ResolvedTenant>();
        let page = ErrorPage {
            branding: Some(ErrorBranding::of(acme_name("Acme"), &branding)),
            ..error_page(ErrorPageKind::NotFound)
        };

        let html = drawn_error(&page);

        assert!(html.contains("--primary: #1A237E;"));
        assert!(html.contains("--background: #FFFFFF;"));
        assert!(html.contains("alt=\"Acme\""));
        assert!(html.contains("<title>404 Page not found | Acme</title>"));
    }

    /// An error page escapes markup in the tenant's name and preserves its
    /// template expression as text.
    #[test]
    fn a_hostile_tenant_name_is_printed_as_text_on_an_error_page() {
        let page = ErrorPage {
            branding: Some(ErrorBranding {
                name: acme_name(HOSTILE),
                logo_url: None,
                primary_color: None,
                background_color: None,
            }),
            ..error_page(ErrorPageKind::Forbidden)
        };

        let html = drawn_error(&page);

        assert!(!html.contains("<img src=x"));
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt; {{ 7 * 7 }}"));
    }

    /// Invalid tenant colours fall back to the platform's colours without
    /// inserting the attempted CSS rule into the page.
    #[test]
    fn a_colour_that_is_not_a_colour_never_reaches_the_css() {
        let hostile = "#FFF;}body{display:none";
        let page = ErrorPage {
            branding: Some(ErrorBranding {
                name: acme_name("Acme"),
                logo_url: None,
                primary_color: HexColor::new(hostile).ok(),
                background_color: HexColor::new("red").ok(),
            }),
            ..error_page(ErrorPageKind::Forbidden)
        };

        let html = drawn_error(&page);

        assert!(!html.contains("display:none"));
        assert!(html.contains(&format!("--primary: {DEFAULT_PRIMARY};")));
        assert!(html.contains(&format!("--background: {DEFAULT_BACKGROUND};")));
    }

    /// An error page fails to render when required values are absent or its
    /// error kind is unknown.
    #[test]
    fn a_missing_value_fails_the_render() {
        let engine = renderer();
        let look = look::Look {
            name: "",
            logo_url: None,
            primary: None,
            background: None,
            custom_css: None,
        }
        .value();

        let english = PreferredLanguages::default();
        let missing = engine.draw(
            error::TEMPLATE,
            &english,
            context! { look => look.clone(), status => 403 },
        );
        let unknown = engine.draw(
            error::TEMPLATE,
            &english,
            context! { look => look, status => 403, kind => "teapot", reference => "r" },
        );

        assert!(matches!(missing, Err(DomainError::Infrastructure(_))));
        assert!(matches!(unknown, Err(DomainError::Infrastructure(_))));
    }

    /// Rendering a login template with only a workspace name fails because
    /// required values are absent.
    #[test]
    fn a_missing_sign_in_value_fails_the_render() {
        let result = renderer().draw(
            "sign_in/log_in.html",
            &PreferredLanguages::default(),
            context! { workspace => "Acme" },
        );

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }
}
