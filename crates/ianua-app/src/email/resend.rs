//! Asking for another copy of a link that arrived in an email.
//!
//! Every emailed token, verification, password reset, invitation, email
//! change, lands someone on a page that may find the link dead. Telling them
//! so is only half an answer; the other half is a way out, and that is a fresh
//! link sent to the same address.
//!
//! Each of those flows answers the request the same way, so the shape of the
//! answer lives here rather than being restated per flow: a wait, in seconds,
//! before another may be asked for.
//!
//! Keying a resend on the token rather than an address is what keeps it from
//! becoming an oracle. Only someone who was already sent a link can ask for
//! its replacement, and the replacement goes to the address the original went
//! to, never one supplied by the caller.
//!
//! [`ResendCooldown::enforce`] is needed only where the presented token
//! survives its own replacement. Password reset keeps the superseded row, so the same token
//! can be handed in twice and the wait has to be checked. Invitations and
//! email changes rewrite the token in place, so a second attempt with the old
//! one finds nothing at all, the wait is still reported, to tell a client how
//! long to hold the button down, but nothing needs to enforce it.

use ianua_domain::message;
use ianua_domain::shared::clock;
use time::{Duration, OffsetDateTime};

use crate::error::AppError;

/// How long a caller must wait between emails in any resend flow.
///
/// Slow enough that a stuck user is not sending themselves a stream of mail,
/// short enough that one who never received the first is not left waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResendCooldown(Duration);

impl ResendCooldown {
    /// A cooldown of `wait`; a negative one counts as none.
    #[must_use]
    pub fn new(wait: Duration) -> Self {
        Self(wait.max(Duration::ZERO))
    }

    /// The answer to a request that was accepted and has just sent mail.
    #[must_use]
    pub fn sent(self) -> TokenResent {
        TokenResent {
            retry_after_seconds: self.0.whole_seconds().unsigned_abs(),
        }
    }

    /// Refuses a resend that comes too soon after the last one.
    ///
    /// `last_sent_at` is when the mail this would replace went out. `None`
    /// means nothing has been sent yet, which no cooldown can be measured
    /// against.
    ///
    /// The refusal carries the seconds still to wait, so a client that
    /// ignored the countdown is told the same number a second time rather
    /// than a bare "too many requests" it has to guess at.
    ///
    /// # Errors
    ///
    /// - `AppError::TooManyRequests` if the cooldown has not yet elapsed.
    pub fn enforce(
        self,
        last_sent_at: Option<OffsetDateTime>,
        subject: &str,
    ) -> Result<(), AppError> {
        let Some(left) = self.left_after(last_sent_at) else {
            return Ok(());
        };

        Err(AppError::TooManyRequests(message!(
            "app-another-can-be-requested-in-seconds",
            format!(
                "another {subject} can be requested in {} seconds",
                left.whole_seconds().max(1)
            )
        )))
    }

    /// How long is still to wait after `last_sent_at`, or nothing once the
    /// wait is over or nothing was sent yet.
    ///
    /// For a resend that must answer the same whether it sent or not, and
    /// so holds back quietly instead of refusing.
    #[must_use]
    pub fn left_after(self, last_sent_at: Option<OffsetDateTime>) -> Option<Duration> {
        let waited = clock::now() - last_sent_at?;
        (waited < self.0).then(|| self.0 - waited)
    }
}

/// The outcome of asking for another email.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenResent {
    /// How long before another may be asked for. The client counts this down
    /// rather than guessing, so the wait it shows is the one enforced here.
    pub retry_after_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    const COOLDOWN_SECONDS: i64 = 60;

    fn enforce_cooldown(
        last_sent_at: Option<OffsetDateTime>,
        subject: &str,
    ) -> Result<(), AppError> {
        ResendCooldown::new(Duration::seconds(COOLDOWN_SECONDS)).enforce(last_sent_at, subject)
    }

    /// Ann asks for an email for the first time. Nothing was sent before, so
    /// she does not wait.
    #[test]
    fn a_first_request_has_nothing_to_wait_for() {
        assert!(enforce_cooldown(None, "email").is_ok());
    }

    /// Right after an email is sent, the answer tells Ann to wait the whole
    /// cooldown before asking again.
    #[test]
    fn a_sent_answer_names_the_whole_cooldown() {
        let resent = ResendCooldown::new(Duration::seconds(45)).sent();

        assert_eq!(resent.retry_after_seconds, 45);
    }

    /// With no cooldown set, Ann can ask again straight after an email was
    /// sent.
    #[test]
    fn a_zero_cooldown_lets_every_request_through() {
        let just_now = clock::now();

        assert!(
            ResendCooldown::new(Duration::ZERO)
                .enforce(Some(just_now), "email")
                .is_ok()
        );
    }

    /// A reset-link request one second after the last send is rate limited.
    #[test]
    fn a_request_inside_the_cooldown_is_refused() {
        let just_now = clock::now() - Duration::seconds(1);

        let result = enforce_cooldown(Some(just_now), "reset link");

        assert!(matches!(result, Err(AppError::TooManyRequests(_))));
    }

    /// The seconds named in a refusal.
    ///
    /// Read out of the message rather than compared against a literal: the
    /// remainder is truncated to whole seconds, so a test that pinned an exact
    /// number would sit on the boundary and fail whenever the clock landed a
    /// microsecond the other side of it.
    fn seconds_named_in(message: &str) -> i64 {
        message
            .split_whitespace()
            .find_map(|word| word.parse::<i64>().ok())
            .unwrap_or_else(|| panic!("no wait named in {message:?}"))
    }

    /// The refusal names the wait, so a client that lost the countdown does
    /// not have to guess at one.
    #[test]
    fn the_refusal_carries_the_seconds_still_to_wait() {
        let just_now = clock::now() - Duration::seconds(1);

        let Err(AppError::TooManyRequests(message)) =
            enforce_cooldown(Some(just_now), "reset link")
        else {
            panic!("a request inside the cooldown must be refused");
        };

        assert!(message.as_str().contains("reset link"), "{message}");
        let wait = seconds_named_in(message.as_str());
        assert!(
            (1..COOLDOWN_SECONDS).contains(&wait),
            "a second into the cooldown leaves most of it to run: {message}"
        );
    }

    /// Ann asks again once the cooldown has passed. She is let through.
    #[test]
    fn a_request_after_the_cooldown_is_allowed() {
        let long_ago = clock::now() - Duration::seconds(COOLDOWN_SECONDS + 1);

        assert!(enforce_cooldown(Some(long_ago), "email").is_ok());
    }

    /// Never zero: a countdown that starts at nothing tells the reader the
    /// button works, and it does not.
    #[test]
    fn the_wait_never_reports_as_zero_seconds() {
        let almost_over = clock::now() - Duration::milliseconds(COOLDOWN_SECONDS * 1000 - 200);

        let Err(AppError::TooManyRequests(message)) = enforce_cooldown(Some(almost_over), "email")
        else {
            panic!("still inside the cooldown");
        };

        assert_eq!(
            seconds_named_in(message.as_str()),
            1,
            "under a second left rounds down to nothing, and is reported as one: {message}"
        );
    }
}
