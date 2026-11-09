//! One call made by a whole cast of actors, each with the answer it must
//! get, every mismatch reported at once.

use std::fmt;

use serde::de::IgnoredAny;

use crate::net::{Call, Client};
use crate::wire::{Answer, Exchange, Status};

/// The answer an actor must get.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Any success.
    Allowed,
    /// A refusal with this status and problem code.
    Refused {
        /// The HTTP status.
        status: Status,
        /// The problem's code, such as `unauthenticated`.
        code: String,
    },
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allowed => f.write_str("a success"),
            Self::Refused { status, code } => write!(f, "a refusal {status} {code}"),
        }
    }
}

impl Outcome {
    /// Whether `answer` is this outcome.
    fn matches<T>(&self, answer: &Answer<T>) -> bool {
        match self {
            Self::Allowed => answer.status().is_success(),
            Self::Refused { status, code } => {
                answer.status() == *status
                    && answer
                        .problem()
                        .is_some_and(|problem| problem.code() == code)
            }
        }
    }
}

/// One actor and the answer it must get.
struct Case<'a> {
    client: &'a Client,
    outcome: Outcome,
}

impl Case<'_> {
    /// Describes this actor's mismatch with the recorded request for diagnosis.
    fn mismatch<T>(&self, answer: &Answer<T>) -> String {
        format!(
            "- {} expected {}, got {} (correlation id {})\n{}",
            self.client.actor(),
            self.outcome,
            answer.summary(),
            answer.correlation_id(),
            answer.exchange()
        )
    }
}

/// One call, made by every actor in turn, in the order they were added.
///
/// ```no_run
/// # async fn example(owner: &ianua_scenarios::net::Client, anonymous: &ianua_scenarios::net::Client) {
/// use ianua_scenarios::expect::Matrix;
/// use ianua_scenarios::net::Call;
/// use ianua_scenarios::wire::Status;
///
/// Matrix::new("reading the members", Call::get("/api/v1/organizations/acme/users"))
///     .allowed(owner)
///     .refused(anonymous, Status::UNAUTHORIZED, "unauthenticated")
///     .run()
///     .await;
/// # }
/// ```
pub struct Matrix<'a> {
    what: String,
    call: Call,
    cases: Vec<Case<'a>>,
}

impl<'a> Matrix<'a> {
    /// A matrix of `call`, described as `what` in its failure.
    #[must_use]
    pub fn new(what: &str, call: Call) -> Self {
        Self {
            what: what.to_owned(),
            call,
            cases: Vec::new(),
        }
    }

    /// `client`'s actor must succeed.
    #[must_use]
    pub fn allowed(self, client: &'a Client) -> Self {
        self.expecting(client, Outcome::Allowed)
    }

    /// `client`'s actor must be refused with `status` and `code`.
    #[must_use]
    pub fn refused(self, client: &'a Client, status: Status, code: &str) -> Self {
        let outcome = Outcome::Refused {
            status,
            code: code.to_owned(),
        };
        self.expecting(client, outcome)
    }

    /// `client`'s actor must get `outcome`.
    #[must_use]
    pub fn expecting(mut self, client: &'a Client, outcome: Outcome) -> Self {
        self.cases.push(Case { client, outcome });
        self
    }

    /// Makes the call as every actor, then fails once, naming every actor
    /// that got another answer than it must. Answers every exchange, in
    /// the order the actors were added, for the step to check further,
    /// such as for a secret in an answer.
    ///
    /// # Panics
    ///
    /// When any actor got another answer, or the matrix has no actor.
    pub async fn run(self) -> Vec<Exchange> {
        assert!(
            !self.cases.is_empty(),
            "the matrix for {} names no actor",
            self.what
        );
        let mut mismatches = Vec::new();
        let mut exchanges = Vec::with_capacity(self.cases.len());
        for case in &self.cases {
            let answer: Answer<IgnoredAny> = case.client.send(self.call.clone()).await;
            exchanges.push(answer.exchange().clone());
            if case.outcome.matches(&answer) {
                continue;
            }
            mismatches.push(case.mismatch(&answer));
        }
        assert!(
            mismatches.is_empty(),
            "{}: {} of {} actors got another answer\n{}",
            self.what,
            mismatches.len(),
            self.cases.len(),
            mismatches.join("\n")
        );
        exchanges
    }
}
