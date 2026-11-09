//! The script and the record of what was asked, held by one task that
//! every connection asks over a bounded channel, so nothing is shared
//! behind a lock.

use tokio::sync::{mpsc, oneshot};

use super::Received;
use super::script::{Reply, Script, Turn};

/// How many questions may wait for the desk at once.
const QUESTIONS: usize = 64;

/// What the desk is asked.
enum Question {
    /// The reply to `received`, keeping it on record.
    Reply {
        /// The request.
        received: Received,
        /// Where the reply goes, `None` when no turn answers it.
        answer: oneshot::Sender<Option<Reply>>,
    },
    /// Everything received so far.
    Received(oneshot::Sender<Vec<Received>>),
    /// How many requests no turn answered.
    Unanswered(oneshot::Sender<usize>),
    /// How many turns were not given yet.
    TurnsLeft(oneshot::Sender<usize>),
}

/// A handle on the desk. Every clone reaches the same script.
#[derive(Clone)]
pub(super) struct Desk {
    questions: mpsc::Sender<Question>,
}

impl Desk {
    /// A desk answering from `script`, its task running until every
    /// handle is dropped.
    pub(super) fn open(script: Script) -> Self {
        let (questions, asked) = mpsc::channel(QUESTIONS);
        let kept = Kept {
            turns: script.into_turns().into_iter().map(Some).collect(),
            received: Vec::new(),
            unanswered: 0,
        };
        tokio::spawn(kept.run(asked));
        Self { questions }
    }

    /// The reply to `received`, or `None` when no turn answers it or the
    /// desk is gone.
    pub(super) async fn reply_to(&self, received: Received) -> Option<Reply> {
        let (answer, replied) = oneshot::channel();
        let question = Question::Reply { received, answer };
        self.questions.send(question).await.ok()?;
        replied.await.ok().flatten()
    }

    /// Everything received so far.
    pub(super) async fn received(&self) -> Vec<Received> {
        self.asked(Question::Received).await.unwrap_or_default()
    }

    /// How many requests no turn answered.
    pub(super) async fn unanswered(&self) -> usize {
        self.asked(Question::Unanswered).await.unwrap_or_default()
    }

    /// How many turns were not given yet.
    pub(super) async fn turns_left(&self) -> usize {
        self.asked(Question::TurnsLeft).await.unwrap_or_default()
    }

    /// The answer to the question `ask` makes of a reply channel.
    async fn asked<T>(&self, ask: impl FnOnce(oneshot::Sender<T>) -> Question) -> Option<T> {
        let (answer, replied) = oneshot::channel();
        self.questions.send(ask(answer)).await.ok()?;
        replied.await.ok()
    }
}

/// What the desk's task holds.
struct Kept {
    turns: Vec<Option<Turn>>,
    received: Vec<Received>,
    unanswered: usize,
}

impl Kept {
    /// Answers every question until every handle is dropped.
    async fn run(mut self, mut asked: mpsc::Receiver<Question>) {
        while let Some(question) = asked.recv().await {
            self.answer(question);
        }
    }

    /// Answers one question. A reply channel nobody listens on any more
    /// is let go.
    fn answer(&mut self, question: Question) {
        match question {
            Question::Reply { received, answer } => {
                let reply = self.next_turn(&received);
                self.received.push(received);
                let _ignored = answer.send(reply);
            }
            Question::Received(answer) => {
                let _ignored = answer.send(self.received.clone());
            }
            Question::Unanswered(answer) => {
                let _ignored = answer.send(self.unanswered);
            }
            Question::TurnsLeft(answer) => {
                let _ignored = answer.send(self.turns.iter().flatten().count());
            }
        }
    }

    /// The first turn not yet given that answers `received`, given now.
    fn next_turn(&mut self, received: &Received) -> Option<Reply> {
        let slot = self
            .turns
            .iter_mut()
            .find(|slot| slot.as_ref().is_some_and(|turn| turn.answers(received)));
        let Some(turn) = slot.and_then(Option::take) else {
            self.unanswered = self.unanswered.saturating_add(1);
            return None;
        };
        Some(turn.reply().clone())
    }
}
