//! Messages held for their recipients until a test asks for them.
//!
//! One task owns every message and every waiting question, and both a
//! delivery and a question are orders sent to it over a bounded channel,
//! so nothing is shared behind a lock. A question that gave up waiting
//! leaves its message for the next one: a message is never lost to a
//! caller that stopped listening.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

/// How many orders may wait for the owning task at once.
const ORDERS: usize = 256;

/// What the owning task is told.
enum Order<M> {
    /// Hold `message` for `to`, or hand it to whoever waits for it.
    Deliver {
        /// The recipient, as [`key`] writes it.
        to: String,
        /// Payload retained until a listener for this recipient accepts it.
        message: M,
    },
    /// Answer the next message for `to`, now or once it comes.
    Ask {
        /// The recipient, as [`key`] writes it.
        to: String,
        /// Where the message goes.
        reply: oneshot::Sender<M>,
    },
}

/// A handle on the messages held for their recipients. Every clone
/// reaches the same messages.
pub(crate) struct Inbox<M> {
    orders: mpsc::Sender<Order<M>>,
}

impl<M> Clone for Inbox<M> {
    fn clone(&self) -> Self {
        Self {
            orders: self.orders.clone(),
        }
    }
}

impl<M: Send + 'static> Inbox<M> {
    /// An empty inbox, its owning task running until every handle is
    /// dropped.
    pub(crate) fn open() -> Self {
        let (orders, received) = mpsc::channel(ORDERS);
        tokio::spawn(run(received));
        Self { orders }
    }

    /// Holds `message` for `to`. Answers `false` once the inbox is gone.
    pub(crate) async fn deliver(&self, to: &str, message: M) -> bool {
        let order = Order::Deliver {
            to: key(to),
            message,
        };
        self.orders.send(order).await.is_ok()
    }

    /// The next message for `to`, waiting at most `within` for one to
    /// come, or `None` when none did.
    pub(crate) async fn next_for(&self, to: &str, within: Duration) -> Option<M> {
        let (reply, answer) = oneshot::channel();
        let order = Order::Ask { to: key(to), reply };
        self.orders.send(order).await.ok()?;
        tokio::time::timeout(within, answer).await.ok()?.ok()
    }
}

/// `recipient` as messages are filed under it: trimmed and in lowercase,
/// as mail addresses compare.
fn key(recipient: &str) -> String {
    recipient.trim().to_ascii_lowercase()
}

/// The messages and questions waiting, for the owning task.
struct Held<M> {
    messages: HashMap<String, VecDeque<M>>,
    questions: HashMap<String, VecDeque<oneshot::Sender<M>>>,
}

/// Runs the owning task: carries out every order until every handle is
/// dropped.
async fn run<M>(mut orders: mpsc::Receiver<Order<M>>) {
    let mut held = Held {
        messages: HashMap::new(),
        questions: HashMap::new(),
    };
    while let Some(order) = orders.recv().await {
        match order {
            Order::Deliver { to, message } => held.deliver(to, message),
            Order::Ask { to, reply } => held.answer(to, reply),
        }
    }
}

impl<M> Held<M> {
    /// Hands `message` to the first question for `to` still waiting, or
    /// holds it.
    fn deliver(&mut self, to: String, message: M) {
        let questions = self.questions.entry(to.clone()).or_default();
        let Some(unclaimed) = answered_first(questions, message) else {
            return;
        };
        self.messages.entry(to).or_default().push_back(unclaimed);
    }

    /// Answers `reply` with the oldest message held for `to`, or keeps the
    /// question until one comes.
    fn answer(&mut self, to: String, reply: oneshot::Sender<M>) {
        let oldest = self.messages.get_mut(&to).and_then(VecDeque::pop_front);
        let Some(message) = oldest else {
            self.questions.entry(to).or_default().push_back(reply);
            return;
        };
        let Err(unclaimed) = reply.send(message) else {
            return;
        };
        self.messages.entry(to).or_default().push_front(unclaimed);
    }
}

/// Hands `message` to the first of `questions` still listening, or answers
/// it back when nobody is.
fn answered_first<M>(questions: &mut VecDeque<oneshot::Sender<M>>, mut message: M) -> Option<M> {
    while let Some(reply) = questions.pop_front() {
        let Err(unclaimed) = reply.send(message) else {
            return None;
        };
        message = unclaimed;
    }
    Some(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHORT: Duration = Duration::from_millis(200);

    /// A message delivered before anyone asks is held for its recipient.
    #[tokio::test]
    async fn a_message_delivered_first_is_held_for_its_recipient() {
        let inbox = Inbox::open();

        inbox.deliver("ann@example.test", 1).await;

        assert_eq!(inbox.next_for("Ann@Example.test", SHORT).await, Some(1));
    }

    /// A question asked first is answered once the message comes.
    #[tokio::test]
    async fn a_question_asked_first_is_answered_when_the_message_comes() {
        let inbox = Inbox::open();
        let asking = inbox.clone();
        let waiting =
            tokio::spawn(async move { asking.next_for("ann@example.test", SHORT * 5).await });

        inbox.deliver("ann@example.test", 7).await;

        assert_eq!(waiting.await.unwrap(), Some(7));
    }

    /// Another recipient's message is never handed out.
    #[tokio::test]
    async fn another_recipients_message_is_never_handed_out() {
        let inbox = Inbox::open();

        inbox.deliver("bob@example.test", 1).await;

        assert_eq!(inbox.next_for("ann@example.test", SHORT).await, None);
    }

    /// A question that gave up leaves the message for the next one.
    #[tokio::test]
    async fn a_question_that_gave_up_leaves_the_message_for_the_next() {
        let inbox = Inbox::open();
        assert_eq!(inbox.next_for("ann@example.test", SHORT).await, None);

        inbox.deliver("ann@example.test", 3).await;

        assert_eq!(inbox.next_for("ann@example.test", SHORT).await, Some(3));
    }
}
