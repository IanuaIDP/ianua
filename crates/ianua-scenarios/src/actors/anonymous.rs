//! Nobody signed in: a client with no token and no cookies, as anyone on
//! the internet reaches the platform.

use crate::net::Client;
use crate::stack::Stack;

/// Someone who never signed in.
#[derive(Debug)]
pub struct Anonymous {
    client: Client,
}

impl Anonymous {
    /// A client of their own on `stack`.
    ///
    /// # Panics
    ///
    /// When the client cannot be built.
    /// Client construction is a scenario prerequisite, so failure aborts setup.
    #[allow(clippy::expect_used)]
    #[must_use]
    pub fn new(stack: &Stack) -> Self {
        Self {
            client: Client::new(stack, "nobody signed in").expect("a client for nobody"),
        }
    }

    /// The client they act through.
    #[must_use]
    pub fn client(&self) -> &Client {
        &self.client
    }
}
