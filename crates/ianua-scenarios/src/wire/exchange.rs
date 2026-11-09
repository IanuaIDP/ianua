//! One request and its answer as a failed scenario prints them, with
//! every credential already taken out by the client that made it.

use std::fmt;

use crate::wire::Status;

/// The longest body printed; the rest is cut off.
const LONGEST_BODY: usize = 2048;

/// A request and the answer to it, redacted: no `Authorization`, cookie,
/// token, password, secret or code is ever held here.
#[derive(Clone)]
pub struct Exchange {
    actor: String,
    method: String,
    url: String,
    correlation_id: String,
    request_headers: Vec<(String, String)>,
    request_body: Option<String>,
    status: Status,
    response_headers: Vec<(String, String)>,
    response_body: String,
}

/// The request half of an [`Exchange`], redacted.
pub(crate) struct Sent {
    /// Who sent it.
    pub(crate) actor: String,
    /// HTTP verb printed with the redacted request URL on failure.
    pub(crate) method: String,
    /// Its address, the query's credentials taken out.
    pub(crate) url: String,
    /// The correlation id it carried.
    pub(crate) correlation_id: String,
    /// Its headers, credentials taken out.
    pub(crate) headers: Vec<(String, String)>,
    /// Its body, credentials taken out.
    pub(crate) body: Option<String>,
}

/// The answer half of an [`Exchange`], redacted.
pub(crate) struct Received {
    /// HTTP outcome printed beside the redacted response body.
    pub(crate) status: Status,
    /// Its headers, credentials taken out.
    pub(crate) headers: Vec<(String, String)>,
    /// Its body, credentials taken out.
    pub(crate) body: String,
}

impl Exchange {
    /// The exchange of `sent` and `received`.
    pub(crate) fn of(sent: Sent, received: Received) -> Self {
        Self {
            actor: sent.actor,
            method: sent.method,
            url: sent.url,
            correlation_id: sent.correlation_id,
            request_headers: sent.headers,
            request_body: sent.body,
            status: received.status,
            response_headers: received.headers,
            response_body: received.body,
        }
    }

    /// Who sent the request.
    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }

    /// The correlation id the request carried, to find it in the
    /// platform's logs.
    #[must_use]
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    /// The answer's body as text, credentials taken out.
    #[must_use]
    pub fn response_body(&self) -> &str {
        &self.response_body
    }

    /// The method and address, as `GET https://…`.
    #[must_use]
    pub fn request_line(&self) -> String {
        format!("{} {}", self.method, self.url)
    }
}

impl fmt::Debug for Exchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for Exchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "  as {}, correlation id {}",
            self.actor, self.correlation_id
        )?;
        writeln!(f, "  > {} {}", self.method, self.url)?;
        for (name, value) in &self.request_headers {
            writeln!(f, "  > {name}: {value}")?;
        }
        if let Some(body) = &self.request_body {
            writeln!(f, "  > {}", cut(body))?;
        }
        writeln!(f, "  < {}", self.status)?;
        for (name, value) in &self.response_headers {
            writeln!(f, "  < {name}: {value}")?;
        }
        write!(f, "  < {}", cut(&self.response_body))
    }
}

/// `body` cut to the longest printed, on a character boundary.
fn cut(body: &str) -> String {
    if body.len() <= LONGEST_BODY {
        return body.to_owned();
    }
    let end = (0..=LONGEST_BODY)
        .rev()
        .find(|at| body.is_char_boundary(*at))
        .unwrap_or(0);
    format!("{}… ({} bytes)", &body[..end], body.len())
}
