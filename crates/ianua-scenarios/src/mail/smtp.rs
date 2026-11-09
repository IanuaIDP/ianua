//! The SMTP conversation the receiver holds with each client: greeting,
//! envelope, message, and the mail filed for each recipient.
//!
//! Lines and messages are bounded, and so are the conversations held at
//! once, so a client that misbehaves cannot make the receiver hold more
//! than a few megabytes.

use std::io;
use std::sync::Arc;

use ianua_boot::shutdown::Shutdown;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use super::{Mail, mime};
use crate::inbox::Inbox;

/// The name the receiver greets with.
const SERVER_NAME: &str = "mail.scenarios.test";

/// The longest command line taken, its line break included.
const LONGEST_LINE: u64 = 4096;

/// The largest message taken.
const LARGEST_MESSAGE: usize = 8 * 1024 * 1024;

/// The conversations held at once.
const CONVERSATIONS: usize = 16;

/// Takes connections on `listener` until `shutdown` stops it, holding each
/// conversation as a task of its own and filing each mail in `inbox`.
pub(super) fn serve(listener: TcpListener, inbox: Inbox<Mail>, shutdown: &Shutdown) {
    let tasks = shutdown.clone();
    shutdown.spawn_until_stopped(async move {
        let permits = Arc::new(Semaphore::new(CONVERSATIONS));
        loop {
            let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
                return;
            };
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let inbox = inbox.clone();
            tasks.spawn_until_stopped(async move {
                if let Err(error) = conversation(stream, &inbox).await {
                    tracing::debug!(%error, "an SMTP conversation ended early");
                }
                drop(permit);
            });
        }
    });
}

/// The envelope a client has given so far.
#[derive(Default)]
struct Envelope {
    sender: Option<String>,
    recipients: Vec<String>,
}

/// The socket halves and envelope of one SMTP conversation.
struct Conversation {
    lines: BufReader<OwnedReadHalf>,
    write: OwnedWriteHalf,
    envelope: Envelope,
}

impl Conversation {
    /// Replaces the envelope sender, discarding recipients from an earlier message.
    async fn sender(&mut self, sender: String) -> io::Result<()> {
        self.envelope = Envelope {
            sender: Some(sender),
            recipients: Vec::new(),
        };
        reply(&mut self.write, "250 OK").await
    }

    /// Reads and files a message before resetting its envelope and acknowledging it.
    async fn message(&mut self, inbox: &Inbox<Mail>) -> io::Result<()> {
        let taken = data(&mut self.lines, &mut self.write, &self.envelope).await?;
        file(inbox, &self.envelope, &taken).await;
        self.envelope = Envelope::default();
        reply(&mut self.write, "250 OK: queued").await
    }

    /// Answers one SMTP command and indicates whether the client ended the session.
    async fn command(&mut self, command: Command, inbox: &Inbox<Mail>) -> io::Result<bool> {
        match command {
            Command::Hello => {
                reply(
                    &mut self.write,
                    &format!("250-{SERVER_NAME}\r\n250 8BITMIME"),
                )
                .await?;
            }
            Command::Sender(sender) => self.sender(sender).await?,
            Command::Recipient(recipient) => {
                self.envelope.recipients.push(recipient);
                reply(&mut self.write, "250 OK").await?;
            }
            Command::Data => self.message(inbox).await?,
            Command::Reset => {
                self.envelope = Envelope::default();
                reply(&mut self.write, "250 OK").await?;
            }
            Command::Nothing => reply(&mut self.write, "250 OK").await?,
            Command::Quit => {
                reply(&mut self.write, &format!("221 {SERVER_NAME} closing")).await?;
                return Ok(true);
            }
            Command::Unknown => reply(&mut self.write, "502 command not implemented").await?,
        }
        Ok(false)
    }
}

/// What a command line asks for.
enum Command {
    Hello,
    Sender(String),
    Recipient(String),
    Data,
    Reset,
    Nothing,
    Quit,
    Unknown,
}

/// One client's whole conversation.
async fn conversation(stream: TcpStream, inbox: &Inbox<Mail>) -> io::Result<()> {
    let (read, mut write) = stream.into_split();
    reply(&mut write, &format!("220 {SERVER_NAME} ESMTP ready")).await?;
    let mut conversation = Conversation {
        lines: BufReader::new(read),
        write,
        envelope: Envelope::default(),
    };
    loop {
        let Some(line) = next_line(&mut conversation.lines).await? else {
            return Ok(());
        };
        if conversation.command(command_of(&line), inbox).await? {
            return Ok(());
        }
    }
}

/// The command `line` writes.
fn command_of(line: &str) -> Command {
    let upper = line.to_ascii_uppercase();
    let verb = upper.split_whitespace().next().unwrap_or("");
    match verb {
        "EHLO" | "HELO" => Command::Hello,
        "MAIL" => path_in(line).map_or(Command::Unknown, Command::Sender),
        "RCPT" => path_in(line).map_or(Command::Unknown, Command::Recipient),
        "DATA" => Command::Data,
        "RSET" => Command::Reset,
        "NOOP" => Command::Nothing,
        "QUIT" => Command::Quit,
        _ => Command::Unknown,
    }
}

/// The address between the angle brackets of `MAIL FROM:<…>` or
/// `RCPT TO:<…>`, any parameters after it left off.
fn path_in(line: &str) -> Option<String> {
    let (_, after) = line.split_once('<')?;
    let (address, _) = after.split_once('>')?;
    Some(address.trim().to_owned())
}

/// Takes the message after `DATA`, up to the line holding a lone dot, with
/// the dots RFC 5321 doubles at a line's start undone.
async fn data(
    lines: &mut BufReader<OwnedReadHalf>,
    write: &mut OwnedWriteHalf,
    envelope: &Envelope,
) -> io::Result<String> {
    if envelope.sender.is_none() || envelope.recipients.is_empty() {
        reply(write, "503 MAIL and RCPT come first").await?;
        return Err(io::Error::other("DATA before the envelope"));
    }
    reply(write, "354 end with <CRLF>.<CRLF>").await?;
    let mut message = String::new();
    loop {
        let Some(line) = next_line(lines).await? else {
            return Err(io::Error::other(
                "the client left in the middle of a message",
            ));
        };
        if line == "." {
            return Ok(message);
        }
        if message.len() + line.len() > LARGEST_MESSAGE {
            return Err(io::Error::other("the message is too large"));
        }
        message.push_str(line.strip_prefix('.').unwrap_or(&line));
        message.push_str("\r\n");
    }
}

/// Files `message` once for each recipient of `envelope`.
async fn file(inbox: &Inbox<Mail>, envelope: &Envelope, message: &str) {
    let decoded = mime::decoded(message);
    let sender = envelope.sender.clone().unwrap_or_default();
    for recipient in &envelope.recipients {
        let mail = Mail {
            sender: sender.clone(),
            recipient: recipient.clone(),
            subject: decoded.subject.clone(),
            text: decoded.text.clone(),
            html: decoded.html.clone(),
        };
        inbox.deliver(recipient, mail).await;
    }
}

/// The next line the client sent, its line break taken off, or `None` once
/// it closed the connection.
async fn next_line(lines: &mut BufReader<OwnedReadHalf>) -> io::Result<Option<String>> {
    let mut line = String::new();
    let read = (&mut *lines)
        .take(LONGEST_LINE)
        .read_line(&mut line)
        .await?;
    if read == 0 {
        return Ok(None);
    }
    if !line.ends_with('\n') {
        return Err(io::Error::other("a line too long, or cut off"));
    }
    Ok(Some(line.trim_end_matches(['\r', '\n']).to_owned()))
}

/// Writes one reply, its line break added.
async fn reply(write: &mut OwnedWriteHalf, text: &str) -> io::Result<()> {
    write.write_all(text.as_bytes()).await?;
    write.write_all(b"\r\n").await?;
    write.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The path is read from between the brackets, parameters left off.
    #[test]
    fn the_path_is_read_from_between_the_brackets() {
        assert_eq!(
            path_in("MAIL FROM:<noreply@s1.test> BODY=8BITMIME").as_deref(),
            Some("noreply@s1.test")
        );
        assert!(
            matches!(command_of("rcpt to:<ann@s1.test>"), Command::Recipient(to) if to == "ann@s1.test")
        );
    }
}
