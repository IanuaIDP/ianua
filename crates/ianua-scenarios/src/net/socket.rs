//! A live stream over WebSocket, opened as the dashboard opens one: an
//! HTTP/1.1 upgrade through the ingress with the actor's own token and
//! address, then frames read as they come.
//!
//! Only what a stream's reader needs is spoken: the handshake and its
//! accept check, text messages from the platform (whole or in parts),
//! pings answered, and the close the platform sends with its code. The
//! client sends nothing but control frames, masked as the protocol asks.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use reqwest::Upgraded;
use sha1::{Digest as _, Sha1};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::{Call, Client, receive};
use crate::wire::{Answer, Status};

/// The value the accept header is worked out with, from RFC 6455.
const ACCEPT_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The largest message read, well above any notification the platform
/// sends; a larger one is read as a broken stream.
const LARGEST_MESSAGE: u64 = 1024 * 1024;

/// The opcode of a frame going on with the message before it.
const CONTINUATION: u8 = 0x0;
/// The opcode of a text message's first frame.
const TEXT: u8 = 0x1;
/// The opcode of a close.
const CLOSE: u8 = 0x8;
/// The opcode of a ping, answered with a pong.
const PING: u8 = 0x9;
/// The opcode of a pong.
const PONG: u8 = 0xA;

/// One frame as it arrived, its payload unmasked.
struct RawFrame {
    /// Whether it ends its message.
    finished: bool,
    /// What kind of frame it is.
    opcode: u8,
    /// What it carries.
    payload: Vec<u8>,
}

impl RawFrame {
    /// What a stream that broke off without a close reads as: a close
    /// with no code.
    fn broken_off() -> Self {
        Self {
            finished: true,
            opcode: CLOSE,
            payload: Vec::new(),
        }
    }
}

/// What opening a stream came to.
pub enum Opened {
    /// The platform switched protocols: the stream is open.
    Open(Socket),
    /// The platform answered the handshake with a refusal, read as the
    /// API's problem.
    Refused(Box<Answer<()>>),
}

impl Opened {
    /// The open stream.
    ///
    /// # Panics
    ///
    /// When the platform refused it, naming the refusal.
    #[must_use]
    pub fn open(self) -> Socket {
        match self {
            Self::Open(socket) => socket,
            Self::Refused(answer) => panic!("the stream was refused: {}", answer.summary()),
        }
    }

    /// The refusal.
    ///
    /// # Panics
    ///
    /// When the stream opened after all.
    #[must_use]
    pub fn refusal(self) -> Answer<()> {
        match self {
            Self::Open(_) => panic!("the stream opened, though it should have been refused"),
            Self::Refused(answer) => *answer,
        }
    }
}

/// One thing a stream gave its reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// A whole text message.
    Text(String),
    /// The platform closed the stream, with its close code when it sent
    /// one.
    Closed(Option<u16>),
}

/// An open stream.
pub struct Socket {
    io: Upgraded,
}

impl std::fmt::Debug for Socket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socket").finish_non_exhaustive()
    }
}

impl Client {
    /// Opens the live stream at `path` as this actor, with their token
    /// and address, as the dashboard's browser opens one.
    ///
    /// # Panics
    ///
    /// When no answer comes, which means the stack is down, or the
    /// platform switches protocols without proving it read the handshake.
    pub async fn open_socket(&self, path: &str) -> Opened {
        self.open_socket_by(Call::get(path)).await
    }

    /// Asks to open a WebSocket with `call`, for a caller that proves
    /// itself with a header of its own, such as a partner's key.
    ///
    /// # Panics
    ///
    /// As [`open_socket`](Self::open_socket).
    pub async fn open_socket_by(&self, call: Call) -> Opened {
        let key = STANDARD.encode(rand::random::<[u8; 16]>());
        let call = handshake(call, &key);
        let url = self.url_of(&call.path);
        let correlation_id = uuid::Uuid::now_v7().to_string();
        let request = self.request(&call, &url, &correlation_id);
        let sent = self.sent(&call, &url, correlation_id);
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => panic!(
                "opening {} as {} got no answer: {error}",
                sent.url, sent.actor
            ),
        };
        if response.status() != Status::SWITCHING_PROTOCOLS {
            return match receive(response, sent).await {
                Ok(arrived) => Opened::Refused(Box::new(Answer::read(arrived))),
                Err(why) => panic!("{why}"),
            };
        }
        Opened::Open(accepted(response, &key).await)
    }
}

impl Socket {
    /// The next thing the stream gives, waiting at most `patience`; `None`
    /// when nothing came in that time. A ping is answered on the way.
    ///
    /// # Panics
    ///
    /// When the stream breaks off without a close, or sends a frame no
    /// stream of the platform sends.
    pub async fn next_within(&mut self, patience: Duration) -> Option<Frame> {
        tokio::time::timeout(patience, self.next_frame()).await.ok()
    }

    /// Every text message the stream gives until it has been quiet for
    /// `quiet`, or until it closes.
    pub async fn texts_until_quiet(&mut self, quiet: Duration) -> Vec<String> {
        let mut texts = Vec::new();
        while let Some(Frame::Text(text)) = self.next_within(quiet).await {
            texts.push(text);
        }
        texts
    }

    /// Sends `text` as one short message, masked as a client's must be,
    /// for a stream that talks both ways, such as an app's behind the
    /// gateway.
    ///
    /// # Panics
    ///
    /// When `text` is past the 125 bytes a short frame carries, or the
    /// stream has broken off.
    pub async fn send_text(&mut self, text: &str) {
        assert!(
            text.len() <= 125,
            "a message of {} bytes is too long for a short frame",
            text.len()
        );
        if let Err(error) = self.send_control(TEXT, text.as_bytes()).await {
            panic!("the stream broke off while sending: {error}");
        }
    }

    /// Closes the stream from this side, as a browser tab closing does.
    pub async fn close(mut self) {
        let _sent = self.send_control(CLOSE, &1000_u16.to_be_bytes()).await;
    }

    /// The next whole message or the close, answering pings on the way.
    async fn next_frame(&mut self) -> Frame {
        let mut message = Vec::new();
        loop {
            let frame = self.read_frame().await;
            match frame.opcode {
                TEXT | CONTINUATION => message.extend(frame.payload),
                PING => {
                    let _sent = self.send_control(PONG, &frame.payload).await;
                    continue;
                }
                PONG => continue,
                CLOSE => return Frame::Closed(close_code(&frame.payload)),
                other => panic!("the stream sent a frame of opcode {other}, which no stream sends"),
            }
            if frame.finished {
                return Frame::Text(String::from_utf8_lossy(&message).into_owned());
            }
        }
    }

    /// The next frame, its payload unmasked.
    async fn read_frame(&mut self) -> RawFrame {
        let mut head = [0_u8; 2];
        if self.io.read_exact(&mut head).await.is_err() {
            return RawFrame::broken_off();
        }
        let [first, second] = head;
        let length = self.payload_length(second & 0x7F).await;
        let mask = self.mask(second & 0x80 != 0).await;
        let mut payload = vec![0_u8; usize::try_from(length).unwrap_or(usize::MAX)];
        if self.io.read_exact(&mut payload).await.is_err() {
            return RawFrame::broken_off();
        }
        if let Some(mask) = mask {
            unmask(&mut payload, mask);
        }
        RawFrame {
            finished: first & 0x80 != 0,
            opcode: first & 0x0F,
            payload,
        }
    }

    /// The length a frame's head announces, reading its extended length.
    ///
    /// # Panics
    ///
    /// When it cannot be read or is past [`LARGEST_MESSAGE`].
    async fn payload_length(&mut self, short: u8) -> u64 {
        let length = match short {
            126 => self.io.read_u16().await.map(u64::from),
            127 => self.io.read_u64().await,
            short => Ok(u64::from(short)),
        };
        let Ok(length) = length else {
            panic!("the stream broke off inside a frame's head");
        };
        assert!(
            length <= LARGEST_MESSAGE,
            "the stream sent a frame of {length} bytes"
        );
        length
    }

    /// The mask of a masked frame, which no server should send, read so
    /// the payload can still be read.
    async fn mask(&mut self, masked: bool) -> Option<[u8; 4]> {
        if !masked {
            return None;
        }
        let mut mask = [0_u8; 4];
        self.io.read_exact(&mut mask).await.ok()?;
        Some(mask)
    }

    /// Sends a control frame of `opcode` carrying `payload`, masked.
    async fn send_control(&mut self, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
        let mask = rand::random::<[u8; 4]>();
        let mut masked = payload.to_vec();
        unmask(&mut masked, mask);
        let length = u8::try_from(masked.len()).unwrap_or(125).min(125);
        let mut frame = vec![0x80 | opcode, 0x80 | length];
        frame.extend_from_slice(&mask);
        frame.extend(masked.into_iter().take(usize::from(length)));
        self.io.write_all(&frame).await?;
        self.io.flush().await
    }
}

/// `call` as a WebSocket handshake with `key`.
fn handshake(call: Call, key: &str) -> Call {
    call.header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", key)
}

/// The stream `response` switched to, once it proved it read `key`.
///
/// # Panics
///
/// When the accept header does not answer `key`, or the connection cannot
/// be taken over.
async fn accepted(response: reqwest::Response, key: &str) -> Socket {
    let expected = STANDARD.encode(Sha1::digest(format!("{key}{ACCEPT_GUID}").as_bytes()));
    let accept = response
        .headers()
        .get("sec-websocket-accept")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    assert_eq!(
        accept.as_deref(),
        Some(expected.as_str()),
        "the platform's accept answers the handshake's key"
    );
    match response.upgrade().await {
        Ok(io) => Socket { io },
        Err(error) => panic!("the switched connection could not be taken over: {error}"),
    }
}

/// `payload` masked or unmasked with `mask`, the same operation both ways.
fn unmask(payload: &mut [u8], mask: [u8; 4]) {
    for (byte, key) in payload.iter_mut().zip(mask.iter().cycle()) {
        *byte ^= key;
    }
}

/// The code a close frame's `payload` starts with, if it carries one.
fn close_code(payload: &[u8]) -> Option<u16> {
    let [high, low, ..] = payload else {
        return None;
    };
    Some(u16::from_be_bytes([*high, *low]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Masking twice with the same mask gives back what was masked.
    #[test]
    fn masking_twice_gives_the_payload_back() {
        let mut payload = b"no longer admitted".to_vec();
        let mask = [0x37, 0xFA, 0x21, 0x3D];

        unmask(&mut payload, mask);
        unmask(&mut payload, mask);

        assert_eq!(payload, b"no longer admitted");
    }

    /// A close frame names its code in its first two bytes; an empty one
    /// names none.
    #[test]
    fn a_close_frame_names_its_code() {
        assert_eq!(close_code(&[0x03, 0xF0, b'x']), Some(1008));
        assert_eq!(close_code(&[]), None);
    }
}
