//! Bounded raw request-target preservation before http::Uri can discard fragments.
//! Accepted bytes are unchanged; Hyper remains the actual HTTP message/body codec.
use hyper::StatusCode;
use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
const MAX_HEAD: usize = 32 * 1024;
const MAX_TARGET: usize = 8192;
pub(crate) enum Ingress {
    Accepted(String),
    Rejected(StatusCode),
}
pub(crate) type Heads = Arc<Mutex<VecDeque<Ingress>>>;
#[derive(Default)]
struct Head {
    bytes: Vec<u8>,
    spaces: u8,
    target_len: usize,
}
enum State {
    Head(Head),
    Fixed(u64),
    Size(Vec<u8>),
    Data(u64),
    DataEnd(u8),
    Trailers { line: Vec<u8>, total: usize },
    Closed,
}
pub(crate) struct GuardedIo {
    socket: TcpStream,
    state: State,
    heads: Heads,
    pending: Vec<u8>,
    offset: usize,
}
impl GuardedIo {
    pub fn new(socket: TcpStream, heads: Heads) -> Self {
        Self {
            socket,
            state: State::Head(Head::default()),
            heads,
            pending: Vec::new(),
            offset: 0,
        }
    }
    fn reject(&mut self, status: StatusCode, out: &mut Vec<u8>) {
        self.heads
            .lock()
            .unwrap()
            .push_back(Ingress::Rejected(status));
        out.extend_from_slice(
            b"GET / HTTP/1.1\r\nHost: invalid.invalid\r\nConnection: close\r\n\r\n",
        );
        self.state = State::Closed;
    }
    fn process(&mut self, input: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut cursor = 0;
        while cursor < input.len() {
            match std::mem::replace(&mut self.state, State::Closed) {
                State::Closed => break,
                State::Head(mut head) => {
                    let byte = input[cursor];
                    cursor += 1;
                    head.bytes.push(byte);
                    if head.spaces == 0 && byte == b' ' {
                        head.spaces = 1;
                    } else if head.spaces == 1 {
                        if byte == b' ' {
                            head.spaces = 2;
                        } else {
                            head.target_len += 1;
                        }
                    }
                    if head.target_len > MAX_TARGET {
                        self.reject(StatusCode::URI_TOO_LONG, &mut out);
                        break;
                    }
                    if head.bytes.len() > MAX_HEAD {
                        self.reject(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE, &mut out);
                        break;
                    }
                    if head.bytes.ends_with(b"\r\n\r\n") {
                        match parse_head(&head.bytes) {
                            Ok((target, state)) => {
                                self.heads
                                    .lock()
                                    .unwrap()
                                    .push_back(Ingress::Accepted(target));
                                out.extend_from_slice(&head.bytes);
                                self.state = state;
                            }
                            Err(status) => {
                                self.reject(status, &mut out);
                                break;
                            }
                        }
                    } else {
                        self.state = State::Head(head);
                    }
                }
                State::Fixed(remaining) => {
                    let size = remaining.min((input.len() - cursor) as u64) as usize;
                    out.extend_from_slice(&input[cursor..cursor + size]);
                    cursor += size;
                    self.state = if remaining == size as u64 {
                        State::Head(Head::default())
                    } else {
                        State::Fixed(remaining - size as u64)
                    };
                }
                State::Data(remaining) => {
                    let size = remaining.min((input.len() - cursor) as u64) as usize;
                    out.extend_from_slice(&input[cursor..cursor + size]);
                    cursor += size;
                    self.state = if remaining == size as u64 {
                        State::DataEnd(0)
                    } else {
                        State::Data(remaining - size as u64)
                    };
                }
                State::Size(mut line) => {
                    let byte = input[cursor];
                    cursor += 1;
                    line.push(byte);
                    out.push(byte);
                    if line.len() > 1024 {
                        return Err(bad_frame());
                    }
                    if line.ends_with(b"\r\n") {
                        let token = line[..line.len() - 2]
                            .split(|b| *b == b';')
                            .next()
                            .unwrap_or_default();
                        if token.is_empty() || !token.iter().all(u8::is_ascii_hexdigit) {
                            return Err(bad_frame());
                        }
                        let size = u64::from_str_radix(
                            std::str::from_utf8(token).map_err(|_| bad_frame())?,
                            16,
                        )
                        .map_err(|_| bad_frame())?;
                        self.state = if size == 0 {
                            State::Trailers {
                                line: Vec::new(),
                                total: 0,
                            }
                        } else {
                            State::Data(size)
                        };
                    } else {
                        self.state = State::Size(line);
                    }
                }
                State::DataEnd(position) => {
                    let byte = input[cursor];
                    cursor += 1;
                    if byte != b"\r\n"[position as usize] {
                        return Err(bad_frame());
                    }
                    out.push(byte);
                    self.state = if position == 0 {
                        State::DataEnd(1)
                    } else {
                        State::Size(Vec::new())
                    };
                }
                State::Trailers {
                    mut line,
                    mut total,
                } => {
                    let byte = input[cursor];
                    cursor += 1;
                    line.push(byte);
                    total += 1;
                    out.push(byte);
                    if total > MAX_HEAD {
                        return Err(bad_frame());
                    }
                    if line.ends_with(b"\r\n") {
                        if line.len() == 2 {
                            self.state = State::Head(Head::default());
                        } else {
                            line.clear();
                            self.state = State::Trailers { line, total };
                        }
                    } else {
                        self.state = State::Trailers { line, total };
                    }
                }
            }
        }
        Ok(out)
    }
}
fn bad_frame() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Invalid HTTP framing")
}
fn parse_head(bytes: &[u8]) -> Result<(String, State), StatusCode> {
    let mut headers = [httparse::EMPTY_HEADER; 100];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(bytes) {
        Ok(httparse::Status::Complete(size)) if size == bytes.len() => {}
        Err(httparse::Error::TooManyHeaders) => {
            return Err(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
        }
        _ => return Err(StatusCode::BAD_REQUEST),
    }
    let target = request.path.ok_or(StatusCode::BAD_REQUEST)?;
    if target.contains('#') {
        return Err(StatusCode::BAD_REQUEST);
    }
    if target.len() > MAX_TARGET {
        return Err(StatusCode::URI_TOO_LONG);
    }
    let mut length = None;
    let mut chunked = false;
    for header in request.headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(StatusCode::BAD_REQUEST);
            }
            let value = std::str::from_utf8(header.value)
                .map_err(|_| StatusCode::BAD_REQUEST)?
                .trim();
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(StatusCode::BAD_REQUEST);
            }
            length = Some(value.parse::<u64>().map_err(|_| StatusCode::BAD_REQUEST)?);
        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked {
                return Err(StatusCode::BAD_REQUEST);
            }
            if !header.value.eq_ignore_ascii_case(b"chunked") {
                return Err(StatusCode::NOT_IMPLEMENTED);
            }
            chunked = true;
        }
    }
    if chunked && length.is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let state = if chunked {
        State::Size(Vec::new())
    } else {
        match length {
            Some(n) if n > 0 => State::Fixed(n),
            _ => State::Head(Head::default()),
        }
    };
    Ok((target.into(), state))
}
impl AsyncRead for GuardedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.offset < this.pending.len() {
                let n = buf.remaining().min(this.pending.len() - this.offset);
                buf.put_slice(&this.pending[this.offset..this.offset + n]);
                this.offset += n;
                return Poll::Ready(Ok(()));
            }
            // Keep the read side pending until the synthetic close response is written.
            // Reporting EOF here lets Hyper cancel a queued response before sending it.
            if matches!(this.state, State::Closed) {
                return Poll::Pending;
            }
            let mut storage = [0; 8192];
            let mut read = ReadBuf::new(&mut storage);
            match Pin::new(&mut this.socket).poll_read(cx, &mut read) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
            if read.filled().is_empty() {
                return if matches!(&this.state,State::Head(head)if head.bytes.is_empty()) {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                };
            }
            this.pending = this.process(read.filled())?;
            this.offset = 0;
        }
    }
}
impl AsyncWrite for GuardedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().socket).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket).poll_shutdown(cx)
    }
    fn is_write_vectored(&self) -> bool {
        self.socket.is_write_vectored()
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().socket).poll_write_vectored(cx, bufs)
    }
}
