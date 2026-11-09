//! Isolated, associated DNS exchanges; no resolver cache or public DNS defaults.
use hickory_proto::{
    op::{Header, Message, MessageType},
    serialize::binary::{BinDecodable, BinDecoder},
};
use nullgate_core::{DnsConfig, ServiceTransport};
use std::{io, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::{Instant, timeout_at},
};

pub(crate) fn decode(bytes: &[u8]) -> Result<Message, ()> {
    let header = Header::read(&mut BinDecoder::new(bytes)).map_err(|_| ())?;
    if header.counts.queries != 1 {
        return Err(());
    }
    let mut decoder = BinDecoder::new(bytes);
    let message = Message::read(&mut decoder).map_err(|_| ())?;
    if decoder.index() != bytes.len() {
        return Err(());
    }
    Ok(message)
}
fn associated(response: &Message, request: &Message, id: u16) -> bool {
    response.metadata.id == id
        && response.metadata.message_type == MessageType::Response
        && response.metadata.op_code == request.metadata.op_code
        && response.queries == request.queries
}
pub(crate) async fn forward(
    bytes: &[u8],
    request: &Message,
    config: &DnsConfig,
    transport: ServiceTransport,
) -> Option<Vec<u8>> {
    let mut id = Message::query().metadata.id;
    if id == request.metadata.id {
        id = id.wrapping_add(1);
    }
    let mut outbound = bytes.to_vec();
    outbound[..2].copy_from_slice(&id.to_be_bytes());
    let total = Instant::now() + Duration::from_millis(config.total_timeout_ms);
    for address in &config.upstreams {
        if Instant::now() >= total {
            break;
        }
        let end = (Instant::now() + Duration::from_millis(config.attempt_timeout_ms)).min(total);
        let exchange = async {
            if transport == ServiceTransport::Tcp {
                return tcp(*address, &outbound, request, id).await;
            }
            let bind = if address.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = UdpSocket::bind(bind).await?;
            socket.connect(address).await?;
            socket.send(&outbound).await?;
            let mut response = vec![0; 65535];
            loop {
                let size = socket.recv(&mut response).await?;
                if let Ok(message) = decode(&response[..size])
                    && associated(&message, request, id)
                {
                    if message.metadata.truncation {
                        return tcp(*address, &outbound, request, id).await;
                    }
                    return Ok(response[..size].to_vec());
                }
                tokio::task::yield_now().await;
            }
        };
        if let Ok(Ok(mut response)) = timeout_at(end, exchange).await {
            response[..2].copy_from_slice(&request.metadata.id.to_be_bytes());
            return Some(response);
        }
    }
    None
}
async fn tcp(
    address: SocketAddr,
    outbound: &[u8],
    request: &Message,
    id: u16,
) -> io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(address).await?;
    stream.write_u16(outbound.len() as u16).await?;
    stream.write_all(outbound).await?;
    loop {
        let size = stream.read_u16().await?;
        if size == 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut response = vec![0; size as usize];
        stream.read_exact(&mut response).await?;
        if let Ok(message) = decode(&response)
            && associated(&message, request, id)
        {
            return Ok(response);
        }
        tokio::task::yield_now().await;
    }
}
