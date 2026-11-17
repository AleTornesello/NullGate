use super::{Sandbox, bounded};
use hickory_proto::{
    op::{Message, MessageType, Query},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use std::{
    net::{Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::{JoinHandle, JoinSet},
};
pub struct Origin {
    pub address: SocketAddr,
    pub certificate: rustls::pki_types::CertificateDer<'static>,
    pub roots: PathBuf,
    job: JoinHandle<()>,
}
impl Origin {
    pub async fn new(sandbox: &Sandbox, tls: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let material =
            rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                .unwrap();
        let certificate = material.cert.der().clone();
        let roots = sandbox.root.join(if tls {
            "tls-roots.pem"
        } else {
            "plain-roots.pem"
        });
        std::fs::write(&roots, material.cert.pem()).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(material.signing_key.serialize_der())
                .into(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let job = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                 Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
                 accepted=listener.accept()=>{let(stream,_)=accepted.unwrap();let acceptor=acceptor.clone();tasks.spawn(async move {if tls {if let Ok(mut io)=acceptor.accept(stream).await{serve_http(&mut io).await;}}else {serve_http(&mut {stream}).await;}});}
                }
            }
        });
        Self {
            address,
            certificate,
            roots,
            job,
        }
    }
    pub fn url(&self, scheme: &str, path: &str) -> String {
        format!("{scheme}://{}{path}", self.address)
    }
}
impl Drop for Origin {
    fn drop(&mut self) {
        self.job.abort();
    }
}
async fn serve_http<S: AsyncRead + AsyncWrite + Unpin>(io: &mut S) {
    let mut header = vec![];
    while !header.ends_with(b"\r\n\r\n") {
        match io.read_u8().await {
            Ok(byte) => header.push(byte),
            Err(_) => return,
        };
        if header.len() > 32768 {
            return;
        }
    }
    let _ = io
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\norigin")
        .await;
    let _ = io.shutdown().await;
}
pub struct DnsOrigin {
    pub address: SocketAddr,
    job: JoinHandle<()>,
}
impl DnsOrigin {
    pub async fn new() -> Self {
        let (tcp, udp) = loop {
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            match UdpSocket::bind(tcp.local_addr().unwrap()).await {
                Ok(udp) => break (tcp, udp),
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
                Err(_) => panic!("DNS fixture bind failed"),
            }
        };
        let address = tcp.local_addr().unwrap();
        let job = tokio::spawn(async move {
            let mut clients = JoinSet::new();
            let mut bytes = vec![0; 65535];
            loop {
                tokio::select! {
                 Some(_)=clients.join_next(),if !clients.is_empty()=>{},
                 packet=udp.recv_from(&mut bytes)=>{let(size,peer)=packet.unwrap();let answer=answer(&bytes[..size]);let _=udp.send_to(&answer,peer).await;},
                 accepted=tcp.accept()=>{let(mut stream,_)=accepted.unwrap();clients.spawn(async move{let Ok(size)=stream.read_u16().await else{return;};let mut bytes=vec![0;size as usize];if stream.read_exact(&mut bytes).await.is_ok(){let answer=answer(&bytes);let _=stream.write_u16(answer.len() as u16).await;let _=stream.write_all(&answer).await;}});}
                }
            }
        });
        Self { address, job }
    }
}
impl Drop for DnsOrigin {
    fn drop(&mut self) {
        self.job.abort();
    }
}
fn answer(bytes: &[u8]) -> Vec<u8> {
    let mut response = Message::from_vec(bytes).unwrap();
    response.metadata.message_type = MessageType::Response;
    response.metadata.recursion_available = true;
    let query = response.queries[0].clone();
    let data = if query.query_type() == RecordType::AAAA {
        RData::AAAA(AAAA(Ipv6Addr::LOCALHOST))
    } else {
        RData::A(A::new(127, 0, 0, 1))
    };
    response
        .answers
        .push(Record::from_rdata(query.name().clone(), 30, data));
    response.to_vec().unwrap()
}
pub async fn dns(address: SocketAddr, name: &str, kind: RecordType, tcp: bool) -> Message {
    let mut message = Message::query();
    message.metadata.id = 0x1234;
    message.metadata.recursion_desired = true;
    message.queries.push(Query::query(
        Name::from_utf8(format!("{}.", name.trim_end_matches('.'))).unwrap(),
        kind,
    ));
    let bytes = message.to_vec().unwrap();
    let response = if tcp {
        let mut io = TcpStream::connect(address).await.unwrap();
        io.write_u16(bytes.len() as u16).await.unwrap();
        io.write_all(&bytes).await.unwrap();
        let size = bounded(io.read_u16()).await.unwrap();
        let mut response = vec![0; size as usize];
        bounded(io.read_exact(&mut response)).await.unwrap();
        response
    } else {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(address).await.unwrap();
        socket.send(&bytes).await.unwrap();
        let mut response = vec![0; 65535];
        let size = bounded(socket.recv(&mut response)).await.unwrap();
        response.truncate(size);
        response
    };
    let response = Message::from_vec(&response).unwrap();
    assert_eq!(response.metadata.id, 0x1234);
    assert_eq!(response.queries, message.queries);
    response
}
