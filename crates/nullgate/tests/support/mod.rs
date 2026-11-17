//! Real-child fixtures. Only static stages and allowlisted lifecycle counts leave the sandbox.
mod upstream;
use reqwest::{Client, Method};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
pub use upstream::{DnsOrigin, Origin, dns};

/// Release rehearsals use the checksum-verified packaged executable; normal CI uses Cargo's binary.
pub fn binary() -> PathBuf {
    std::env::var_os("NULLGATE_E2E_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_nullgate")))
}
pub const PASSWORD: &str = "Task16-fixture-only-NEVER-LOG-password";
pub const PRIVATE_QUERY: &str = "NEVER-LOG-query-credential";
pub async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(45), future)
        .await
        .expect("bounded local operation timed out")
}
pub fn client() -> Client {
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}
pub struct Sandbox {
    pub root: PathBuf,
    case: &'static str,
    stage: Arc<Mutex<&'static str>>,
}
impl Sandbox {
    pub fn new(case: &'static str) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "nullgate-e2e-{}-{}-{}",
            std::process::id(),
            case,
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        Self {
            root,
            case,
            stage: Arc::new(Mutex::new("created")),
        }
    }
    pub fn stage(&self, stage: &'static str) {
        *self.stage.lock().unwrap() = stage;
    }
    pub fn config(&self, upstream: SocketAddr, auth: &str, http: SocketAddr) -> PathBuf {
        let path = self.root.join("runtime.toml");
        std::fs::write(
            &path,
            format!(
                r#"schema_version=1
data_dir="data"
[dns]
udp_listen="127.0.0.1:0"
tcp_listen="127.0.0.1:0"
upstreams=["{upstream}"]
attempt_timeout_ms=100
total_timeout_ms=400
[http]
listen="{http}"
[web]
listen="127.0.0.1:0"
[auth]
mode="{auth}"
"#
            ),
        )
        .unwrap();
        path
    }
    pub fn raw_logs(&self) -> String {
        let mut text = String::new();
        for file in std::fs::read_dir(&self.root).unwrap().flatten() {
            if file.path().extension().is_some_and(|s| s == "log") {
                text.push_str(&std::fs::read_to_string(file.path()).unwrap_or_default());
            }
        }
        text
    }
    pub fn assert_logs_safe(&self) {
        let text = self.raw_logs();
        for secret in [
            PASSWORD,
            PRIVATE_QUERY,
            "PRIVATE KEY",
            "nullgate_session=",
            "authorization: Bearer",
        ] {
            assert!(
                !text.contains(secret),
                "runtime log exposed forbidden fixture data"
            );
        }
    }
    pub async fn provision(&self, config: &PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let password = self.root.join("password");
        std::fs::write(&password, PASSWORD).unwrap();
        std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();
        let log = std::fs::File::create(self.root.join("provision.log")).unwrap();
        let mut child = Process(
            Command::new(binary())
                .arg("provision-admin")
                .arg("--config")
                .arg(config)
                .args(["--username", "admin", "--password-file"])
                .arg(&password)
                .stdout(Stdio::null())
                .stderr(log)
                .spawn()
                .unwrap(),
        );
        assert!(
            exit(&mut child.0).await.success(),
            "explicit fixture provisioning failed"
        );
        std::fs::remove_file(password).unwrap();
        // Account-management UI is out of scope; seed a Viewer through trusted offline storage.
        let mut repo =
            nullgate_core::AuthRepository::open(self.root.join("data/nullgate.sqlite3")).unwrap();
        let hash = repo.user("admin").unwrap().unwrap().password_hash;
        repo.insert_user(
            "viewer",
            &hash,
            nullgate_core::Role::Viewer,
            nullgate_core::AccountCreation::NoAuthentication,
        )
        .unwrap();
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        let text = self.raw_logs();
        let summary = json!({"case":self.case,"last_stage":*self.stage.lock().unwrap(),"panicked":std::thread::panicking(),
   "ready_events":text.lines().filter(|s|s.contains("runtime ready")).count(),
   "restart_events":text.lines().filter(|s|s.contains("proxy restart scheduled")).count(),
   "stopped_events":text.lines().filter(|s|s.contains("runtime stopped")).count(),
   "startup_failures":text.lines().filter(|s|s.contains("startup failed")).count()});
        let artifacts = std::env::var_os("NULLGATE_E2E_ARTIFACTS")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/e2e-artifacts")
            });
        if std::fs::create_dir_all(&artifacts).is_ok() {
            let _ = std::fs::write(
                artifacts.join(format!("{}.json", self.case)),
                summary.to_string(),
            );
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
pub struct Process(pub Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
async fn exit(child: &mut Child) -> std::process::ExitStatus {
    bounded(async {
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            tick.tick().await;
        }
    })
    .await
}
#[derive(Clone, Copy)]
pub struct Ready {
    pub dns_udp: SocketAddr,
    pub dns_tcp: SocketAddr,
    pub http: SocketAddr,
    pub web: SocketAddr,
}
pub struct Runtime {
    process: Process,
    pub log: PathBuf,
    pub ready: Ready,
}
impl Runtime {
    pub async fn start(
        sandbox: &Sandbox,
        config: &PathBuf,
        roots: &PathBuf,
        limit: Option<u64>,
        generation: usize,
    ) -> Self {
        let log = sandbox.root.join(format!("runtime-{generation}.log"));
        let output = std::fs::File::create(&log).unwrap();
        let mut command = if let Some(limit) = limit {
            let mut c = Command::new("prlimit");
            c.arg(format!("--nofile={limit}:{limit}"))
                .arg("--")
                .arg(binary());
            c
        } else {
            Command::new(binary())
        };
        let empty = sandbox.root.join("empty-roots");
        std::fs::create_dir_all(&empty).unwrap();
        let process = Process(
            command
                .arg("--config")
                .arg(config)
                .env("RUST_LOG", "info")
                .env("SSL_CERT_FILE", roots)
                .env("SSL_CERT_DIR", empty)
                .stdout(Stdio::null())
                .stderr(output)
                .spawn()
                .unwrap(),
        );
        let mut runtime = Self {
            process,
            log,
            ready: Ready {
                dns_udp: "127.0.0.1:0".parse().unwrap(),
                dns_tcp: "127.0.0.1:0".parse().unwrap(),
                http: "127.0.0.1:0".parse().unwrap(),
                web: "127.0.0.1:0".parse().unwrap(),
            },
        };
        runtime.refresh_ready(false).await;
        let response = client()
            .get(format!("http://{}/api/v1/auth/csrf", runtime.ready.web))
            .send()
            .await
            .expect("readiness API probe failed");
        assert_eq!(response.status().as_u16(), 200);
        drop(TcpStream::connect(runtime.ready.dns_tcp).await.unwrap());
        drop(TcpStream::connect(runtime.ready.http).await.unwrap());
        runtime
    }
    pub async fn refresh_ready(&mut self, after_restart: bool) {
        bounded(async {
            let mut tick = tokio::time::interval(Duration::from_millis(10));
            loop {
                assert!(
                    self.process.0.try_wait().unwrap().is_none(),
                    "real executable exited unexpectedly; see sanitized scenario artifact"
                );
                let text = std::fs::read_to_string(&self.log).unwrap();
                let lines = text.lines().collect::<Vec<_>>();
                let start = if after_restart {
                    lines
                        .iter()
                        .rposition(|line| line.contains("proxy restart scheduled"))
                        .map_or(lines.len(), |index| index + 1)
                } else {
                    0
                };
                if let Some(line) = lines[start..]
                    .iter()
                    .rev()
                    .find(|s| s.contains("runtime ready"))
                {
                    let address = |key: &str| {
                        line.split_whitespace()
                            .find_map(|s| s.strip_prefix(key))
                            .unwrap()
                            .parse()
                            .unwrap()
                    };
                    self.ready = Ready {
                        dns_udp: address("dns_udp="),
                        dns_tcp: address("dns_tcp="),
                        http: address("http="),
                        web: address("web="),
                    };
                    // Policy saves also log readiness. Require live post-restart health,
                    // not merely a later occurrence of an old ready event.
                    if after_restart {
                        let response = client()
                            .get(format!("http://{}/api/v1/metrics", self.ready.web))
                            .send()
                            .await;
                        if let Ok(response) = response
                            && let Ok(metrics) = response.json::<Value>().await
                            && metrics["health"]["ready"] == true
                            && metrics["health"]["http"]["restarts"]
                                .as_u64()
                                .is_some_and(|n| n > 0)
                        {
                            return;
                        }
                    } else {
                        return;
                    }
                }
                tick.tick().await;
            }
        })
        .await;
    }
    pub async fn stop(mut self) {
        assert!(
            Command::new("kill")
                .args(["-TERM", &self.process.0.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            exit(&mut self.process.0).await.success(),
            "graceful child exit failed"
        );
    }
}
pub struct Api {
    pub origin: String,
    pub cookie: String,
    pub csrf: String,
    pub client: Client,
}
impl Api {
    pub fn anonymous(address: SocketAddr) -> Self {
        Self {
            origin: format!("http://{address}"),
            cookie: String::new(),
            csrf: String::new(),
            client: client(),
        }
    }
    pub async fn login(address: SocketAddr, name: &str) -> Self {
        let mut api = Self::anonymous(address);
        let response = api
            .client
            .get(format!("{}/api/v1/auth/csrf", api.origin))
            .send()
            .await
            .unwrap();
        api.cookie = cookie(&response, "nullgate_csrf");
        api.csrf = response.json::<Value>().await.unwrap()["csrf"]
            .as_str()
            .unwrap()
            .into();
        let response = api
            .send(
                Method::POST,
                "/api/v1/auth/login",
                Some(json!({"username":name,"password":PASSWORD})),
            )
            .await;
        assert_eq!(response.status().as_u16(), 200, "fixture login failed");
        api.cookie = cookie(&response, "nullgate_session");
        api.csrf = api.json(Method::GET, "/api/v1/auth/csrf", None).await.1["csrf"]
            .as_str()
            .unwrap()
            .into();
        api
    }
    pub async fn send(&self, method: Method, path: &str, body: Option<Value>) -> reqwest::Response {
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.origin))
            .header("cookie", &self.cookie)
            .header("origin", &self.origin)
            .header("x-csrf-token", &self.csrf);
        if let Some(body) = body {
            request = request.json(&body);
        }
        request
            .send()
            .await
            .expect("local management request failed")
    }
    pub async fn json(&self, method: Method, path: &str, body: Option<Value>) -> (u16, Value) {
        let response = self.send(method, path, body).await;
        let status = response.status().as_u16();
        let body = response.bytes().await.unwrap();
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }
    pub async fn revision(&self) -> u64 {
        let (status, body) = self.json(Method::GET, "/api/v1/lists", None).await;
        assert_eq!(status, 200);
        body["revision"].as_u64().unwrap()
    }
    pub async fn rules(&self, list: i64, revision: u64, text: String) -> Value {
        let (status, result) = self
            .json(
                Method::POST,
                &format!("/api/v1/lists/{list}/rules"),
                Some(json!({"expected_revision":revision,"text":text})),
            )
            .await;
        assert_eq!(status, 200);
        result
    }
}
fn cookie(response: &reqwest::Response, name: &str) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|h| {
            h.split(';')
                .next()
                .filter(|c| c.starts_with(&format!("{name}=")))
        })
        .expect("expected cookie absent")
        .into()
}
pub async fn head<S: AsyncRead + Unpin>(io: &mut S) -> Vec<u8> {
    bounded(async {
        let mut header = vec![];
        while !header.ends_with(b"\r\n\r\n") {
            header.push(io.read_u8().await.unwrap());
            assert!(header.len() < 32768);
        }
        header
    })
    .await
}
pub fn status(header: &[u8]) -> u16 {
    std::str::from_utf8(header)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}
pub async fn get<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    target: &str,
    authority: &str,
) -> (u16, Vec<u8>) {
    io.write_all(format!("GET {target} HTTP/1.1\r\nHost: {authority}\r\nAuthorization: Bearer {PRIVATE_QUERY}\r\n\r\n").as_bytes()).await.unwrap();
    let header = head(io).await;
    let size = std::str::from_utf8(&header)
        .unwrap()
        .lines()
        .find_map(|s| {
            s.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|s| s.trim().parse::<usize>().unwrap())
        })
        .unwrap();
    let mut body = vec![0; size];
    bounded(io.read_exact(&mut body)).await.unwrap();
    (status(&header), body)
}
pub async fn connect(proxy: SocketAddr, host: &str, port: u16) -> (TcpStream, u16) {
    let mut io = TcpStream::connect(proxy).await.unwrap();
    io.write_all(
        format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let response = head(&mut io).await;
    (io, status(&response))
}
pub async fn tls(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    root: rustls::pki_types::CertificateDer<'static>,
) -> (tokio_rustls::client::TlsStream<TcpStream>, Vec<u8>) {
    let (io, code) = connect(proxy, host, port).await;
    assert_eq!(code, 200);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root).unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let stream = bounded(tokio_rustls::TlsConnector::from(Arc::new(config)).connect(
        rustls::pki_types::ServerName::try_from(host.to_owned()).unwrap(),
        io,
    ))
    .await
    .unwrap();
    let leaf = stream.get_ref().1.peer_certificates().unwrap()[0].to_vec();
    (stream, leaf)
}
pub async fn closed<S: AsyncRead + Unpin>(io: &mut S) {
    let result = bounded(io.read(&mut [0])).await;
    assert!(
        matches!(result, Ok(0) | Err(_)),
        "invalidated connection remained open"
    );
}
