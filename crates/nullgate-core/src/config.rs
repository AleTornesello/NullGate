//! Validated startup configuration. These types do not start services or read secret files.
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub schema_version: u32,
    pub data_dir: PathBuf,
    pub dns: DnsConfig,
    pub http: HttpConfig,
    pub web: WebConfig,
    #[serde(default)]
    pub limits: ResourceLimits,
    #[serde(default, deserialize_with = "deserialize_auth")]
    pub auth: AuthMode,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    pub udp_listen: SocketAddr,
    pub tcp_listen: SocketAddr,
    pub upstreams: Vec<SocketAddr>,
    #[serde(default = "attempt_timeout")]
    pub attempt_timeout_ms: u64,
    #[serde(default = "total_timeout")]
    pub total_timeout_ms: u64,
}
fn attempt_timeout() -> u64 {
    2000
}
fn total_timeout() -> u64 {
    5000
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpConfig {
    pub listen: SocketAddr,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebConfig {
    pub listen: SocketAddr,
    #[serde(default)]
    pub public_origin: Option<String>,
    #[serde(default)]
    pub tls_terminated_by_proxy: bool,
    pub tls: Option<TlsFiles>,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFiles {
    pub certificate_file: PathBuf,
    pub private_key_file: PathBuf,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    pub storage_queue_capacity: u16,
    pub max_connections: u32,
}
impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            storage_queue_capacity: 32,
            max_connections: 1024,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    #[default]
    Local,
    Oidc,
    None,
}
#[derive(Debug, Eq, PartialEq)]
pub struct ConfigError {
    pub key: String,
    pub line: Option<usize>,
    pub message: &'static str,
}
impl AppConfig {
    /// Parse schema 1, reject unknown keys, validate cross-field settings and resolve paths.
    pub fn parse(text: &str, config_path: &Path) -> Result<Self, ConfigError> {
        if text.len() > 65_536 {
            return Err(ConfigError::field("config", "Configuration exceeds 64 KiB"));
        }
        let deserializer = toml::Deserializer::parse(text)
            .map_err(|error| ConfigError::decode(text, "config".into(), &error))?;
        let mut config: Self = serde_path_to_error::deserialize(deserializer).map_err(|error| {
            let path = error.path().to_string();
            ConfigError::decode(
                text,
                if path.is_empty() {
                    "config".into()
                } else {
                    path
                },
                error.inner(),
            )
        })?;
        config.validate()?;
        let absolute = if config_path.is_absolute() {
            config_path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|_| {
                    ConfigError::field("config", "Cannot resolve configuration directory")
                })?
                .join(config_path)
        };
        let base = absolute
            .parent()
            .ok_or_else(|| ConfigError::field("config", "Configuration path needs a filename"))?;
        if config.data_dir.is_relative() {
            config.data_dir = base.join(&config.data_dir);
        }
        if let Some(tls) = &mut config.web.tls {
            if tls.certificate_file.is_relative() {
                tls.certificate_file = base.join(&tls.certificate_file);
            }
            if tls.private_key_file.is_relative() {
                tls.private_key_file = base.join(&tls.private_key_file);
            }
        }
        Ok(config)
    }
    /// Read a bounded UTF-8 configuration file; errors never include its contents.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        use std::io::Read;
        let file = std::fs::File::open(path)
            .map_err(|_| ConfigError::field("config", "Cannot open configuration file"))?;
        let mut bytes = Vec::new();
        file.take(65_537)
            .read_to_end(&mut bytes)
            .map_err(|_| ConfigError::field("config", "Cannot read configuration file"))?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| ConfigError::field("config", "Configuration must be UTF-8"))?;
        Self::parse(text, path)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != 1 {
            return Err(ConfigError::field(
                "schema_version",
                "Unsupported configuration schema; expected 1",
            ));
        }
        validate_path(&self.data_dir, "data_dir")?;
        if self.dns.upstreams.is_empty() {
            return Err(ConfigError::field(
                "dns.upstreams",
                "At least one upstream is required",
            ));
        }
        for address in &self.dns.upstreams {
            if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
                return Err(ConfigError::field(
                    "dns.upstreams",
                    "Use a concrete unicast address with a nonzero port",
                ));
            }
        }
        if self.dns.attempt_timeout_ms == 0
            || self.dns.attempt_timeout_ms > self.dns.total_timeout_ms
        {
            return Err(ConfigError::field(
                "dns.attempt_timeout_ms",
                "Timeout must be positive and no greater than the total timeout",
            ));
        }
        if self.dns.total_timeout_ms == 0 || self.dns.total_timeout_ms > 60_000 {
            return Err(ConfigError::field(
                "dns.total_timeout_ms",
                "Total timeout must be between 1 and 60000ms",
            ));
        }
        if self.limits.storage_queue_capacity == 0
            || self.limits.max_connections == 0
            || self.limits.max_connections > 65_535
        {
            return Err(ConfigError::field(
                "limits",
                "Queue capacity and connection limit must be between 1 and 65535",
            ));
        }
        if self.dns.udp_listen.ip().is_multicast()
            || self.dns.tcp_listen.ip().is_multicast()
            || self.http.listen.ip().is_multicast()
            || self.web.listen.ip().is_multicast()
        {
            return Err(ConfigError::field(
                "listeners",
                "Multicast listeners are unsupported",
            ));
        }
        let tcp = [
            ("dns.tcp_listen", self.dns.tcp_listen),
            ("http.listen", self.http.listen),
            ("web.listen", self.web.listen),
        ];
        for (i, (_, a)) in tcp.iter().enumerate() {
            for (key, b) in &tcp[i + 1..] {
                if overlap(*a, *b) {
                    return Err(ConfigError::field(
                        key,
                        "TCP listener overlaps another configured listener",
                    ));
                }
            }
        }
        if self.web.tls_terminated_by_proxy
            && (!self.web.listen.ip().is_loopback()
                || self.web.tls.is_some()
                || self.web.public_origin.is_none())
        {
            return Err(ConfigError::field(
                "web.tls_terminated_by_proxy",
                "TLS offload requires a loopback backend, explicit HTTPS origin and no direct TLS files",
            ));
        }
        if let Some(origin) = &self.web.public_origin {
            let invalid = || {
                ConfigError::field(
                    "web.public_origin",
                    "Use an explicit matching HTTP(S) origin without credentials, path, query or fragment",
                )
            };
            let normalized = crate::normalize_url(origin).map_err(|_| invalid())?;
            let secure = self.web.tls.is_some() || self.web.tls_terminated_by_proxy;
            let path = origin
                .split_once("://")
                .and_then(|(_, rest)| rest.split_once('/'))
                .map(|(_, path)| path);
            if origin.contains(['?', '#', '@'])
                || path.is_some_and(|path| !path.is_empty())
                || normalized.scheme()
                    != if secure {
                        crate::HttpScheme::Https
                    } else {
                        crate::HttpScheme::Http
                    }
            {
                return Err(invalid());
            }
        }
        if let Some(tls) = &self.web.tls {
            validate_path(&tls.certificate_file, "web.tls.certificate_file")?;
            validate_path(&tls.private_key_file, "web.tls.private_key_file")?;
        } else if !self.web.listen.ip().is_loopback() {
            return Err(ConfigError::field(
                "web.tls",
                "A non-loopback web listener requires TLS file references",
            ));
        }
        Ok(())
    }
    pub fn database_path(&self) -> PathBuf {
        self.data_dir.join("nullgate.sqlite3")
    }
}
impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.key, self.message)?;
        if let Some(line) = self.line {
            write!(f, " (line {line})")?;
        }
        Ok(())
    }
}
impl std::error::Error for ConfigError {}

impl ConfigError {
    fn field(key: &str, message: &'static str) -> Self {
        Self {
            key: key.into(),
            line: None,
            message,
        }
    }
    fn decode(text: &str, key: String, error: &toml::de::Error) -> Self {
        let line = error.span().map(|span| {
            text.as_bytes()[..span.start.min(text.len())]
                .iter()
                .filter(|b| **b == b'\n')
                .count()
                + 1
        });
        // Serde reports a missing field on its containing table. Recover only a
        // schema-owned identifier; never copy an offending value or source excerpt.
        let mut key = if key == "." { String::new() } else { key };
        let detail = error.message();
        let message = if let Some(rest) = detail.strip_prefix("missing field `") {
            let missing = rest.split('`').next().unwrap_or("");
            const FIELDS: &[&str] = &[
                "schema_version",
                "data_dir",
                "dns",
                "http",
                "web",
                "limits",
                "auth",
                "udp_listen",
                "tcp_listen",
                "upstreams",
                "attempt_timeout_ms",
                "total_timeout_ms",
                "listen",
                "tls",
                "certificate_file",
                "private_key_file",
                "storage_queue_capacity",
                "max_connections",
                "mode",
            ];
            if FIELDS.contains(&missing) {
                if !key.is_empty() && key != "config" {
                    key.push('.');
                } else {
                    key.clear();
                }
                key.push_str(missing);
            }
            "Missing required configuration field"
        } else if detail.starts_with("unknown field") {
            "Unknown configuration field"
        } else if detail.starts_with("invalid type") {
            "Invalid configuration field type"
        } else if detail.starts_with("unknown variant") || detail.starts_with("invalid") {
            "Invalid configuration field value"
        } else {
            "Malformed TOML configuration"
        };
        if key.is_empty() {
            key = "config".into();
        }
        Self { key, line, message }
    }
}
fn validate_path(path: &Path, key: &str) -> Result<(), ConfigError> {
    if path.as_os_str().is_empty() || path.to_string_lossy().chars().any(char::is_control) {
        return Err(ConfigError::field(
            key,
            "Use a nonempty path without control characters",
        ));
    }
    Ok(())
}
fn overlap(a: SocketAddr, b: SocketAddr) -> bool {
    if a.port() == 0 || a.port() != b.port() {
        return false;
    }
    a.ip() == b.ip()
        || (a.is_ipv4() == b.is_ipv4() && (a.ip().is_unspecified() || b.ip().is_unspecified()))
        || (a.is_ipv6() && a.ip().is_unspecified())
        || (b.is_ipv6() && b.ip().is_unspecified())
}

fn deserialize_auth<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<AuthMode, D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Fields {
        mode: AuthMode,
    }
    Fields::deserialize(deserializer).map(|fields| fields.mode)
}
