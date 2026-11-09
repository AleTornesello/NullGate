//! Typed rules and shared normalization. No DNS resolution or other I/O occurs here.

use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Maximum UTF-8 import body size, in bytes.
pub const MAX_IMPORT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum raw rule line or request target size, in bytes.
pub const MAX_RULE_LINE_BYTES: usize = 8 * 1024;
/// Maximum distinct canonical rules in one compiled policy.
pub const MAX_RULES: usize = 100_000;

/// A validated lowercase IDNA A-label name, without the root dot.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DomainName(String);

impl DomainName {
    /// The canonical DNS name. Construction goes through [`normalize_host`].
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::borrow::Borrow<str> for DomainName {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

/// A normalized host. IPv6 strings are bracketed on input; address equality is numeric.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum NormalizedHost {
    Dns(DomainName),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

impl fmt::Display for NormalizedHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(name) => f.write_str(name.as_str()),
            Self::Ipv4(ip) => ip.fmt(f),
            Self::Ipv6(ip) => write!(f, "[{ip}]"),
        }
    }
}

/// Only HTTP and HTTPS URL rules are supported.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum HttpScheme {
    Http,
    Https,
}

/// A request URL with query removed, effective port and canonical path bytes.
/// Fields are private so normalization cannot be bypassed by callers.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct NormalizedUrl {
    pub(crate) scheme: HttpScheme,
    pub(crate) host: NormalizedHost,
    pub(crate) port: u16,
    pub(crate) path: String,
}

impl NormalizedUrl {
    pub fn scheme(&self) -> HttpScheme {
        self.scheme
    }
    pub fn host(&self) -> &NormalizedHost {
        &self.host
    }
    /// Explicit port or the scheme default (80/443).
    pub fn port(&self) -> u16 {
        self.port
    }
    /// ASCII path, with reserved percent escapes preserved and no query.
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// A validated host and effective nonzero port, suitable for comparing CONNECT targets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedAuthority {
    host: NormalizedHost,
    port: u16,
}

impl NormalizedAuthority {
    pub fn host(&self) -> &NormalizedHost {
        &self.host
    }
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// A canonical URL rule; only its raw `*` path bytes have wildcard semantics.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct UrlPattern(pub(crate) NormalizedUrl);

impl UrlPattern {
    /// Read-only canonical form; constructing a pattern requires [`Rule::parse`].
    pub fn url(&self) -> &NormalizedUrl {
        &self.0
    }
}

/// Typed rules. Domain variants cannot contain IP literals or unvalidated names.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Rule {
    ExactDomain(DomainName),
    Subdomains(DomainName),
    Url(UrlPattern),
}

impl Rule {
    /// Parse one rule, without import whitespace/comment handling.
    pub fn parse(input: &str) -> Result<Self, RuleError> {
        if input.len() > MAX_RULE_LINE_BYTES {
            return Err(RuleError::LineTooLong);
        }
        if input.contains("://") {
            return normalize_url(input)
                .map(|url| Self::Url(UrlPattern(url)))
                .map_err(RuleError::Url);
        }
        let (name, wildcard) = match input.strip_prefix("*.") {
            Some(name) => (name, true),
            None => (input, false),
        };
        match normalize_host(name).map_err(RuleError::Host)? {
            NormalizedHost::Dns(name) if wildcard => Ok(Self::Subdomains(name)),
            NormalizedHost::Dns(name) => Ok(Self::ExactDomain(name)),
            _ => Err(RuleError::IpDomain),
        }
    }
}

/// Host normalization failure. Errors never include the untrusted input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostError {
    TooLong,
    InvalidName,
    InvalidIp,
}

/// URL/authority normalization failure; protocol layers map these to HTTP responses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UrlError {
    TooLong,
    InvalidScheme,
    InvalidAuthority,
    InvalidPort,
    InvalidPath,
    InvalidEscape,
    Fragment,
}

/// Single-rule parsing failure, with stable diagnostic codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleError {
    Host(HostError),
    Url(UrlError),
    IpDomain,
    LineTooLong,
}

impl RuleError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Host(_) => "invalid_host",
            Self::Url(UrlError::InvalidScheme) => "unsupported_scheme",
            Self::Url(UrlError::InvalidAuthority) => "invalid_authority",
            Self::Url(UrlError::InvalidPort) => "invalid_port",
            Self::Url(UrlError::InvalidPath) => "invalid_path",
            Self::Url(UrlError::InvalidEscape) => "invalid_escape",
            Self::Url(UrlError::Fragment) => "fragment_unsupported",
            Self::Url(UrlError::TooLong) | Self::LineTooLong => "line_too_long",
            Self::IpDomain => "ip_domain_unsupported",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::Host(_) => "Invalid domain name or unsupported rule syntax",
            Self::Url(error) => error.message(),
            Self::IpDomain => "IP literals are supported only in URL rules",
            Self::LineTooLong => "Rule line exceeds the byte limit",
        }
    }
}

impl UrlError {
    fn message(self) -> &'static str {
        match self {
            Self::TooLong => "URL exceeds the byte limit",
            Self::InvalidScheme => "Only HTTP and HTTPS URL schemes are supported",
            Self::InvalidAuthority => "Invalid URL authority",
            Self::InvalidPort => "Port must be decimal in the range 1 through 65535",
            Self::InvalidPath => "Invalid raw URL character",
            Self::InvalidEscape => "Invalid or control-byte percent escape in path",
            Self::Fragment => "Fragments cannot be filtered",
        }
    }
}

/// Fatal whole-import errors: do not apply a partial report when this is present.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportError {
    BodyTooLarge,
}

macro_rules! error_display {
    ($type:ty, $message:expr) => {
        impl fmt::Display for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(($message)(*self))
            }
        }
        impl std::error::Error for $type {}
    };
}
error_display!(HostError, |_: HostError| "Invalid or ambiguous host");
error_display!(UrlError, UrlError::message);
error_display!(RuleError, RuleError::message);
error_display!(
    ImportError,
    |_: ImportError| "Import exceeds the byte limit"
);

/// One accepted unique rule, retaining its original 1-based line number.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedRule {
    pub line: usize,
    pub rule: Rule,
}

/// Safe line-specific diagnostic, without echoing URLs or credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleDiagnostic {
    pub line: usize,
    pub code: &'static str,
    pub message: &'static str,
}

/// Duplicate membership within this import, pointing to the first accepted line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DuplicateRule {
    pub line: usize,
    pub original_line: usize,
}

/// An import has no persistence/publication side effects. Valid lines survive malformed ones.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImportReport {
    pub accepted: Vec<AcceptedRule>,
    pub malformed: Vec<RuleDiagnostic>,
    pub duplicates: Vec<DuplicateRule>,
    pub ignored_lines: usize,
    pub fatal_error: Option<ImportError>,
}

/// Normalize IDNA UTS #46 non-transitionally, with STD3, hyphen and DNS-length checks.
/// One root dot (including mapped Unicode dot separators) is removed. No resolution occurs.
pub fn normalize_host(input: &str) -> Result<NormalizedHost, HostError> {
    if input.len() > MAX_RULE_LINE_BYTES {
        return Err(HostError::TooLong);
    }
    if input
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '\u{feff}')
    {
        return Err(HostError::InvalidName);
    }
    if input.starts_with('[') {
        return input
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .and_then(|ip| ip.parse::<Ipv6Addr>().ok())
            .map(NormalizedHost::Ipv6)
            .ok_or(HostError::InvalidIp);
    }
    let ascii = idna::uts46::Uts46::new()
        .to_ascii(
            input.as_bytes(),
            idna::AsciiDenyList::STD3,
            idna::uts46::Hyphens::Check,
            idna::uts46::DnsLength::VerifyAllowRootDot,
        )
        .map_err(|_| HostError::InvalidName)?;
    let name = ascii
        .strip_suffix('.')
        .unwrap_or(&ascii)
        .to_ascii_lowercase();
    if let Ok(ip) = name.parse::<Ipv4Addr>() {
        if input != ip.to_string() {
            return Err(HostError::InvalidIp);
        }
        return Ok(NormalizedHost::Ipv4(ip));
    }
    // A numeric final label can trigger IPv4 reinterpretation in downstream URL stacks.
    let last = name.rsplit('.').next().unwrap_or("");
    if last.bytes().all(|b| b.is_ascii_digit())
        || last
            .strip_prefix("0x")
            .is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(HostError::InvalidIp);
    }
    Ok(NormalizedHost::Dns(DomainName(name)))
}

/// Normalize an HTTP(S) request/rule URL. Queries are ignored; fragments are rejected.
/// This deliberately does not use browser URL heuristics or decode reserved path bytes.
pub fn normalize_url(input: &str) -> Result<NormalizedUrl, UrlError> {
    validate_url_text(input)?;
    let (scheme, rest) = input.split_once("://").ok_or(UrlError::InvalidScheme)?;
    let (scheme, default_port) = if scheme.eq_ignore_ascii_case("http") {
        (HttpScheme::Http, 80)
    } else if scheme.eq_ignore_ascii_case("https") {
        (HttpScheme::Https, 443)
    } else {
        return Err(UrlError::InvalidScheme);
    };
    let boundary = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = normalize_authority(&rest[..boundary], Some(default_port))?;
    let path = rest[boundary..].split('?').next().unwrap_or("");
    Ok(NormalizedUrl {
        scheme,
        host: authority.host,
        port: authority.port,
        path: normalize_path(path)?,
    })
}

fn validate_url_text(input: &str) -> Result<(), UrlError> {
    if input.len() > MAX_RULE_LINE_BYTES {
        return Err(UrlError::TooLong);
    }
    if input.contains('#') {
        return Err(UrlError::Fragment);
    }
    if input
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
    {
        return Err(UrlError::InvalidPath);
    }
    Ok(())
}

/// Parse a host/port authority. `None` requires an explicit port, as CONNECT does.
pub fn normalize_authority(
    input: &str,
    default_port: Option<u16>,
) -> Result<NormalizedAuthority, UrlError> {
    validate_url_text(input)?;
    if input.is_empty() || input.contains(['/', '?', '@', '%', '*']) {
        return Err(UrlError::InvalidAuthority);
    }
    if default_port == Some(0) {
        return Err(UrlError::InvalidPort);
    }
    let (host, port) = if input.starts_with('[') {
        let end = input.find(']').ok_or(UrlError::InvalidAuthority)?;
        let tail = &input[end + 1..];
        let port = if tail.is_empty() {
            None
        } else {
            Some(tail.strip_prefix(':').ok_or(UrlError::InvalidAuthority)?)
        };
        (&input[..=end], port)
    } else {
        match input.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (input, None),
        }
    };
    let port = match port {
        Some(raw) => {
            if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
                return Err(UrlError::InvalidPort);
            }
            raw.parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or(UrlError::InvalidPort)?
        }
        None => default_port.ok_or(UrlError::InvalidPort)?,
    };
    Ok(NormalizedAuthority {
        host: normalize_host(host).map_err(|_| UrlError::InvalidAuthority)?,
        port,
    })
}

fn unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn push_escape(output: &mut String, byte: u8) {
    const HEX: &[u8] = b"0123456789ABCDEF";
    output.push('%');
    output.push(HEX[(byte >> 4) as usize] as char);
    output.push(HEX[(byte & 15) as usize] as char);
}

fn normalize_path(input: &str) -> Result<String, UrlError> {
    if input.is_empty() {
        return Ok("/".into());
    }
    if !input.starts_with('/') {
        return Err(UrlError::InvalidPath);
    }
    let bytes = input.as_bytes();
    let mut canonical = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            let hi = bytes.get(i + 1).and_then(|b| (*b as char).to_digit(16));
            let lo = bytes.get(i + 2).and_then(|b| (*b as char).to_digit(16));
            let byte = match (hi, lo) {
                (Some(hi), Some(lo)) => (hi * 16 + lo) as u8,
                _ => return Err(UrlError::InvalidEscape),
            };
            if byte.is_ascii_control() {
                return Err(UrlError::InvalidEscape);
            }
            if unreserved(byte) {
                canonical.push(byte as char);
            } else {
                push_escape(&mut canonical, byte);
            }
            i += 3;
            continue;
        }
        if !b.is_ascii() {
            push_escape(&mut canonical, b);
        } else if unreserved(b) || b"!$&'()*+,;=:@/".contains(&b) {
            canonical.push(b as char);
        } else {
            return Err(UrlError::InvalidPath);
        }
        i += 1;
    }
    // Equivalent to RFC 3986 remove_dot_segments for absolute paths. Empty segments
    // are real entries: a preceding repeated slash must survive unless '..' removes it.
    let mut stack = Vec::new();
    let mut segments = canonical[1..].split('/').peekable();
    while let Some(segment) = segments.next() {
        match segment {
            "." | ".." => {
                if segment == ".." {
                    stack.pop();
                }
                if segments.peek().is_none() {
                    stack.push("");
                }
            }
            _ => stack.push(segment),
        }
    }
    Ok(format!("/{}", stack.join("/")))
}

/// Parse one provenance group's UTF-8 text, retaining first occurrences and line diagnostics.
/// Empty input is a valid empty report. An oversized body is rejected without partial output.
pub fn parse_blocklist(input: &str) -> ImportReport {
    if input.len() > MAX_IMPORT_BYTES {
        return ImportReport {
            fatal_error: Some(ImportError::BodyTooLarge),
            ..ImportReport::default()
        };
    }
    let input = input.strip_prefix('\u{feff}').unwrap_or(input);
    let mut report = ImportReport::default();
    let mut seen = HashMap::new();
    for (index, raw) in input.split_inclusive('\n').enumerate() {
        let line = index + 1;
        let raw = match raw.strip_suffix('\n') {
            Some(raw) => raw.strip_suffix('\r').unwrap_or(raw),
            None => raw,
        };
        let text = raw.trim_matches([' ', '\t']);
        let parsed = if raw.len() > MAX_RULE_LINE_BYTES {
            Err(RuleError::LineTooLong)
        } else if text.is_empty() || text.starts_with('#') {
            report.ignored_lines += 1;
            continue;
        } else {
            Rule::parse(text)
        };
        match parsed {
            Ok(rule) => match seen.entry(rule.clone()) {
                std::collections::hash_map::Entry::Occupied(original) => {
                    report.duplicates.push(DuplicateRule {
                        line,
                        original_line: *original.get(),
                    });
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(line);
                    report.accepted.push(AcceptedRule { line, rule });
                }
            },
            Err(error) => report.malformed.push(RuleDiagnostic {
                line,
                code: error.code(),
                message: error.message(),
            }),
        }
    }
    report
}
