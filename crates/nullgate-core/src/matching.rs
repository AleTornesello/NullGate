//! Immutable policy indexes and bounded wildcard matching.

use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::{DomainName, HttpScheme, MAX_RULES, NormalizedHost, NormalizedUrl, Rule};

/// A candidate policy cannot exceed its distinct-rule budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompileError {
    TooManyRules,
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Policy exceeds the unique rule limit")
    }
}
impl std::error::Error for CompileError {}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct UrlKey(HttpScheme, NormalizedHost, u16);

#[derive(Clone, Copy, Debug)]
enum Token {
    Byte(u8),
    Star,
}

#[derive(Clone, Debug)]
struct Pattern {
    tokens: Vec<Token>,
    parent: Option<Vec<Token>>,
}

impl Pattern {
    fn compile(path: &str) -> Self {
        Self {
            tokens: tokenize(path),
            parent: path.strip_suffix("/*").map(tokenize),
        }
    }

    fn matches(&self, path: &str) -> bool {
        wildcard_match(&self.tokens, path.as_bytes())
            || self
                .parent
                .as_ref()
                .is_some_and(|parent| wildcard_match(parent, path.as_bytes()))
    }
}

fn tokenize(pattern: &str) -> Vec<Token> {
    let mut tokens = Vec::with_capacity(pattern.len());
    for byte in pattern.bytes() {
        if byte == b'*' {
            if !matches!(tokens.last(), Some(Token::Star)) {
                tokens.push(Token::Star);
            }
        } else {
            tokens.push(Token::Byte(byte));
        }
    }
    tokens
}

// Match a literal byte or save the latest star. On mismatch, extend that star by
// one byte and retry its suffix. No recursion or exponential branch exploration:
// each retry advances star_end, with at most pattern.len() comparisons per byte.
fn wildcard_match(pattern: &[Token], path: &[u8]) -> bool {
    let (mut p, mut s) = (0, 0);
    let (mut star, mut star_end) = (None, 0);
    while s < path.len() {
        match pattern.get(p) {
            Some(Token::Byte(byte)) if *byte == path[s] => {
                p += 1;
                s += 1;
            }
            Some(Token::Star) => {
                star = Some(p);
                star_end = s;
                p += 1;
            }
            _ => match star {
                Some(position) => {
                    star_end += 1;
                    s = star_end;
                    p = position + 1;
                }
                None => return false,
            },
        }
    }
    while matches!(pattern.get(p), Some(Token::Star)) {
        p += 1;
    }
    p == pattern.len()
}

/// An immutable union of verified rules, with independent domain, URL and inspection indexes.
#[derive(Clone, Debug, Default)]
pub struct RuleSet {
    exact: HashSet<DomainName>,
    subdomains: HashSet<DomainName>,
    urls: HashMap<UrlKey, Vec<Pattern>>,
    inspection: HashSet<NormalizedHost>,
    count: usize,
}

impl RuleSet {
    /// Compile a global union. Duplicate typed canonical rules consume only one slot.
    pub fn compile(rules: impl IntoIterator<Item = Rule>) -> Result<Self, CompileError> {
        let mut set = Self::default();
        let mut unique = HashSet::new();
        for rule in rules {
            if !unique.insert(rule.clone()) {
                continue;
            }
            if unique.len() > MAX_RULES {
                return Err(CompileError::TooManyRules);
            }
            match rule {
                Rule::ExactDomain(name) => {
                    set.exact.insert(name);
                }
                Rule::Subdomains(name) => {
                    set.subdomains.insert(name);
                }
                Rule::Url(pattern) => {
                    let url = pattern.0;
                    if url.scheme == HttpScheme::Https {
                        set.inspection.insert(url.host.clone());
                    }
                    set.urls
                        .entry(UrlKey(url.scheme, url.host, url.port))
                        .or_default()
                        .push(Pattern::compile(&url.path));
                }
            }
        }
        set.count = unique.len();
        Ok(set)
    }

    /// Match **only** domain rules, suitable for DNS. URL rules never enter this index.
    pub fn blocks_domain(&self, host: &NormalizedHost) -> bool {
        let NormalizedHost::Dns(name) = host else {
            return false;
        };
        if self.exact.contains(name) {
            return true;
        }
        let mut suffix = name.as_str();
        while let Some((_, rest)) = suffix.split_once('.') {
            // The loop starts at the first parent: wildcard never includes its apex.
            if self.subdomains.contains(rest) {
                return true;
            }
            suffix = rest;
        }
        false
    }

    /// Apply whole-domain blocking, then scheme/host/port/path URL blocking.
    pub fn blocks_url(&self, url: &NormalizedUrl) -> bool {
        self.blocks_domain(&url.host)
            || self
                .urls
                .get(&UrlKey(url.scheme, url.host.clone(), url.port))
                .is_some_and(|patterns| patterns.iter().any(|pattern| pattern.matches(&url.path)))
    }

    /// Exact HTTPS-rule hosts only. A domain-blocked host must be rejected, not decrypted.
    /// Selection is host-wide, while URL enforcement retains each rule's port.
    pub fn requires_inspection(&self, host: &NormalizedHost) -> bool {
        !self.blocks_domain(host) && self.inspection.contains(host)
    }

    /// Number of distinct canonical rules, including redundant-but-distinct patterns.
    pub fn len(&self) -> usize {
        self.count
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
