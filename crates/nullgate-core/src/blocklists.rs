//! Durable blocklist commands and detached repository snapshots.

use crate::{CompileError, ImportReport, Rule, RuleSet};
use serde::{Deserialize, Serialize};

/// Provenance is independent of a rule's presence in other sources.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceKind {
    Manual,
    File { filename: String },
    Remote { url: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportOutcome {
    Applied,
    NoValidRules,
    FetchFailed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredDiagnostic {
    pub line: usize,
    pub code: String,
    pub message: String,
}

/// Only the latest bounded summary is stored; full parser output is returned with a commit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportSummary {
    pub outcome: ImportOutcome,
    pub accepted: usize,
    pub duplicates: usize,
    pub malformed: usize,
    pub ignored: usize,
    pub added: usize,
    pub removed: usize,
    pub diagnostics: Vec<StoredDiagnostic>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleEntry {
    pub rule: Rule,
    pub(crate) input: String,
}
impl RuleEntry {
    pub fn input(&self) -> &str {
        &self.input
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlocklistSource {
    pub id: i64,
    pub kind: SourceKind,
    pub entries: Vec<RuleEntry>,
    pub last_attempt: Option<i64>,
    pub last_success: Option<i64>,
    pub last_report: Option<ImportSummary>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Blocklist {
    pub id: i64,
    pub name: String,
    pub sources: Vec<BlocklistSource>,
}

/// Detached consistent state at a durable revision. All lists are active.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositorySnapshot {
    pub revision: u64,
    pub lists: Vec<Blocklist>,
}
impl RepositorySnapshot {
    pub fn source(&self, id: i64) -> Option<&BlocklistSource> {
        self.lists
            .iter()
            .flat_map(|list| &list.sources)
            .find(|source| source.id == id)
    }
    pub fn compile(&self) -> Result<RuleSet, CompileError> {
        RuleSet::compile(
            self.lists
                .iter()
                .flat_map(|list| &list.sources)
                .flat_map(|source| &source.entries)
                .map(|entry| entry.rule.clone()),
        )
    }
}

/// One atomic logical edit. `at` is an administrator-service supplied Unix timestamp in seconds.
#[derive(Clone, Debug)]
pub enum Mutation {
    /// Atomically create/reuse manual/file provenance and import a valid subset.
    ImportList {
        list_id: i64,
        kind: SourceKind,
        text: String,
        at: i64,
    },
    CreateList {
        name: String,
    },
    RenameList {
        list_id: i64,
        name: String,
    },
    DeleteList {
        list_id: i64,
    },
    AddSource {
        list_id: i64,
        kind: SourceKind,
    },
    DeleteSource {
        source_id: i64,
    },
    ClearSource {
        source_id: i64,
    },
    RemoveRule {
        source_id: i64,
        rule: Rule,
    },
    Import {
        source_id: i64,
        text: String,
        at: i64,
    },
    ReplaceEntries {
        source_id: i64,
        text: String,
        at: i64,
    },
    RecordFetchFailure {
        source_id: i64,
        at: i64,
    },
}
impl Mutation {
    /// Reject invalid UTF-8 or oversized bodies before constructing an import command.
    pub fn import_bytes(
        source_id: i64,
        bytes: &[u8],
        at: i64,
    ) -> Result<Self, crate::StorageError> {
        if bytes.len() > crate::MAX_IMPORT_BYTES {
            return Err(crate::StorageError::ImportTooLarge);
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| crate::StorageError::InvalidUtf8)?
            .into();
        Ok(Self::Import {
            source_id,
            text,
            at,
        })
    }
}

/// Durable commit only; live publication belongs to the orchestrator in Task 4.
#[derive(Debug)]
pub struct StorageCommit {
    pub snapshot: RepositorySnapshot,
    pub rules: RuleSet,
    pub import_report: Option<ImportReport>,
}

/// Blocking repository API. Run it on a bounded blocking worker when integrating async services.
pub trait BlocklistRepository {
    fn snapshot(&mut self) -> Result<RepositorySnapshot, crate::StorageError>;
    fn apply(
        &mut self,
        expected_revision: u64,
        mutation: Mutation,
    ) -> Result<StorageCommit, crate::StorageError>;
}

/// Stable persisted key. Not reparsed: valid Unicode input can expand past raw-input limits.
pub(crate) fn canonical_key(rule: &Rule) -> String {
    match rule {
        Rule::ExactDomain(name) => name.as_str().into(),
        Rule::Subdomains(name) => format!("*.{}", name.as_str()),
        Rule::Url(pattern) => {
            let url = pattern.url();
            let scheme = match url.scheme() {
                crate::HttpScheme::Http => "http",
                crate::HttpScheme::Https => "https",
            };
            format!("{scheme}://{}:{}{}", url.host(), url.port(), url.path())
        }
    }
}

// Unit variants in Serde's internally tagged enums can discard extra fields.
// Use a strict wire struct, then check which fields belong to the selected kind.
impl<'de> Deserialize<'de> for SourceKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Tag {
            Manual,
            File,
            Remote,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            #[serde(rename = "type")]
            tag: Tag,
            filename: Option<String>,
            url: Option<String>,
        }
        let fields = Fields::deserialize(deserializer)?;
        match (fields.tag, fields.filename, fields.url) {
            (Tag::Manual, None, None) => Ok(Self::Manual),
            (Tag::File, Some(filename), None) => Ok(Self::File { filename }),
            (Tag::Remote, None, Some(url)) => Ok(Self::Remote { url }),
            _ => Err(serde::de::Error::custom(
                "Invalid source fields for selected type",
            )),
        }
    }
}
