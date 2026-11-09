//! Blocking SQLite repository. The async orchestrator must call it on a bounded blocking worker.

use crate::blocklists::canonical_key;
use crate::{
    Blocklist, BlocklistRepository, BlocklistSource, ImportOutcome, ImportReport, ImportSummary,
    Mutation, RepositorySnapshot, Rule, RuleEntry, SourceKind, StorageCommit, StoredDiagnostic,
    normalize_url, parse_blocklist,
};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;
use std::time::Duration;

/// Safe errors never retain SQL text, source URLs, input lines or database diagnostic values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageError {
    Open,
    Database,
    Busy,
    ReadOnly,
    Corrupt,
    UnsupportedSchema(i64),
    Conflict { expected: u64, actual: u64 },
    InvalidName,
    DuplicateName,
    InvalidSource,
    InvalidTimestamp,
    NotFound,
    NoValidRules,
    ImportTooLarge,
    InvalidUtf8,
    Capacity,
    RevisionExhausted,
}
impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict { expected, actual } => write!(f, "Revision conflict: expected {expected}, current {actual}"),
            Self::UnsupportedSchema(version) => write!(f, "Unsupported database schema {version}; expected 1"),
            other => f.write_str(match other {
                Self::Open => "Cannot open database or data directory",
                Self::Database => "Database operation failed; no edit was committed",
                Self::Busy => "Database is busy; retry using the current revision",
                Self::ReadOnly => "Database is read-only",
                Self::Corrupt => "Database state is corrupt; recover from a verified backup",
                Self::InvalidName => "Names must be nonempty, trimmed, at most 128 UTF-8 bytes and contain no controls",
                Self::DuplicateName => "A blocklist with this name already exists",
                Self::InvalidSource => "Invalid source metadata or operation for this source kind",
                Self::InvalidTimestamp => "Import timestamp must be nonnegative Unix seconds",
                Self::NotFound => "Blocklist, source or membership not found",
                Self::NoValidRules => "Replacement has no valid rules; previous entries were preserved",
                Self::ImportTooLarge => "Import exceeds the byte limit",
                Self::InvalidUtf8 => "Import must be UTF-8",
                Self::Capacity => "Candidate policy exceeds the unique rule limit",
                Self::RevisionExhausted => "Repository revision or identifier space exhausted",
                Self::Conflict { .. } | Self::UnsupportedSchema(_) => unreachable!(),
            }),
        }
    }
}
impl std::error::Error for StorageError {}
impl From<rusqlite::Error> for StorageError {
    fn from(error: rusqlite::Error) -> Self {
        match error.sqlite_error_code() {
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
                Self::Busy
            }
            Some(rusqlite::ErrorCode::ReadOnly) => Self::ReadOnly,
            Some(rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase) => {
                Self::Corrupt
            }
            _ => Self::Database,
        }
    }
}

/// A single mutable SQLite connection, with WAL, foreign keys and FULL durability.
/// This API is synchronous and is not a live policy publisher.
#[derive(Debug)]
pub struct SqliteRepository {
    connection: Connection,
}
impl SqliteRepository {
    /// Create schema 1 if absent; refuse unknown schemas and invalid persisted rules.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        Self::open_mode(path.as_ref(), false)
    }
    /// Read an existing schema without attempting migration or changing its journal mode.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        Self::open_mode(path.as_ref(), true)
    }
    fn open_mode(path: &Path, read_only: bool) -> Result<Self, StorageError> {
        if path.as_os_str().is_empty() || path == Path::new(":memory:") {
            return Err(StorageError::Open);
        }
        if !read_only {
            if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
                let mut builder = std::fs::DirBuilder::new();
                builder.recursive(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder.create(parent).map_err(|_| StorageError::Open)?;
            }
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(path) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(StorageError::Open),
            }
        }
        let flags = if read_only {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        };
        let mut connection = Connection::open_with_flags(path, flags)?;
        connection.busy_timeout(Duration::from_millis(100))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version != 1 && (version != 0 || read_only) {
            return Err(StorageError::UnsupportedSchema(version));
        }
        if version == 0 {
            let tables: i64 = connection.query_row("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'", [], |row| row.get(0))?;
            if tables != 0 {
                return Err(StorageError::UnsupportedSchema(0));
            }
        }
        if !read_only {
            let mode: String =
                connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
            if !mode.eq_ignore_ascii_case("wal") {
                let mode: String =
                    connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
                if !mode.eq_ignore_ascii_case("wal") {
                    return Err(StorageError::Database);
                }
            }
            connection.pragma_update(None, "synchronous", "FULL")?;
        }
        if version == 0 {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            // Recheck under the writer lock if two initializers opened an empty file.
            let locked_version: i64 =
                tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
            if locked_version == 0 {
                tx.execute_batch(SCHEMA)?;
            } else if locked_version != 1 {
                return Err(StorageError::UnsupportedSchema(locked_version));
            }
            tx.commit()?;
        }
        let mut repository = Self { connection };
        repository.snapshot()?;
        Ok(repository)
    }
    fn read_state(&mut self) -> Result<(RepositorySnapshot, i64), StorageError> {
        let tx = self.connection.transaction()?;
        let state = read_state(&tx)?;
        tx.commit()?;
        Ok(state)
    }
}

impl BlocklistRepository for SqliteRepository {
    fn snapshot(&mut self) -> Result<RepositorySnapshot, StorageError> {
        self.read_state().map(|(snapshot, _)| snapshot)
    }

    fn apply(
        &mut self,
        expected_revision: u64,
        mutation: Mutation,
    ) -> Result<StorageCommit, StorageError> {
        let (before, mut next_id) = self.read_state()?;
        if before.revision != expected_revision {
            return Err(StorageError::Conflict {
                expected: expected_revision,
                actual: before.revision,
            });
        }
        let mut candidate = before.clone();
        let report = edit(&mut candidate, &mut next_id, mutation)?;
        let rules = candidate.compile().map_err(|_| StorageError::Capacity)?;
        candidate.revision = expected_revision
            .checked_add(1)
            .filter(|rev| *rev <= i64::MAX as u64)
            .ok_or(StorageError::RevisionExhausted)?;
        // Compilation is finished before taking the write lock. Another process may
        // have committed during compilation, so verify the base revision again here.
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let actual: i64 = tx.query_row("SELECT revision FROM state WHERE id = 1", [], |row| {
            row.get(0)
        })?;
        let actual = u64::try_from(actual).map_err(|_| StorageError::Corrupt)?;
        if actual != expected_revision {
            return Err(StorageError::Conflict {
                expected: expected_revision,
                actual,
            });
        }
        persist_diff(&tx, &before, &candidate)?;
        tx.execute(
            "UPDATE state SET revision = ?1, next_id = ?2 WHERE id = 1",
            params![candidate.revision as i64, next_id],
        )?;
        tx.commit()?;
        Ok(StorageCommit {
            snapshot: candidate,
            rules,
            import_report: report,
        })
    }
}

const SCHEMA: &str = "
CREATE TABLE state (id INTEGER PRIMARY KEY CHECK (id = 1), revision INTEGER NOT NULL CHECK (revision >= 0), next_id INTEGER NOT NULL CHECK (next_id > 0));
INSERT INTO state VALUES (1, 0, 1);
CREATE TABLE lists (id INTEGER PRIMARY KEY CHECK (id > 0), name TEXT NOT NULL UNIQUE);
CREATE TABLE sources (id INTEGER PRIMARY KEY CHECK (id > 0), list_id INTEGER NOT NULL REFERENCES lists(id) ON DELETE CASCADE, kind TEXT NOT NULL, last_attempt INTEGER, last_success INTEGER, report TEXT);
CREATE TABLE entries (source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE, canonical_key TEXT NOT NULL, input TEXT NOT NULL, PRIMARY KEY (source_id, canonical_key));
PRAGMA user_version = 1;";

fn valid_name(name: &str) -> Result<(), StorageError> {
    if name.is_empty()
        || name.len() > 128
        || name.trim() != name
        || name.chars().any(char::is_control)
    {
        return Err(StorageError::InvalidName);
    }
    Ok(())
}
fn valid_source(kind: &SourceKind) -> Result<(), StorageError> {
    match kind {
        SourceKind::Manual => Ok(()),
        SourceKind::File { filename } => {
            valid_name(filename).map_err(|_| StorageError::InvalidSource)
        }
        SourceKind::Remote { url } => normalize_url(url)
            .map(|_| ())
            .map_err(|_| StorageError::InvalidSource),
    }
}
fn source_mut(
    snapshot: &mut RepositorySnapshot,
    id: i64,
) -> Result<&mut BlocklistSource, StorageError> {
    snapshot
        .lists
        .iter_mut()
        .flat_map(|list| &mut list.sources)
        .find(|source| source.id == id)
        .ok_or(StorageError::NotFound)
}
fn allocate(next: &mut i64) -> Result<i64, StorageError> {
    let id = *next;
    *next = next.checked_add(1).ok_or(StorageError::RevisionExhausted)?;
    Ok(id)
}
fn check_time(at: i64) -> Result<(), StorageError> {
    if at < 0 {
        Err(StorageError::InvalidTimestamp)
    } else {
        Ok(())
    }
}

fn edit(
    snapshot: &mut RepositorySnapshot,
    next_id: &mut i64,
    mutation: Mutation,
) -> Result<Option<ImportReport>, StorageError> {
    match mutation {
        Mutation::CreateList { name } => {
            valid_name(&name)?;
            if snapshot.lists.iter().any(|list| list.name == name) {
                return Err(StorageError::DuplicateName);
            }
            snapshot.lists.push(Blocklist {
                id: allocate(next_id)?,
                name,
                sources: Vec::new(),
            });
        }
        Mutation::RenameList { list_id, name } => {
            valid_name(&name)?;
            if snapshot
                .lists
                .iter()
                .any(|list| list.name == name && list.id != list_id)
            {
                return Err(StorageError::DuplicateName);
            }
            snapshot
                .lists
                .iter_mut()
                .find(|list| list.id == list_id)
                .ok_or(StorageError::NotFound)?
                .name = name;
        }
        Mutation::DeleteList { list_id } => {
            let index = snapshot
                .lists
                .iter()
                .position(|list| list.id == list_id)
                .ok_or(StorageError::NotFound)?;
            snapshot.lists.remove(index);
        }
        Mutation::AddSource { list_id, kind } => {
            valid_source(&kind)?;
            let list = snapshot
                .lists
                .iter_mut()
                .find(|list| list.id == list_id)
                .ok_or(StorageError::NotFound)?;
            list.sources.push(BlocklistSource {
                id: allocate(next_id)?,
                kind,
                entries: Vec::new(),
                last_attempt: None,
                last_success: None,
                last_report: None,
            });
        }
        Mutation::DeleteSource { source_id } => {
            let list = snapshot
                .lists
                .iter_mut()
                .find(|list| list.sources.iter().any(|source| source.id == source_id))
                .ok_or(StorageError::NotFound)?;
            list.sources.retain(|source| source.id != source_id);
        }
        Mutation::ClearSource { source_id } => {
            source_mut(snapshot, source_id)?.entries.clear();
        }
        Mutation::RemoveRule { source_id, rule } => {
            let source = source_mut(snapshot, source_id)?;
            let index = source
                .entries
                .iter()
                .position(|entry| entry.rule == rule)
                .ok_or(StorageError::NotFound)?;
            source.entries.remove(index);
        }
        Mutation::Import {
            source_id,
            text,
            at,
        } => {
            return import_into(source_mut(snapshot, source_id)?, &text, at, false).map(Some);
        }
        Mutation::ReplaceEntries {
            source_id,
            text,
            at,
        } => {
            return import_into(source_mut(snapshot, source_id)?, &text, at, true).map(Some);
        }
        Mutation::RecordFetchFailure { source_id, at } => {
            check_time(at)?;
            let source = source_mut(snapshot, source_id)?;
            if !matches!(source.kind, SourceKind::Remote { .. }) {
                return Err(StorageError::InvalidSource);
            }
            source.last_attempt = Some(at);
            source.last_report = Some(ImportSummary {
                outcome: ImportOutcome::FetchFailed,
                accepted: 0,
                duplicates: 0,
                malformed: 0,
                ignored: 0,
                added: 0,
                removed: 0,
                diagnostics: Vec::new(),
            });
        }
    }
    Ok(None)
}

fn import_into(
    source: &mut BlocklistSource,
    text: &str,
    at: i64,
    replace: bool,
) -> Result<ImportReport, StorageError> {
    check_time(at)?;
    let remote = matches!(source.kind, SourceKind::Remote { .. });
    if remote && replace {
        return Err(StorageError::InvalidSource);
    }
    let report = parse_blocklist(text);
    if report.fatal_error.is_some() {
        return Err(StorageError::ImportTooLarge);
    }
    if replace && report.accepted.is_empty() && !report.malformed.is_empty() {
        return Err(StorageError::NoValidRules);
    }
    let outcome = if remote && report.accepted.is_empty() {
        ImportOutcome::NoValidRules
    } else {
        ImportOutcome::Applied
    };
    let before: HashSet<_> = source
        .entries
        .iter()
        .map(|entry| entry.rule.clone())
        .collect();
    if outcome == ImportOutcome::Applied {
        if remote || replace {
            source.entries.clear();
        }
        let mut present: HashSet<_> = source
            .entries
            .iter()
            .map(|entry| entry.rule.clone())
            .collect();
        let lines: Vec<_> = text
            .strip_prefix('\u{feff}')
            .unwrap_or(text)
            .lines()
            .collect();
        for accepted in &report.accepted {
            if present.insert(accepted.rule.clone()) {
                let raw = lines[accepted.line - 1].trim_matches([' ', '\t']);
                let input = if matches!(accepted.rule, Rule::Url(_)) {
                    raw.split('?').next().unwrap_or(raw)
                } else {
                    raw
                };
                source.entries.push(RuleEntry {
                    rule: accepted.rule.clone(),
                    input: input.into(),
                });
            }
        }
        source
            .entries
            .sort_by_cached_key(|entry| canonical_key(&entry.rule));
        source.last_success = Some(at);
    }
    let after: HashSet<_> = source
        .entries
        .iter()
        .map(|entry| entry.rule.clone())
        .collect();
    source.last_attempt = Some(at);
    source.last_report = Some(ImportSummary {
        outcome,
        accepted: report.accepted.len(),
        duplicates: report.duplicates.len(),
        malformed: report.malformed.len(),
        ignored: report.ignored_lines,
        added: after.difference(&before).count(),
        removed: before.difference(&after).count(),
        diagnostics: report
            .malformed
            .iter()
            .take(1000)
            .map(|diagnostic| StoredDiagnostic {
                line: diagnostic.line,
                code: diagnostic.code.into(),
                message: diagnostic.message.into(),
            })
            .collect(),
    });
    Ok(report)
}

fn read_state(connection: &Connection) -> Result<(RepositorySnapshot, i64), StorageError> {
    let has_orphans: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
        [],
        |row| row.get(0),
    )?;
    if has_orphans {
        return Err(StorageError::Corrupt);
    }
    let (revision, next_id): (i64, i64) = connection.query_row(
        "SELECT revision, next_id FROM state WHERE id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let revision = u64::try_from(revision).map_err(|_| StorageError::Corrupt)?;
    if next_id <= 0 {
        return Err(StorageError::Corrupt);
    }
    let mut snapshot = RepositorySnapshot {
        revision,
        lists: Vec::new(),
    };
    let mut list_statement = connection.prepare("SELECT id, name FROM lists ORDER BY id")?;
    let lists = list_statement.query_map([], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut max_id = 0;
    for row in lists {
        let (id, name) = row?;
        if id <= 0 {
            return Err(StorageError::Corrupt);
        }
        valid_name(&name).map_err(|_| StorageError::Corrupt)?;
        max_id = max_id.max(id);
        let mut list = Blocklist {
            id,
            name,
            sources: Vec::new(),
        };
        let mut source_statement = connection.prepare("SELECT id, kind, last_attempt, last_success, report FROM sources WHERE list_id = ?1 ORDER BY id")?;
        let sources = source_statement.query_map([id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })?;
        for row in sources {
            let (id, kind, last_attempt, last_success, report) = row?;
            if id <= 0
                || last_attempt.is_some_and(|at| at < 0)
                || last_success.is_some_and(|at| at < 0)
            {
                return Err(StorageError::Corrupt);
            }
            max_id = max_id.max(id);
            let kind = toml::from_str(&kind).map_err(|_| StorageError::Corrupt)?;
            valid_source(&kind).map_err(|_| StorageError::Corrupt)?;
            let last_report: Option<ImportSummary> = report
                .map(|text| toml::from_str(&text))
                .transpose()
                .map_err(|_| StorageError::Corrupt)?;
            if let Some(report) = &last_report
                && (report.diagnostics.len() > 1000
                    || report.diagnostics.len() > report.malformed
                    || report
                        .diagnostics
                        .iter()
                        .any(|diagnostic| diagnostic.line == 0))
            {
                return Err(StorageError::Corrupt);
            }
            if last_report.is_some() != last_attempt.is_some()
                || (last_success.is_some() && last_attempt.is_none())
            {
                return Err(StorageError::Corrupt);
            }
            let mut source = BlocklistSource {
                id,
                kind,
                entries: Vec::new(),
                last_attempt,
                last_success,
                last_report,
            };
            let mut entry_statement = connection.prepare("SELECT canonical_key, input FROM entries WHERE source_id = ?1 ORDER BY canonical_key")?;
            let entries = entry_statement.query_map([id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in entries {
                let (key, input) = row?;
                let rule = Rule::parse(&input).map_err(|_| StorageError::Corrupt)?;
                if canonical_key(&rule) != key
                    || (matches!(rule, Rule::Url(_)) && input.contains('?'))
                {
                    return Err(StorageError::Corrupt);
                }
                source.entries.push(RuleEntry { rule, input });
            }
            list.sources.push(source);
        }
        snapshot.lists.push(list);
    }
    if next_id <= max_id {
        return Err(StorageError::Corrupt);
    }
    snapshot.compile().map_err(|_| StorageError::Corrupt)?;
    Ok((snapshot, next_id))
}

fn persist_diff(
    connection: &Connection,
    before: &RepositorySnapshot,
    after: &RepositorySnapshot,
) -> Result<(), StorageError> {
    let old_lists: HashMap<_, _> = before.lists.iter().map(|list| (list.id, list)).collect();
    let new_lists: HashSet<_> = after.lists.iter().map(|list| list.id).collect();
    for list in &before.lists {
        if !new_lists.contains(&list.id) {
            connection.execute("DELETE FROM lists WHERE id = ?1", [list.id])?;
        }
    }
    for list in &after.lists {
        match old_lists.get(&list.id) {
            None => {
                connection.execute(
                    "INSERT INTO lists (id, name) VALUES (?1, ?2)",
                    params![list.id, list.name],
                )?;
            }
            Some(old) if old.name != list.name => {
                connection.execute(
                    "UPDATE lists SET name = ?1 WHERE id = ?2",
                    params![list.name, list.id],
                )?;
            }
            _ => {}
        }
    }
    let old_sources: HashMap<_, _> = before
        .lists
        .iter()
        .flat_map(|list| &list.sources)
        .map(|source| (source.id, source))
        .collect();
    let new_sources: HashSet<_> = after
        .lists
        .iter()
        .flat_map(|list| &list.sources)
        .map(|source| source.id)
        .collect();
    for source in old_sources.values() {
        if !new_sources.contains(&source.id) {
            connection.execute("DELETE FROM sources WHERE id = ?1", [source.id])?;
        }
    }
    for list in &after.lists {
        for source in &list.sources {
            let old = old_sources.get(&source.id).copied();
            if old == Some(source) {
                continue;
            }
            let kind = toml::to_string(&source.kind).map_err(|_| StorageError::Database)?;
            let report = source
                .last_report
                .as_ref()
                .map(toml::to_string)
                .transpose()
                .map_err(|_| StorageError::Database)?;
            if old.is_some() {
                connection.execute("UPDATE sources SET kind = ?1, last_attempt = ?2, last_success = ?3, report = ?4 WHERE id = ?5", params![kind, source.last_attempt, source.last_success, report, source.id])?;
            } else {
                connection.execute("INSERT INTO sources (id, list_id, kind, last_attempt, last_success, report) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![source.id, list.id, kind, source.last_attempt, source.last_success, report])?;
            }
            if old.is_none_or(|old| old.entries != source.entries) {
                connection.execute("DELETE FROM entries WHERE source_id = ?1", [source.id])?;
                let mut insert = connection.prepare(
                    "INSERT INTO entries (source_id, canonical_key, input) VALUES (?1, ?2, ?3)",
                )?;
                for entry in &source.entries {
                    insert.execute(params![source.id, canonical_key(&entry.rule), entry.input])?;
                }
            }
        }
    }
    Ok(())
}
