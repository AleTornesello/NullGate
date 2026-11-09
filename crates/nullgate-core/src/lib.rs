//! Shared rule engine, startup configuration and durable blocklist repository for NullGate.
//!
//! Rule parsing performs no I/O. Domain, URL and inspection indexes remain separate.
//! [`AppConfig::load`] reads versioned TOML. [`SqliteRepository`] stores revisioned,
//! source-aware blocklists; its blocking methods must run off async reactor threads.
//! A [`StorageCommit`] represents durable storage, not live policy publication.
//!
//! ```no_run
//! use nullgate_core::{AppConfig, BlocklistRepository, Mutation, SqliteRepository};
//! let config = AppConfig::load(std::path::Path::new("config/nullgate.toml"))?;
//! let mut repository = SqliteRepository::open(config.database_path())?;
//! let current = repository.snapshot()?;
//! let commit = repository.apply(current.revision, Mutation::CreateList { name: "Local rules".into() })?;
//! assert_eq!(commit.snapshot.revision, current.revision + 1);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod matching;
mod rules;

pub use matching::{CompileError, RuleSet};
pub use rules::*;

pub mod blocklists;
pub mod config;
pub mod storage;
pub use blocklists::*;
pub use config::*;
pub use storage::*;
