//! Shared, deterministic rule parsing and matching for NullGate.
//!
//! Parsing performs no I/O. Domain, URL and inspection indexes remain separate.

mod matching;
mod rules;

pub use matching::{CompileError, RuleSet};
pub use rules::*;
