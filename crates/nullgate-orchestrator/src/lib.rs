//! Proxy lifecycle and rule coordination for NullGate.
//!
//! The policy coordinator implements bounded durable saves and atomic publication.
//! Proxy services and executable startup are not wired yet.

//!
//! ```no_run
//! use nullgate_core::{Mutation, PolicyManagement};
//! use nullgate_orchestrator::{PolicyCoordinator, PolicyOptions};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let coordinator = PolicyCoordinator::open("data/nullgate.sqlite3".into(), PolicyOptions::default()).await?;
//!     let writer = coordinator.handle();
//!     let revision = writer.subscribe().current()?.revision();
//!     let result = writer.save(revision, Mutation::CreateList { name: "Local rules".into() }).await?;
//!     assert_eq!(writer.subscribe().current()?.revision(), result.snapshot.revision());
//!     coordinator.shutdown().await?;
//!     Ok(())
//! }
//! ```

pub mod policy;
pub use policy::{PolicyCoordinator, PolicyHandle, PolicyOptions};
