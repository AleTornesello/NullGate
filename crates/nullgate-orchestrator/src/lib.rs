//! Proxy lifecycle and rule coordination for NullGate.
//!
//! The policy coordinator implements bounded durable saves and atomic publication.
//! Application startup composes policy ownership and supervised DNS/HTTP services.

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

pub mod supervisor;
pub use supervisor::{
    ManagedProxy, ProxyFactory, ProxyHealth, ProxyPhase, RuntimeError, RuntimeMonitor,
    RuntimePhase, RuntimeStatus, Supervisor,
};

pub mod application;
pub use application::Application;
pub use nullgate_core::ServiceTransport;
pub use nullgate_core::{AppConfig, ConfigError};

pub mod provision;
pub use provision::provision_local_administrator;
