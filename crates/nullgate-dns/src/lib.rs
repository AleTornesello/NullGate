//! Cancellable UDP/TCP DNS filtering over immutable policy subscriptions.
//!
//! Bind both configured listeners before reporting readiness. Each query captures current
//! policy; only domain rules affect DNS. The orchestrator supervises this service for the executable.
//!
//! ```no_run
//! use nullgate_core::{DnsConfig, PolicySubscription, ServiceFailure};
//! use nullgate_dns::{DnsOptions, DnsService};
//! use tokio_util::sync::CancellationToken;
//!
//! # async fn example(config: DnsConfig, policy: PolicySubscription) -> Result<(), ServiceFailure> {
//! let cancel = CancellationToken::new();
//! let service = DnsService::start(config, policy, DnsOptions::default(), cancel.clone()).await?;
//! let ready = service.monitor().current();
//! // Pass the monitor to supervision; the bound addresses can use ephemeral test ports.
//! cancel.cancel();
//! service.shutdown().await?;
//! # Ok(())
//! # }
//! ```
pub mod server;
pub use server::{DnsOptions, DnsService};
mod upstream;
