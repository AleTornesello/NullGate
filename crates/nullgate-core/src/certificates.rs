//! Public certificate capability. It carries no signing or private-storage operations.
use std::sync::Arc;
pub trait PublicCaCertificate: Send + Sync {
    fn certificate_pem(&self) -> Arc<[u8]>;
}
