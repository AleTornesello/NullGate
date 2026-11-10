//! Opaque tokens, hashed persistence and browser cookie encoding.
use crate::auth::AuthError;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
pub(crate) fn random() -> Result<String, AuthError> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| AuthError::Unavailable)?;
    Ok(hex(&bytes))
}
pub(crate) fn valid(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit())
}
pub(crate) fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}
pub(crate) fn csrf(token: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"nullgate csrf v1:");
    hash.update(token.as_bytes());
    hex(&hash.finalize())
}
pub(crate) fn equal(left: &str, right: &str) -> bool {
    valid(left) && valid(right) && bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}
pub(crate) fn cookie(name: &str, token: &str, secure: bool, age: u64) -> String {
    format!(
        "{name}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={age}{}",
        if secure { "; Secure" } else { "" }
    )
}
