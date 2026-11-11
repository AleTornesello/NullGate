//! Persistent inspection CA and bounded-lifetime leaf issuance. This module performs no interception.
mod storage;
use nullgate_core::{NormalizedHost, PublicCaCertificate};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PublicKeyData, SanType,
};
use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    sign::CertifiedKey,
};
use std::{
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use time::{Duration, OffsetDateTime};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaError {
    Storage,
    UnsafeStorage,
    Incomplete,
    Corrupt,
    Expired,
    NotYetValid,
    Clock,
    Crypto,
}
impl std::fmt::Display for CaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
 Self::Storage=>"Inspection CA storage operation failed; restore the complete offline backup before retrying",
 Self::UnsafeStorage=>"Inspection CA storage is unsafe; require a private directory and owner-only regular material file without links",
 Self::Incomplete=>"Inspection CA material is incomplete; restore the complete offline backup, never regenerate implicitly",
 Self::Corrupt=>"Inspection CA material is corrupt or mismatched; restore the complete offline backup",
 Self::Expired=>"Inspection CA expired; perform explicit offline rotation and redistribute client trust",
 Self::NotYetValid=>"Inspection CA is not yet valid; check the system clock or restore the correct backup",
 Self::Clock=>"Inspection CA clock is invalid",Self::Crypto=>"Inspection CA cryptographic operation failed",
 })
    }
}
impl std::error::Error for CaError {}
pub trait CaClock: Send + Sync {
    fn unix_seconds(&self) -> Result<i64, CaError>;
}
pub struct SystemCaClock;
impl CaClock for SystemCaClock {
    fn unix_seconds(&self) -> Result<i64, CaError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CaError::Clock)?
            .as_secs()
            .try_into()
            .map_err(|_| CaError::Clock)
    }
}
struct PublicCertificate(Arc<[u8]>);
impl PublicCaCertificate for PublicCertificate {
    fn certificate_pem(&self) -> Arc<[u8]> {
        self.0.clone()
    }
}
/// Blocking API: open/issue on bounded blocking workers. Private root material cannot be exported.
pub struct CaProvider {
    issuer: Issuer<'static, KeyPair>,
    root: CertificateDer<'static>,
    public: Arc<dyn PublicCaCertificate>,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    clock: Arc<dyn CaClock>,
}
impl std::fmt::Debug for CaProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CaProvider { signer: [REDACTED] }")
    }
}
impl CaProvider {
    pub fn open(data_dir: &Path) -> Result<Self, CaError> {
        Self::open_with_clock(data_dir, Arc::new(SystemCaClock))
    }
    pub fn open_with_clock(data_dir: &Path, clock: Arc<dyn CaClock>) -> Result<Self, CaError> {
        let now = now(clock.as_ref())?;
        let store = storage::Store::claim(data_dir)?;
        let (cert, key) = if store.fresh() {
            let mut params = CertificateParams::default();
            params.not_before = now
                .checked_sub(Duration::minutes(5))
                .ok_or(CaError::Clock)?;
            params.not_after = now
                .checked_add(Duration::days(3650))
                .ok_or(CaError::Clock)?;
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let mut name = DistinguishedName::new();
            name.push(DnType::CommonName, "NullGate Local Inspection CA");
            params.distinguished_name = name;
            let key = KeyPair::generate().map_err(|_| CaError::Crypto)?;
            let cert = params.self_signed(&key).map_err(|_| CaError::Crypto)?;
            let (cert, key) = (cert.der().to_vec(), key.serialize_der());
            store.write(&cert, &key)?;
            (cert, key)
        } else {
            store.read()?
        };
        let key = KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(key),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        )
        .map_err(|_| CaError::Corrupt)?;
        let (remaining, parsed) =
            x509_parser::parse_x509_certificate(&cert).map_err(|_| CaError::Corrupt)?;
        if !remaining.is_empty()
            || parsed.subject() != parsed.issuer()
            || parsed.public_key().raw != key.subject_public_key_info()
            || parsed.extensions_map().is_err()
        {
            return Err(CaError::Corrupt);
        }
        let constraints = parsed
            .basic_constraints()
            .map_err(|_| CaError::Corrupt)?
            .ok_or(CaError::Corrupt)?;
        let usage = parsed
            .key_usage()
            .map_err(|_| CaError::Corrupt)?
            .ok_or(CaError::Corrupt)?;
        if !constraints.value.ca
            || constraints.value.path_len_constraint != Some(0)
            || !usage.value.key_cert_sign()
        {
            return Err(CaError::Corrupt);
        }
        parsed
            .verify_signature(None)
            .map_err(|_| CaError::Corrupt)?;
        let not_before =
            OffsetDateTime::from_unix_timestamp(parsed.validity().not_before.timestamp())
                .map_err(|_| CaError::Corrupt)?;
        let not_after =
            OffsetDateTime::from_unix_timestamp(parsed.validity().not_after.timestamp())
                .map_err(|_| CaError::Corrupt)?;
        valid(now, not_before, not_after)?;
        let public = Arc::new(PublicCertificate(
            pem::encode(&pem::Pem::new("CERTIFICATE", cert.clone()))
                .into_bytes()
                .into(),
        ));
        let root = CertificateDer::from(cert);
        let issuer = Issuer::from_ca_cert_der(&root, key).map_err(|_| CaError::Corrupt)?;
        Ok(Self {
            issuer,
            root,
            public,
            not_before,
            not_after,
            clock,
        })
    }
    pub fn public_certificate(&self) -> Arc<dyn PublicCaCertificate> {
        self.public.clone()
    }
    pub fn issue(&self, host: &NormalizedHost) -> Result<Arc<CertifiedKey>, CaError> {
        let now = now(self.clock.as_ref())?;
        valid(now, self.not_before, self.not_after)?;
        let mut params = CertificateParams::default();
        params.not_before = now
            .checked_sub(Duration::minutes(5))
            .ok_or(CaError::Clock)?
            .max(self.not_before);
        params.not_after = now
            .checked_add(Duration::days(7))
            .ok_or(CaError::Clock)?
            .min(self.not_after);
        params.distinguished_name = DistinguishedName::new();
        params.subject_alt_names = vec![match host {
            NormalizedHost::Dns(name) => {
                SanType::DnsName(name.as_str().try_into().map_err(|_| CaError::Crypto)?)
            }
            NormalizedHost::Ipv4(ip) => SanType::IpAddress((*ip).into()),
            NormalizedHost::Ipv6(ip) => SanType::IpAddress((*ip).into()),
        }];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let key = KeyPair::generate().map_err(|_| CaError::Crypto)?;
        let cert = params
            .signed_by(&key, &self.issuer)
            .map_err(|_| CaError::Crypto)?;
        let key = rustls::crypto::aws_lc_rs::sign::any_supported_type(
            &PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .map_err(|_| CaError::Crypto)?;
        let certified = CertifiedKey::new(vec![cert.der().clone(), self.root.clone()], key);
        certified.keys_match().map_err(|_| CaError::Crypto)?;
        Ok(Arc::new(certified))
    }
}
fn now(clock: &dyn CaClock) -> Result<OffsetDateTime, CaError> {
    let seconds = clock.unix_seconds()?;
    if seconds < 0 {
        return Err(CaError::Clock);
    }
    OffsetDateTime::from_unix_timestamp(seconds).map_err(|_| CaError::Clock)
}
fn valid(
    now: OffsetDateTime,
    before: OffsetDateTime,
    after: OffsetDateTime,
) -> Result<(), CaError> {
    if now < before {
        Err(CaError::NotYetValid)
    } else if now >= after {
        Err(CaError::Expired)
    } else {
        Ok(())
    }
}
