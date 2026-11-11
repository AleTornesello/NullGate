use nullgate_core::normalize_host;
use nullgate_http::ca::{CaClock, CaError, CaProvider};
use rustls::{
    RootCertStore,
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    pki_types::{ServerName, UnixTime},
};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
};
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("nullgate-ca-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn bundle(&self) -> PathBuf {
        self.0.join("inspection-ca/material.bin")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Clock(AtomicI64);
impl CaClock for Clock {
    fn unix_seconds(&self) -> Result<i64, CaError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}
fn clock() -> Arc<Clock> {
    Arc::new(Clock(AtomicI64::new(1_800_000_000)))
}
#[test]
fn persistent_ca_reuses_exact_identity_and_issues_valid_dns_and_ip_leaves() {
    let dir = Scratch::new();
    let clock = clock();
    let ca = CaProvider::open_with_clock(&dir.0, clock.clone()).unwrap();
    let public = ca.public_certificate();
    let pem = public.certificate_pem();
    assert!(
        std::str::from_utf8(&pem)
            .unwrap()
            .starts_with("-----BEGIN CERTIFICATE-----")
    );
    assert!(!String::from_utf8_lossy(&pem).contains("PRIVATE KEY"));
    let root = pem::parse(&pem).unwrap();
    let root_der: rustls::pki_types::CertificateDer<'static> = root.contents().to_vec().into();
    let mut roots = RootCertStore::empty();
    roots.add(root_der.clone()).unwrap();
    let verifier = WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
    )
    .build()
    .unwrap();
    for host in [
        "example.com",
        "sub.example.com",
        "127.0.0.1",
        "[::1]",
        "bücher.example",
    ] {
        let host = normalize_host(host).unwrap();
        let leaf = ca.issue(&host).unwrap();
        leaf.keys_match().unwrap();
        let name = match &host {
            nullgate_core::NormalizedHost::Dns(name) => name.as_str().to_owned(),
            _ => host.to_string().trim_matches(['[', ']']).to_owned(),
        };
        verifier
            .verify_server_cert(
                &leaf.cert[0],
                &[],
                &ServerName::try_from(name).unwrap(),
                &[],
                UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_800_000_000)),
            )
            .unwrap();
        assert!(
            verifier
                .verify_server_cert(
                    &leaf.cert[0],
                    &[],
                    &ServerName::try_from("wrong.example").unwrap(),
                    &[],
                    UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_800_000_000))
                )
                .is_err()
        );
        let (_, parsed) = x509_parser::parse_x509_certificate(&leaf.cert[0]).unwrap();
        assert_eq!(
            parsed.validity().not_after.timestamp(),
            1_800_000_000 + 7 * 86400
        );
    }
    let before = std::fs::read(dir.bundle()).unwrap();
    drop(ca);
    let reopened = CaProvider::open_with_clock(&dir.0, clock).unwrap();
    assert_eq!(reopened.public_certificate().certificate_pem(), pem);
    assert_eq!(std::fs::read(dir.bundle()).unwrap(), before);
    assert!(normalize_host("*.example.com").is_err());
    assert!(normalize_host("example.com:443").is_err());
}
#[test]
fn expiration_is_deterministic_and_never_rotates_the_root() {
    let dir = Scratch::new();
    let clock = clock();
    let ca = CaProvider::open_with_clock(&dir.0, clock.clone()).unwrap();
    let before = std::fs::read(dir.bundle()).unwrap();
    let expiry = 1_800_000_000 + 3650 * 86400;
    clock.0.store(expiry - 3600, Ordering::SeqCst);
    let leaf = ca.issue(&normalize_host("example.com").unwrap()).unwrap();
    let (_, parsed) = x509_parser::parse_x509_certificate(&leaf.cert[0]).unwrap();
    assert_eq!(parsed.validity().not_after.timestamp(), expiry);
    clock.0.store(expiry, Ordering::SeqCst);
    assert!(matches!(
        ca.issue(&normalize_host("example.com").unwrap()),
        Err(CaError::Expired)
    ));
    assert!(matches!(
        CaProvider::open_with_clock(&dir.0, clock.clone()),
        Err(CaError::Expired)
    ));
    assert_eq!(std::fs::read(dir.bundle()).unwrap(), before);
    clock.0.store(1_800_000_000 - 301, Ordering::SeqCst);
    assert!(matches!(
        CaProvider::open_with_clock(&dir.0, clock),
        Err(CaError::NotYetValid)
    ));
}
#[test]
fn corrupt_and_incomplete_material_is_not_replaced() {
    let dir = Scratch::new();
    CaProvider::open_with_clock(&dir.0, clock()).unwrap();
    let original = std::fs::read(dir.bundle()).unwrap();
    for bytes in [
        vec![],
        b"private secret corrupt marker".to_vec(),
        original[..original.len() - 10].to_vec(),
        {
            let mut bytes = original.clone();
            bytes.push(0);
            bytes
        },
    ] {
        std::fs::write(dir.bundle(), &bytes).unwrap();
        let error = CaProvider::open_with_clock(&dir.0, clock()).err().unwrap();
        assert!(matches!(error, CaError::Corrupt));
        assert!(!format!("{error:?} {error}").contains("private secret"));
        assert_eq!(std::fs::read(dir.bundle()).unwrap(), bytes);
    }
    std::fs::remove_file(dir.bundle()).unwrap();
    assert!(matches!(
        CaProvider::open_with_clock(&dir.0, clock()),
        Err(CaError::Incomplete)
    ));
}
#[cfg(unix)]
#[test]
fn private_storage_rejects_permissions_links_and_special_files() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = Scratch::new();
    CaProvider::open_with_clock(&dir.0, clock()).unwrap();
    let private = dir.0.join("inspection-ca");
    let bundle = dir.bundle();
    assert_eq!(
        std::fs::metadata(&private).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(&bundle).unwrap().permissions().mode() & 0o777,
        0o600
    );
    std::fs::set_permissions(&bundle, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        CaProvider::open_with_clock(&dir.0, clock()),
        Err(CaError::UnsafeStorage)
    ));
    std::fs::set_permissions(&bundle, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::hard_link(&bundle, dir.0.join("linked")).unwrap();
    assert!(matches!(
        CaProvider::open_with_clock(&dir.0, clock()),
        Err(CaError::UnsafeStorage)
    ));
    std::fs::remove_file(dir.0.join("linked")).unwrap();
    let saved = dir.0.join("saved");
    std::fs::rename(&bundle, &saved).unwrap();
    symlink(&saved, &bundle).unwrap();
    assert!(matches!(
        CaProvider::open_with_clock(&dir.0, clock()),
        Err(CaError::UnsafeStorage)
    ));
    std::fs::remove_file(&bundle).unwrap();
    std::fs::rename(saved, &bundle).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        CaProvider::open_with_clock(&dir.0, clock()),
        Err(CaError::UnsafeStorage)
    ));
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::remove_file(&bundle).unwrap();
    std::fs::create_dir(&bundle).unwrap();
    assert!(matches!(
        CaProvider::open_with_clock(&dir.0, clock()),
        Err(CaError::UnsafeStorage)
    ));
}

fn bundle(cert: &[u8], key: &[u8]) -> Vec<u8> {
    let mut bytes = b"NULLCA01".to_vec();
    bytes.extend_from_slice(&(cert.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&(key.len() as u32).to_be_bytes());
    bytes.extend_from_slice(cert);
    bytes.extend_from_slice(key);
    bytes
}
#[test]
fn mismatched_non_ca_and_bad_signature_material_is_rejected_without_overwrite() {
    let dir = Scratch::new();
    let ca = CaProvider::open_with_clock(&dir.0, clock()).unwrap();
    let original = std::fs::read(dir.bundle()).unwrap();
    let cert_len = u32::from_be_bytes(original[8..12].try_into().unwrap()) as usize;
    let cert = &original[16..16 + cert_len];
    let key = &original[16 + cert_len..];
    let different = rcgen::KeyPair::generate().unwrap();
    let non_ca = rcgen::CertificateParams::new(vec!["example.com".into()])
        .unwrap()
        .self_signed(&different)
        .unwrap();
    let mut bad_signature = cert.to_vec();
    *bad_signature.last_mut().unwrap() ^= 1;
    for bytes in [
        bundle(cert, &different.serialize_der()),
        bundle(non_ca.der(), &different.serialize_der()),
        bundle(&bad_signature, key),
    ] {
        std::fs::write(dir.bundle(), &bytes).unwrap();
        assert!(matches!(
            CaProvider::open_with_clock(&dir.0, clock()),
            Err(CaError::Corrupt)
        ));
        assert!(std::fs::read(dir.bundle()).unwrap() == bytes);
    }
    let debug = format!("{ca:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("PRIVATE KEY"));
    assert!(debug.len() < 100);
}
#[cfg(unix)]
#[test]
fn directory_symlinks_fifo_and_untrusted_writable_parent_are_rejected() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = Scratch::new();
    let private = dir.0.join("inspection-ca");
    let other = dir.0.join("other");
    std::fs::create_dir(&other).unwrap();
    symlink(&other, &private).unwrap();
    assert!(matches!(
        CaProvider::open_with_clock(&dir.0, clock()),
        Err(CaError::UnsafeStorage)
    ));
    assert!(!other.join("material.bin").exists());
    std::fs::remove_file(&private).unwrap();
    CaProvider::open_with_clock(&dir.0, clock()).unwrap();
    std::fs::remove_file(dir.bundle()).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(dir.bundle())
            .status()
            .unwrap()
            .success()
    );
    assert!(matches!(
        CaProvider::open_with_clock(&dir.0, clock()),
        Err(CaError::UnsafeStorage)
    ));
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        CaProvider::open_with_clock(&dir.0, clock()),
        Err(CaError::UnsafeStorage)
    ));
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();
}
#[test]
fn concurrent_first_open_never_overwrites_a_generated_identity() {
    let dir = Scratch::new();
    let barrier = Arc::new(std::sync::Barrier::new(4));
    let mut jobs = vec![];
    for _ in 0..4 {
        let barrier = barrier.clone();
        let path = dir.0.clone();
        jobs.push(std::thread::spawn(move || {
            barrier.wait();
            CaProvider::open_with_clock(&path, clock())
                .map(|ca| ca.public_certificate().certificate_pem())
        }));
    }
    let results = jobs
        .into_iter()
        .map(|job| job.join().unwrap())
        .collect::<Vec<_>>();
    let expected = CaProvider::open_with_clock(&dir.0, clock())
        .unwrap()
        .public_certificate()
        .certificate_pem();
    let mut successes = 0;
    for result in results {
        match result {
            Ok(pem) => {
                successes += 1;
                assert_eq!(pem, expected);
            }
            Err(error) => assert!(matches!(error, CaError::Incomplete | CaError::Corrupt)),
        }
    }
    assert!(successes >= 1);
}
