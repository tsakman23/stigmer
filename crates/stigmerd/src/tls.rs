//! TLS: the certificate pair from PEM files, served through a resolver whose pair can be swapped
//! without touching established connections.
//!
//! Only TLS 1.3 is offered, with no client certificates. Error messages name files, never their
//! contents.

use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};

use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;

/// The `Strict-Transport-Security` value sent on every TLS response.
pub(crate) const HSTS: &str = "max-age=31536000";

/// The two PEM files of a certificate pair.
#[derive(Debug, Clone)]
pub(crate) struct PairFiles {
    pub(crate) cert: PathBuf,
    pub(crate) key: PathBuf,
}

/// The ring provider; the only one this binary builds.
pub(crate) fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Reads and parses both files and checks that the key belongs to the leaf certificate.
pub(crate) fn load_pair(
    files: &PairFiles,
    provider: &CryptoProvider,
) -> Result<CertifiedKey, String> {
    let cert_pem = read(&files.cert, "certificate")?;
    let chain = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| format!("cannot parse the TLS certificate {}", files.cert.display()))?;
    if chain.is_empty() {
        return Err(format!("no certificate found in {}", files.cert.display()));
    }
    let key_pem = read(&files.key, "key")?;
    // The parse error is not shown: it can quote lines of the key file.
    let key = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|_| {
        format!(
            "no PKCS#8, RSA or SEC1 private key found in {}",
            files.key.display()
        )
    })?;
    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|_| format!("unsupported private key in {}", files.key.display()))?;
    let pair = CertifiedKey::new(chain, signing_key);
    pair.keys_match().map_err(|_| {
        format!(
            "the private key in {} does not match the certificate in {}",
            files.key.display(),
            files.cert.display()
        )
    })?;
    Ok(pair)
}

fn read(path: &Path, what: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("cannot read the TLS {what} {}: {e}", path.display()))
}

/// Warns on stderr when the key file can be read by anyone but its owner (unix only).
pub(crate) fn warn_if_key_exposed(key: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(key) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                eprintln!(
                    "stigmerd: warning: TLS key {} is accessible by group or others (mode {mode:o}); \
                     restrict it with chmod 600",
                    key.display()
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = key;
}

/// The pair handed to every new handshake; replacing it leaves established connections alone.
#[derive(Debug)]
pub(crate) struct CurrentPair(RwLock<Arc<CertifiedKey>>);

impl CurrentPair {
    pub(crate) fn new(pair: CertifiedKey) -> Self {
        Self(RwLock::new(Arc::new(pair)))
    }

    fn get(&self) -> Arc<CertifiedKey> {
        // A panic while holding the lock cannot leave a half-written Arc behind.
        Arc::clone(&self.0.read().unwrap_or_else(PoisonError::into_inner))
    }
}

impl ResolvesServerCert for CurrentPair {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.get())
    }
}

/// TLS 1.3 only, no client certificates, HTTP/2 or HTTP/1.1 by ALPN.
pub(crate) fn server_config(
    provider: Arc<CryptoProvider>,
    current: Arc<CurrentPair>,
) -> Result<Arc<ServerConfig>, String> {
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("cannot set up TLS: {e}"))?
        .with_no_client_auth()
        .with_cert_resolver(current);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
