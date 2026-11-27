//! TLS: the certificate pair from PEM files, served through a resolver whose pair is swapped
//! when the files change, without touching established connections.
//!
//! Only TLS 1.3 is offered, with no client certificates. Error messages name files, never their
//! contents.

use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, SystemTime};

use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use tokio::time::MissedTickBehavior;

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
    warn_if_exposed(key, "TLS key");
}

/// Warns on stderr when `file`, a secret named `what`, can be read by anyone but its owner
/// (unix only).
pub(crate) fn warn_if_exposed(file: &Path, what: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(file) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                eprintln!(
                    "stigmerd: warning: {what} {} is accessible by group or others (mode {mode:o}); \
                     restrict it with chmod 600",
                    file.display()
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (file, what);
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

    fn replace(&self, pair: CertifiedKey) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(pair);
    }
}

/// The modification times of both files; `None` for a file that cannot be read.
type Stamps = (Option<SystemTime>, Option<SystemTime>);

fn stamps(files: &PairFiles) -> Stamps {
    let modified = |path: &Path| std::fs::metadata(path).and_then(|m| m.modified()).ok();
    (modified(&files.cert), modified(&files.key))
}

/// Checks both files every `every` and, once either has changed since the served pair was
/// loaded, loads both and swaps the pair in only if it parses and the key matches the
/// certificate. A bad candidate (a parse error, or a new certificate whose key has not been
/// written yet) keeps the current pair, is warned about once and is tried again on every tick
/// until it loads or the files change again. Runs until the process exits.
pub(crate) async fn reload_on_change(
    files: PairFiles,
    provider: Arc<CryptoProvider>,
    current: Arc<CurrentPair>,
    every: Duration,
) {
    let mut loaded = stamps(&files);
    let mut warned: Option<Stamps> = None;
    let mut ticks = tokio::time::interval(every);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        let now = stamps(&files);
        if now == loaded {
            continue;
        }
        match load_pair(&files, &provider) {
            Ok(pair) => {
                current.replace(pair);
                loaded = now;
                warned = None;
            }
            Err(why) if warned != Some(now) => {
                eprintln!("stigmerd: warning: keeping the current TLS certificate: {why}");
                warned = Some(now);
            }
            Err(_) => {}
        }
    }
}

impl ResolvesServerCert for CurrentPair {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.get())
    }
}

/// TLS 1.3 only, no client certificates, HTTP/1.1 only by ALPN.
pub(crate) fn server_config(
    provider: Arc<CryptoProvider>,
    current: Arc<CurrentPair>,
) -> Result<Arc<ServerConfig>, String> {
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("cannot set up TLS: {e}"))?
        .with_no_client_auth()
        .with_cert_resolver(current);
    // HTTP/1.1 only: hyper's header read timeout covers HTTP/1 alone, so an idle HTTP/2
    // connection would hold a connection slot for ever. A client offering only h2 is refused
    // with a no_application_protocol alert.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
