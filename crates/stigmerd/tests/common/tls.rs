//! A throwaway test CA, certificate files for the server and a small blocking TLS client.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::pki_types::ServerName;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned, SupportedProtocolVersion,
};

#[allow(unused_imports)] // each test crate uses a different subset
pub use rustls::version::{TLS12, TLS13};

/// A CA created for one test; it signs leaves for `localhost` and `127.0.0.1`.
pub struct TestCa {
    params: CertificateParams,
    key: KeyPair,
    roots: RootCertStore,
}

/// A leaf certificate and its key, as PEM, plus the certificate's DER for fingerprints.
pub struct Leaf {
    pub cert_pem: String,
    pub key_pem: String,
    pub der: Vec<u8>,
}

impl TestCa {
    pub fn new() -> Self {
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "stigmer test CA");
        let cert = params.self_signed(&key).expect("self-signed ca");
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).expect("add root");
        Self { params, key, roots }
    }

    pub fn leaf(&self) -> Leaf {
        let key = KeyPair::generate().expect("leaf key");
        let params = CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
            .expect("leaf params");
        let issuer = Issuer::from_params(&self.params, &self.key);
        let cert = params.signed_by(&key, &issuer).expect("signed leaf");
        Leaf {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            der: cert.der().to_vec(),
        }
    }

    /// A client that trusts only this CA and speaks only `version`.
    pub fn client(&self, version: &'static SupportedProtocolVersion) -> Arc<ClientConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[version])
            .expect("protocol versions")
            .with_root_certificates(self.roots.clone())
            .with_no_client_auth();
        Arc::new(config)
    }
}

/// Where the server reads its certificate pair from.
pub struct PairFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl PairFiles {
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            cert: dir.join("cert.pem"),
            key: dir.join("key.pem"),
        }
    }

    /// Writes both files (key 0600 on unix).
    pub fn write(&self, leaf: &Leaf) {
        self.write_cert(&leaf.cert_pem);
        self.write_key(&leaf.key_pem);
    }

    pub fn write_cert(&self, pem: &str) {
        std::fs::write(&self.cert, pem).expect("write cert");
    }

    pub fn write_key(&self, pem: &str) {
        std::fs::write(&self.key, pem).expect("write key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.key, std::fs::Permissions::from_mode(0o600))
                .expect("chmod key");
        }
    }

    /// The serve flags naming these files.
    pub fn flags(&self) -> Vec<String> {
        vec![
            "--tls-cert".to_owned(),
            self.cert.display().to_string(),
            "--tls-key".to_owned(),
            self.key.display().to_string(),
        ]
    }
}

/// What one TLS exchange saw: the server's leaf certificate and the raw HTTP response.
pub struct TlsReply {
    pub peer_cert: Vec<u8>,
    pub response: String,
}

/// Connects with `config` (server name `localhost`), writes `request` and reads until the
/// server closes. An error is a failed handshake or connection.
pub fn https_raw(
    addr: &str,
    config: Arc<ClientConfig>,
    request: &[u8],
) -> Result<TlsReply, std::io::Error> {
    let name = ServerName::try_from("localhost").expect("server name");
    let conn = ClientConnection::new(config, name).map_err(std::io::Error::other)?;
    let sock = TcpStream::connect(addr)?;
    sock.set_read_timeout(Some(super::RAW_READ_TIMEOUT))?;
    let mut tls = StreamOwned::new(conn, sock);
    tls.write_all(request)?;
    tls.flush()?;
    let peer_cert = tls
        .conn
        .peer_certificates()
        .and_then(|chain| chain.first())
        .map(|c| c.to_vec())
        .unwrap_or_default();
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            // A server that closes without close_notify after a complete response.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !raw.is_empty() => break,
            Err(e) => return Err(e),
        }
    }
    Ok(TlsReply {
        peer_cert,
        response: String::from_utf8_lossy(&raw).into_owned(),
    })
}

/// A `Connection: close` request for `path` with optional extra header lines.
pub fn get(path: &str, extra: &[(&str, &str)]) -> Vec<u8> {
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.into_bytes()
}

/// A `Connection: close` request with a body.
pub fn request(method: &str, path: &str, extra: &[(&str, &str)], body: &str) -> Vec<u8> {
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    req.into_bytes()
}

/// `https_raw` with TLS 1.3 that must succeed.
pub fn https_get(addr: &str, ca: &TestCa, path: &str, extra: &[(&str, &str)]) -> TlsReply {
    https_raw(addr, ca.client(&TLS13), &get(path, extra)).expect("tls exchange")
}
