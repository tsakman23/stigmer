//! TLS to Postgres through rustls with the ring provider (no aws-lc, no OpenSSL).
//!
//! `Require` encrypts without checking who answers, as libpq's `sslmode=require` does: the
//! certificate is not verified, only the handshake signatures. `VerifyFull` checks the chain
//! against the platform's trusted roots and the certificate against the host name, as libpq's
//! `sslmode=verify-full` does; with a [`CaBundle`] it trusts that bundle's certificates instead
//! of the platform's roots (libpq's `sslrootcert`).

use std::fmt;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use stigmer_store::StoreError;
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::error::backend;
use crate::PgTls;

/// The CA certificates trusted with [`PgTls::VerifyFull`] instead of the platform's roots, for
/// a Postgres server whose certificate comes from a private CA.
#[derive(Clone, PartialEq, Eq)]
pub struct CaBundle(Arc<[CertificateDer<'static>]>);

impl CaBundle {
    /// The certificates of a PEM bundle (one or more `CERTIFICATE` blocks; anything else in
    /// the text is skipped). A bundle with no certificate, or one that cannot serve as a trust
    /// anchor, is refused.
    pub fn from_pem(pem: &[u8]) -> Result<CaBundle, StoreError> {
        let certs = CertificateDer::pem_slice_iter(pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| StoreError::Backend("the CA bundle is not valid PEM".into()))?;
        if certs.is_empty() {
            return Err(StoreError::Backend(
                "the CA bundle holds no certificate".into(),
            ));
        }
        let bundle = CaBundle(certs.into());
        bundle.roots()?;
        Ok(bundle)
    }

    /// The number of certificates in the bundle.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always false: a bundle holds at least one certificate.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn roots(&self) -> Result<RootCertStore, StoreError> {
        let mut roots = RootCertStore::empty();
        for (n, cert) in (1..).zip(self.0.iter()) {
            roots.add(cert.clone()).map_err(|e| {
                StoreError::Backend(format!(
                    "certificate {n} of the CA bundle is not a usable CA certificate: {e}"
                ))
            })?;
        }
        Ok(roots)
    }
}

impl fmt::Debug for CaBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CaBundle({} certificates)", self.0.len())
    }
}

/// The connector for `tls` (with `ca_bundle` as the roots for verify-full, when given), or
/// `None` for plain connections.
pub(crate) fn connector(
    tls: PgTls,
    ca_bundle: Option<&CaBundle>,
) -> Result<Option<MakeRustlsConnect>, StoreError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(backend)?;
    let config = match tls {
        PgTls::Disable => return Ok(None),
        PgTls::Require => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(EncryptOnly(provider)))
            .with_no_client_auth(),
        PgTls::VerifyFull => builder
            .with_root_certificates(match ca_bundle {
                Some(bundle) => bundle.roots()?,
                None => platform_roots()?,
            })
            .with_no_client_auth(),
    };
    Ok(Some(MakeRustlsConnect::new(config)))
}

/// The platform's trusted root certificates; none at all is an error, not an empty trust store.
fn platform_roots() -> Result<RootCertStore, StoreError> {
    let found = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    let (added, _unparsable) = roots.add_parsable_certificates(found.certs);
    if added == 0 {
        return Err(StoreError::Backend(
            "TLS verify-full: no trusted root certificates found on this system".into(),
        ));
    }
    Ok(roots)
}

/// Accepts any server certificate but still checks the handshake signatures (`sslmode=require`).
#[derive(Debug)]
struct EncryptOnly(Arc<CryptoProvider>);

impl ServerCertVerifier for EncryptOnly {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disable_has_no_connector_and_require_builds_one() {
        assert!(connector(PgTls::Disable, None).unwrap().is_none());
        assert!(connector(PgTls::Require, None).unwrap().is_some());
    }
}
