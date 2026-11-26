//! TLS to Postgres through rustls with the ring provider (no aws-lc, no OpenSSL).
//!
//! `Require` encrypts without checking who answers, as libpq's `sslmode=require` does: the
//! certificate is not verified, only the handshake signatures. `VerifyFull` checks the chain
//! against the platform's trusted roots and the certificate against the host name, as libpq's
//! `sslmode=verify-full` does.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use stigmer_store::StoreError;
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::error::backend;
use crate::PgTls;

/// The connector for `tls`, or `None` for plain connections.
pub(crate) fn connector(tls: PgTls) -> Result<Option<MakeRustlsConnect>, StoreError> {
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
            .with_root_certificates(platform_roots()?)
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
        assert!(connector(PgTls::Disable).unwrap().is_none());
        assert!(connector(PgTls::Require).unwrap().is_some());
    }
}
