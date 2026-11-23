//! Transport security: the roots https is verified against, and when a credential may go over
//! plain HTTP.

use std::path::Path;
use std::sync::Arc;

use stigmer_core::is_loopback_host;
use ureq::http::Uri;
use ureq::tls::{parse_pem, Certificate, PemItem, RootCerts, TlsConfig};

use crate::exit::CliError;

const CA_HINT: &str =
    "pass a readable PEM file of CA certificates to --ca-cert (or STIGMER_CA_CERT)";

/// The TLS settings for https: Mozilla's roots (webpki), plus every certificate in the PEM file
/// `ca_cert` when given. An unreadable file or one without a certificate is a usage error.
pub(crate) fn tls_config(ca_cert: Option<&Path>) -> Result<TlsConfig, CliError> {
    let Some(path) = ca_cert else {
        return Ok(TlsConfig::builder().root_certs(RootCerts::WebPki).build());
    };
    let pem = std::fs::read(path).map_err(|e| {
        CliError::usage(
            format!(
                "cannot read the CA certificate file {}: {e}",
                path.display()
            ),
            CA_HINT,
        )
    })?;
    let mut extra: Vec<Certificate<'static>> = Vec::new();
    for item in parse_pem(&pem) {
        match item {
            Ok(PemItem::Certificate(cert)) => extra.push(cert),
            // A key or other block is not a CA certificate, but is well formed.
            Ok(_) => {}
            Err(_) => {
                return Err(CliError::usage(
                    format!("malformed PEM block in {}", path.display()),
                    CA_HINT,
                ))
            }
        }
    }
    if extra.is_empty() {
        return Err(CliError::usage(
            format!("no CA certificate found in {}", path.display()),
            CA_HINT,
        ));
    }
    let roots: Vec<Certificate<'static>> = webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .map(|der| Certificate::from_der(der.as_ref()).to_owned())
        .chain(extra)
        .collect();
    Ok(TlsConfig::builder()
        .root_certs(RootCerts::Specific(Arc::new(roots)))
        .build())
}

/// Refuses to send a credential (token or invite) over plain HTTP to a host that is not
/// loopback, unless `insecure` (`--insecure`) says the network is trusted.
pub(crate) fn check_credential_transport(url: &str, insecure: bool) -> Result<(), CliError> {
    let uri: Uri = url.parse().map_err(|_| {
        CliError::usage(
            format!("invalid --url {url:?}"),
            "pass a URL such as https://board.example.com",
        )
    })?;
    if uri.scheme_str() == Some("https") || insecure {
        return Ok(());
    }
    let host = uri.host().unwrap_or_default();
    if is_loopback_host(host) {
        return Ok(());
    }
    Err(CliError::usage(
        format!("refusing to send a credential over plain http to {host}"),
        "use an https:// URL (or --insecure for a trusted network)",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::Exit;

    #[test]
    fn plain_http_is_refused_only_for_remote_hosts() {
        for ok in [
            "http://127.0.0.1:7878",
            "http://127.9.9.9",
            "http://localhost:7878/",
            "http://LOCALHOST",
            "http://[::1]:7878",
            "https://board.example.com",
            "https://10.0.0.1:443",
        ] {
            assert_eq!(check_credential_transport(ok, false), Ok(()), "{ok}");
        }
        for refused in [
            "http://board.example.com",
            "http://10.0.0.1:7878",
            "http://[::2]:7878",
            "http://localhost.example.com",
            "http://128.0.0.1",
        ] {
            let err = check_credential_transport(refused, false).unwrap_err();
            assert_eq!(err.exit, Exit::Usage, "{refused}");
        }
    }

    #[test]
    fn look_alike_hosts_are_not_loopback() {
        for refused in [
            "http://localhost@evil.example",
            "http://localhost:7878@evil.example:7878",
            "http://127.0.0.1.evil.example",
            "http://evil-localhost",
            "http://localhost.",
        ] {
            let err = check_credential_transport(refused, false).unwrap_err();
            assert_eq!(err.exit, Exit::Usage, "{refused}");
        }
        // An IPv4-mapped loopback address is loopback.
        assert_eq!(
            check_credential_transport("http://[::ffff:127.0.0.1]:7878", false),
            Ok(())
        );
    }

    #[test]
    fn a_malformed_pem_block_is_a_usage_error_even_beside_a_good_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        let key = rcgen::KeyPair::generate().unwrap();
        let good = rcgen::CertificateParams::new(vec!["one.test".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap()
            .pem();
        let corrupt = "-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n-----END CERTIFICATE-----\n";
        std::fs::write(&path, format!("{good}{corrupt}")).unwrap();
        let err = tls_config(Some(&path)).unwrap_err();
        assert_eq!(err.exit, Exit::Usage);
        assert!(err.message().contains("malformed"), "{}", err.message());
        let truncated = "-----BEGIN CERTIFICATE-----\nMIIB\n";
        std::fs::write(&path, format!("{good}{truncated}")).unwrap();
        assert_eq!(tls_config(Some(&path)).unwrap_err().exit, Exit::Usage);
    }

    #[test]
    fn insecure_flag_allows_plain_http_to_a_remote_host() {
        assert_eq!(
            check_credential_transport("http://board.example.com:7878", true),
            Ok(())
        );
        assert_eq!(check_credential_transport("http://10.0.0.1", true), Ok(()));
    }

    #[test]
    fn ca_file_adds_its_certificates_to_the_webpki_roots() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        let pem = |name: &str| {
            let key = rcgen::KeyPair::generate().unwrap();
            let params = rcgen::CertificateParams::new(vec![name.to_owned()]).unwrap();
            params.self_signed(&key).unwrap().pem()
        };
        std::fs::write(&path, format!("{}{}", pem("one.test"), pem("two.test"))).unwrap();
        let config = tls_config(Some(&path)).unwrap();
        let RootCerts::Specific(roots) = config.root_certs() else {
            panic!("expected specific roots");
        };
        assert_eq!(
            roots.len(),
            webpki_root_certs::TLS_SERVER_ROOT_CERTS.len() + 2
        );
        assert!(matches!(
            tls_config(None).unwrap().root_certs(),
            RootCerts::WebPki
        ));
    }

    #[test]
    fn a_bad_url_is_a_usage_error() {
        let err = check_credential_transport("not a url", false).unwrap_err();
        assert_eq!(err.exit, Exit::Usage);
    }
}
