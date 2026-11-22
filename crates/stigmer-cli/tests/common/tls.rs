//! A throwaway test CA and a leaf for `localhost` and `127.0.0.1`, written as PEM files.

use std::path::{Path, PathBuf};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

/// PEM files for one TLS test: the CA (for the client) and the server's pair.
pub struct TlsFiles {
    pub ca: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl TlsFiles {
    /// Generates a CA and a leaf signed by it into `dir`.
    pub fn generate(dir: &Path) -> Self {
        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "stigmer cli test CA");
        let ca_cert = ca_params.self_signed(&ca_key).expect("self-signed ca");
        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf_params =
            CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
                .expect("leaf params");
        let issuer = Issuer::from_params(&ca_params, &ca_key);
        let leaf = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("signed leaf");
        let files = Self {
            ca: dir.join("ca.pem"),
            cert: dir.join("cert.pem"),
            key: dir.join("key.pem"),
        };
        std::fs::write(&files.ca, ca_cert.pem()).expect("write ca");
        std::fs::write(&files.cert, leaf.pem()).expect("write cert");
        std::fs::write(&files.key, leaf_key.serialize_pem()).expect("write key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&files.key, std::fs::Permissions::from_mode(0o600))
                .expect("chmod key");
        }
        files
    }
}
