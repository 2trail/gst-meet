#[cfg(any(
  feature = "tls-rustls-native-roots",
  feature = "tls-rustls-webpki-roots"
))]
use std::sync::Arc;

#[cfg(not(feature = "tls-insecure"))]
use anyhow::bail;
use anyhow::{Context, Result};
use tokio_tungstenite::Connector;

#[cfg(feature = "tls-rustls-native-roots")]
pub(crate) fn wss_connector(insecure: bool) -> Result<tokio_tungstenite::Connector> {
  let mut roots = rustls::RootCertStore::empty();
  for cert in
    rustls_native_certs::load_native_certs().context("failed to load native root certs")?
  {
    roots.add(cert).map_err(|e| anyhow::anyhow!("failed to add native root cert: {:?}", e))?;
  }

  let config = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();
  #[cfg(feature = "tls-insecure")]
  let config = if insecure {
    use rustls::client::danger::HandshakeSignatureValid;
    use rustls::client::danger::ServerCertVerified;
    use rustls::client::danger::ServerCertVerifier;
    
    struct InsecureVerifier;
    impl ServerCertVerifier for InsecureVerifier {
      fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
      ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
      }
      
      fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
      ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
      }
      
      fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
      ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
      }
      
      fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
          rustls::SignatureScheme::RSA_PKCS1_SHA1,
          rustls::SignatureScheme::ECDSA_SHA1_Legacy,
          rustls::SignatureScheme::RSA_PKCS1_SHA256,
          rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
          rustls::SignatureScheme::RSA_PKCS1_SHA384,
          rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
          rustls::SignatureScheme::RSA_PKCS1_SHA512,
          rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
          rustls::SignatureScheme::RSA_PSS_SHA256,
          rustls::SignatureScheme::RSA_PSS_SHA384,
          rustls::SignatureScheme::RSA_PSS_SHA512,
          rustls::SignatureScheme::ED25519,
          rustls::SignatureScheme::ED448,
        ]
      }
    }
    
    rustls::ClientConfig::builder()
      .dangerous()
      .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
      .with_no_client_auth()
  } else {
    config
  };
  #[cfg(not(feature = "tls-insecure"))]
  if insecure {
    bail!(
      "Insecure TLS mode can only be enabled if the tls-insecure feature was enabled at compile time."
    )
  }
  Ok(Connector::Rustls(Arc::new(config)))
}

#[cfg(feature = "tls-rustls-webpki-roots")]
pub(crate) fn wss_connector(insecure: bool) -> Result<tokio_tungstenite::Connector> {
  let mut roots = rustls::RootCertStore::empty();
  roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

  let config = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();
  #[cfg(feature = "tls-insecure")]
  let config = if insecure {
    use rustls::client::danger::HandshakeSignatureValid;
    use rustls::client::danger::ServerCertVerified;
    use rustls::client::danger::ServerCertVerifier;
    
    struct InsecureVerifier;
    impl ServerCertVerifier for InsecureVerifier {
      fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
      ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
      }
      
      fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
      ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
      }
      
      fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
      ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
      }
      
      fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
          rustls::SignatureScheme::RSA_PKCS1_SHA1,
          rustls::SignatureScheme::ECDSA_SHA1_Legacy,
          rustls::SignatureScheme::RSA_PKCS1_SHA256,
          rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
          rustls::SignatureScheme::RSA_PKCS1_SHA384,
          rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
          rustls::SignatureScheme::RSA_PKCS1_SHA512,
          rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
          rustls::SignatureScheme::RSA_PSS_SHA256,
          rustls::SignatureScheme::RSA_PSS_SHA384,
          rustls::SignatureScheme::RSA_PSS_SHA512,
          rustls::SignatureScheme::ED25519,
          rustls::SignatureScheme::ED448,
        ]
      }
    }
    
    rustls::ClientConfig::builder()
      .dangerous()
      .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
      .with_no_client_auth()
  } else {
    config
  };
  #[cfg(not(feature = "tls-insecure"))]
  if insecure {
    bail!(
      "Insecure TLS mode can only be enabled if the tls-insecure feature was enabled at compile time."
    )
  }
  Ok(Connector::Rustls(Arc::new(config)))
}

#[cfg(any(feature = "tls-native", feature = "tls-native-vendored"))]
pub(crate) fn wss_connector(insecure: bool) -> Result<tokio_tungstenite::Connector> {
  let mut builder = native_tls::TlsConnector::builder();
  builder.min_protocol_version(Some(native_tls::Protocol::Tlsv12));
  #[cfg(feature = "tls-insecure")]
  if insecure {
    builder.danger_accept_invalid_certs(true);
    builder.danger_accept_invalid_hostnames(true);
  }
  #[cfg(not(feature = "tls-insecure"))]
  if insecure {
    bail!(
      "Insecure TLS mode can only be enabled if the tls-insecure feature was enabled at compile time."
    )
  }
  Ok(Connector::NativeTls(
    builder
      .build()
      .context("failed to build native TLS connector")?,
  ))
}
