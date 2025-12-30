//! TLS backend abstraction for mTLS authentication.

use crate::error::{Result, TlsError};
use crate::tls::TlsConfig;
use std::sync::Arc;
use rustls::pki_types::CertificateDer;

/// Type of TLS backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsBackendType {
    /// Rustls backend (default).
    Rustls,
    /// OpenSSL backend (optional, requires feature).
    #[cfg(feature = "openssl")]
    OpenSsl,
}

/// Trait for TLS backends.
pub trait TlsBackend: Send + Sync {
    /// Creates a client TLS configuration from the given TlsConfig.
    fn create_client_config(&self, config: &TlsConfig) -> Result<ClientTlsConfig>;

    /// Creates a server TLS configuration from the given TlsConfig.
    fn create_server_config(&self, config: &TlsConfig) -> Result<ServerTlsConfig>;

    /// Returns the backend type.
    fn backend_type(&self) -> TlsBackendType;
}

/// Client TLS configuration (backend-specific).
#[derive(Debug, Clone)]
pub struct ClientTlsConfig {
    /// Backend-specific client configuration.
    pub inner: Arc<dyn std::any::Any + Send + Sync>,
}

/// Server TLS configuration (backend-specific).
#[derive(Debug, Clone)]
pub struct ServerTlsConfig {
    /// Backend-specific server configuration.
    pub inner: Arc<dyn std::any::Any + Send + Sync>,
}

/// Default TLS backend using rustls.
#[derive(Debug, Clone, Default)]
pub struct RustlsBackend;

impl RustlsBackend {
    /// Creates a new RustlsBackend.
    pub fn new() -> Self {
        Self
    }
}

impl TlsBackend for RustlsBackend {
    fn create_client_config(&self, config: &TlsConfig) -> Result<ClientTlsConfig> {
        use rustls::ClientConfig;

        let cert_manager = config.certificate_manager();
        let mut root_store = rustls::RootCertStore::empty();
        if let Some(store) = cert_manager.root_store() {
            root_store = store.clone();
        }

        let cert_chain: Vec<CertificateDer<'static>> = cert_manager.cert_chain().iter().cloned().collect();
        let private_key = cert_manager.parse_private_key()?;

        let client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(cert_chain, private_key)
            .map_err(|e| TlsError::Config(format!("Failed to create client config: {}", e)))?;

        Ok(ClientTlsConfig {
            inner: Arc::new(client_config),
        })
    }

    fn create_server_config(&self, config: &TlsConfig) -> Result<ServerTlsConfig> {
        use rustls::server::{ServerConfig, WebPkiClientVerifier};

        let cert_manager = config.certificate_manager();
        let cert_chain: Vec<CertificateDer<'static>> = cert_manager.cert_chain().iter().cloned().collect();
        let private_key = cert_manager.parse_private_key()?;

        // Build the server config with client authentication if required
        let server_config = if config.require_client_auth() {
            let mut root_store = rustls::RootCertStore::empty();
            if let Some(store) = cert_manager.root_store() {
                root_store = store.clone();
            }
            let client_auth = WebPkiClientVerifier::builder(root_store.into())
                .build()
                .map_err(|e| TlsError::Config(format!("Failed to build client verifier: {}", e)))?;
            ServerConfig::builder()
                .with_client_cert_verifier(client_auth)
                .with_single_cert(cert_chain, private_key)
                .map_err(|e| TlsError::Config(format!("Failed to create server config with client auth: {}", e)))?
        } else {
            let client_auth = WebPkiClientVerifier::no_client_auth();
            ServerConfig::builder()
                .with_client_cert_verifier(client_auth)
                .with_single_cert(cert_chain, private_key)
                .map_err(|e| TlsError::Config(format!("Failed to create server config without client auth: {}", e)))?
        };

        Ok(ServerTlsConfig {
            inner: Arc::new(server_config),
        })
    }

    fn backend_type(&self) -> TlsBackendType {
        TlsBackendType::Rustls
    }
}

/// Get the default TLS backend (Rustls).
pub fn default_backend() -> Arc<dyn TlsBackend> {
    Arc::new(RustlsBackend::new())
}
