//! Secure socket factory for creating TLS sockets with pre-connection IP validation.

use crate::error::{Result, ValidationError};
use crate::ip::IPWhitelistValidator;
use crate::tls::{default_backend, TlsBackend, TlsConfig};
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream as TokioTcpStream;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsConnector;

/// Factory for creating secure sockets with mTLS and IP validation.
#[derive(Clone)]
pub struct SecureSocketFactory {
    /// TLS configuration.
    tls_config: TlsConfig,
    /// IP whitelist validator (optional).
    ip_validator: Option<IPWhitelistValidator>,
    /// TLS backend.
    backend: Arc<dyn TlsBackend>,
}

impl SecureSocketFactory {
    /// Creates a new SecureSocketFactory with the given TLS configuration.
    pub fn new(tls_config: TlsConfig) -> Self {
        Self {
            tls_config,
            ip_validator: None,
            backend: default_backend(),
        }
    }

    /// Creates a new SecureSocketFactory with the given TLS configuration and IP validator.
    pub fn with_ip_validator(tls_config: TlsConfig, ip_validator: IPWhitelistValidator) -> Self {
        Self {
            tls_config,
            ip_validator: Some(ip_validator),
            backend: default_backend(),
        }
    }

    /// Sets a custom TLS backend.
    pub fn with_backend(mut self, backend: Arc<dyn TlsBackend>) -> Self {
        self.backend = backend;
        self
    }

    /// Creates a client TLS socket with server IP validation.
    pub async fn create_client_socket(
        &self,
        server_addr: SocketAddr,
    ) -> Result<tokio_rustls::client::TlsStream<TokioTcpStream>> {
        // Validate server IP if IP validator is configured
        if let Some(validator) = &self.ip_validator {
            validator.validate(server_addr.ip())?;
        }

        // Create TCP connection
        let tcp_stream = TokioTcpStream::connect(&server_addr).await.map_err(|e| {
            ValidationError::Connection(format!("Failed to connect to {}: {}", server_addr, e))
        })?;

        // Create TLS connector from the backend configuration
        let client_config = self.backend.create_client_config(&self.tls_config)?;
        let client_config_arc = client_config
            .inner
            .downcast::<rustls::ClientConfig>()
            .map_err(|_| ValidationError::Connection("Invalid client config type".to_string()))?;
        let connector = TlsConnector::from(client_config_arc);

        // Perform TLS handshake - use IP address directly for ServerName
        let domain = ServerName::IpAddress(server_addr.ip().into());

        let tls_stream = connector
            .connect(domain, tcp_stream)
            .await
            .map_err(|e| ValidationError::Connection(format!("TLS handshake failed: {}", e)))?;

        Ok(tls_stream)
    }

    /// Creates a server TLS socket with client IP validation.
    pub async fn create_server_socket(
        &self,
        tcp_stream: TokioTcpStream,
        client_addr: SocketAddr,
    ) -> Result<TlsStream<TokioTcpStream>> {
        // Validate client IP if IP validator is configured
        if let Some(validator) = &self.ip_validator {
            validator.validate(client_addr.ip())?;
        }

        // Create TLS acceptor from the backend configuration
        let server_config = self.backend.create_server_config(&self.tls_config)?;
        let server_config_arc = server_config
            .inner
            .downcast::<rustls::ServerConfig>()
            .map_err(|_| ValidationError::Connection("Invalid server config type".to_string()))?;
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config_arc);

        // Perform TLS handshake
        let tls_stream = acceptor
            .accept(tcp_stream)
            .await
            .map_err(|e| ValidationError::Connection(format!("TLS handshake failed: {}", e)))?;

        Ok(tls_stream)
    }

    /// Returns a reference to the TLS configuration.
    pub fn tls_config(&self) -> &TlsConfig {
        &self.tls_config
    }

    /// Returns a reference to the IP validator, if any.
    pub fn ip_validator(&self) -> Option<&IPWhitelistValidator> {
        self.ip_validator.as_ref()
    }

    /// Returns a reference to the TLS backend.
    pub fn backend(&self) -> &Arc<dyn TlsBackend> {
        &self.backend
    }
}
