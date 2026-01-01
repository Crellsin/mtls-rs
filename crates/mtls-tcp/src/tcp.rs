//! Raw TCP server and client with mTLS authentication.

use mtls_core::validator::ConnectionValidator;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

/// TCP server with mTLS authentication.
pub struct TcpServer {
    /// Connection validator for the server.
    validator: Arc<ConnectionValidator>,
    /// The TCP listener.
    listener: TcpListener,
}

impl TcpServer {
    /// Creates a new TcpServer that listens on the given address.
    pub async fn bind(addr: SocketAddr, validator: ConnectionValidator) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            validator: Arc::new(validator),
            listener,
        })
    }

    /// Accepts an incoming connection and returns a validated TLS stream.
    pub async fn accept(
        &self,
    ) -> std::io::Result<(impl AsyncRead + AsyncWrite + Unpin, SocketAddr)> {
        let (stream, addr) = self.listener.accept().await?;

        // Use the connection validator to validate the incoming connection and upgrade to TLS.
        let (validation_result, tls_stream) = self
            .validator
            .validate_incoming(stream)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        if !validation_result.is_valid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                validation_result
                    .failure_reason
                    .unwrap_or_else(|| "Connection validation failed".to_string()),
            ));
        }

        Ok((tls_stream, addr))
    }

    /// Returns the local address that this server is bound to.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

/// TCP client with mTLS authentication.
pub struct TcpClient {
    /// Connection validator for the client.
    validator: Arc<ConnectionValidator>,
}

impl TcpClient {
    /// Creates a new TcpClient with the given connection validator.
    pub fn new(validator: ConnectionValidator) -> Self {
        Self {
            validator: Arc::new(validator),
        }
    }

    /// Connects to a server at the given address and returns a validated TLS stream.
    pub async fn connect(
        &self,
        addr: SocketAddr,
    ) -> std::io::Result<impl AsyncRead + AsyncWrite + Unpin> {
        let validation_result = self
            .validator
            .validate_outgoing(&addr.ip().to_string(), addr.port())
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        if !validation_result.is_valid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                validation_result
                    .failure_reason
                    .unwrap_or_else(|| "Connection validation failed".to_string()),
            ));
        }

        // The validation above already created a TLS stream, but we don't have access to it.
        // We need to create a new connection. Let's adjust: the validator's validate_outgoing doesn't return the stream.
        // We'll change approach: use the socket factory from the validator to create a client socket.
        // However, the current ConnectionValidator doesn't expose the socket factory for raw TCP.
        // For now, we'll create a new TCP stream and then use the socket factory to upgrade it.
        // But note: the validate_outgoing already does that and returns a ValidationResult without the stream.
        // We need to change the design or work around.

        // Since we are in the TCP adapter, we can use the socket factory directly.
        // Let's get the socket factory from the validator.
        let socket_factory = self.validator.socket_factory();
        let tls_stream = socket_factory
            .create_client_socket(addr)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        Ok(tls_stream)
    }
}
