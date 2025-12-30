//! Connection validator orchestrator for mTLS authentication.

use crate::error::{Result, ValidationError};
use crate::cert::CertificateManager;
use crate::config::{ServerConfig, ClientConfig};
use crate::ip::IPWhitelistValidator;
use crate::tls::{TlsConfig, default_backend};
use crate::socket::SecureSocketFactory;
use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use tokio::net::TcpStream;

/// Result of a connection validation.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Remote IP address.
    pub remote_ip: IpAddr,
    /// Certificate information (if available and validated).
    pub certificate_info: Option<crate::cert::CertificateInfo>,
    /// Whether the connection is valid.
    pub is_valid: bool,
    /// Validation failure reason, if any.
    pub failure_reason: Option<String>,
}

/// Orchestrates certificate and IP validation for mTLS connections.
#[derive(Clone)]
pub struct ConnectionValidator {
    /// Certificate manager for this validator.
    certificate_manager: CertificateManager,
    /// IP whitelist validator (optional).
    ip_validator: Option<IPWhitelistValidator>,
    /// Secure socket factory.
    socket_factory: SecureSocketFactory,
    /// Whether this validator is for a server (true) or client (false).
    is_server: bool,
}

impl ConnectionValidator {
    /// Creates a new ConnectionValidator for server use.
    pub fn create_for_server(config: ServerConfig) -> Result<Self> {
        // Create certificate manager for server
        let cert_manager = CertificateManager::for_server(
            config.cert_path,
            config.key_path,
            config.ca_cert_path,
        )?;

        // Create TLS configuration for server
        let tls_config = TlsConfig::new_server(cert_manager.clone());

        // Create IP whitelist validator if configured
        let ip_validator = if config.client_ipv4_whitelist.is_some() || config.client_ipv6_whitelist.is_some() {
            let mut ip_config = crate::config::IpWhitelistConfig::new();
            if let Some(ipv4_nets) = config.client_ipv4_whitelist {
                ip_config.ipv4 = ipv4_nets;
            }
            if let Some(ipv6_nets) = config.client_ipv6_whitelist {
                ip_config.ipv6 = ipv6_nets;
            }
            Some(IPWhitelistValidator::new(&ip_config))
        } else {
            None
        };

        // Create secure socket factory with optional IP validator
        let socket_factory = if let Some(validator) = &ip_validator {
            SecureSocketFactory::with_ip_validator(tls_config, validator.clone())
        } else {
            SecureSocketFactory::new(tls_config)
        };

        Ok(Self {
            certificate_manager: cert_manager,
            ip_validator,
            socket_factory,
            is_server: true,
        })
    }

    /// Creates a new ConnectionValidator for client use.
    pub fn create_for_client(config: ClientConfig) -> Result<Self> {
        // Create certificate manager for client
        let cert_manager = CertificateManager::for_client(
            config.cert_path,
            config.key_path,
            config.ca_cert_path,
        )?;

        // Create TLS configuration for client
        let tls_config = TlsConfig::new_client(cert_manager.clone())
            .with_verify_server(config.verify_server);

        // Create IP whitelist validator if configured
        let ip_validator = if config.server_ipv4_whitelist.is_some() || config.server_ipv6_whitelist.is_some() {
            let mut ip_config = crate::config::IpWhitelistConfig::new();
            if let Some(ipv4_nets) = config.server_ipv4_whitelist {
                ip_config.ipv4 = ipv4_nets;
            }
            if let Some(ipv6_nets) = config.server_ipv6_whitelist {
                ip_config.ipv6 = ipv6_nets;
            }
            Some(IPWhitelistValidator::new(&ip_config))
        } else {
            None
        };

        // Create secure socket factory with optional IP validator
        let socket_factory = if let Some(validator) = &ip_validator {
            SecureSocketFactory::with_ip_validator(tls_config, validator.clone())
        } else {
            SecureSocketFactory::new(tls_config)
        };

        Ok(Self {
            certificate_manager: cert_manager,
            ip_validator,
            socket_factory,
            is_server: false,
        })
    }

    /// Validates an outgoing connection (for clients).
    pub async fn validate_outgoing(
        &self,
        host: &str,
        port: u16,
    ) -> Result<ValidationResult> {
        if self.is_server {
            return Err(ValidationError::Connection(
                "Cannot validate outgoing connection on server validator".to_string(),
            ).into());
        }

        // Resolve host to IP address
        let addr: SocketAddr = format!("{}:{}", host, port).parse()
            .map_err(|e| ValidationError::Connection(format!("Invalid address {}:{}: {}", host, port, e)))?;

        // Create a TLS socket (this will perform IP validation and TLS handshake)
        match self.socket_factory.create_client_socket(addr).await {
            Ok(tls_stream) => {
                // Extract remote IP from the socket
                let remote_ip = tls_stream.get_ref().0.peer_addr()
                    .map_err(|e| ValidationError::Connection(format!("Failed to get peer address: {}", e)))?.ip();

                // For now, we don't have a way to extract the server's certificate in the client side.
                // In a real implementation, we might want to extract it from the TLS session.
                Ok(ValidationResult {
                    remote_ip,
                    certificate_info: None,
                    is_valid: true,
                    failure_reason: None,
                })
            }
            Err(e) => {
                Ok(ValidationResult {
                    remote_ip: addr.ip(),
                    certificate_info: None,
                    is_valid: false,
                    failure_reason: Some(format!("Connection validation failed: {}", e)),
                })
            }
        }
    }

    /// Validates an incoming connection (for servers).
    pub async fn validate_incoming(
        &self,
        stream: TcpStream,
    ) -> Result<(ValidationResult, tokio_rustls::server::TlsStream<TcpStream>)> {
        if !self.is_server {
            return Err(ValidationError::Connection(
                "Cannot validate incoming connection on client validator".to_string(),
            ).into());
        }

        let client_addr = stream.peer_addr()
            .map_err(|e| ValidationError::Connection(format!("Failed to get peer address: {}", e)))?;

        // Create a TLS socket (this will perform IP validation and TLS handshake)
        match self.socket_factory.create_server_socket(stream, client_addr).await {
            Ok(tls_stream) => {
                // Extract remote IP from the socket
                let remote_ip = client_addr.ip();

                // Extract client certificate information if available
                let certificate_info = if let Some(session) = tls_stream.get_ref().1.peer_certificates() {
                    if !session.is_empty() {
                        // Parse the first certificate in the chain
                        match x509_parser::parse_x509_certificate(&session[0]) {
                            Ok((_, cert)) => Some(crate::cert::CertificateInfo::from_x509(&cert)),
                            Err(e) => {
                                // We couldn't parse the certificate, but the TLS handshake succeeded.
                                // This might be okay if the certificate is used only for authentication and not for extraction.
                                None
                            }
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                let validation_result = ValidationResult {
                    remote_ip,
                    certificate_info,
                    is_valid: true,
                    failure_reason: None,
                };

                Ok((validation_result, tls_stream))
            }
            Err(e) => {
                let validation_result = ValidationResult {
                    remote_ip: client_addr.ip(),
                    certificate_info: None,
                    is_valid: false,
                    failure_reason: Some(format!("Connection validation failed: {}", e)),
                };
                Err(e)
            }
        }
    }

    /// Returns a reference to the certificate manager.
    pub fn certificate_manager(&self) -> &CertificateManager {
        &self.certificate_manager
    }

    /// Returns a reference to the IP validator, if any.
    pub fn ip_validator(&self) -> Option<&IPWhitelistValidator> {
        self.ip_validator.as_ref()
    }

    /// Returns a reference to the secure socket factory.
    pub fn socket_factory(&self) -> &SecureSocketFactory {
        &self.socket_factory
    }

    /// Returns whether this validator is for a server.
    pub fn is_server(&self) -> bool {
        self.is_server
    }
}
