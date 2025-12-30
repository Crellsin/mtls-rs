//! Error types for the mTLS authentication library.

use thiserror::Error;
use std::io;
use std::path::PathBuf;

/// Main error type for the mTLS library.
#[derive(Error, Debug)]
pub enum MtlsError {
    /// I/O error (e.g., reading certificate files).
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Certificate error.
    #[error("Certificate error: {0}")]
    Certificate(#[from] CertificateError),

    /// IP validation error.
    #[error("IP validation error: {0}")]
    IpValidation(#[from] IpValidationError),

    /// TLS error.
    #[error("TLS error: {0}")]
    Tls(#[from] TlsError),

    /// Validation error (e.g., connection validation failed).
    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Other errors.
    #[error("{0}")]
    Other(String),
}

/// Errors related to certificate operations.
#[derive(Error, Debug)]
pub enum CertificateError {
    #[error("Certificate file not found: {0}")]
    FileNotFound(PathBuf),

    #[error("Failed to parse certificate: {0}")]
    Parse(String),

    #[error("Certificate validation failed: {0}")]
    Validation(String),

    #[error("Invalid certificate: {0}")]
    Invalid(String),

    #[error("Unsupported key type: {0}")]
    UnsupportedKeyType(String),

    #[error("Certificate expired")]
    Expired,

    #[error("Certificate not yet valid")]
    NotYetValid,

    #[error("Certificate chain validation failed: {0}")]
    ChainValidation(String),
}

/// Errors related to IP validation.
#[derive(Error, Debug)]
pub enum IpValidationError {
    #[error("Invalid IP address: {0}")]
    InvalidIp(String),

    #[error("Invalid CIDR notation: {0}")]
    InvalidCidr(String),

    #[error("IP address {0} not in whitelist")]
    NotInWhitelist(String),

    #[error("Failed to parse IP whitelist configuration: {0}")]
    ConfigParse(String),
}

/// Errors related to TLS operations.
#[derive(Error, Debug)]
pub enum TlsError {
    #[error("TLS configuration error: {0}")]
    Config(String),

    #[error("TLS handshake error: {0}")]
    Handshake(String),

    #[error("Failed to create TLS context: {0}")]
    ContextCreation(String),

    #[error("Unsupported TLS version or cipher")]
    Unsupported,
}

/// Errors related to connection validation.
#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("Certificate required but not provided")]
    CertificateRequired,

    #[error("IP address not allowed: {0}")]
    IpNotAllowed(String),

    #[error("Connection validation failed: {0}")]
    Connection(String),

    #[error("Server validation failed: {0}")]
    Server(String),

    #[error("Client validation failed: {0}")]
    Client(String),
}

// Convenience type alias for Result<T, MtlsError>.
pub type Result<T> = std::result::Result<T, MtlsError>;
