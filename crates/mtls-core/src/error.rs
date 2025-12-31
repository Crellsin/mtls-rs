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
    /// Certificate file not found at the given path.
    #[error("Certificate file not found: {0}")]
    FileNotFound(PathBuf),

    /// Failed to parse certificate data.
    #[error("Failed to parse certificate: {0}")]
    Parse(String),

    /// Certificate validation failed.
    #[error("Certificate validation failed: {0}")]
    Validation(String),

    /// Invalid certificate (e.g., malformed or corrupted).
    #[error("Invalid certificate: {0}")]
    Invalid(String),

    /// Unsupported key type (e.g., not RSA or ECDSA).
    #[error("Unsupported key type: {0}")]
    UnsupportedKeyType(String),

    /// Certificate has expired.
    #[error("Certificate expired")]
    Expired,

    /// Certificate is not yet valid (validity start date in future).
    #[error("Certificate not yet valid")]
    NotYetValid,

    /// Certificate chain validation failed (e.g., untrusted CA).
    #[error("Certificate chain validation failed: {0}")]
    ChainValidation(String),
}

/// Errors related to IP validation.
#[derive(Error, Debug)]
pub enum IpValidationError {
    /// Invalid IP address format.
    #[error("Invalid IP address: {0}")]
    InvalidIp(String),

    /// Invalid CIDR notation.
    #[error("Invalid CIDR notation: {0}")]
    InvalidCidr(String),

    /// IP address is not in the whitelist.
    #[error("IP address {0} not in whitelist")]
    NotInWhitelist(String),

    /// Failed to parse IP whitelist configuration.
    #[error("Failed to parse IP whitelist configuration: {0}")]
    ConfigParse(String),
}

/// Errors related to TLS operations.
#[derive(Error, Debug)]
pub enum TlsError {
    /// TLS configuration error (e.g., invalid cipher suite).
    #[error("TLS configuration error: {0}")]
    Config(String),

    /// TLS handshake error.
    #[error("TLS handshake error: {0}")]
    Handshake(String),

    /// Failed to create TLS context.
    #[error("Failed to create TLS context: {0}")]
    ContextCreation(String),

    /// Unsupported TLS version or cipher.
    #[error("Unsupported TLS version or cipher")]
    Unsupported,
}

/// Errors related to connection validation.
#[derive(Error, Debug)]
pub enum ValidationError {
    /// Certificate required but not provided by client.
    #[error("Certificate required but not provided")]
    CertificateRequired,

    /// IP address not allowed (failed whitelist check).
    #[error("IP address not allowed: {0}")]
    IpNotAllowed(String),

    /// General connection validation failure.
    #[error("Connection validation failed: {0}")]
    Connection(String),

    /// Server validation failed (e.g., server certificate invalid).
    #[error("Server validation failed: {0}")]
    Server(String),

    /// Client validation failed (e.g., client certificate invalid).
    #[error("Client validation failed: {0}")]
    Client(String),
}

/// Convenience type alias for `Result<T, MtlsError>`.
pub type Result<T> = std::result::Result<T, MtlsError>;
