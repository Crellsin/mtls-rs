//! TLS configuration for mTLS authentication.

use crate::error::{Result, TlsError};
use crate::cert::CertificateManager;
use std::sync::Arc;

/// TLS configuration for creating client and server TLS contexts.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Certificate manager for this configuration.
    certificate_manager: CertificateManager,
    /// Minimum TLS version (default: TLS 1.2).
    min_tls_version: TlsVersion,
    /// Maximum TLS version (default: TLS 1.3).
    max_tls_version: TlsVersion,
    /// Whether to require client authentication (for servers).
    require_client_auth: bool,
    /// Whether to verify the server certificate (for clients).
    verify_server: bool,
    /// Allowed cipher suites (if None, use secure defaults).
    cipher_suites: Option<Vec<CipherSuite>>,
}

/// TLS version enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    /// TLS 1.2
    Tls12,
    /// TLS 1.3
    Tls13,
}

/// Cipher suite enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    EcdheRsaWithAes256GcmSha384,
    /// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    EcdheRsaWithAes128GcmSha256,
    /// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    EcdheEcdsaWithAes256GcmSha384,
    /// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    EcdheEcdsaWithAes128GcmSha256,
    /// TLS_AES_256_GCM_SHA384 (TLS 1.3)
    Aes256GcmSha384,
    /// TLS_AES_128_GCM_SHA256 (TLS 1.3)
    Aes128GcmSha256,
    /// TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)
    Chacha20Poly1305Sha256,
}

impl TlsConfig {
    /// Creates a new TLS configuration for a server.
    pub fn new_server(certificate_manager: CertificateManager) -> Self {
        Self {
            certificate_manager,
            min_tls_version: TlsVersion::Tls12,
            max_tls_version: TlsVersion::Tls13,
            require_client_auth: true,
            verify_server: false, // Not applicable for servers
            cipher_suites: None,
        }
    }

    /// Creates a new TLS configuration for a client.
    pub fn new_client(certificate_manager: CertificateManager) -> Self {
        Self {
            certificate_manager,
            min_tls_version: TlsVersion::Tls12,
            max_tls_version: TlsVersion::Tls13,
            require_client_auth: false, // Not applicable for clients
            verify_server: true,
            cipher_suites: None,
        }
    }

    /// Sets the minimum TLS version.
    pub fn with_min_tls_version(mut self, version: TlsVersion) -> Self {
        self.min_tls_version = version;
        self
    }

    /// Sets the maximum TLS version.
    pub fn with_max_tls_version(mut self, version: TlsVersion) -> Self {
        self.max_tls_version = version;
        self
    }

    /// Sets whether to require client authentication (for servers).
    pub fn with_require_client_auth(mut self, require: bool) -> Self {
        self.require_client_auth = require;
        self
    }

    /// Sets whether to verify the server certificate (for clients).
    pub fn with_verify_server(mut self, verify: bool) -> Self {
        self.verify_server = verify;
        self
    }

    /// Sets the allowed cipher suites.
    pub fn with_cipher_suites(mut self, suites: Vec<CipherSuite>) -> Self {
        self.cipher_suites = Some(suites);
        self
    }

    /// Returns a reference to the certificate manager.
    pub fn certificate_manager(&self) -> &CertificateManager {
        &self.certificate_manager
    }

    /// Returns the minimum TLS version.
    pub fn min_tls_version(&self) -> TlsVersion {
        self.min_tls_version
    }

    /// Returns the maximum TLS version.
    pub fn max_tls_version(&self) -> TlsVersion {
        self.max_tls_version
    }

    /// Returns whether client authentication is required (for servers).
    pub fn require_client_auth(&self) -> bool {
        self.require_client_auth
    }

    /// Returns whether to verify the server certificate (for clients).
    pub fn verify_server(&self) -> bool {
        self.verify_server
    }

    /// Returns the allowed cipher suites, if specified.
    pub fn cipher_suites(&self) -> Option<&[CipherSuite]> {
        self.cipher_suites.as_deref()
    }
}
