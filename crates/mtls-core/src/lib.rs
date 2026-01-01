//! mTLS authentication core library.
//!
//! This library provides mutual TLS authentication with IP whitelisting for Rust applications.
//! It is designed to be framework-agnostic and can be used with various async runtimes and web frameworks.
//!
//! # Example
//! ```no_run
//! use mtls_core::{ConnectionValidator, ServerConfig, ClientConfig};
//! use std::path::Path;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Server configuration
//! let server_config = ServerConfig::new(
//!     Path::new("certs/server.pem"),
//!     Path::new("certs/server.key"),
//!     Path::new("certs/ca.crt"),
//! );
//!
//! let server_validator = ConnectionValidator::create_for_server(server_config)?;
//!
//! // Client configuration
//! let client_config = ClientConfig::new(
//!     Path::new("certs/client.pem"),
//!     Path::new("certs/client.key"),
//! ).with_ca_cert_path(Path::new("certs/ca.crt"));
//!
//! let client_validator = ConnectionValidator::create_for_client(client_config)?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]
#![warn(unused_extern_crates)]

pub mod cert;
pub mod config;
pub mod error;
pub mod ip;
pub mod socket;
pub mod tls;
pub mod validator;

// Re-export commonly used types
pub use cert::{CertificateInfo, CertificateManager, CertificateValidation};
pub use config::{ClientConfig, IpWhitelistConfig, ServerConfig};
pub use error::{MtlsError, Result};
pub use ip::{IPWhitelistValidator, NetworkSet};
pub use tls::{default_backend, TlsBackend, TlsBackendType, TlsConfig};
pub use validator::ConnectionValidator;

/// Prelude module for convenient imports.
pub mod prelude {
    pub use crate::cert::{CertificateInfo, CertificateManager, CertificateValidation};
    pub use crate::config::{ClientConfig, IpWhitelistConfig, ServerConfig};
    pub use crate::error::{MtlsError, Result};
    pub use crate::ip::{IPWhitelistValidator, NetworkSet};
    pub use crate::tls::{default_backend, TlsBackend, TlsBackendType, TlsConfig};
    pub use crate::validator::ConnectionValidator;
}
