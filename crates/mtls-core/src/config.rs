//! Configuration structures for the mTLS authentication library.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::net::IpAddr;
use ipnetwork::IpNetwork;

/// Configuration for server-side mTLS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Path to the server certificate file (PEM format).
    pub cert_path: PathBuf,
    /// Path to the server private key file (PEM format).
    pub key_path: PathBuf,
    /// Path to the CA certificate file for validating client certificates.
    pub ca_cert_path: PathBuf,
    /// List of allowed IPv4 networks for clients (optional).
    #[serde(default)]
    pub client_ipv4_whitelist: Option<Vec<IpNetwork>>,
    /// List of allowed IPv6 networks for clients (optional).
    #[serde(default)]
    pub client_ipv6_whitelist: Option<Vec<IpNetwork>>,
    /// Whether to require client certificate authentication.
    #[serde(default = "default_require_client_auth")]
    pub require_client_auth: bool,
    /// Timeout for connection validation in seconds (optional).
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

fn default_require_client_auth() -> bool {
    true
}

/// Configuration for client-side mTLS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Path to the client certificate file (PEM format).
    pub cert_path: PathBuf,
    /// Path to the client private key file (PEM format).
    pub key_path: PathBuf,
    /// Path to the CA certificate file for validating server certificates (optional).
    #[serde(default)]
    pub ca_cert_path: Option<PathBuf>,
    /// List of allowed IPv4 networks for servers (optional).
    #[serde(default)]
    pub server_ipv4_whitelist: Option<Vec<IpNetwork>>,
    /// List of allowed IPv6 networks for servers (optional).
    #[serde(default)]
    pub server_ipv6_whitelist: Option<Vec<IpNetwork>>,
    /// Whether to verify the server certificate.
    #[serde(default = "default_verify_server")]
    pub verify_server: bool,
    /// Timeout for connection validation in seconds (optional).
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

fn default_verify_server() -> bool {
    true
}

/// Generic configuration for IP whitelist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpWhitelistConfig {
    /// IPv4 networks to allow.
    #[serde(default)]
    pub ipv4: Vec<IpNetwork>,
    /// IPv6 networks to allow.
    #[serde(default)]
    pub ipv6: Vec<IpNetwork>,
    /// Whether to validate IPv4 addresses.
    #[serde(default = "default_validate_ipv4")]
    pub validate_ipv4: bool,
    /// Whether to validate IPv6 addresses.
    #[serde(default = "default_validate_ipv6")]
    pub validate_ipv6: bool,
}

fn default_validate_ipv4() -> bool {
    true
}

fn default_validate_ipv6() -> bool {
    true
}

impl ServerConfig {
    /// Creates a new ServerConfig with the required certificate paths.
    pub fn new(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
        ca_cert_path: impl AsRef<Path>,
    ) -> Self {
        Self {
            cert_path: cert_path.as_ref().to_path_buf(),
            key_path: key_path.as_ref().to_path_buf(),
            ca_cert_path: ca_cert_path.as_ref().to_path_buf(),
            client_ipv4_whitelist: None,
            client_ipv6_whitelist: None,
            require_client_auth: true,
            timeout_seconds: None,
        }
    }

    /// Sets the client IPv4 whitelist.
    pub fn with_client_ipv4_whitelist(mut self, networks: Vec<IpNetwork>) -> Self {
        self.client_ipv4_whitelist = Some(networks);
        self
    }

    /// Sets the client IPv6 whitelist.
    pub fn with_client_ipv6_whitelist(mut self, networks: Vec<IpNetwork>) -> Self {
        self.client_ipv6_whitelist = Some(networks);
        self
    }

    /// Sets whether to require client authentication.
    pub fn with_require_client_auth(mut self, require: bool) -> Self {
        self.require_client_auth = require;
        self
    }
}

impl ClientConfig {
    /// Creates a new ClientConfig with the required certificate paths.
    pub fn new(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Self {
        Self {
            cert_path: cert_path.as_ref().to_path_buf(),
            key_path: key_path.as_ref().to_path_buf(),
            ca_cert_path: None,
            server_ipv4_whitelist: None,
            server_ipv6_whitelist: None,
            verify_server: true,
            timeout_seconds: None,
        }
    }

    /// Sets the CA certificate path.
    pub fn with_ca_cert_path(mut self, ca_cert_path: impl AsRef<Path>) -> Self {
        self.ca_cert_path = Some(ca_cert_path.as_ref().to_path_buf());
        self
    }

    /// Sets the server IPv4 whitelist.
    pub fn with_server_ipv4_whitelist(mut self, networks: Vec<IpNetwork>) -> Self {
        self.server_ipv4_whitelist = Some(networks);
        self
    }

    /// Sets the server IPv6 whitelist.
    pub fn with_server_ipv6_whitelist(mut self, networks: Vec<IpNetwork>) -> Self {
        self.server_ipv6_whitelist = Some(networks);
        self
    }

    /// Sets whether to verify the server certificate.
    pub fn with_verify_server(mut self, verify: bool) -> Self {
        self.verify_server = verify;
        self
    }
}

impl IpWhitelistConfig {
    /// Creates a new empty IP whitelist configuration.
    pub fn new() -> Self {
        Self {
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            validate_ipv4: true,
            validate_ipv6: true,
        }
    }

    /// Adds an IPv4 network to the whitelist.
    pub fn add_ipv4_network(&mut self, network: IpNetwork) {
        self.ipv4.push(network);
    }

    /// Adds an IPv6 network to the whitelist.
    pub fn add_ipv6_network(&mut self, network: IpNetwork) {
        self.ipv6.push(network);
    }

    /// Checks if an IP address is allowed by the whitelist.
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                if !self.validate_ipv4 {
                    return true;
                }
                self.ipv4.iter().any(|network| network.contains(std::net::IpAddr::V4(ipv4)))
            }
            IpAddr::V6(ipv6) => {
                if !self.validate_ipv6 {
                    return true;
                }
                self.ipv6.iter().any(|network| network.contains(std::net::IpAddr::V6(ipv6)))
            }
        }
    }
}

impl Default for IpWhitelistConfig {
    fn default() -> Self {
        Self::new()
    }
}
