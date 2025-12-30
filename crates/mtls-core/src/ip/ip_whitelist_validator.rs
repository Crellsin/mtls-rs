//! IP whitelist validator for mTLS authentication.

use crate::error::{Result, IpValidationError};
use crate::config::IpWhitelistConfig;
use std::net::IpAddr;
use ipnetwork::IpNetwork;

/// Validates IP addresses against a whitelist.
#[derive(Debug, Clone)]
pub struct IPWhitelistValidator {
    /// IPv4 networks allowed.
    ipv4_networks: Vec<IpNetwork>,
    /// IPv6 networks allowed.
    ipv6_networks: Vec<IpNetwork>,
    /// Whether to validate IPv4 addresses.
    validate_ipv4: bool,
    /// Whether to validate IPv6 addresses.
    validate_ipv6: bool,
}

impl IPWhitelistValidator {
    /// Creates a new IPWhitelistValidator from configuration.
    pub fn new(config: &IpWhitelistConfig) -> Self {
        Self {
            ipv4_networks: config.ipv4.clone(),
            ipv6_networks: config.ipv6.clone(),
            validate_ipv4: config.validate_ipv4,
            validate_ipv6: config.validate_ipv6,
        }
    }

    /// Creates a new IPWhitelistValidator with empty whitelists (allowing all IPs).
    pub fn empty() -> Self {
        Self {
            ipv4_networks: Vec::new(),
            ipv6_networks: Vec::new(),
            validate_ipv4: false,
            validate_ipv6: false,
        }
    }

    /// Creates a new IPWhitelistValidator with the given IPv4 and IPv6 networks.
    pub fn from_networks(
        ipv4_networks: Vec<IpNetwork>,
        ipv6_networks: Vec<IpNetwork>,
        validate_ipv4: bool,
        validate_ipv6: bool,
    ) -> Self {
        Self {
            ipv4_networks,
            ipv6_networks,
            validate_ipv4,
            validate_ipv6,
        }
    }

    /// Validates an IP address against the whitelist.
    pub fn validate(&self, ip: IpAddr) -> Result<()> {
        match ip {
            IpAddr::V4(ipv4) => {
                if !self.validate_ipv4 {
                    return Ok(());
                }
                if self.ipv4_networks.is_empty() {
                    // If no networks are specified, we allow all (or could deny, depending on policy).
                    // We'll allow by default to be permissive.
                    return Ok(());
                }
                if self.ipv4_networks.iter().any(|network| network.contains(std::net::IpAddr::V4(ipv4))) {
                    Ok(())
                } else {
                    Err(IpValidationError::NotInWhitelist(ip.to_string()).into())
                }
            }
            IpAddr::V6(ipv6) => {
                if !self.validate_ipv6 {
                    return Ok(());
                }
                if self.ipv6_networks.is_empty() {
                    return Ok(());
                }
                if self.ipv6_networks.iter().any(|network| network.contains(std::net::IpAddr::V6(ipv6))) {
                    Ok(())
                } else {
                    Err(IpValidationError::NotInWhitelist(ip.to_string()).into())
                }
            }
        }
    }

    /// Adds an IPv4 network to the whitelist.
    pub fn add_ipv4_network(&mut self, network: IpNetwork) {
        self.ipv4_networks.push(network);
    }

    /// Adds an IPv6 network to the whitelist.
    pub fn add_ipv6_network(&mut self, network: IpNetwork) {
        self.ipv6_networks.push(network);
    }

    /// Returns a reference to the IPv4 networks.
    pub fn ipv4_networks(&self) -> &[IpNetwork] {
        &self.ipv4_networks
    }

    /// Returns a reference to the IPv6 networks.
    pub fn ipv6_networks(&self) -> &[IpNetwork] {
        &self.ipv6_networks
    }

    /// Returns whether IPv4 validation is enabled.
    pub fn validate_ipv4(&self) -> bool {
        self.validate_ipv4
    }

    /// Returns whether IPv6 validation is enabled.
    pub fn validate_ipv6(&self) -> bool {
        self.validate_ipv6
    }

    /// Sets whether to validate IPv4 addresses.
    pub fn set_validate_ipv4(&mut self, validate: bool) {
        self.validate_ipv4 = validate;
    }

    /// Sets whether to validate IPv6 addresses.
    pub fn set_validate_ipv6(&mut self, validate: bool) {
        self.validate_ipv6 = validate;
    }
}
