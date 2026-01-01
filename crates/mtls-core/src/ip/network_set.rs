//! Network set for efficient IP network storage and lookup.

use crate::error::Result;
use ipnetwork::IpNetwork;
use std::collections::HashSet;
use std::net::IpAddr;

/// A set of IP networks for efficient lookup.
#[derive(Debug, Clone, Default)]
pub struct NetworkSet {
    /// IPv4 networks.
    ipv4_networks: Vec<IpNetwork>,
    /// IPv6 networks.
    ipv6_networks: Vec<IpNetwork>,
    /// IPv4 addresses (for individual IPs, not networks).
    ipv4_addresses: HashSet<std::net::Ipv4Addr>,
    /// IPv6 addresses (for individual IPs, not networks).
    ipv6_addresses: HashSet<std::net::Ipv6Addr>,
}

impl NetworkSet {
    /// Creates a new empty NetworkSet.
    pub fn new() -> Self {
        Self {
            ipv4_networks: Vec::new(),
            ipv6_networks: Vec::new(),
            ipv4_addresses: HashSet::new(),
            ipv6_addresses: HashSet::new(),
        }
    }

    /// Adds a network to the set.
    pub fn add_network(&mut self, network: IpNetwork) -> Result<()> {
        match network {
            IpNetwork::V4(net) => {
                self.ipv4_networks.push(IpNetwork::V4(net));
            }
            IpNetwork::V6(net) => {
                self.ipv6_networks.push(IpNetwork::V6(net));
            }
        }
        Ok(())
    }

    /// Adds an individual IP address to the set.
    pub fn add_address(&mut self, addr: IpAddr) {
        match addr {
            IpAddr::V4(ipv4) => {
                self.ipv4_addresses.insert(ipv4);
            }
            IpAddr::V6(ipv6) => {
                self.ipv6_addresses.insert(ipv6);
            }
        }
    }

    /// Checks if an IP address is contained in the set (either as an individual address or within a network).
    pub fn contains(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(ipv4) => {
                if self.ipv4_addresses.contains(&ipv4) {
                    return true;
                }
                self.ipv4_networks
                    .iter()
                    .any(|network| network.contains(std::net::IpAddr::V4(ipv4)))
            }
            IpAddr::V6(ipv6) => {
                if self.ipv6_addresses.contains(&ipv6) {
                    return true;
                }
                self.ipv6_networks
                    .iter()
                    .any(|network| network.contains(std::net::IpAddr::V6(ipv6)))
            }
        }
    }

    /// Returns the number of networks (both IPv4 and IPv6) in the set.
    pub fn network_count(&self) -> usize {
        self.ipv4_networks.len() + self.ipv6_networks.len()
    }

    /// Returns the number of individual IP addresses in the set.
    pub fn address_count(&self) -> usize {
        self.ipv4_addresses.len() + self.ipv6_addresses.len()
    }

    /// Returns an iterator over all IPv4 networks.
    pub fn ipv4_networks(&self) -> impl Iterator<Item = &IpNetwork> {
        self.ipv4_networks.iter()
    }

    /// Returns an iterator over all IPv6 networks.
    pub fn ipv6_networks(&self) -> impl Iterator<Item = &IpNetwork> {
        self.ipv6_networks.iter()
    }

    /// Returns an iterator over all IPv4 addresses.
    pub fn ipv4_addresses(&self) -> impl Iterator<Item = &std::net::Ipv4Addr> {
        self.ipv4_addresses.iter()
    }

    /// Returns an iterator over all IPv6 addresses.
    pub fn ipv6_addresses(&self) -> impl Iterator<Item = &std::net::Ipv6Addr> {
        self.ipv6_addresses.iter()
    }

    /// Clears all networks and addresses from the set.
    pub fn clear(&mut self) {
        self.ipv4_networks.clear();
        self.ipv6_networks.clear();
        self.ipv4_addresses.clear();
        self.ipv6_addresses.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_network_set() {
        let mut set = NetworkSet::new();
        let network = IpNetwork::from_str("192.168.1.0/24").unwrap();
        set.add_network(network).unwrap();
        let addr = IpAddr::from_str("192.168.1.100").unwrap();
        assert!(set.contains(addr));
        let addr2 = IpAddr::from_str("192.168.2.100").unwrap();
        assert!(!set.contains(addr2));
    }

    #[test]
    fn test_address_set() {
        let mut set = NetworkSet::new();
        let addr = IpAddr::from_str("10.0.0.1").unwrap();
        set.add_address(addr);
        assert!(set.contains(addr));
        let addr2 = IpAddr::from_str("10.0.0.2").unwrap();
        assert!(!set.contains(addr2));
    }
}
