//! Integration tests for mTLS core functionality.

use mtls_core::{ConnectionValidator, ServerConfig, ClientConfig, CertificateManager};
use std::path::Path;

#[test]
fn test_certificate_manager_creation() {
    // Use test certificates
    let cert_path = Path::new("tests/certs/server/server.crt");
    let key_path = Path::new("tests/certs/server/server.key");
    let ca_cert_path = Path::new("tests/certs/server/ca.crt");

    let manager = CertificateManager::for_server(cert_path, key_path, ca_cert_path);
    assert!(manager.is_ok());
}

#[test]
fn test_certificate_manager_client_creation() {
    let cert_path = Path::new("tests/certs/client/client.crt");
    let key_path = Path::new("tests/certs/client/client.key");
    let ca_cert_path = Path::new("tests/certs/client/ca.crt");

    let manager = CertificateManager::for_client(cert_path, key_path, Some(ca_cert_path));
    assert!(manager.is_ok());
}

#[test]
fn test_server_config_creation() {
    let config = ServerConfig::new(
        Path::new("tests/certs/server/server.crt"),
        Path::new("tests/certs/server/server.key"),
        Path::new("tests/certs/server/ca.crt"),
    );
    assert!(config.is_ok());
}

#[test]
fn test_client_config_creation() {
    let config = ClientConfig::new(
        Path::new("tests/certs/client/client.crt"),
        Path::new("tests/certs/client/client.key"),
    )
    .with_ca_cert_path(Path::new("tests/certs/client/ca.crt"));
    assert!(config.is_ok());
}

#[test]
fn test_connection_validator_creation() {
    let server_config = ServerConfig::new(
        Path::new("tests/certs/server/server.crt"),
        Path::new("tests/certs/server/server.key"),
        Path::new("tests/certs/server/ca.crt"),
    ).unwrap();

    let server_validator = ConnectionValidator::create_for_server(server_config);
    assert!(server_validator.is_ok());

    let client_config = ClientConfig::new(
        Path::new("tests/certs/client/client.crt"),
        Path::new("tests/certs/client/client.key"),
    )
    .with_ca_cert_path(Path::new("tests/certs/client/ca.crt"))
    .unwrap();

    let client_validator = ConnectionValidator::create_for_client(client_config);
    assert!(client_validator.is_ok());
}
